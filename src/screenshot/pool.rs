use anyhow::{Result, Context};
use fantoccini::Client;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

use crate::screenshot::client;
use crate::screenshot::config::{
    CONNECTION_TIMEOUT, MAX_CONNECTIONS, MIN_CONNECTIONS
};

/// Represents a client connection with its creation timestamp
struct PooledClient {
    client: Client,
    created_at: Instant,
}

/// Connection pool for managing WebDriver client instances
#[derive(Clone)]
pub struct ConnectionPool {
    webdriver_url: String,
    viewport_size: Option<(u32, u32)>,
    headless: bool,
    pool: Arc<Mutex<VecDeque<PooledClient>>>,
    semaphore: Arc<Semaphore>,
    pub active_connections: Arc<AtomicUsize>,
    pub total_connections: Arc<AtomicUsize>,
    last_scale_time: Arc<Mutex<Instant>>,
    scale_interval: Duration,
    max_client_age: Duration,
}

impl ConnectionPool {
    /// Create a new connection pool with the specified configuration
    pub async fn new(
        webdriver_url: &str,
        viewport_size: Option<(u32, u32)>,
        headless: bool,
    ) -> Result<Self> {
        debug!("Creating new connection pool with WebDriver URL: {}", webdriver_url);
        
        let pool = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_CONNECTIONS)));
        let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let total_connections = Arc::new(AtomicUsize::new(0));
        let last_scale_time = Arc::new(Mutex::new(Instant::now()));
        let scale_interval = Duration::from_secs(60); // Scale at most once a minute
        let max_client_age = Duration::from_secs(3600); // 1 hour max session

        let connection_pool = Self {
            webdriver_url: webdriver_url.to_string(),
            viewport_size,
            headless,
            pool,
            semaphore,
            active_connections,
            total_connections,
            last_scale_time,
            scale_interval,
            max_client_age,
        };

        // Initialize with minimum connections
        debug!("Initializing connection pool with {} connections", MIN_CONNECTIONS);
        {
            let mut pool = connection_pool.pool.lock().await;
            for i in 0..MIN_CONNECTIONS {
                trace!("Creating initial connection {}/{}", i+1, MIN_CONNECTIONS);
                match client::create_client(&connection_pool.webdriver_url, viewport_size, headless).await {
                    Ok(client) => {
                        pool.push_back(PooledClient {
                            client,
                            created_at: Instant::now(),
                        });
                        connection_pool.total_connections.fetch_add(1, Ordering::SeqCst);
                        trace!("Successfully created initial connection {}/{}", i+1, MIN_CONNECTIONS);
                    }
                    Err(e) => {
                        warn!("Failed to create initial connection {}/{}: {}", i+1, MIN_CONNECTIONS, e);
                    }
                }
            }
        }

        info!("Connection pool initialized with {} initial connections", 
              connection_pool.total_connections.load(Ordering::SeqCst));
              
        Ok(connection_pool)
    }

    /// Dynamically adjusts the connection pool size based on usage
    /// 
    /// Scales up or down the number of browser connections based on
    /// current load to optimize resource usage while maintaining performance.
    pub async fn scale_pool(&self) -> Result<()> {
        let active = self.active_connections.load(Ordering::Acquire);
        let total = self.total_connections.load(Ordering::Acquire);
        
        trace!("Evaluating pool scaling: active={}, total={}", active, total);
        
        // Guard against division by zero
        if total == 0 {
            debug!("No connections in pool yet, cannot scale");
            return Ok(());
        }
        
        // Calculate usage percentage safely using floating point
        let usage_percent = (active as f64 * 100.0) / (total as f64);
        
        // Scale up logic - create client outside of any locks
        if usage_percent > 80.0 && total < MAX_CONNECTIONS {
            debug!("High connection usage ({:.1}%), scaling up from {} connections", 
                  usage_percent, total);
            
            // Create new client outside of any lock
            let new_client = match client::create_client(
                &self.webdriver_url,
                self.viewport_size,
                self.headless
            ).await {
                Ok(client) => client,
                Err(e) => {
                    warn!("Failed to scale up connection pool: {}", e);
                    return Ok(());
                }
            };
            
            // Use a scope guard pattern to ensure the client is always closed if we fail
            // to add it to the pool (prevents leaks)
            struct ClientGuard {
                client: Option<Client>,
            }
            
            impl ClientGuard {
                fn new(client: Client) -> Self {
                    Self { client: Some(client) }
                }
                
                fn take(&mut self) -> Client {
                    self.client.take().expect("Client already taken")
                }
            }
            
            impl Drop for ClientGuard {
                fn drop(&mut self) {
                    if let Some(client) = &self.client {
                        warn!("Client guard dropping client that wasn't added to pool");
                        // Can't do async close in drop, so we spawn a task
                        let client_clone = client.clone();
                        tokio::spawn(async move {
                            if let Err(e) = client_clone.close().await {
                                warn!("Error closing leaked client: {}", e);
                            }
                        });
                    }
                }
            }
            
            let mut guard = ClientGuard::new(new_client);
            
            // Now that we have a client, add it to the pool with minimal lock time
            // Use a timeout to prevent deadlock if the lock is held too long
            match timeout(Duration::from_secs(5), self.pool.lock()).await {
                Ok(mut pool) => {
                    pool.push_back(PooledClient {
                        client: guard.take(),
                        created_at: Instant::now(),
                    });
                    self.total_connections.fetch_add(1, Ordering::Release);
                    info!("Scaled up connection pool to {}", total + 1);
                }
                Err(_) => {
                    warn!("Timeout waiting for pool lock during scale up");
                    // guard will close client on drop
                    return Ok(());
                }
            }
        } 
        // Scale down logic - with safe lock management
        else if usage_percent < 20.0 && total > MIN_CONNECTIONS {
            debug!("Low connection usage ({:.1}%), scaling down from {} connections", 
                  usage_percent, total);
                  
            // Use a timeout to prevent deadlock if the lock is held too long
            let client_to_close = match timeout(Duration::from_secs(5), self.pool.lock()).await {
                Ok(mut pool) => pool.pop_back().map(|pc| pc.client),
                Err(_) => {
                    warn!("Timeout waiting for pool lock during scale down");
                    return Ok(());
                }
            };
            
            // Close client outside of lock
            if let Some(client) = client_to_close {
                if let Err(e) = client.close().await {
                    warn!("Error closing connection during scale down: {}", e);
                }
                self.total_connections.fetch_sub(1, Ordering::Release);
                info!("Scaled down connection pool to {}", total - 1);
            }
        }
        
        Ok(())
    }

    /// Gets a WebDriver client from the pool or creates a new one
    pub async fn get_client(&self) -> Result<Client> {
        debug!("Attempting to acquire client from pool");
        
        // Acquire a permit from the semaphore with timeout
        let permit = match timeout(
            CONNECTION_TIMEOUT,
            self.semaphore.acquire()
        ).await {
            Ok(result) => match result {
                Ok(permit) => permit,
                Err(e) => {
                    error!("Failed to acquire semaphore permit: {}", e);
                    return Err(anyhow::anyhow!("Failed to acquire connection permit: {}", e));
                }
            },
            Err(_) => {
                error!("Timeout waiting for available connection after {:?}", CONNECTION_TIMEOUT);
                return Err(anyhow::anyhow!("Timeout waiting for connection"));
            }
        };

        // Create a permit guard that will be dropped when this function returns
        // This ensures the permit is always released, even on error paths
        struct PermitGuard<'a> {
            _permit: tokio::sync::SemaphorePermit<'a>,
        }

        impl<'a> PermitGuard<'a> {
            fn new(permit: tokio::sync::SemaphorePermit<'a>) -> Self {
                Self { _permit: permit }
            }
        }

        impl<'a> Drop for PermitGuard<'a> {
            fn drop(&mut self) {
                // Permit is automatically dropped here
            }
        }

        let permit_guard = PermitGuard::new(permit);

        trace!("Acquired semaphore permit, getting client from pool");
        
        // Get a client from the pool with minimal lock time
        let pooled_client = {
            let mut pool = self.pool.lock().await;
            pool.pop_front()
        };

        // Process client outside of any locks
        let client = if let Some(pooled_client) = pooled_client {
            // Check if client is too old
            let client_age = Instant::now().duration_since(pooled_client.created_at);
            if client_age > self.max_client_age {
                debug!("Client exceeded max age ({:?}), replacing with fresh instance", client_age);
                // Close old client without holding any locks
                if let Err(e) = pooled_client.client.close().await {
                    warn!("Error closing aged client: {}", e);
                }
                
                // Create a new one
                match client::create_client(
                    &self.webdriver_url,
                    self.viewport_size,
                    self.headless
                ).await {
                    Ok(client) => client,
                    Err(e) => {
                        // Permit guard will be dropped here, releasing the permit
                        error!("Failed to create new client: {}", e);
                        return Err(e).context("Failed to create new client to replace aged one");
                    }
                }
            } else {
                trace!("Reusing existing client from pool (age: {:?})", client_age);
                pooled_client.client
            }
        } else {
            debug!("No clients in pool, creating new client");
            match client::create_client(
                &self.webdriver_url,
                self.viewport_size,
                self.headless
            ).await {
                Ok(client) => client,
                Err(e) => {
                    // Permit guard will be dropped here, releasing the permit
                    error!("Failed to create new client: {}", e);
                    return Err(e).context("Failed to create new client on demand");
                }
            }
        };

        // Update active connection count (already done by permit_guard.activate)
        let active = self.active_connections.load(Ordering::Acquire);
        let total = self.total_connections.load(Ordering::Acquire);
        debug!("Client acquired. Active connections: {}/{}", active, total);
        
        // Check if we need to scale the pool with throttling - do this as a background task
        if active > 0 && total > 0 {
            let should_scale = {
                let mut last_time = self.last_scale_time.lock().await;
                let now = Instant::now();
                if now.duration_since(*last_time) >= self.scale_interval {
                    *last_time = now;
                    true
                } else {
                    false
                }
            };

            if should_scale {
                // Clone what we need for the background task
                let pool_ref = Arc::new(self.clone());
                
                // Spawn a background task to handle scaling
                tokio::spawn(async move {
                    debug!("Pool scaling interval reached, checking if scaling needed in background");
                    if let Err(e) = pool_ref.scale_pool().await {
                        warn!("Error during pool scaling: {}", e);
                    }
                });
            }
        }

        // We'll forget the permit_guard so it doesn't release the semaphore when dropped
        // The permit will be released when return_client is called
        std::mem::forget(permit_guard);

        Ok(client)
    }

    /// Returns a WebDriver client to the connection pool
    /// 
    /// This function is idempotent - calling it multiple times for the same client
    /// or after an error won't cause issues. It ensures the active connection counter
    /// is always properly decremented.
    pub async fn return_client(&self, client: Client) {
        trace!("Returning client to pool");
        
        // Create new pooled client with current timestamp
        let now = Instant::now();
        let pooled_client = PooledClient {
            client,
            created_at: now,
        };
        
        // Add to pool with minimal lock time
        {
            let mut pool = self.pool.lock().await;
            pool.push_back(pooled_client);
        }
        
        // Release a permit from the semaphore
        self.semaphore.add_permits(1);
        
        // Update active connection count
        let active = self.active_connections.fetch_sub(1, Ordering::Release);
        let total = self.total_connections.load(Ordering::Acquire);
        debug!("Client returned to pool. Active connections: {}/{}", active, total);
    }

    /// Closes the specified client without returning it to the pool
    ///
    /// Use this when a client is known to be in an error state
    pub async fn discard_client(&self, client: Client) {
        debug!("Discarding unhealthy client");
        
        // Try to close the client
        if let Err(e) = client.close().await {
            warn!("Error closing discarded client: {}", e);
        }
        
        // Release a permit from the semaphore
        self.semaphore.add_permits(1);
        
        // Update active connection count
        let active = self.active_connections.fetch_sub(1, Ordering::Release);
        let total = self.total_connections.load(Ordering::Acquire);
        debug!("Client discarded. Active connections: {}/{}", active, total);
    }

    /// Closes all WebDriver connections in the pool
    pub async fn close(&self) -> Result<()> {
        info!("Closing connection pool and all WebDriver connections");
        
        // Acquire all permits if possible (with timeout)
        let timeout_duration = Duration::from_secs(5);
        let permits_needed = self.active_connections.load(Ordering::Acquire);
        
        if permits_needed > 0 {
            debug!("Waiting up to {:?} for {} active connections to complete", 
                  timeout_duration, permits_needed);
            
            match timeout(
                timeout_duration,
                self.semaphore.acquire_many(permits_needed as u32)
            ).await {
                Ok(Ok(_)) => {
                    info!("All active connections completed normally");
                },
                Ok(Err(e)) => {
                    warn!("Error waiting for active connections: {}", e);
                },
                Err(_) => {
                    warn!("Timeout waiting for active connections to complete");
                }
            }
        }
        
        // Now close all pooled connections
        let mut pool = self.pool.lock().await;
        let total = pool.len();
        let active = self.active_connections.load(Ordering::Acquire);
        
        debug!("Closing {} pooled connections", total);
        let mut close_errors = 0;
        
        while let Some(pooled_client) = pool.pop_front() {
            if let Err(e) = pooled_client.client.close().await {
                error!("Failed to close WebDriver client: {}", e);
                close_errors += 1;
            }
        }
        
        if close_errors > 0 {
            warn!("Failed to properly close {} WebDriver connections", close_errors);
        }
        
        if active > 0 {
            warn!("Closing with {} active connections that may not be properly cleaned up", active);
        }
        
        // Reset counters
        self.active_connections.store(0, Ordering::Release);
        self.total_connections.store(0, Ordering::Release);
        
        info!("Connection pool shutdown complete");
        Ok(())
    }

    /// Check if a browser client is still healthy
    async fn is_client_healthy(&self, client: &Client) -> bool {
        // First, try a simple operation that shouldn't fail if the connection is alive
        let current_url_result = timeout(
            Duration::from_secs(5), 
            client.current_url()
        ).await;

        match &current_url_result {
            Ok(Ok(_)) => {
                // If the URL check succeeds, try a simple DOM interaction
                // as a more thorough health check
                match timeout(
                    Duration::from_secs(5),
                    client.execute("return document.readyState", vec![])
                ).await {
                    Ok(Ok(_)) => true,
                    Ok(Err(e)) => {
                        debug!("Client failed DOM interaction health check: {}", e);
                        false
                    },
                    Err(_) => {
                        debug!("Timeout during DOM interaction health check");
                        false
                    }
                }
            },
            Ok(Err(e)) => {
                debug!("Client failed URL health check: {}", e);
                false
            },
            Err(_) => {
                debug!("Timeout during URL health check");
                false
            }
        }
    }

    /// Get a healthy client, cleaning up unhealthy ones
    pub async fn get_healthy_client(&self) -> Result<Client> {
        let client = self.get_client().await?;
        
        // Check if client is healthy
        if !self.is_client_healthy(&client).await {
            debug!("Discarding unhealthy client and creating new one");
            
            // Properly discard the unhealthy client
            self.discard_client(client).await;
            
            // Try again with a new client
            return self.get_client().await;
        }
        
        Ok(client)
    }
} 