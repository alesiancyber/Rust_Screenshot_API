use anyhow::{Result, Context};
use chrono;
use fantoccini::Client;
use fantoccini::Locator;
use sanitize_filename::sanitize;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn};
use std::fmt;

use crate::screenshot::config::{MAX_RETRIES, RETRY_DELAY};
use crate::screenshot::model::Screenshot;
use crate::screenshot::pool::ConnectionPool;

/// Manages browser connections and takes screenshots of web pages
pub struct ScreenshotTaker {
    screenshot_dir: String,
    connection_pool: ConnectionPool,
    shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
}

impl fmt::Debug for ScreenshotTaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScreenshotTaker")
            .field("screenshot_dir", &self.screenshot_dir)
            .field("active_connections", &self.connection_pool.active_connections.load(Ordering::Relaxed))
            .field("total_connections", &self.connection_pool.total_connections.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for ScreenshotTaker {
    fn drop(&mut self) {
        // Signal that shutdown is requested to prevent new operations
        self.shutdown_requested.store(true, Ordering::Release);
        debug!("ScreenshotTaker is being dropped, signaling shutdown");
        
        // We can't do async operations in drop, but we can signal
        // that resources should be cleaned up
    }
}

impl ScreenshotTaker {
    /// Creates a new ScreenshotTaker with the specified configuration
    pub async fn new(
        screenshot_dir: &str,
        webdriver_url: Option<&str>,
        viewport_size: Option<(u32, u32)>,
        headless: bool,
    ) -> Result<Self> {
        debug!("Creating new ScreenshotTaker with dir: {}, headless: {}", screenshot_dir, headless);
        
        // Create screenshot directory if it doesn't exist
        trace!("Ensuring screenshot directory exists: {}", screenshot_dir);
        fs::create_dir_all(screenshot_dir)
            .with_context(|| format!("Failed to create directory: {}", screenshot_dir))?;

        let webdriver_url = webdriver_url.unwrap_or("http://localhost:4444");
        debug!("Using WebDriver URL: {}", webdriver_url);
        
        // Initialize connection pool
        let connection_pool = ConnectionPool::new(
            webdriver_url,
            viewport_size,
            headless
        ).await?;

        info!("ScreenshotTaker initialized with {} initial connections", 
              connection_pool.total_connections.load(Ordering::Acquire));
              
        Ok(Self {
            screenshot_dir: screenshot_dir.to_string(),
            connection_pool,
            shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Takes a screenshot of the specified URL with automatic retries
    pub async fn take_screenshot(&self, url: &str, base_name: &str) -> Result<Screenshot> {
        // Check if shutdown has been requested
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(anyhow::anyhow!("Screenshot service is shutting down"));
        }
        
        info!("Taking screenshot of URL: {}", url);
        let mut retries = 0;
        let mut last_error = None;

        while retries < MAX_RETRIES {
            // Check for shutdown request before each attempt
            if self.shutdown_requested.load(Ordering::Acquire) {
                return Err(anyhow::anyhow!("Screenshot operation canceled - service is shutting down"));
            }
            
            debug!("Screenshot attempt {}/{} for {}", retries + 1, MAX_RETRIES, url);
            
            // Get a client from the pool - use healthy client to ensure proper operation
            let client = match self.connection_pool.get_healthy_client().await {
                Ok(client) => client,
                Err(e) => {
                    error!("Failed to get WebDriver client: {}", e);
                    return Err(e);
                }
            };
            
            // Attempt to take screenshot
            match self.take_screenshot_with_client(&client, url, base_name).await {
                Ok(screenshot) => {
                    info!("Successfully captured screenshot for {}", url);
                    // Return client to the pool
                    self.connection_pool.return_client(client).await;
                    return Ok(screenshot);
                }
                Err(e) => {
                    warn!("Failed to take screenshot of {}: {}", url, e);
                    last_error = Some(e);
                    
                    // Discard the client instead of trying to close it directly
                    debug!("Discarding potentially broken WebDriver client");
                    self.connection_pool.discard_client(client).await;
                    
                    // Check before retrying
                    if retries + 1 < MAX_RETRIES {
                        warn!("Retrying screenshot capture (attempt {}/{})", retries + 1, MAX_RETRIES);
                        debug!("Waiting {:?} before retry", RETRY_DELAY);
                        sleep(RETRY_DELAY).await;
                    }
                }
            }

            retries += 1;
        }

        error!("Failed to take screenshot of {} after {} attempts", url, MAX_RETRIES);
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to take screenshot after {} retries", MAX_RETRIES)))
    }

    /// Implementation of screenshot capture using a specific WebDriver client
    async fn take_screenshot_with_client(&self, client: &Client, url: &str, base_name: &str) -> Result<Screenshot> {
        // Navigate to the URL
        debug!("Navigating to URL: {}", url);
        match client.goto(url).await {
            Ok(_) => trace!("Successfully navigated to {}", url),
            Err(e) => {
                error!("Failed to navigate to {}: {}", url, e);
                return Err(e).context(format!("Failed to navigate to {}", url));
            }
        }
        
        // Wait for body and a short delay to ensure images load
        debug!("Waiting for page body to load");
        match client.wait().forever().for_element(Locator::Css("body")).await {
            Ok(_) => trace!("Body element found, page loaded"),
            Err(e) => {
                error!("Failed to find body element on {}: {}", url, e);
                return Err(e).context("Failed to wait for page to load");
            }
        }
        
        debug!("Waiting additional 500ms for page content to render");
        sleep(Duration::from_millis(500)).await;
        
        // Take screenshot
        debug!("Capturing screenshot");
        let screenshot_data = match client.screenshot().await {
            Ok(data) => {
                trace!("Screenshot captured successfully, {} bytes", data.len());
                data
            },
            Err(e) => {
                error!("Failed to capture screenshot: {}", e);
                return Err(e).context("Failed to capture screenshot");
            }
        };
        
        // Save to file
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let sanitized_name = sanitize(base_name);
        let file_path = Path::new(&self.screenshot_dir)
            .join(format!("{}_{}.png", sanitized_name, timestamp));
            
        debug!("Saving screenshot to {}", file_path.display());
        match fs::write(&file_path, &screenshot_data) {
            Ok(_) => trace!("Screenshot file written successfully"),
            Err(e) => {
                error!("Failed to write screenshot to {}: {}", file_path.display(), e);
                return Err(e).context(format!("Failed to write screenshot to {}", file_path.display()));
            }
        }
        
        info!("Screenshot saved to {}", file_path.display());

        // Create Screenshot object
        let screenshot = Screenshot::from_raw(
            file_path.to_string_lossy().into_owned(),
            &screenshot_data
        );

        Ok(screenshot)
    }

    /// Get access to active connections counter
    pub fn active_connections(&self) -> Arc<AtomicUsize> {
        self.connection_pool.active_connections.clone()
    }

    /// Get access to total connections counter
    pub fn total_connections(&self) -> Arc<AtomicUsize> {
        self.connection_pool.total_connections.clone()
    }

    /// Closes all WebDriver connections in the pool
    pub async fn close(&self) -> Result<()> {
        // Signal shutdown
        self.shutdown_requested.store(true, Ordering::Release);
        info!("Closing ScreenshotTaker");
        self.connection_pool.close().await
    }
} 