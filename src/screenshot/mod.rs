use anyhow::{Result, Context};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fantoccini::{Client, ClientBuilder};
use tracing::{info, error, warn, debug, trace};
use std::path::Path;
use std::fs;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::collections::VecDeque;
use std::time::Duration;
use sanitize_filename::sanitize;
use std::sync::atomic::{AtomicUsize, Ordering};

// Constants for screenshot behavior and performance tuning
const MAX_RETRIES: u32 = 3;            // Maximum number of screenshot capture attempts
const RETRY_DELAY: Duration = Duration::from_secs(1);  // Delay between retry attempts
const MIN_CONNECTIONS: usize = 2;      // Minimum number of browser connections to maintain
pub const MAX_CONNECTIONS: usize = 10; // Maximum number of concurrent browser connections
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10); // Timeout for acquiring a connection

/// Represents a captured screenshot with both file path and base64-encoded data
#[derive(Debug)]
pub struct Screenshot {
    #[allow(dead_code)]
    pub file_path: String,      // Path where the screenshot is saved
    pub image_data: String,     // Base64-encoded image data for API responses
}

impl Screenshot {
    /// Creates a new Screenshot instance
    /// 
    /// # Arguments
    /// * `file_path` - Path where the screenshot is saved
    /// * `image_data` - Base64-encoded image data
    #[allow(dead_code)]
    pub fn new(file_path: String, image_data: String) -> Self {
        Self { file_path, image_data }
    }
}

/// Manages browser connections and takes screenshots of web pages
/// 
/// This struct handles the creation and management of a connection pool
/// of browser instances via WebDriver, and provides methods to take
/// screenshots with automatic retries and resource cleanup.
pub struct ScreenshotTaker {
    screenshot_dir: String,                        // Directory to save screenshots
    webdriver_url: Option<String>,                 // WebDriver server URL
    viewport_size: Option<(u32, u32)>,             // Optional viewport dimensions
    headless: bool,                                // Whether to run browser in headless mode
    connection_pool: Arc<Mutex<VecDeque<Client>>>, // Pool of browser connections
    semaphore: Arc<Semaphore>,                     // Limits concurrent connections
    pub active_connections: Arc<AtomicUsize>,      // Count of currently active connections
    pub total_connections: Arc<AtomicUsize>,       // Total connections in the pool
}

impl ScreenshotTaker {
    /// Creates a new ScreenshotTaker with the specified configuration
    /// 
    /// This initializes a connection pool with the minimum number of browser
    /// connections and ensures the screenshot directory exists.
    /// 
    /// # Arguments
    /// * `screenshot_dir` - Directory to save screenshots
    /// * `webdriver_url` - Optional WebDriver server URL (defaults to http://localhost:4444)
    /// * `viewport_size` - Optional viewport dimensions for browser windows
    /// * `headless` - Whether to run browsers in headless mode
    /// 
    /// # Returns
    /// * `Result<Self>` - A configured ScreenshotTaker or an error
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

        let webdriver_url = webdriver_url.unwrap_or("http://localhost:4444").to_string();
        debug!("Using WebDriver URL: {}", webdriver_url);
        
        let connection_pool = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_CONNECTIONS)));
        let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let total_connections = Arc::new(AtomicUsize::new(0));

        // Initialize with minimum connections
        debug!("Initializing connection pool with {} connections", MIN_CONNECTIONS);
        {
            let mut pool = connection_pool.lock().await;
            for i in 0..MIN_CONNECTIONS {
                trace!("Creating initial connection {}/{}", i+1, MIN_CONNECTIONS);
                match Self::create_client(&webdriver_url, viewport_size, headless).await {
                    Ok(client) => {
                        pool.push_back(client);
                        total_connections.fetch_add(1, Ordering::SeqCst);
                        trace!("Successfully created initial connection {}/{}", i+1, MIN_CONNECTIONS);
                    }
                    Err(e) => {
                        warn!("Failed to create initial connection {}/{}: {}", i+1, MIN_CONNECTIONS, e);
                    }
                }
            }
        }

        info!("ScreenshotTaker initialized with {} initial connections", 
              total_connections.load(Ordering::SeqCst));
              
        Ok(Self {
            screenshot_dir: screenshot_dir.to_string(),
            webdriver_url: Some(webdriver_url),
            viewport_size,
            headless,
            connection_pool,
            semaphore,
            active_connections,
            total_connections,
        })
    }

    /// Creates a new WebDriver client with the specified configuration
    /// 
    /// Sets up a Chrome browser instance with appropriate security and performance
    /// settings for taking screenshots.
    /// 
    /// # Arguments
    /// * `webdriver_url` - WebDriver server URL
    /// * `viewport_size` - Optional viewport dimensions
    /// * `headless` - Whether to run in headless mode
    /// 
    /// # Returns
    /// * `Result<Client>` - A configured WebDriver client or an error
    async fn create_client(
        webdriver_url: &str,
        viewport_size: Option<(u32, u32)>,
        headless: bool,
    ) -> Result<Client> {
        trace!("Creating new WebDriver client connecting to {}", webdriver_url);
        let mut caps = serde_json::map::Map::new();
        let mut chrome_opts = serde_json::map::Map::new();
        
        // Optimize Chrome arguments for security screenshots while maintaining performance
        debug!("Configuring Chrome options with headless={}", headless);
        let args: Vec<String> = vec![
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--disable-extensions",
            "--disable-notifications",
            "--disable-infobars",
            "--disable-popup-blocking",
            "--disable-background-networking",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-breakpad",
            "--disable-component-extensions-with-background-pages",
            "--disable-features=TranslateUI",
            "--disable-ipc-flooding-protection",
            "--disable-renderer-backgrounding",
            "--enable-features=NetworkService,NetworkServiceInProcess",
            "--force-color-profile=srgb",
            "--metrics-recording-only",
            "--mute-audio",
            "--window-size=1280,800",
            "--start-maximized",
            if headless { "--headless=new" } else { "" }
        ].into_iter()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
        
        trace!("Setting Chrome arguments: {:?}", args);
        chrome_opts.insert("args".to_string(), serde_json::Value::Array(
            args.into_iter().map(serde_json::Value::String).collect()
        ));

        // Enable images and JavaScript, but block other resource types
        trace!("Configuring Chrome content settings");
        let mut prefs = serde_json::map::Map::new();
        prefs.insert("profile.default_content_setting_values.images".to_string(), 1.into()); // 1 = allow
        prefs.insert("profile.managed_default_content_settings.javascript".to_string(), 1.into()); // 1 = allow
        prefs.insert("profile.managed_default_content_settings.plugins".to_string(), 2.into()); // 2 = block
        prefs.insert("profile.managed_default_content_settings.popups".to_string(), 2.into()); // 2 = block
        prefs.insert("profile.managed_default_content_settings.geolocation".to_string(), 2.into()); // 2 = block
        prefs.insert("profile.managed_default_content_settings.media_stream".to_string(), 2.into()); // 2 = block
        chrome_opts.insert("prefs".to_string(), serde_json::Value::Object(prefs));
        
        caps.insert("goog:chromeOptions".to_string(), serde_json::Value::Object(chrome_opts));
        
        debug!("Connecting to WebDriver at {}", webdriver_url);
        let client = match ClientBuilder::native()
            .capabilities(caps)
            .connect(webdriver_url)
            .await {
                Ok(client) => client,
                Err(e) => {
                    error!("Failed to connect to WebDriver at {}: {}", webdriver_url, e);
                    return Err(e).context(format!("Failed to connect to WebDriver at {}", webdriver_url));
                }
            };

        // Set viewport size if specified
        if let Some((width, height)) = viewport_size {
            debug!("Setting viewport size to {}x{}", width, height);
            if let Err(e) = client.set_window_size(width, height).await {
                warn!("Failed to set window size to {}x{}: {}", width, height, e);
                // Continue anyway, as this is not a critical error
            }
        }

        trace!("Successfully created WebDriver client");
        Ok(client)
    }

    /// Dynamically adjusts the connection pool size based on usage
    /// 
    /// Scales up or down the number of browser connections based on
    /// current load to optimize resource usage while maintaining performance.
    /// 
    /// # Returns
    /// * `Result<()>` - Success or an error
    async fn scale_pool(&self) -> Result<()> {
        let active = self.active_connections.load(Ordering::SeqCst);
        let total = self.total_connections.load(Ordering::SeqCst);
        
        trace!("Evaluating pool scaling: active={}, total={}", active, total);
        
        if active > total * 80 / 100 && total < MAX_CONNECTIONS {
            // Scale up - add one connection
            debug!("High connection usage ({}%), scaling up from {} connections", 
                  (active * 100) / total, total);
                  
            match Self::create_client(
                self.webdriver_url.as_ref().unwrap(),
                self.viewport_size,
                self.headless
            ).await {
                Ok(client) => {
                    let mut pool = self.connection_pool.lock().await;
                    pool.push_back(client);
                    self.total_connections.fetch_add(1, Ordering::SeqCst);
                    info!("Scaled up connection pool to {}", total + 1);
                }
                Err(e) => {
                    warn!("Failed to scale up connection pool: {}", e);
                }
            }
        } else if active < total * 20 / 100 && total > MIN_CONNECTIONS {
            // Scale down - remove one connection
            debug!("Low connection usage ({}%), scaling down from {} connections", 
                  (active * 100) / total, total);
                  
            let client_to_close = {
                let mut pool = self.connection_pool.lock().await;
                pool.pop_back()
            };
            
            if let Some(client) = client_to_close {
                if let Err(e) = client.close().await {
                    warn!("Error closing connection during scale down: {}", e);
                }
                self.total_connections.fetch_sub(1, Ordering::SeqCst);
                info!("Scaled down connection pool to {}", total - 1);
            }
        }
        Ok(())
    }

    /// Gets a WebDriver client from the pool or creates a new one
    /// 
    /// Acquires a permit from the semaphore to limit concurrent connections,
    /// then either reuses an existing client or creates a new one.
    /// 
    /// # Returns
    /// * `Result<Client>` - A WebDriver client or an error
    async fn get_client(&self) -> Result<Client> {
        debug!("Attempting to acquire client from pool");
        
        // Acquire a permit from the semaphore with timeout
        let _permit = match tokio::time::timeout(
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

        trace!("Acquired semaphore permit, getting client from pool");
        
        // Get a client from the pool or create a new one
        let client = {
            let mut pool = self.connection_pool.lock().await;
            if let Some(client) = pool.pop_front() {
                trace!("Reusing existing client from pool");
                client
            } else {
                debug!("No clients in pool, creating new client");
                match Self::create_client(
                    self.webdriver_url.as_ref().unwrap(),
                    self.viewport_size,
                    self.headless
                ).await {
                    Ok(client) => client,
                    Err(e) => {
                        error!("Failed to create new client: {}", e);
                        return Err(e).context("Failed to create new client on demand");
                    }
                }
            }
        };

        // Update active connection count
        let active = self.active_connections.fetch_add(1, Ordering::SeqCst) + 1;
        let total = self.total_connections.load(Ordering::SeqCst);
        debug!("Client acquired. Active connections: {}/{}", active, total);
        
        // Check if we need to scale the pool
        if let Err(e) = self.scale_pool().await {
            warn!("Error during pool scaling: {}", e);
        }

        Ok(client)
    }

    /// Returns a WebDriver client to the connection pool
    /// 
    /// Puts the client back in the pool for reuse and updates
    /// the active connection count.
    /// 
    /// # Arguments
    /// * `client` - The WebDriver client to return to the pool
    async fn return_client(&self, client: Client) {
        trace!("Returning client to pool");
        let mut pool = self.connection_pool.lock().await;
        pool.push_back(client);
        
        let active = self.active_connections.fetch_sub(1, Ordering::SeqCst) - 1;
        let total = self.total_connections.load(Ordering::SeqCst);
        debug!("Client returned to pool. Active connections: {}/{}", active, total);
    }

    /// Takes a screenshot of the specified URL with automatic retries
    /// 
    /// This is the main public method for capturing screenshots. It handles
    /// getting a connection, taking the screenshot, and implementing retries
    /// on failure.
    /// 
    /// # Arguments
    /// * `url` - The URL to screenshot
    /// * `base_name` - Base filename for the screenshot (will be sanitized)
    /// 
    /// # Returns
    /// * `Result<Screenshot>` - A Screenshot object or an error
    pub async fn take_screenshot(&self, url: &str, base_name: &str) -> Result<Screenshot> {
        info!("Taking screenshot of URL: {}", url);
        let mut retries = 0;
        let mut last_error = None;

        while retries < MAX_RETRIES {
            debug!("Screenshot attempt {}/{} for {}", retries + 1, MAX_RETRIES, url);
            
            // Get a client from the pool
            let client = match self.get_client().await {
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
                    self.return_client(client).await;
                    return Ok(screenshot);
                }
                Err(e) => {
                    warn!("Failed to take screenshot of {}: {}", url, e);
                    last_error = Some(e);
                    
                    // Try to close the client in case it's in a bad state
                    debug!("Closing potentially broken WebDriver client");
                    if let Err(close_err) = client.close().await {
                        error!("Failed to close WebDriver client: {}", close_err);
                    }
                    
                    let active = self.active_connections.load(Ordering::SeqCst);
                    if active > 0 {
                        warn!("Retrying screenshot capture (attempt {}/{})", retries + 1, MAX_RETRIES);
                        debug!("Waiting {:?} before retry", RETRY_DELAY);
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                }
            }

            retries += 1;
        }

        error!("Failed to take screenshot of {} after {} attempts", url, MAX_RETRIES);
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to take screenshot after {} retries", MAX_RETRIES)))
    }

    /// Implementation of screenshot capture using a specific WebDriver client
    /// 
    /// This is the internal method that does the actual work of navigating
    /// to a URL, waiting for it to load, capturing the screenshot, and saving
    /// it to disk.
    /// 
    /// # Arguments
    /// * `client` - The WebDriver client to use
    /// * `url` - The URL to screenshot
    /// * `base_name` - Base filename for the screenshot
    /// 
    /// # Returns
    /// * `Result<Screenshot>` - A Screenshot object or an error
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
        match client.wait().forever().for_element(fantoccini::Locator::Css("body")).await {
            Ok(_) => trace!("Body element found, page loaded"),
            Err(e) => {
                error!("Failed to find body element on {}: {}", url, e);
                return Err(e).context("Failed to wait for page to load");
            }
        }
        
        debug!("Waiting additional 500ms for page content to render");
        tokio::time::sleep(Duration::from_millis(500)).await;
        
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

        // Convert to base64
        trace!("Converting screenshot to base64");
        let base64_data = BASE64.encode(&screenshot_data);
        trace!("Base64 conversion complete, {} chars", base64_data.len());

        Ok(Screenshot { 
            file_path: file_path.to_string_lossy().into_owned(),
            image_data: base64_data,
        })
    }

    /// Closes all WebDriver connections in the pool
    /// 
    /// Call this method when shutting down the application to
    /// clean up browser resources.
    /// 
    /// # Returns
    /// * `Result<()>` - Success or an error
    pub async fn close(&self) -> Result<()> {
        info!("Closing ScreenshotTaker and all WebDriver connections");
        let mut pool = self.connection_pool.lock().await;
        let total = pool.len();
        let active = self.active_connections.load(Ordering::SeqCst);
        
        debug!("Closing {} pooled connections", total);
        let mut close_errors = 0;
        
        while let Some(client) = pool.pop_front() {
            if let Err(e) = client.close().await {
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
        
        info!("ScreenshotTaker shutdown complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_screenshot() {
        let dir = "test_screenshots";
        
        // Create the ScreenshotTaker
        let taker = ScreenshotTaker::new(
            dir,
            None,
            Some((800, 600)),
            false
        ).await.unwrap();
        
        // Take screenshot
        let result = taker.take_screenshot("https://example.com", "test").await;
        assert!(result.is_ok());
        let screenshot = result.unwrap();
        assert!(Path::new(&screenshot.file_path).exists());
        
        // Cleanup screenshot file
        fs::remove_file(&screenshot.file_path).unwrap();
        
        // Close the taker
        taker.close().await.unwrap();
        
        // Clean up the directory after test
        if Path::new(dir).exists() {
            match fs::remove_dir(dir) {
                Ok(_) => {},
                Err(e) => println!("Warning: Could not remove test directory: {}", e),
            }
        }
    }
} 