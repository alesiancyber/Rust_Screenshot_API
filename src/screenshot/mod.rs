use anyhow::{Result, Context};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fantoccini::{Client, ClientBuilder};
use log::{info, error, warn};
use std::path::Path;
use std::fs;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::collections::VecDeque;
use std::time::Duration;
use sanitize_filename::sanitize;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);
const MIN_CONNECTIONS: usize = 2;
pub const MAX_CONNECTIONS: usize = 10;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct Screenshot {
    #[allow(dead_code)]
    pub file_path: String,
    pub image_data: String,
}

impl Screenshot {
    #[allow(dead_code)]
    pub fn new(file_path: String, image_data: String) -> Self {
        Self { file_path, image_data }
    }
}

pub struct ScreenshotTaker {
    screenshot_dir: String,
    webdriver_url: Option<String>,
    viewport_size: Option<(u32, u32)>,
    headless: bool,
    connection_pool: Arc<Mutex<VecDeque<Client>>>,
    semaphore: Arc<Semaphore>,
    pub active_connections: Arc<AtomicUsize>,
    pub total_connections: Arc<AtomicUsize>,
}

impl ScreenshotTaker {
    pub async fn new(
        screenshot_dir: &str,
        webdriver_url: Option<&str>,
        viewport_size: Option<(u32, u32)>,
        headless: bool,
    ) -> Result<Self> {
        // Create screenshot directory if it doesn't exist
        fs::create_dir_all(screenshot_dir)
            .with_context(|| format!("Failed to create directory: {}", screenshot_dir))?;

        let webdriver_url = webdriver_url.unwrap_or("http://localhost:4444").to_string();
        let connection_pool = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_CONNECTIONS)));
        let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let total_connections = Arc::new(AtomicUsize::new(0));

        // Initialize with minimum connections
        {
            let mut pool = connection_pool.lock().await;
            for _ in 0..MIN_CONNECTIONS {
                if let Ok(client) = Self::create_client(&webdriver_url, viewport_size, headless).await {
                    pool.push_back(client);
                    total_connections.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

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

    async fn create_client(
        webdriver_url: &str,
        viewport_size: Option<(u32, u32)>,
        headless: bool,
    ) -> Result<Client> {
        let mut caps = serde_json::map::Map::new();
        let mut chrome_opts = serde_json::map::Map::new();
        
        // Optimize Chrome arguments for security screenshots while maintaining performance
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
        
        chrome_opts.insert("args".to_string(), serde_json::Value::Array(
            args.into_iter().map(serde_json::Value::String).collect()
        ));

        // Enable images and JavaScript, but block other resource types
        let mut prefs = serde_json::map::Map::new();
        prefs.insert("profile.default_content_setting_values.images".to_string(), 1.into()); // 1 = allow
        prefs.insert("profile.managed_default_content_settings.javascript".to_string(), 1.into()); // 1 = allow
        prefs.insert("profile.managed_default_content_settings.plugins".to_string(), 2.into()); // 2 = block
        prefs.insert("profile.managed_default_content_settings.popups".to_string(), 2.into()); // 2 = block
        prefs.insert("profile.managed_default_content_settings.geolocation".to_string(), 2.into()); // 2 = block
        prefs.insert("profile.managed_default_content_settings.media_stream".to_string(), 2.into()); // 2 = block
        chrome_opts.insert("prefs".to_string(), serde_json::Value::Object(prefs));
        
        caps.insert("goog:chromeOptions".to_string(), serde_json::Value::Object(chrome_opts));
        
        let client = ClientBuilder::native()
            .capabilities(caps)
            .connect(webdriver_url)
            .await?;

        if let Some((width, height)) = viewport_size {
            client.set_window_size(width, height).await?;
        }

        Ok(client)
    }

    async fn scale_pool(&self) -> Result<()> {
        let active = self.active_connections.load(Ordering::SeqCst);
        let total = self.total_connections.load(Ordering::SeqCst);
        
        if active > total * 80 / 100 && total < MAX_CONNECTIONS {
            // Scale up - add one connection
            if let Ok(client) = Self::create_client(
                self.webdriver_url.as_ref().unwrap(),
                self.viewport_size,
                self.headless
            ).await {
                let mut pool = self.connection_pool.lock().await;
                pool.push_back(client);
                self.total_connections.fetch_add(1, Ordering::SeqCst);
                info!("Scaled up connection pool to {}", total + 1);
            }
        } else if active < total * 20 / 100 && total > MIN_CONNECTIONS {
            // Scale down - remove one connection
            if let Some(client) = self.connection_pool.lock().await.pop_back() {
                if let Err(e) = client.close().await {
                    warn!("Error closing connection during scale down: {}", e);
                }
                self.total_connections.fetch_sub(1, Ordering::SeqCst);
                info!("Scaled down connection pool to {}", total - 1);
            }
        }
        Ok(())
    }

    async fn get_client(&self) -> Result<Client> {
        let _permit = tokio::time::timeout(
            CONNECTION_TIMEOUT,
            self.semaphore.acquire()
        ).await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for connection"))??;

        let client = {
            let mut pool = self.connection_pool.lock().await;
            if let Some(client) = pool.pop_front() {
                client
            } else {
                // Create new client if pool is empty
                Self::create_client(
                    self.webdriver_url.as_ref().unwrap(),
                    self.viewport_size,
                    self.headless
                ).await?
            }
        };

        self.active_connections.fetch_add(1, Ordering::SeqCst);
        
        // Check if we need to scale
        self.scale_pool().await?;

        Ok(client)
    }

    async fn return_client(&self, client: Client) {
        let mut pool = self.connection_pool.lock().await;
        pool.push_back(client);
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    pub async fn take_screenshot(&self, url: &str, base_name: &str) -> Result<Screenshot> {
        let mut retries = 0;
        let mut last_error = None;

        while retries < MAX_RETRIES {
            let client = self.get_client().await?;
            
            match self.take_screenshot_with_client(&client, url, base_name).await {
                Ok(screenshot) => {
                    self.return_client(client).await;
                    return Ok(screenshot);
                }
                Err(e) => {
                    last_error = Some(e);
                    // Try to close the client in case it's in a bad state
                    if let Err(close_err) = client.close().await {
                        error!("Failed to close WebDriver client: {}", close_err);
                    }
                    let active = self.active_connections.load(Ordering::SeqCst);
                    if active > 0 {
                        warn!("Retrying screenshot capture (attempt {}/{})", retries + 1, MAX_RETRIES);
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                }
            }

            retries += 1;
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to take screenshot after {} retries", MAX_RETRIES)))
    }

    async fn take_screenshot_with_client(&self, client: &Client, url: &str, base_name: &str) -> Result<Screenshot> {
        // Navigate to the URL
        client.goto(url).await?;
        
        // Wait for body and a short delay to ensure images load
        client.wait().forever().for_element(fantoccini::Locator::Css("body")).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        // Take screenshot
        let screenshot_data = client.screenshot().await?;
        
        // Save to file
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let sanitized_name = sanitize(base_name);
        let file_path = Path::new(&self.screenshot_dir)
            .join(format!("{}_{}.png", sanitized_name, timestamp));
            
        fs::write(&file_path, &screenshot_data)?;
        info!("Screenshot saved to {}", file_path.display());

        // Convert to base64
        let base64_data = BASE64.encode(&screenshot_data);

        Ok(Screenshot { 
            file_path: file_path.to_string_lossy().into_owned(),
            image_data: base64_data,
        })
    }

    pub async fn close(&self) -> Result<()> {
        let mut pool = self.connection_pool.lock().await;
        let active = self.active_connections.load(Ordering::SeqCst);
        
        while let Some(client) = pool.pop_front() {
            if let Err(e) = client.close().await {
                error!("Failed to close WebDriver client: {}", e);
            }
        }
        
        if active > 0 {
            warn!("Closing with {} active connections", active);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_screenshot() {
        let taker = ScreenshotTaker::new(
            "test_screenshots",
            None,
            Some((800, 600)),
            false
        ).await.unwrap();
        let result = taker.take_screenshot("https://example.com", "test").await;
        assert!(result.is_ok());
        let screenshot = result.unwrap();
        assert!(Path::new(&screenshot.file_path).exists());
        // Cleanup
        fs::remove_file(&screenshot.file_path).unwrap();
        taker.close().await.unwrap();
    }
} 