use std::time::Duration;

/// Configuration for the API server
#[derive(Clone)]
pub struct ApiConfig {
    pub screenshot_dir: String,      // Directory to save screenshots
    pub viewport_width: u32,         // Width of browser viewport
    pub viewport_height: u32,        // Height of browser viewport
    pub headless: bool,              // Whether to run browser in headless mode
    pub webdriver_url: Option<String>, // WebDriver server URL
    pub request_timeout: Duration,   // Request timeout duration
}

impl ApiConfig {
    /// Creates a default configuration
    pub fn default() -> Self {
        Self {
            screenshot_dir: "screenshots".to_string(),
            viewport_width: 1280,
            viewport_height: 800,
            headless: true,
            webdriver_url: None,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Maximum number of jobs that can be queued at once
pub const QUEUE_SIZE: usize = 100; // Increased for production 