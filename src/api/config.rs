use std::time::Duration;
use crate::utils::benchmarking::OperationTimer;

/// Default capacity for the job queue
pub const QUEUE_SIZE: usize = 10;

/// Configuration for the API
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Directory to save screenshots in
    pub screenshot_dir: String,
    
    /// Width of the browser viewport
    pub viewport_width: u32,
    
    /// Height of the browser viewport
    pub viewport_height: u32,
    
    /// Whether to run the browser in headless mode
    pub headless: bool,
    
    /// Optional WebDriver URL (uses default if None)
    pub webdriver_url: Option<String>,
    
    /// Timeout for API requests
    pub request_timeout: Duration,
    
    /// Timer for operation benchmarking
    pub timer: Option<OperationTimer>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            screenshot_dir: "screenshots".to_string(),
            viewport_width: 1280,
            viewport_height: 800,
            headless: true,
            webdriver_url: None,
            request_timeout: Duration::from_secs(30),
            timer: Some(OperationTimer::new()),
        }
    }
} 