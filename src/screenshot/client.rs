use anyhow::{Result, Context};
use fantoccini::{Client, ClientBuilder};
use tracing::{error, debug, trace};
use crate::screenshot::config;

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
pub async fn create_client(
    webdriver_url: &str,
    viewport_size: Option<(u32, u32)>,
    headless: bool,
) -> Result<Client> {
    trace!("Creating new WebDriver client connecting to {}", webdriver_url);
    let mut caps = serde_json::map::Map::new();
    let mut chrome_opts = serde_json::map::Map::new();
    
    // Optimize Chrome arguments for security screenshots while maintaining performance
    debug!("Configuring Chrome options with headless={}", headless);
    let args = config::chrome_arguments(headless);
    
    trace!("Setting Chrome arguments: {:?}", args);
    chrome_opts.insert("args".to_string(), serde_json::Value::Array(
        args.into_iter().map(serde_json::Value::String).collect()
    ));

    // Enable images and JavaScript, but block other resource types
    trace!("Configuring Chrome content settings");
    let prefs = config::chrome_preferences();
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
            error!("Failed to set window size to {}x{}: {}", width, height, e);
            // Continue anyway, as this is not a critical error
        }
    }

    trace!("Successfully created WebDriver client");
    Ok(client)
} 