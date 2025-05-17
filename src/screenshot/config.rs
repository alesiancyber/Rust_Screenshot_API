use std::time::Duration;

// Constants for screenshot behavior and performance tuning
pub const MAX_RETRIES: u32 = 3;            // Maximum number of screenshot capture attempts
pub const RETRY_DELAY: Duration = Duration::from_secs(1);  // Delay between retry attempts
pub const MIN_CONNECTIONS: usize = 2;      // Minimum number of browser connections to maintain
pub const MAX_CONNECTIONS: usize = 10;     // Maximum number of concurrent browser connections
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10); // Timeout for acquiring a connection

// Chrome browser arguments
pub fn chrome_arguments(headless: bool) -> Vec<String> {
    vec![
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
    .collect()
}

// Chrome content settings preferences
pub fn chrome_preferences() -> serde_json::Map<String, serde_json::Value> {
    let mut prefs = serde_json::Map::new();
    prefs.insert("profile.default_content_setting_values.images".to_string(), 1.into()); // 1 = allow
    prefs.insert("profile.managed_default_content_settings.javascript".to_string(), 1.into()); // 1 = allow
    prefs.insert("profile.managed_default_content_settings.plugins".to_string(), 2.into()); // 2 = block
    prefs.insert("profile.managed_default_content_settings.popups".to_string(), 2.into()); // 2 = block
    prefs.insert("profile.managed_default_content_settings.geolocation".to_string(), 2.into()); // 2 = block
    prefs.insert("profile.managed_default_content_settings.media_stream".to_string(), 2.into()); // 2 = block
    prefs
} 