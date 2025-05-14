pub mod data_classifier;
mod api;
mod screenshot;
mod url_crawler;
mod url_parser;
mod utils;
mod ssl;

use anyhow::Result;
use crate::api::{ApiConfig, start_server};
use crate::utils::logger::init_logger;
use std::time::Duration;

#[actix_web::main]
async fn main() -> Result<()> {
    // Initialize logger
    let _ = init_logger("logs");

    // Configure API
    let config = ApiConfig {
        screenshot_dir: "screenshots".to_string(),
        viewport_width: 1280,
        viewport_height: 800,
        headless: true,
        webdriver_url: None,
        request_timeout: Duration::from_secs(30),
    };

    // Start server
    start_server("127.0.0.1", 8080, Some(config)).await?;

    Ok(())
}
