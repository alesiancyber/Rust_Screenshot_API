pub mod config;
pub mod models;
pub mod handlers;
pub mod processor;
pub mod workers;

use actix_web::{web, App, HttpServer};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error, debug};

use crate::screenshot::ScreenshotTaker;
use self::config::{ApiConfig, QUEUE_SIZE};
use self::handlers::{screenshot_handler, health_check};
use self::workers::start_workers;

/// Starts the API server with the specified configuration
/// 
/// Initializes the screenshot service, sets up worker threads, and
/// starts the HTTP server with the configured endpoints.
/// 
/// # Arguments
/// * `host` - Host address to bind to (e.g., "127.0.0.1")
/// * `port` - Port to listen on
/// * `config` - Optional API configuration (uses defaults if None)
/// 
/// # Returns
/// * `Result<()>` - Success or an error
#[tracing::instrument(skip(config))]
pub async fn start_server(host: &str, port: u16, config: Option<ApiConfig>) -> Result<()> {
    info!("Starting screenshot API server on {}:{}", host, port);
    
    let config = config.unwrap_or_else(|| {
        debug!("Using default API configuration");
        ApiConfig::default()
    });
    
    debug!("Initializing screenshot service with dir: {}, viewport: {}x{}, headless: {}", 
          config.screenshot_dir, config.viewport_width, config.viewport_height, config.headless);

    let screenshot_taker = Arc::new(match ScreenshotTaker::new(
        &config.screenshot_dir,
        config.webdriver_url.as_deref(),
        Some((config.viewport_width, config.viewport_height)),
        config.headless
    ).await {
        Ok(taker) => taker,
        Err(e) => {
            error!("Failed to initialize ScreenshotTaker: {}", e);
            return Err(e);
        }
    });

    // Create the job queue
    debug!("Creating job queue with capacity: {}", QUEUE_SIZE);
    let (job_tx, job_rx) = mpsc::channel::<models::ScreenshotJob>(QUEUE_SIZE);
    
    // Start worker threads
    start_workers(job_rx, screenshot_taker.clone(), config.clone()).await;

    // Wrap shared data for the web handlers
    let job_tx_data = web::Data::new(job_tx);
    let config_data = web::Data::new(config);
    let screenshot_taker_data = web::Data::new(screenshot_taker.clone());

    info!("Starting HTTP server at {}:{}", host, port);
    let server_result = HttpServer::new(move || {
        App::new()
            .app_data(config_data.clone())
            .app_data(job_tx_data.clone())
            .app_data(screenshot_taker_data.clone())
            .service(web::resource("/screenshot").route(web::post().to(screenshot_handler)))
            .service(web::resource("/health").route(web::get().to(health_check)))
    })
    .bind((host, port))
    .map_err(|e| {
        error!("Failed to bind to {}:{}: {}", host, port, e);
        e
    })?
    .run()
    .await;

    // Cleanup
    info!("Server shutting down, cleaning up resources");
    match screenshot_taker.close().await {
        Ok(_) => debug!("Successfully closed screenshot service"),
        Err(e) => error!("Error closing screenshot service: {}", e),
    }

    if let Err(e) = server_result {
        error!("Server error: {}", e);
        return Err(e.into());
    }

    info!("Server shutdown complete");
    Ok(())
} 