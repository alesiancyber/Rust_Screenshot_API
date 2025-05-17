pub mod config;
pub mod models;
pub mod handlers;
pub mod processor;
pub mod workers;

use actix_web::{web, App, HttpServer};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, error, debug};

use crate::screenshot::ScreenshotTaker;
use self::config::{ApiConfig, QUEUE_SIZE};
use self::handlers::{screenshot_handler, health_check};
use self::workers::{start_workers, create_job_channel, create_shutdown_channel};

/// Shared application state
#[allow(dead_code)]
pub struct AppState {
    /// Channel for sending jobs to workers
    pub job_tx: mpsc::Sender<models::ScreenshotJob>,
    
    /// Channel for sending shutdown signal
    pub shutdown_tx: Option<oneshot::Sender<()>>,
    
    /// Shared screenshot service
    pub screenshot_taker: Arc<ScreenshotTaker>,
    
    /// API configuration
    pub config: ApiConfig,
}

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

    println!("1. About to initialize ScreenshotTaker");
    let screenshot_taker = Arc::new(match ScreenshotTaker::new(
        &config.screenshot_dir,
        config.webdriver_url.as_deref(),
        Some((config.viewport_width, config.viewport_height)),
        config.headless
    ).await {
        Ok(taker) => taker,
        Err(e) => {
            println!("ERROR initializing ScreenshotTaker: {}", e);
            error!("Failed to initialize ScreenshotTaker: {}", e);
            return Err(e);
        }
    });
    println!("2. ScreenshotTaker initialized");

    // Create the job queue
    println!("3. Job queue created");
    let (job_tx, job_rx) = mpsc::channel::<models::ScreenshotJob>(QUEUE_SIZE);
    
    // Create shutdown channel
    println!("4. Shutdown channel created");
    let (shutdown_tx, shutdown_rx) = create_shutdown_channel();
    
    // Clone values needed for the worker task
    let worker_config = config.clone();
    let worker_screenshot_taker = screenshot_taker.clone();
    
    // Start worker threads in the background
    println!("5. Starting workers in background");
    let worker_handle = tokio::spawn(async move {
        start_workers(
            job_rx,
            worker_screenshot_taker,
            worker_config,
            None,
            shutdown_rx
        ).await;
    });
    println!("6. Workers started in background");

    // Wrap shared data for the web handlers
    let job_tx_data = web::Data::new(job_tx);
    let config_data = web::Data::new(config);
    let screenshot_taker_data = web::Data::new(screenshot_taker.clone());

    info!("Starting HTTP server at {}:{}", host, port);
    println!(">>> Attempting to bind to {}:{}", host, port);
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

    // When server terminates, send shutdown signal to workers
    let _ = shutdown_tx.send(());

    // Wait for workers to shut down
    if let Err(e) = worker_handle.await {
        error!("Error while waiting for workers to shut down: {}", e);
    }

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

#[allow(dead_code)]
pub async fn init_api(
    config: ApiConfig,
    screenshot_taker: Arc<ScreenshotTaker>,
) -> Result<()> {
    let (job_tx, job_rx) = create_job_channel(None);
    let (shutdown_tx, shutdown_rx) = create_shutdown_channel();
    
    // Store channels in shared state
    let _state = Arc::new(AppState {
        job_tx,
        shutdown_tx: Some(shutdown_tx),
        screenshot_taker: Arc::clone(&screenshot_taker),
        config: config.clone(),
    });
    
    // Start worker tasks
    start_workers(
        job_rx,
        screenshot_taker.clone(),
        config.clone(),
        None,
        shutdown_rx
    ).await;
    
    Ok(())
} 