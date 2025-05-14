use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use log::info;
use std::time::Duration;
use tokio::time::timeout;
use crate::url_parser::ParsedUrl;
use crate::url_crawler::crawl_redirect_chain;
use crate::screenshot::{ScreenshotTaker, MAX_CONNECTIONS};
use crate::utils::url_to_snake_case;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::{mpsc, oneshot};

const QUEUE_SIZE: usize = 2;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScreenshotRequest {
    url: String,
}

#[derive(Debug, Serialize)]
pub struct ScreenshotResponse {
    original_url: String,
    anonymized_url: String,
    final_url: String,
    identifiers: Vec<Identifier>,
    original_screenshot: Option<String>,
    final_screenshot: Option<String>,
    status: String,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Identifier {
    value: String,
    decoded_value: Option<String>,
    anonymized_value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthStatus {
    status: String,
    active_connections: usize,
    total_connections: usize,
    uptime: Duration,
}

pub struct ScreenshotJob {
    pub request: ScreenshotRequest,
    pub response_tx: oneshot::Sender<Result<ScreenshotResponse, String>>,
}

impl ScreenshotResponse {
    fn new(url: String) -> Self {
        Self {
            original_url: url,
            anonymized_url: String::new(),
            final_url: String::new(),
            identifiers: Vec::new(),
            original_screenshot: None,
            final_screenshot: None,
            status: "pending".to_string(),
            message: None,
        }
    }
}

#[derive(Clone)]
pub struct ApiConfig {
    pub screenshot_dir: String,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub headless: bool,
    pub webdriver_url: Option<String>,
    pub request_timeout: Duration,
}

async fn process_request(
    request: ScreenshotRequest,
    _config: &ApiConfig,
    screenshot_taker: Arc<ScreenshotTaker>,
) -> Result<ScreenshotResponse> {
    let mut response = ScreenshotResponse::new(request.url.clone());
    
    // Step 1: Parse and anonymize the URL
    info!("Parsing URL: {}", request.url);
    let parsed_url = ParsedUrl::new(&request.url)?;
    response.anonymized_url = parsed_url.anonymized_url.clone();
    
    // Add identifiers to response
    for identifier in &parsed_url.identifiers {
        response.identifiers.push(Identifier {
            value: identifier.value.clone(),
            decoded_value: identifier.decoded_value.clone(),
            anonymized_value: identifier.anonymized_value.clone(),
        });
    }

    // Step 2: Check redirect chain
    info!("Checking redirect chain for: {}", parsed_url.anonymized_url);
    let redirect_chain = crawl_redirect_chain(&parsed_url.anonymized_url).await?;
    if let Some(final_url) = redirect_chain.last() {
        response.final_url = final_url.clone();
    }

    // Step 3: Take screenshots
    let base_name = url_to_snake_case(&parsed_url.anonymized_url);
    
    // Take screenshot of original URL
    let original_screenshot = screenshot_taker.take_screenshot(
        &parsed_url.anonymized_url,
        &format!("{}_original", base_name)
    ).await?;
    response.original_screenshot = Some(original_screenshot.image_data);

    // Take screenshot of final URL if different
    if let Some(final_url) = redirect_chain.last() {
        if final_url != &parsed_url.anonymized_url {
            let dest_name = url_to_snake_case(final_url);
            let final_screenshot = screenshot_taker.take_screenshot(
                final_url,
                &format!("{}_destination", dest_name)
            ).await?;
            response.final_screenshot = Some(final_screenshot.image_data);
        }
    }

    response.status = "success".to_string();
    Ok(response)
}

async fn screenshot_handler(
    request: web::Json<ScreenshotRequest>,
    config: web::Data<ApiConfig>,
    job_tx: web::Data<mpsc::Sender<ScreenshotJob>>,
) -> impl Responder {
    let (response_tx, response_rx) = oneshot::channel();
    let job = ScreenshotJob {
        request: request.into_inner(),
        response_tx,
    };

    // Try to enqueue the job
    if let Err(_) = job_tx.try_send(job) {
        return HttpResponse::TooManyRequests().body("Server is busy, try again later.");
    }

    // Wait for the result
    match timeout(config.request_timeout, response_rx).await {
        Ok(Ok(Ok(response))) => HttpResponse::Ok().json(response),
        Ok(Ok(Err(e))) => HttpResponse::InternalServerError().body(e),
        Ok(Err(_)) => HttpResponse::InternalServerError().body("Worker dropped."),
        Err(_) => HttpResponse::RequestTimeout().body("Request timed out."),
    }
}

async fn health_check(screenshot_taker: web::Data<Arc<ScreenshotTaker>>) -> impl Responder {
    let active = screenshot_taker.active_connections.load(Ordering::SeqCst);
    let total = screenshot_taker.total_connections.load(Ordering::SeqCst);
    
    let status = if active < total {
        "healthy"
    } else if active == total {
        "degraded"
    } else {
        "unhealthy"
    };

    HttpResponse::Ok().json(HealthStatus {
        status: status.to_string(),
        active_connections: active,
        total_connections: total,
        uptime: Duration::from_secs(0), // TODO: Add uptime tracking
    })
}

pub async fn start_server(host: &str, port: u16, config: Option<ApiConfig>) -> Result<()> {
    let config = config.unwrap_or_else(|| ApiConfig {
        screenshot_dir: "screenshots".to_string(),
        viewport_width: 1280,
        viewport_height: 800,
        headless: true,
        webdriver_url: None,
        request_timeout: Duration::from_secs(30),
    });

    let screenshot_taker = Arc::new(ScreenshotTaker::new(
        &config.screenshot_dir,
        config.webdriver_url.as_deref(),
        Some((config.viewport_width, config.viewport_height)),
        config.headless
    ).await?);

    // Create the job queue
    let (job_tx, job_rx) = mpsc::channel::<ScreenshotJob>(QUEUE_SIZE);
    let job_tx_data = web::Data::new(job_tx.clone());
    let config_data = web::Data::new(config.clone());
    let screenshot_taker_data = web::Data::new(screenshot_taker.clone());

    // Spawn worker tasks (all share the same receiver)
    let job_rx = Arc::new(tokio::sync::Mutex::new(job_rx));
    for _ in 0..MAX_CONNECTIONS {
        let screenshot_taker = screenshot_taker.clone();
        let job_rx = job_rx.clone();
        let config = config.clone();
        tokio::spawn(async move {
            loop {
                let job_opt = { job_rx.lock().await.recv().await };
                if let Some(job) = job_opt {
                    let result = process_request(job.request, &config, screenshot_taker.clone()).await;
                    let _ = job.response_tx.send(result.map_err(|e| e.to_string()));
                } else {
                    break;
                }
            }
        });
    }

    info!("Starting server at {}:{}", host, port);
    HttpServer::new(move || {
        App::new()
            .app_data(config_data.clone())
            .app_data(job_tx_data.clone())
            .app_data(screenshot_taker_data.clone())
            .service(web::resource("/screenshot").route(web::post().to(screenshot_handler)))
            .service(web::resource("/health").route(web::get().to(health_check)))
    })
    .bind((host, port))?
    .run()
    .await?;

    // Cleanup
    screenshot_taker.close().await?;

    Ok(())
} 