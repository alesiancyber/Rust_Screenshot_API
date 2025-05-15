use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{info, warn, error, debug, trace, instrument};
use std::time::Duration;
use tokio::time::timeout;
use crate::url_parser::ParsedUrl;
use crate::url_crawler::crawl_redirect_chain;
use crate::screenshot::{ScreenshotTaker, MAX_CONNECTIONS};
use crate::utils::url_to_snake_case;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::{mpsc, oneshot};
use crate::data_classifier::classifier::classify_sensitive;
use crate::ssl::{CertificateInfo, get_certificate_info_from_url};
use url;
use crate::utils::whois::{WhoisResult, lookup};

// Maximum number of jobs that can be queued at once
const QUEUE_SIZE: usize = 100; // Increased for production
// TODO: Make worker count and queue size configurable

/// Represents a request to capture a screenshot of a URL
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScreenshotRequest {
    url: String,
}

/// Complete screenshot analysis response including various URL transformations,
/// screenshots, SSL information, WHOIS data, and identified sensitive information
#[derive(Debug, Serialize)]
pub struct ScreenshotResponse {
    original_url: String,            // The URL as provided in the request
    final_url: String,               // The final URL after following redirects
    decoded_url: String,             // URL with encoded parameters decoded
    replacement_url: String,         // URL with sensitive data replaced
    anonymized_url: String,          // URL with all query params removed
    redirect_chain: Vec<String>,     // All URLs in the redirect chain
    identifiers: Vec<Identifier>,    // Sensitive data identified in the URL
    original_screenshot: Option<String>, // Base64 screenshot of original URL
    final_screenshot: Option<String>,    // Base64 screenshot of final URL
    status: String,                  // Status of the request (success/error)
    message: Option<String>,         // Optional message, usually for errors
    ssl_info: Option<CertificateInfo>, // SSL certificate information
    whois_info: Option<WhoisResult>, // WHOIS domain information
}

/// Represents a piece of identified data in a URL that might be sensitive
#[derive(Debug, Serialize)]
pub struct Identifier {
    value: String,                   // Original value found in URL
    decoded_value: Option<String>,   // Decoded value, if encoded
    value_classification: String,    // Classification of the data (PII, etc.)
    replacement_value: Option<String>, // Suggested replacement value
    encoded_replacement_value: Option<String>, // Encoded replacement value
}

/// Standard error response format for the API
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    status: String,                  // Always "error"
    message: String,                 // Detailed error message
}

/// Response for health check endpoint
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    status: String,                  // healthy, degraded, or unhealthy
    active_connections: usize,       // Number of active browser connections
    total_connections: usize,        // Total browser connections in pool
    uptime: Duration,                // Server uptime
}

/// Internal job representation for the worker queue
pub struct ScreenshotJob {
    pub request: ScreenshotRequest,
    pub response_tx: oneshot::Sender<Result<ScreenshotResponse, String>>,
}

impl ScreenshotResponse {
    /// Creates a new response object initialized with the original URL
    fn new(url: String) -> Self {
        trace!("Creating new ScreenshotResponse for URL: {}", url);
        Self {
            original_url: url.clone(),
            final_url: String::new(),
            decoded_url: url.clone(),
            replacement_url: url.clone(),
            anonymized_url: String::new(),
            redirect_chain: Vec::new(),
            identifiers: Vec::new(),
            original_screenshot: None,
            final_screenshot: None,
            status: "pending".to_string(),
            message: None,
            ssl_info: None,
            whois_info: None,
        }
    }
}

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

/// Processes a screenshot request to generate a complete analysis
/// 
/// This function performs the following steps:
/// 1. Parses and analyzes the URL for sensitive data
/// 2. Follows the redirect chain to the final destination
/// 3. Captures screenshots of both the original and final URLs
/// 4. Collects SSL certificate and WHOIS information
/// 
/// # Arguments
/// * `request` - The screenshot request containing the URL
/// * `_config` - API configuration parameters
/// * `screenshot_taker` - Shared screenshot service instance
/// 
/// # Returns
/// * `Result<ScreenshotResponse>` - Complete analysis or an error
#[instrument(skip(screenshot_taker, _config), fields(url = %request.url))]
async fn process_request(
    request: ScreenshotRequest,
    _config: &ApiConfig,
    screenshot_taker: Arc<ScreenshotTaker>,
) -> Result<ScreenshotResponse> {
    info!("Processing screenshot request for URL: {}", request.url);
    let mut response = ScreenshotResponse::new(request.url.clone());
    
    // Step 1: Parse and anonymize the URL
    debug!("Parsing URL: {}", request.url);
    let parsed_url = match ParsedUrl::new(&request.url) {
        Ok(parsed) => parsed,
        Err(e) => {
            error!("Failed to parse URL {}: {}", request.url, e);
            return Err(e);
        }
    };
    
    response.anonymized_url = parsed_url.anonymized_url.clone();
    trace!("Anonymized URL: {}", response.anonymized_url);
    
    // Create decoded URL by replacing base64 values
    let mut decoded_url = request.url.clone();
    let mut replacement_url = request.url.clone();
    
    // Add identifiers to response with the new structure
    debug!("Analyzing {} identifiers found in URL", parsed_url.identifiers.len());
    for identifier in &parsed_url.identifiers {
        // Determine the classification using the classifier module
        let data_type = if let Some(decoded) = &identifier.decoded_value {
            trace!("Classifying decoded value: {}", decoded);
            if let Some(classification) = classify_sensitive(decoded) {
                let class_str = format!("{:?}", classification).to_lowercase();
                debug!("Classified as: {}", class_str);
                class_str
            } else {
                debug!("No classification found for value");
                "unknown".to_string()
            }
        } else {
            debug!("No decoded value available for classification");
            "unknown".to_string()
        };
        
        // Replace the encoded values with decoded values in decoded_url
        if let Some(decoded) = &identifier.decoded_value {
            trace!("Replacing encoded value with decoded in URL");
            decoded_url = decoded_url.replace(&identifier.value, decoded);
        }
        
        // Replace the encoded values with replacement values in replacement_url
        if let Some(anonymized) = &identifier.anonymized_value {
            trace!("Replacing encoded value with anonymized value in URL");
            replacement_url = replacement_url.replace(&identifier.value, anonymized);
        }
        
        response.identifiers.push(Identifier {
            value: identifier.value.clone(),
            decoded_value: identifier.decoded_value.clone(),
            value_classification: data_type,
            replacement_value: identifier.anonymized_value.clone(),
            encoded_replacement_value: identifier.anonymized_value.clone(),  // This assumes the value is already base64 encoded
        });
    }
    
    // Update the decoded and replacement URLs
    debug!("Decoded URL: {}", decoded_url);
    debug!("Replacement URL: {}", replacement_url);
    response.decoded_url = decoded_url;
    response.replacement_url = replacement_url;
    
    // Step 2: Check redirect chain
    info!("Checking redirect chain for: {}", parsed_url.anonymized_url);
    let redirect_chain = match crawl_redirect_chain(&parsed_url.anonymized_url).await {
        Ok(chain) => {
            debug!("Found redirect chain with {} URLs", chain.len());
            chain
        },
        Err(e) => {
            error!("Failed to crawl redirect chain for {}: {}", parsed_url.anonymized_url, e);
            return Err(e);
        }
    };
    
    response.redirect_chain = redirect_chain.clone();
    
    let mut ssl_domain = None;
    if let Some(final_url) = redirect_chain.last() {
        info!("Final URL after redirects: {}", final_url);
        response.final_url = final_url.clone();
        // Extract domain for SSL check
        if let Ok(url) = url::Url::parse(final_url) {
            ssl_domain = url.host_str().map(|s| s.to_string());
            debug!("Extracted SSL domain: {:?}", ssl_domain);
        }
    } else {
        // Fallback: use domain from original URL
        debug!("No redirects found, using original domain");
        if let Ok(url) = url::Url::parse(&parsed_url.anonymized_url) {
            ssl_domain = url.host_str().map(|s| s.to_string());
            debug!("Extracted SSL domain from original URL: {:?}", ssl_domain);
        }
    }
    
    // Step 2.5: SSL info
    if let Some(domain) = &ssl_domain {
        let ssl_url = format!("https://{}", domain);
        debug!("Retrieving SSL certificate for: {}", ssl_url);
        match get_certificate_info_from_url(&ssl_url) {
            Ok(info) => {
                debug!("SSL certificate info retrieved for {}", domain);
                response.ssl_info = Some(info);
            },
            Err(e) => {
                warn!("Failed to get SSL certificate for {}: {}", domain, e);
            }
        }
    }
    
    // Step 2.6: Whois info
    debug!("Performing WHOIS lookup for URL: {}", request.url);
    match lookup(&request.url).await {
        Ok(info) => {
            debug!("WHOIS information retrieved");
            response.whois_info = Some(info);
        },
        Err(e) => {
            warn!("Failed to get WHOIS information: {}", e);
        }
    }
    
    // Step 3: Take screenshots
    let base_name = url_to_snake_case(&parsed_url.anonymized_url);
    
    // Take screenshot of original URL
    info!("Taking screenshot of original URL: {}", parsed_url.anonymized_url);
    let original_screenshot = match screenshot_taker.take_screenshot(
        &parsed_url.anonymized_url,
        &format!("{}_original", base_name)
    ).await {
        Ok(screenshot) => {
            debug!("Successfully captured screenshot of original URL");
            screenshot
        },
        Err(e) => {
            error!("Failed to capture screenshot of original URL: {}", e);
            return Err(e);
        }
    };
    
    response.original_screenshot = Some(original_screenshot.image_data);
    
    // Take screenshot of final URL if different
    if let Some(final_url) = redirect_chain.last() {
        if final_url != &parsed_url.anonymized_url {
            info!("Taking screenshot of final URL: {}", final_url);
            let dest_name = url_to_snake_case(final_url);
            match screenshot_taker.take_screenshot(
                final_url,
                &format!("{}_destination", dest_name)
            ).await {
                Ok(screenshot) => {
                    debug!("Successfully captured screenshot of final URL");
                    response.final_screenshot = Some(screenshot.image_data);
                },
                Err(e) => {
                    warn!("Failed to capture screenshot of final URL: {}", e);
                    // Continue anyway as we have the original screenshot
                }
            }
        } else {
            debug!("Final URL is same as original, skipping second screenshot");
        }
    }
    
    response.status = "success".to_string();
    info!("Successfully processed screenshot request for: {}", request.url);
    Ok(response)
}

/// HTTP handler for screenshot requests
/// 
/// Validates the request, submits it to the worker queue, and awaits the result
/// with a timeout.
/// 
/// # Arguments
/// * `request` - JSON request containing the URL to screenshot
/// * `config` - API configuration
/// * `job_tx` - Job queue sender
/// 
/// # Returns
/// * HTTP response with screenshot data or error information
#[instrument(skip(config, job_tx))]
async fn screenshot_handler(
    request: web::Json<ScreenshotRequest>,
    config: web::Data<ApiConfig>,
    job_tx: web::Data<mpsc::Sender<ScreenshotJob>>,
) -> impl Responder {
    info!("Received screenshot request for URL: {}", request.url);
    
    // Input validation: Only allow http/https URLs
    if !request.url.starts_with("http://") && !request.url.starts_with("https://") {
        warn!("Rejected invalid URL (not http/https): {}", request.url);
        return HttpResponse::BadRequest().json(ErrorResponse {
            status: "error".to_string(),
            message: "Invalid URL: must start with http:// or https://".to_string(),
        });
    }

    let (response_tx, response_rx) = oneshot::channel();
    let job = ScreenshotJob {
        request: request.into_inner(),
        response_tx,
    };

    // Try to enqueue the job
    debug!("Attempting to enqueue screenshot job");
    if let Err(_) = job_tx.try_send(job) {
        warn!("Queue full, rejecting request");
        return HttpResponse::TooManyRequests().json(ErrorResponse {
            status: "error".to_string(),
            message: "Server is busy, try again later.".to_string(),
        });
    }

    // Wait for the result
    debug!("Job enqueued, waiting for result with timeout: {:?}", config.request_timeout);
    match timeout(config.request_timeout, response_rx).await {
        Ok(Ok(Ok(response))) => {
            info!("Screenshot request completed successfully");
            HttpResponse::Ok().json(response)
        },
        Ok(Ok(Err(e))) => {
            error!("Screenshot request failed: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                status: "error".to_string(),
                message: e,
            })
        },
        Ok(Err(_)) => {
            error!("Worker channel closed unexpectedly");
            HttpResponse::InternalServerError().json(ErrorResponse {
                status: "error".to_string(),
                message: "Worker dropped.".to_string(),
            })
        },
        Err(_) => {
            error!("Request timed out after {:?}", config.request_timeout);
            HttpResponse::RequestTimeout().json(ErrorResponse {
                status: "error".to_string(),
                message: "Request timed out.".to_string(),
            })
        },
    }
}

/// Health check endpoint for monitoring service status
/// 
/// Returns information about the current state of the screenshot service,
/// including connection pool usage and overall health status.
/// 
/// # Arguments
/// * `screenshot_taker` - Shared screenshot service instance
/// 
/// # Returns
/// * HTTP response with health status information
#[instrument(skip(screenshot_taker))]
async fn health_check(screenshot_taker: web::Data<Arc<ScreenshotTaker>>) -> impl Responder {
    debug!("Processing health check request");
    
    let active = screenshot_taker.active_connections.load(Ordering::SeqCst);
    let total = screenshot_taker.total_connections.load(Ordering::SeqCst);
    
    let status = if active < total {
        "healthy"
    } else if active == total {
        "degraded"
    } else {
        "unhealthy"
    };

    info!("Health check: status={}, active={}/{}", status, active, total);
    HttpResponse::Ok().json(HealthStatus {
        status: status.to_string(),
        active_connections: active,
        total_connections: total,
        uptime: Duration::from_secs(0), // TODO: Add uptime tracking
    })
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
#[instrument(skip(config))]
pub async fn start_server(host: &str, port: u16, config: Option<ApiConfig>) -> Result<()> {
    info!("Starting screenshot API server on {}:{}", host, port);
    
    let config = config.unwrap_or_else(|| {
        debug!("Using default API configuration");
        ApiConfig {
            screenshot_dir: "screenshots".to_string(),
            viewport_width: 1280,
            viewport_height: 800,
            headless: true,
            webdriver_url: None,
            request_timeout: Duration::from_secs(30),
        }
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
    let (job_tx, job_rx) = mpsc::channel::<ScreenshotJob>(QUEUE_SIZE);
    let job_tx_data = web::Data::new(job_tx.clone());
    let config_data = web::Data::new(config.clone());
    let screenshot_taker_data = web::Data::new(screenshot_taker.clone());

    // Spawn worker tasks (all share the same receiver)
    info!("Spawning {} worker threads", MAX_CONNECTIONS);
    let job_rx = Arc::new(tokio::sync::Mutex::new(job_rx));
    for worker_id in 0..MAX_CONNECTIONS {
        let screenshot_taker = screenshot_taker.clone();
        let job_rx = job_rx.clone();
        let config = config.clone();
        tokio::spawn(async move {
            debug!("Worker thread {} started", worker_id);
            loop {
                trace!("Worker {} waiting for job", worker_id);
                let job_opt = { job_rx.lock().await.recv().await };
                
                match job_opt {
                    Some(job) => {
                        debug!("Worker {} processing job for URL: {}", worker_id, job.request.url);
                        let result = process_request(job.request, &config, screenshot_taker.clone()).await;
                        
                        match &result {
                            Ok(_) => debug!("Worker {} completed job successfully", worker_id),
                            Err(e) => warn!("Worker {} job failed: {}", worker_id, e),
                        }
                        
                        if let Err(_) = job.response_tx.send(result.map_err(|e| e.to_string())) {
                            warn!("Worker {} failed to send response - receiver dropped", worker_id);
                        }
                    },
                    None => {
                        info!("Worker {} shutting down - channel closed", worker_id);
                        break;
                    }
                }
            }
        });
    }

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
        Err(e) => warn!("Error closing screenshot service: {}", e),
    }

    if let Err(e) = server_result {
        error!("Server error: {}", e);
        return Err(e.into());
    }

    info!("Server shutdown complete");
    Ok(())
} 