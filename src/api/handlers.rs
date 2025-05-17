use actix_web::{web, HttpResponse, Responder};
use tracing::{info, warn, error, debug, instrument};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::{timeout, sleep};
use tokio::sync::{mpsc, oneshot};
use std::time::Duration;

use crate::api::models::{ScreenshotJob, ScreenshotRequest, ErrorResponse, HealthStatus};
use crate::api::config::ApiConfig;
use crate::screenshot::ScreenshotTaker;
use crate::url_parser::ParsedUrl;

/// HTTP handler for screenshot requests
/// 
/// Validates the request, submits it to the worker queue, and awaits the result
/// with a timeout.
/// 
/// The response includes comprehensive URL analysis data:
/// - Original, final, decoded, and anonymized URLs
/// - All URLs in the redirect chain and the number of redirects (hop count)
/// - All URLs referenced in parameters of the original URL
/// - All unique domains found in the URL and its parameters
/// - Any sensitive data identified with their anonymized replacements
/// - Screenshots of both original and final URLs (if they differ)
/// - SSL certificate and WHOIS information
/// 
/// # Arguments
/// * `request` - JSON request containing the URL to screenshot
/// * `config` - API configuration
/// * `job_tx` - Job queue sender
/// 
/// # Returns
/// * HTTP response with screenshot data or error information
#[instrument(skip(config, job_tx))]
pub async fn screenshot_handler(
    request: web::Json<ScreenshotRequest>,
    config: web::Data<ApiConfig>,
    job_tx: web::Data<mpsc::Sender<ScreenshotJob>>,
) -> impl Responder {
    info!("Received screenshot request for URL: {}", request.url);
    
    // Improved URL validation using the URL parser
    match ParsedUrl::new(&request.url).await {
        Err(e) => {
            warn!("Rejected invalid URL: {} - {}", request.url, e);
            return HttpResponse::BadRequest().json(ErrorResponse {
                status: "error".to_string(),
                message: format!("Invalid URL: {}", e),
            });
        },
        Ok(_) => {
            debug!("URL validation passed: {}", request.url);
        }
    }

    // Try to enqueue the job with a brief retry strategy
    debug!("Attempting to enqueue screenshot job");
    
    // Try sending a few times with a short delay between attempts
    let max_attempts = 3;
    let retry_delay = Duration::from_millis(100);
    let mut attempts = 0;
    let request_url = request.url.clone();
    
    while attempts < max_attempts {
        // Create a new channel for each attempt
        let (response_tx, response_rx) = oneshot::channel();
        
        let job = ScreenshotJob {
            request: ScreenshotRequest { url: request_url.clone() },
            response_tx,
        };
        
        match job_tx.try_send(job) {
            Ok(_) => {
                debug!("Job successfully enqueued after {} attempt(s)", attempts + 1);
                
                // Wait for the result
                debug!("Waiting for result with timeout: {:?}", config.request_timeout);
                return match timeout(config.request_timeout, response_rx).await {
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
                };
            },
            Err(mpsc::error::TrySendError::Full(_)) => {
                attempts += 1;
                if attempts < max_attempts {
                    warn!("Queue full, retrying (attempt {}/{})", attempts, max_attempts);
                    sleep(retry_delay).await;
                    // We'll create a new job on the next loop iteration
                } else {
                    warn!("Queue full after {} attempts, rejecting request", max_attempts);
                    return HttpResponse::TooManyRequests().json(ErrorResponse {
                        status: "error".to_string(),
                        message: format!("Server is busy, try again later. Queue has been full for {:?}", retry_delay * attempts as u32),
                    });
                }
            },
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("Worker queue has been closed!");
                return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                    status: "error".to_string(),
                    message: "Service is shutting down or unavailable.".to_string(),
                });
            }
        }
    }
    
    // This should never be reached because we either return success or error inside the loop
    error!("Unexpected code path in screenshot_handler");
    HttpResponse::InternalServerError().json(ErrorResponse {
        status: "error".to_string(),
        message: "Internal error in request handling.".to_string(),
    })
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
pub async fn health_check(screenshot_taker: web::Data<Arc<ScreenshotTaker>>) -> impl Responder {
    debug!("Processing health check request");
    
    // Use Ordering::Acquire which is sufficient for reading values
    let active = screenshot_taker.active_connections().load(Ordering::Acquire);
    let total = screenshot_taker.total_connections().load(Ordering::Acquire);
    
    // Safer health status logic that handles cases where counts aren't updated atomically
    let status = if active >= total && total > 0 {
        // If active >= total and total is not zero, we're at full capacity
        "degraded"
    } else if active > total {
        // This shouldn't happen, but we handle it just in case
        warn!("Health check: active connections ({}) greater than total connections ({})", active, total);
        "unhealthy"
    } else if total == 0 {
        // No connections available
        warn!("Health check: no screenshot connections available");
        "unhealthy"
    } else {
        // Normal operating condition
        "healthy"
    };

    info!("Health check: status={}, active={}/{}", status, active, total);
    HttpResponse::Ok().json(HealthStatus {
        status: status.to_string(),
        active_connections: active,
        total_connections: total,
        uptime: std::time::Duration::from_secs(0), // TODO: Add uptime tracking
    })
} 