use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::ssl::CertificateInfo;
use crate::utils::whois::WhoisResult;
use tokio::sync::oneshot;
use tracing::trace;

/// Represents a request to capture a screenshot of a URL
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScreenshotRequest {
    pub url: String,
}

/// Complete screenshot analysis response including various URL transformations,
/// screenshots, SSL information, WHOIS data, and identified sensitive information
#[derive(Debug, Serialize)]
pub struct ScreenshotResponse {
    pub original_url: String,            // The URL as provided in the request
    pub final_url: String,               // The final URL after following redirects
    pub decoded_url: String,             // URL with encoded parameters decoded
    pub replacement_url: String,         // URL with sensitive data replaced
    pub anonymized_url: String,          // URL with all query params removed
    pub redirect_chain: Vec<String>,     // All URLs in the redirect chain
    pub redirect_hop_count: usize,       // Number of redirects followed
    pub referenced_urls: Vec<String>,    // URLs found in parameters or path segments
    pub unique_domains: Vec<String>,     // All unique domains found in the URL and its parameters
    pub identifiers: Vec<Identifier>,    // Sensitive data identified in the URL
    pub original_screenshot: Option<String>, // Base64 screenshot of original URL
    pub final_screenshot: Option<String>,    // Base64 screenshot of final URL
    pub status: String,                  // Status of the request (success/error)
    pub message: Option<String>,         // Optional message, usually for errors
    pub original_ssl_info: Option<CertificateInfo>, // SSL certificate information for original domain
    pub final_ssl_info: Option<CertificateInfo>,    // SSL certificate information for final domain
    pub original_whois_info: Option<WhoisResult>,   // WHOIS domain information for original domain
    pub final_whois_info: Option<WhoisResult>,      // WHOIS domain information for final domain
}

/// Represents a piece of identified data in a URL that might be sensitive
#[derive(Debug, Serialize)]
pub struct Identifier {
    pub value: String,                   // Original value found in URL
    pub decoded_value: Option<String>,   // Decoded value, if encoded
    pub value_classification: String,    // Classification of the data (PII, etc.)
    pub replacement_value: Option<String>, // Suggested replacement value
    pub encoded_replacement_value: Option<String>, // Encoded replacement value
}

/// Standard error response format for the API
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: String,                  // Always "error"
    pub message: String,                 // Detailed error message
}

/// Response for health check endpoint
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,                  // healthy, degraded, or unhealthy
    pub active_connections: usize,       // Number of active browser connections
    pub total_connections: usize,        // Total browser connections in pool
    pub uptime: Duration,                // Server uptime
}

/// Internal job representation for the worker queue
pub struct ScreenshotJob {
    pub request: ScreenshotRequest,
    pub response_tx: oneshot::Sender<Result<ScreenshotResponse, String>>,
}

impl ScreenshotResponse {
    /// Creates a new response object initialized with the original URL
    pub fn new(url: String) -> Self {
        trace!("Creating new ScreenshotResponse for URL: {}", url);
        Self {
            original_url: url.clone(),
            final_url: String::new(),
            decoded_url: url.clone(),
            replacement_url: url.clone(),
            anonymized_url: String::new(),
            redirect_chain: Vec::new(),
            redirect_hop_count: 0,
            referenced_urls: Vec::new(),
            unique_domains: Vec::new(),
            identifiers: Vec::new(),
            original_screenshot: None,
            final_screenshot: None,
            status: "pending".to_string(),
            message: None,
            original_ssl_info: None,
            final_ssl_info: None,
            original_whois_info: None,
            final_whois_info: None,
        }
    }
} 