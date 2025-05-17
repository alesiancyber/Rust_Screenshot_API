use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use crate::utils::whois::WhoisResult;
use crate::ssl::CertificateInfo;
use crate::utils::benchmarking::OperationTimer;

/// Request to take a screenshot
#[derive(Debug, Deserialize, Clone)]
pub struct ScreenshotRequest {
    /// URL to screenshot
    pub url: String,
}

/// Internal job structure for screenshot tasks
#[derive(Debug)]
pub struct ScreenshotJob {
    /// The screenshot request
    pub request: ScreenshotRequest,
    
    /// Sender for the response channel
    pub response_tx: oneshot::Sender<Result<ScreenshotResponse, String>>,
    
    /// Optional timer for benchmarking operations
    pub timer: Option<OperationTimer>,
}

impl Clone for ScreenshotJob {
    fn clone(&self) -> Self {
        // Create a new oneshot channel for the clone
        let (tx, _) = oneshot::channel();
        Self {
            request: self.request.clone(),
            response_tx: tx,
            timer: self.timer.clone(),
        }
    }
}

/// Represents a sensitive identifier found in a URL
#[derive(Debug, Serialize, Clone)]
pub struct Identifier {
    /// The original encoded/obfuscated value
    pub value: String,
    
    /// The decoded plain-text value
    pub decoded_value: Option<String>,
    
    /// The type of sensitive data (email, phone, etc.)
    pub value_classification: String,
    
    /// The replacement value used in the anonymized URL
    pub replacement_value: Option<String>,
    
    /// The encoded replacement value
    pub encoded_replacement_value: Option<String>,
}

/// Response for a screenshot request
#[derive(Debug, Serialize, Clone)]
pub struct ScreenshotResponse {
    /// Original URL from the request
    pub original_url: String,
    
    /// URL with sensitive data anonymized
    pub anonymized_url: String,
    
    /// URL with base64 and other encoding decoded
    pub decoded_url: String,
    
    /// URL used for the screenshot (with replacements)
    pub replacement_url: String,
    
    /// Final URL after redirects
    pub final_url: String,
    
    /// All URLs in the redirect chain
    pub redirect_chain: Vec<String>,
    
    /// Number of redirects followed
    pub redirect_hop_count: usize,
    
    /// URLs referenced in query parameters
    pub referenced_urls: Vec<String>,
    
    /// All domains found in the URL
    pub unique_domains: Vec<String>,
    
    /// Sensitive identifiers detected
    pub identifiers: Vec<Identifier>,
    
    /// Screenshot of the original URL
    pub original_screenshot: Option<String>,
    
    /// Screenshot of the final URL
    pub final_screenshot: Option<String>,
    
    /// SSL certificate information for original domain
    pub original_ssl_info: Option<CertificateInfo>,
    
    /// SSL certificate information for final domain
    pub final_ssl_info: Option<CertificateInfo>,
    
    /// WHOIS information for original domain
    pub original_whois_info: Option<WhoisResult>,
    
    /// WHOIS information for final domain
    pub final_whois_info: Option<WhoisResult>,
    
    /// Overall request status
    pub status: String,
    
    /// Error message if any
    pub message: Option<String>,
    
    /// Detailed timing report
    pub timing_report: Option<String>,
}

impl ScreenshotResponse {
    /// Create a new screenshot response for the given URL
    pub fn new(url: String) -> Self {
        Self {
            original_url: url.clone(),
            anonymized_url: String::new(),
            decoded_url: String::new(),
            replacement_url: url,
            final_url: String::new(),
            redirect_chain: Vec::new(),
            redirect_hop_count: 0,
            referenced_urls: Vec::new(),
            unique_domains: Vec::new(),
            identifiers: Vec::new(),
            original_screenshot: None,
            final_screenshot: None,
            original_ssl_info: None,
            final_ssl_info: None,
            original_whois_info: None,
            final_whois_info: None,
            status: "pending".to_string(),
            message: None,
            timing_report: None,
        }
    }
}

/// Health status response for the /health endpoint
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    /// Status indicator: healthy, degraded, or unhealthy
    pub status: String,
    
    /// Number of active connections
    pub active_connections: usize,
    
    /// Total number of connections
    pub total_connections: usize,
    
    /// Server uptime in seconds
    pub uptime: std::time::Duration,
}

/// Error response for API endpoints
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Status indicator: error
    pub status: String,
    
    /// Error message details
    pub message: String,
} 