use anyhow::{Result, bail};
use tracing::{error};

// Constants for validation
const MAX_URL_LENGTH: usize = 2048;  // Maximum allowable URL length

/// Validates basic URL requirements
pub async fn validate_url(url: &str) -> Result<()> {
    if url.is_empty() {
        let msg = "URL cannot be empty";
        error!("Received empty URL");
        bail!(msg);
    }
    
    if url.len() > MAX_URL_LENGTH {
        let msg = format!("URL exceeds maximum length of {} characters", MAX_URL_LENGTH);
        error!("URL exceeds maximum length: {} > {}", url.len(), MAX_URL_LENGTH);
        bail!(msg);
    }
    
    if !url.starts_with("http://") && !url.starts_with("https://") {
        let msg = "URL must start with http:// or https://";
        error!("URL lacks proper protocol: {}", url);
        bail!(msg);
    }
    
    Ok(())
}

/// Extracts the domain from a parsed URL, handling different host types
pub async fn extract_domain(parsed_url: &url::Url) -> Result<String> {
    match parsed_url.host_str() {
        Some(host) => Ok(host.trim_start_matches("www.").to_string()),
        None => {
            tracing::warn!("URL has no host component");
            Ok(String::new())
        }
    }
} 