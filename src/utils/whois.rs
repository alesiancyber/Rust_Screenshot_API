use anyhow::{Result, Context};
use std::process::Command;
use serde::Serialize;
use tracing::{info, debug, warn, error, trace};
use crate::url_parser::ParsedUrl;

/// The result of a whois lookup.
/// Contains domain ownership and registration information.
#[derive(Debug, Serialize)]
pub struct WhoisResult {
    pub domain: String,
    pub organisation: Option<String>,
    pub created: Option<String>,
    pub changed: Option<String>,
    // pub raw: String,
}

/// Extract a field from the whois output by checking for multiple possible keys.
/// 
/// This function handles the inconsistent field names across different whois servers
/// by checking multiple possible keys for the same information.
/// 
/// # Arguments
/// * `raw` - The raw whois output text
/// * `keys` - Array of possible field names to search for
/// 
/// # Returns
/// * `Option<String>` - The extracted field value, if found
fn extract_field(raw: &str, keys: &[&str]) -> Option<String> {
    trace!("Extracting field from whois data, looking for keys: {:?}", keys);
    for line in raw.lines() {
        for key in keys {
            if line.to_lowercase().starts_with(&format!("{}:", key.to_lowercase())) {
                let value = line.splitn(2, ':').nth(1).map(|s| s.trim().to_string());
                if let Some(ref v) = value {
                    trace!("Found value for key '{}': '{}'", key, v);
                }
                return value;
            }
        }
    }
    debug!("No value found for any of these keys: {:?}", keys);
    None
}

/// Run a whois lookup for the domain extracted from the given URL using ParsedUrl.
/// 
/// This function performs the following steps:
/// 1. Parses the provided URL to extract the domain
/// 2. Executes the system's whois command for the domain
/// 3. Parses the whois output to extract relevant information
/// 
/// # Arguments
/// * `url` - The URL to analyze, must include protocol (e.g., "https://example.com")
/// 
/// # Returns
/// * `Result<WhoisResult>` - Structured whois information or an error
pub async fn lookup(url: &str) -> Result<WhoisResult> {
    // Use your URL parser to extract the domain
    debug!("Parsing URL for whois lookup: {}", url);
    let parsed = ParsedUrl::new(url).context("Failed to parse URL")?;
    
    // Use the domain directly
    let domain = &parsed.domain;
    info!("Performing whois lookup for domain: {}", domain);
    
    debug!("Executing whois command for domain: {}", domain);
    let output = match Command::new("whois")
        .arg(domain)
        .output() {
            Ok(o) => o,
            Err(e) => {
                error!("Failed to run whois command for {}: {}", domain, e);
                return Err(e).context("Failed to run whois command");
            }
        };
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Whois command exited with non-zero status: {}", stderr);
    }
    
    debug!("Parsing whois output for domain: {}", domain);
    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    trace!("Raw whois output length: {} bytes", raw.len());
    
    debug!("Extracting organisation information");
    let organisation = extract_field(&raw, &["organisation", "organization", "orgname"]);
    
    debug!("Extracting creation date");
    let created = extract_field(&raw, &["created"]);
    
    debug!("Extracting last changed date");
    let changed = extract_field(&raw, &["changed"]);
    
    info!("Successfully completed whois lookup for: {}", domain);
    debug!("Whois results - Organisation: {:?}, Created: {:?}, Changed: {:?}", 
          organisation.as_ref().map(|_| "Found").unwrap_or("None"), 
          created.as_ref().map(|_| "Found").unwrap_or("None"), 
          changed.as_ref().map(|_| "Found").unwrap_or("None"));
    
    Ok(WhoisResult {
        domain: domain.clone(),
        organisation,
        created,
        changed,
        // raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[ignore]
    async fn test_lookup_real_url() {
        let url = "https://www.verisign.com";
        let result = lookup(url).await.expect("whois lookup should succeed");
        println!("Domain: {}", result.domain);
        println!("Organisation: {:?}", result.organisation);
        println!("Created: {:?}", result.created);
        println!("Changed: {:?}", result.changed);
        assert!(result.organisation.is_some() || result.created.is_some() || result.changed.is_some());
    }
}