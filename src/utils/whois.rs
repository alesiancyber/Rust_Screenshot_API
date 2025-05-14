use anyhow::{Result, Context};
use std::process::Command;
use serde::Serialize;
use crate::url_parser::ParsedUrl;

/// The result of a whois lookup.
#[derive(Debug, Serialize)]
pub struct WhoisResult {
    pub domain: String,
    pub organisation: Option<String>,
    pub created: Option<String>,
    pub changed: Option<String>,
    // pub raw: String,
}

/// Extract a field from the whois output by checking for multiple possible keys.
fn extract_field(raw: &str, keys: &[&str]) -> Option<String> {
    for line in raw.lines() {
        for key in keys {
            if line.to_lowercase().starts_with(&format!("{}:", key.to_lowercase())) {
                return line.splitn(2, ':').nth(1).map(|s| s.trim().to_string());
            }
        }
    }
    None
}

/// Run a whois lookup for the domain extracted from the given URL using ParsedUrl.
pub async fn lookup(url: &str) -> Result<WhoisResult> {
    // Use your URL parser to extract the domain
    let parsed = ParsedUrl::new(url).context("Failed to parse URL")?;
    
    // Use the domain directly
    let domain = &parsed.domain;
    
    let output = Command::new("whois")
        .arg(domain)
        .output()
        .context("Failed to run whois command")?;
    
    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let organisation = extract_field(&raw, &["organisation", "organization", "orgname"]);
    let created = extract_field(&raw, &["created"]);
    let changed = extract_field(&raw, &["changed"]);
    
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