use anyhow::Result;
use url::Url;
use std::collections::HashMap;
use tracing::{debug, trace};
use crate::utils::anonymizer::Anonymizer;

use super::identifier::{Identifier, analyze_potential_base64};
use super::url_collection::UrlCollection;

/// Process query parameters from a URL for potential sensitive information
///
/// Analyzes each query parameter value for potential base64-encoded sensitive data
/// and adds any discovered URLs to the collection for tracking.
///
/// # Arguments
/// * `url` - The parsed URL to examine
/// * `identifiers` - Collection to store any sensitive data identifiers found
/// * `replacement_params` - Map to store anonymized replacements for sensitive parameters
/// * `url_collection` - Collection to track discovered URLs
/// * `anonymizer` - Service to anonymize any sensitive data found
///
/// # Returns
/// * `Result<()>` - Success or failure of the processing operation
pub async fn process_query_parameters(
    url: &Url,
    identifiers: &mut Vec<Identifier>,
    replacement_params: &mut HashMap<String, String>,
    url_collection: &mut UrlCollection,
    anonymizer: &Anonymizer
) -> Result<()> {
    debug!("Processing query parameters");
    
    // Extract query pairs from the URL
    let query_pairs: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    
    for (key, value) in query_pairs {
        trace!("Checking parameter: {}", key);
        
        // Check if value is a URL (common in redirects, referrers, etc.)
        if value.starts_with("http://") || value.starts_with("https://") {
            debug!("Found URL in parameter '{}': {}", key, value);
            url_collection.add_referenced_url(&value, Some(&key))?;
            
            // Important: Don't skip further processing - URL parameters may still need to be anonymized
            // But we'll preserve URLs in "url" parameter, which is common for redirects
            if key == "url" || key == "redirect_uri" || key == "redirect_url" {
                debug!("Preserving redirect URL parameter '{}' value", key);
                // Add this to the replacement parameters to ensure it's kept
                replacement_params.insert(key.clone(), value.clone());
                continue;
            }
            
            // For other URL parameters, still check for encoding
        }
        
        // Check if value might be base64-encoded sensitive data
        if value.len() > 8 {  // Minimum realistic length for base64 encoded data
            let context = format!("query parameter '{}'", key);
            if let Some(identifier) = analyze_potential_base64(&value, anonymizer, &context).await? {
                debug!("Found sensitive data in parameter '{}'", key);
                
                // Add anonymized replacement if available
                if let Some(anonymized) = &identifier.anonymized_value {
                    replacement_params.insert(key, anonymized.clone());
                }
                
                // Add the identifier after using it for replacement_params
                identifiers.push(identifier);
            }
        }
    }
    
    Ok(())
}

/// Process path segments from a URL for potential sensitive information
///
/// Analyzes each path segment for potential base64-encoded sensitive data
/// and adds any discovered URLs to the collection for tracking.
///
/// # Arguments
/// * `url` - The parsed URL to examine
/// * `identifiers` - Collection to store any sensitive data identifiers found
/// * `anonymizer` - Service to anonymize any sensitive data found
///
/// # Returns
/// * `Result<()>` - Success or failure of the processing operation
pub async fn process_path_segments(
    url: &Url,
    identifiers: &mut Vec<Identifier>,
    anonymizer: &Anonymizer
) -> Result<()> {
    debug!("Processing path segments");
    
    let path_segments: Vec<String> = url.path_segments()
        .map(|segments| segments.map(String::from).collect())
        .unwrap_or_default();
    
    for (index, segment) in path_segments.iter().enumerate() {
        trace!("Checking path segment {}: {}", index, segment);
        
        // Skip short segments and common file extensions
        if segment.len() < 8 || segment.contains('.') {
            continue;
        }
        
        // Check if segment might be base64-encoded sensitive data
        let context = format!("path segment {}", index);
        if let Some(identifier) = analyze_potential_base64(segment, anonymizer, &context).await? {
            debug!("Found sensitive data in path segment {}", index);
            identifiers.push(identifier);
            
            // Note: We don't modify the path segments here, only in query parameters
            // Path segment anonymization would require a different approach
        }
    }
    
    Ok(())
}