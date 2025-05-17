use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tracing::{debug, info, warn, trace};
use crate::data_classifier::classifier::classify_sensitive;
use crate::utils::anonymizer::Anonymizer;
use std::sync::Arc;

/// Represents an identifier found in a URL that may contain sensitive information
/// 
/// An identifier is typically a base64-encoded value that, when decoded,
/// contains sensitive information like personal data, tokens, or credentials.
#[derive(Debug, Clone)]
pub struct Identifier {
    pub value: String,                  // The original encoded value found in the URL
    pub decoded_value: Option<String>,  // The decoded value, if it could be decoded
    pub anonymized_value: Option<String>, // Anonymized replacement for the sensitive data
}

/// Analyzes a string value to check if it's base64-encoded sensitive data
/// 
/// This function:
/// 1. Attempts to decode the value as base64
/// 2. Checks if the decoded value contains sensitive information
/// 3. If sensitive data is found, creates an anonymized replacement
/// 
/// # Arguments
/// * `value` - The value to check for base64 encoding
/// * `anonymizer` - Anonymizer service for replacing sensitive data
/// * `context` - Description of where the value was found for logging
/// 
/// # Returns
/// * `Result<Option<Identifier>>` - An identifier if sensitive data was found, None otherwise
pub async fn analyze_potential_base64(
    value: &str,
    anonymizer: &Anonymizer,
    context: &str,
) -> Result<Option<Identifier>> {
    // Clone the values to move into the blocking task
    let value_clone = value.to_string();
    let context_clone = context.to_string();
    // Use Arc to safely share the Anonymizer with the blocking task
    let anonymizer_arc = Arc::new(anonymizer.clone());
    
    tokio::task::spawn_blocking(move || {
        // Dereference the arc inside the blocking task
        let anonymizer_ref = &*anonymizer_arc;
        analyze_base64_internal(&value_clone, anonymizer_ref, &context_clone)
    }).await?
}

// Internal helper function to perform the actual base64 analysis
fn analyze_base64_internal(
    value: &str,
    anonymizer: &Anonymizer,
    context: &str,
) -> Result<Option<Identifier>> {
    let value_str = value.to_string();
    
    // Attempt to decode as base64 - no need for URL decoding since form_urlencoded already handles that
    trace!("Attempting base64 decode for: {}", 
           if value_str.len() > 30 { format!("{}... (length: {})", &value_str[..30], value_str.len()) } 
           else { value_str.clone() });
    
    // Handle both standard base64 and URL-safe base64
    let decoded_result = BASE64.decode(value_str.as_bytes());
    
    match decoded_result {
        Ok(decoded_bytes) => {
            trace!("Successfully base64 decoded value from {} (byte length: {})", context, decoded_bytes.len());
            
            // Attempt to convert decoded bytes to UTF-8 string
            match String::from_utf8(decoded_bytes) {
                Ok(decoded_str) => {
                    debug!("Decoded base64 value to string: {}", 
                           if decoded_str.len() > 30 { format!("{}... (length: {})", &decoded_str[..30], decoded_str.len()) } 
                           else { decoded_str.clone() });
                    
                    // Check if the decoded string contains sensitive information
                    if let Some(data_type) = classify_sensitive(&decoded_str) {
                        info!("Found sensitive data in {}: type={:?}", context, data_type);
                        debug!("Sensitive data value: {}", 
                              if decoded_str.len() > 20 { format!("{}...", &decoded_str[..20]) } 
                              else { decoded_str.clone() });
                        
                        // Create anonymized replacement
                        let anonymized = anonymizer.anonymize_value(&decoded_str, Some(data_type.clone()));
                        debug!("Anonymized value: {}", anonymized);
                        
                        // Create identifier record
                        let identifier = Identifier {
                            value: value_str,
                            decoded_value: Some(decoded_str),
                            anonymized_value: Some(anonymized),
                        };
                        
                        return Ok(Some(identifier));
                    } else {
                        // We found a valid base64 value, but it doesn't contain sensitive information
                        debug!("Base64 decoded value does not contain recognized sensitive data");
                    }
                },
                Err(e) => {
                    // The base64 decoded to valid bytes, but not valid UTF-8
                    warn!("Failed to decode base64 value as UTF-8: {}", e);
                    trace!("Base64 value was decodable but produced invalid UTF-8: {}", value_str);
                }
            }
        },
        Err(_) => {
            // Not a valid base64 encoded string
            trace!("Value is not base64 encoded");
        }
    }
    
    Ok(None)
}