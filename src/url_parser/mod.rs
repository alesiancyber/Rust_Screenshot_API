use anyhow::{Result, Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use log::{debug, info, warn};
use url::Url;
use crate::utils::anonymizer::Anonymizer;
use crate::data_classifier::classifier::classify_sensitive;

const MAX_URL_LENGTH: usize = 2048;
const MAX_IDENTIFIERS: usize = 100;

/// Represents a parsed URL with detected identifiers and their anonymized versions
#[derive(Debug)]
pub struct ParsedUrl {
    #[allow(dead_code)]
    pub original_url: String,
    #[allow(dead_code)]
    pub base_url: String,
    pub domain: String,
    pub identifiers: Vec<Identifier>,
    pub anonymized_url: String,
}

/// Represents an identifier found in a URL that may contain sensitive information
#[derive(Debug, Clone)]
pub struct Identifier {
    pub value: String,
    pub decoded_value: Option<String>,
    pub anonymized_value: Option<String>,
}

impl ParsedUrl {
    /// Creates a new ParsedUrl by analyzing the provided URL string
    /// 
    /// # Arguments
    /// * `url` - The URL to parse and analyze for sensitive data
    /// 
    /// # Returns
    /// * `Result<ParsedUrl>` - The parsed URL with identified sensitive data, or an error
    pub fn new(url: &str) -> Result<Self> {
        // Validate input
        if url.is_empty() {
            bail!("URL cannot be empty");
        }
        if url.len() > MAX_URL_LENGTH {
            bail!("URL exceeds maximum length of {} characters", MAX_URL_LENGTH);
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            bail!("URL must start with http:// or https://");
        }
        info!("Parsing URL: {}", url);
        
        let parsed_url = Url::parse(url)
            .context("Failed to parse URL")?;
        
        // Extract domain and strip www. prefix
        let domain = parsed_url.host_str()
            .unwrap_or_default()
            .trim_start_matches("www.")
            .to_string();
        
        let base_url = format!("{}://{}{}", 
            parsed_url.scheme(),
            parsed_url.host_str().unwrap_or_default(),
            parsed_url.path()
        );
        debug!("Base URL extracted: {}", base_url);
        let mut identifiers = Vec::new();
        let anonymizer = Anonymizer::new();
        let mut anonymized_url = url.to_string();
        
        // Check query parameters for base64 encoded values
        info!("Checking query parameters for base64 encoded values");
        for (key, value) in parsed_url.query_pairs() {
            debug!("Checking query parameter: {}={}", key, value);
            if identifiers.len() >= MAX_IDENTIFIERS {
                warn!("Maximum number of identifiers reached");
                break;
            }
            Self::check_and_process_value(
                &value,
                &mut identifiers,
                &mut anonymized_url,
                &anonymizer,
                &format!("query parameter {}", key)
            )?;
        }
        // Check path segments for base64 encoded values
        info!("Checking path segments for base64 encoded values");
        for segment in parsed_url.path_segments().unwrap_or_else(|| "".split('/')) {
            if segment.is_empty() {
                continue;
            }
            debug!("Checking path segment: {}", segment);
            if identifiers.len() >= MAX_IDENTIFIERS {
                warn!("Maximum number of identifiers reached");
                break;
            }
            Self::check_and_process_value(
                segment,
                &mut identifiers,
                &mut anonymized_url,
                &anonymizer,
                "path segment"
            )?;
        }
        info!("URL parsing complete. Found {} identifiers", identifiers.len());
        for (i, id) in identifiers.iter().enumerate() {
            info!("Identifier {}: encoded={}, decoded={:?}, anonymized={:?}",
                i, id.value, id.decoded_value, id.anonymized_value);
        }
        Ok(ParsedUrl {
            original_url: url.to_string(),
            base_url,
            domain,
            identifiers,
            anonymized_url,
        })
    }

    /// Checks if a value is base64-encoded and contains sensitive information
    /// If it does, processes it and adds to the identifiers list
    fn check_and_process_value(
        value: &str,
        identifiers: &mut Vec<Identifier>,
        anonymized_url: &mut String,
        anonymizer: &Anonymizer,
        context: &str,
    ) -> Result<()> {
        let value_str = value.to_string();
        debug!("Checking {} value: {}", context, value_str);
        if let Ok(decoded) = BASE64.decode(value_str.as_bytes()) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                if let Some(data_type) = classify_sensitive(&decoded_str) {
                    info!("Found sensitive data in {}: {}", context, decoded_str);
                    let anonymized = anonymizer.anonymize_value(&decoded_str, Some(data_type.clone()));
                    debug!("Anonymized value: {}", anonymized);
                    let identifier = Identifier {
                        value: value_str.clone(),
                        decoded_value: Some(decoded_str),
                        anonymized_value: Some(anonymized.clone()),
                    };
                    identifiers.push(identifier);
                    let anonymized_encoded = BASE64.encode(anonymized.as_bytes());
                    debug!("Replacing {} with {} in URL", value_str, anonymized_encoded);
                    *anonymized_url = anonymized_url.replace(&value_str, &anonymized_encoded);
                } else {
                    warn!("Found base64 encoded value in {} but it's not sensitive: {}", context, decoded_str);
                }
            } else {
                warn!("Failed to decode base64 value as UTF-8: {}", value_str);
            }
        } else {
            debug!("Value is not base64 encoded: {}", value_str);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_url_with_base64() {
        let test_url = "https://example.com/verify?token=SGVsbG8gV29ybGQ="; // Base64 for "Hello World"
        let parsed = ParsedUrl::new(test_url).unwrap();
        
        assert_eq!(parsed.base_url, "https://example.com/verify");
        assert!(!parsed.identifiers.is_empty());
        assert_eq!(parsed.identifiers[0].decoded_value.as_ref().unwrap(), "Hello World");
        assert!(parsed.identifiers[0].anonymized_value.is_some());
        assert_eq!(parsed.domain, "example.com");
    }
    
    #[test]
    fn test_empty_url() {
        let result = ParsedUrl::new("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("URL cannot be empty"));
    }
    
    #[test]
    fn test_url_without_protocol() {
        let result = ParsedUrl::new("example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must start with http:// or https://"));
    }
    
    #[test]
    fn test_url_with_multiple_base64_values() {
        let test_url = "https://example.com/verify?token1=SGVsbG8gV29ybGQ=&token2=Qm9uam91cg==";
        let parsed = ParsedUrl::new(test_url).unwrap();
        assert_eq!(parsed.identifiers.len(), 2);
        assert_eq!(parsed.domain, "example.com");
    }
    
    #[test]
    fn test_url_with_invalid_base64() {
        let test_url = "https://example.com/verify?token=invalid-base64!";
        let parsed = ParsedUrl::new(test_url).unwrap();
        assert!(parsed.identifiers.is_empty());
        assert_eq!(parsed.domain, "example.com");
    }
}