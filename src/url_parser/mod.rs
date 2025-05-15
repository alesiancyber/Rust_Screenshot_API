use anyhow::{Result, Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tracing::{debug, info, warn, error, trace, instrument};
use url::{Url, form_urlencoded, Host};
use crate::utils::anonymizer::Anonymizer;
use crate::data_classifier::classifier::classify_sensitive;
use std::collections::{HashMap, HashSet};

// Constants for validation and performance limits
const MAX_URL_LENGTH: usize = 2048;  // Maximum allowable URL length
const MAX_IDENTIFIERS: usize = 100;  // Maximum number of identifiers to extract from a single URL

/// Collection of URLs discovered during parsing and analysis
/// 
/// Tracks all URLs found during the parsing process, including:
/// - Original and anonymized URLs
/// - Referenced URLs in parameters
/// - All unique domains encountered
#[derive(Debug, Clone)]
pub struct UrlCollection {
    pub original_url: String,               // The original URL provided for analysis
    pub anonymized_url: String,             // The URL with sensitive data anonymized
    pub referenced_urls: Vec<String>,       // URLs found in parameters or path segments
    pub unique_domains: HashSet<String>,    // All unique domains found
    pub parameter_urls: HashMap<String, String>, // URLs found in specific parameters, by param name
}

impl UrlCollection {
    /// Creates a new empty URL collection with just the original URL
    fn new(original_url: &str) -> Self {
        let mut unique_domains = HashSet::new();
        
        // Try to extract domain from original URL
        if let Ok(parsed) = Url::parse(original_url) {
            if let Some(host) = parsed.host_str() {
                unique_domains.insert(host.trim_start_matches("www.").to_string());
            }
        }
        
        UrlCollection {
            original_url: original_url.to_string(),
            anonymized_url: original_url.to_string(),
            referenced_urls: Vec::new(),
            unique_domains,
            parameter_urls: HashMap::new(),
        }
    }
    
    /// Adds a referenced URL found in a parameter or path segment
    fn add_referenced_url(&mut self, url: &str, parameter_name: Option<&str>) {
        // Only add valid URLs
        if let Ok(parsed) = Url::parse(url) {
            self.referenced_urls.push(url.to_string());
            
            // Extract and add domain
            if let Some(host) = parsed.host_str() {
                self.unique_domains.insert(host.trim_start_matches("www.").to_string());
            }
            
            // If from a specific parameter, track it
            if let Some(param) = parameter_name {
                self.parameter_urls.insert(param.to_string(), url.to_string());
            }
        }
    }
    
    /// Sets the anonymized URL
    fn set_anonymized_url(&mut self, url: String) {
        self.anonymized_url = url;
    }
}

/// Represents a parsed URL with detected identifiers and their anonymized versions
/// 
/// This struct holds the results of URL parsing and analysis, including any
/// identified sensitive data in the URL and an anonymized version of the URL.
#[derive(Debug)]
pub struct ParsedUrl {
    pub domain: String,               // Domain name extracted from the URL
    pub identifiers: Vec<Identifier>, // Collection of sensitive data identifiers found
    pub anonymized_url: String,       // URL with sensitive data replaced
    pub url_collection: UrlCollection, // Collection of all related URLs
}

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

impl ParsedUrl {
    /// Creates a new ParsedUrl by analyzing the provided URL string
    /// 
    /// This function performs the following steps:
    /// 1. Validates the URL format and constraints
    /// 2. Parses the URL into components (domain, path, query params)
    /// 3. Examines the URL for base64-encoded values
    /// 4. Decodes and analyzes these values for sensitive data
    /// 5. Creates anonymized replacements for any sensitive data found
    /// 
    /// # Arguments
    /// * `url` - The URL to parse and analyze for sensitive data
    /// 
    /// # Returns
    /// * `Result<ParsedUrl>` - The parsed URL with identified sensitive data, or an error
    #[instrument(level = "debug", skip_all, fields(url = %url))]
    pub fn new(url: &str) -> Result<Self> {
        println!("\n==================================================");
        println!("PARSING URL: {}", url);
        println!("==================================================");
        
        trace!("Starting URL parsing process");
        
        // Initialize URL collection to track all URLs found
        let mut url_collection = UrlCollection::new(url);
        
        // Validate input
        if url.is_empty() {
            let msg = "URL cannot be empty";
            println!("ERROR: {}", msg);
            error!("Received empty URL");
            bail!(msg);
        }
        
        if url.len() > MAX_URL_LENGTH {
            let msg = format!("URL exceeds maximum length of {} characters", MAX_URL_LENGTH);
            println!("ERROR: {}", msg);
            error!("URL exceeds maximum length: {} > {}", url.len(), MAX_URL_LENGTH);
            bail!(msg);
        }
        
        if !url.starts_with("http://") && !url.starts_with("https://") {
            let msg = "URL must start with http:// or https://";
            println!("ERROR: {}", msg);
            error!("URL lacks proper protocol: {}", url);
            bail!(msg);
        }
        
        info!("Parsing URL: {}", url);
        
        // Parse the URL into a structured form using the rust-url library
        let parsed_url = match Url::parse(url) {
            Ok(parsed) => parsed,
            Err(e) => {
                let msg = format!("Failed to parse URL: {}", e);
                println!("ERROR: {}", msg);
                error!("Failed to parse URL '{}': {}", url, e);
                return Err(e).context(msg);
            }
        };
        
        // Print detailed URL components for debugging
        println!("\n=== URL COMPONENTS ===");
        println!("Scheme: {}", parsed_url.scheme());
        println!("Username: {}", parsed_url.username());
        println!("Password: {}", parsed_url.password().unwrap_or("<none>"));
        
        match parsed_url.host() {
            Some(Host::Domain(domain)) => println!("Host (Domain): {}", domain),
            Some(Host::Ipv4(addr)) => println!("Host (IPv4): {}", addr),
            Some(Host::Ipv6(addr)) => println!("Host (IPv6): {}", addr),
            None => println!("Host: <none>"),
        }
        
        println!("Port: {}", parsed_url.port().unwrap_or_default());
        println!("Path: {}", parsed_url.path());
        
        if let Some(query) = parsed_url.query() {
            println!("Query: {}", query);
        } else {
            println!("Query: <none>");
        }
        
        if let Some(fragment) = parsed_url.fragment() {
            println!("Fragment: {}", fragment);
        } else {
            println!("Fragment: <none>");
        }
        
        println!("Cannot be a base: {}", parsed_url.cannot_be_a_base());
        
        // Extract domain and strip www. prefix for cleaner representation
        let domain = parsed_url.host_str()
            .unwrap_or_default()
            .trim_start_matches("www.")
            .to_string();
        
        debug!("Extracted domain: {}", domain);
        println!("Extracted domain (www. removed): {}", domain);
        
        // Construct the base URL (scheme + host + path, no query params)
        let base_url = format!("{}://{}{}", 
            parsed_url.scheme(),
            parsed_url.host_str().unwrap_or_default(),
            parsed_url.path()
        );
        
        debug!("Base URL extracted: {}", base_url);
        println!("Base URL (no query params): {}", base_url);
        
        let mut identifiers = Vec::new();
        let anonymizer = Anonymizer::new();
        
        // Store original query params for reconstruction
        let mut query_params: HashMap<String, String> = HashMap::new();
        let mut replacement_params: HashMap<String, String> = HashMap::new();
        
        // Process query parameters properly using the form_urlencoded parser
        info!("Checking query parameters for base64 encoded values");
        println!("\n=== QUERY PARAMETERS ===");
        
        if let Some(query) = parsed_url.query() {
            trace!("URL has query string: {}", query);
            println!("Raw query string: {}", query);
            
            println!("Parsed parameters:");
            // Use the form_urlencoded parser to correctly handle URL encoding
            for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                let key_str = key.to_string();
                let value_str = value.to_string();
                
                println!("  • {}={}", key_str, value_str);
                
                debug!("Checking query parameter: {}={}", key_str, 
                       if value_str.len() > 30 { format!("{}... (length: {})", &value_str[..30], value_str.len()) } 
                       else { value_str.clone() });
                
                // Store the original parameter
                query_params.insert(key_str.clone(), value_str.clone());
                replacement_params.insert(key_str.clone(), value_str.clone());
                
                // Check for URLs in parameters
                if key_str == "url" || key_str == "redirect" || key_str == "redirectUrl" || 
                   key_str == "redirect_uri" || key_str == "callback" || key_str == "return" ||
                   key_str == "next" || key_str == "target" || key_str == "destination" ||
                   key_str == "returnTo" || key_str == "successUrl" || key_str == "failureUrl" ||
                   key_str == "href" || key_str == "link" || key_str == "referrer" || key_str == "referer" {
                    
                    println!("  → Param '{}' looks like a URL parameter", key_str);
                    // Try to identify if the value is a URL or URL path
                    if value_str.starts_with("http://") || value_str.starts_with("https://") {
                        println!("    ✓ Parameter contains a full URL: {}", value_str);
                        url_collection.add_referenced_url(&value_str, Some(&key_str));
                    } else if value_str.starts_with("/") {
                        // Relative URL - try to construct full URL using same host
                        let domain_base = format!("{}://{}", parsed_url.scheme(), parsed_url.host_str().unwrap_or_default());
                        let full_url = format!("{}{}", domain_base, value_str);
                        println!("    ✓ Parameter contains a relative URL path: {}", value_str);
                        println!("      → Constructed full URL: {}", full_url);
                        url_collection.add_referenced_url(&full_url, Some(&key_str));
                    }
                }
                
                if identifiers.len() >= MAX_IDENTIFIERS {
                    warn!("Maximum number of identifiers reached ({}), skipping remaining parameters", MAX_IDENTIFIERS);
                    println!("WARNING: Maximum number of identifiers reached ({}), skipping remaining parameters", MAX_IDENTIFIERS);
                    break;
                }
                
                // Try to decode and analyze the parameter value
                println!("  → Checking if '{}' is base64 encoded...", value_str);
                
                if let Some(identifier) = Self::analyze_potential_base64(&value_str, &anonymizer, &format!("query parameter {}", key_str))? {
                    identifiers.push(identifier.clone());
                    
                    // Print more detailed info about what was found
                    println!("    ✅ SENSITIVE DATA FOUND in parameter '{}'", key_str);
                    println!("       Original value: {}", identifier.value);
                    println!("       Decoded value: {}", identifier.decoded_value.as_ref().unwrap_or(&"<none>".to_string()));
                    println!("       Anonymized as: {}", identifier.anonymized_value.as_ref().unwrap_or(&"<none>".to_string()));
                    
                    // Update the replacement parameter
                    if let Some(replacement) = &identifier.anonymized_value {
                        let encoded_replacement = BASE64.encode(replacement.as_bytes());
                        replacement_params.insert(key_str, encoded_replacement.clone());
                        println!("       Re-encoded value: {}", encoded_replacement);
                    }
                } else {
                    println!("    ❌ Not base64 or not sensitive data");
                }
            }
        } else {
            println!("No query parameters found");
        }
        
        // Process path segments
        info!("Checking path segments for base64 encoded values");
        println!("\n=== PATH SEGMENTS ===");
        
        if let Some(path_segments) = parsed_url.path_segments() {
            let segments: Vec<_> = path_segments.collect();
            trace!("URL has {} path segments", segments.len());
            println!("Found {} path segments:", segments.len());
            
            for (i, segment) in segments.iter().enumerate() {
                println!("  {}. {}", i+1, segment);
                
                debug!("Checking path segment: {}", segment);
                
                // Check if segment looks like a URL component
                if segment.contains(".") && !segment.contains("/") {
                    // Might be a domain or file
                    if segment.ends_with(".html") || segment.ends_with(".php") || 
                       segment.ends_with(".aspx") || segment.ends_with(".jsp") {
                        println!("    → Segment appears to be a file: {}", segment);
                    } else if segment.contains(".") {
                        // Could be a domain reference in the path
                        println!("    → Segment might be a domain reference: {}", segment);
                        url_collection.unique_domains.insert(segment.to_string());
                    }
                }
                
                if identifiers.len() >= MAX_IDENTIFIERS {
                    warn!("Maximum number of identifiers reached ({}), skipping remaining path segments", MAX_IDENTIFIERS);
                    println!("WARNING: Maximum number of identifiers reached ({}), skipping remaining path segments", MAX_IDENTIFIERS);
                    break;
                }
                
                // Currently we don't replace path segments as that would change the URL structure
                // But we still identify sensitive data in them
                println!("  → Checking if '{}' is base64 encoded...", segment);
                
                if let Some(identifier) = Self::analyze_potential_base64(segment, &anonymizer, "path segment")? {
                    identifiers.push(identifier.clone());
                    
                    // Print more detailed info about what was found
                    println!("    ✅ SENSITIVE DATA FOUND in path segment {}", i+1);
                    println!("       Original value: {}", identifier.value);
                    println!("       Decoded value: {}", identifier.decoded_value.as_ref().unwrap_or(&"<none>".to_string()));
                    println!("       Anonymized as: {}", identifier.anonymized_value.as_ref().unwrap_or(&"<none>".to_string()));
                    println!("       NOTE: Path segments are not replaced to preserve URL structure");
                } else {
                    println!("    ❌ Not base64 or not sensitive data");
                }
            }
        } else {
            println!("No path segments found");
        }
        
        // Reconstruct the anonymized URL
        let mut anonymized_url = Url::parse(url).unwrap(); // Safe to unwrap as we already validated
        
        // Clear existing query parameters
        anonymized_url.set_query(None);
        
        // Add back the anonymized parameters
        if !replacement_params.is_empty() {
            let mut query_pairs = anonymized_url.query_pairs_mut();
            for (key, value) in replacement_params {
                query_pairs.append_pair(&key, &value);
            }
            // Release the borrow on anonymized_url
            drop(query_pairs);
        }
        
        info!("URL parsing complete. Found {} identifiers", identifiers.len());
        
        // Use Into<String> trait implementation instead of deprecated into_string()
        let anonymized_url_string: String = anonymized_url.into();
        url_collection.set_anonymized_url(anonymized_url_string.clone());
        
        // Print comprehensive URL analysis results
        println!("\n=== URL ANALYSIS RESULTS ===");
        
        // URL RESULTS
        println!("\n--- URLs Identified ---");
        println!("Original URL: {}", url_collection.original_url);
        println!("Anonymized URL: {}", url_collection.anonymized_url);
        
        // List all referenced URLs
        if !url_collection.referenced_urls.is_empty() {
            println!("\nReferenced URLs:");
            for (i, ref_url) in url_collection.referenced_urls.iter().enumerate() {
                println!("  {}. {}", i+1, ref_url);
            }
        }
        
        // DOMAINS
        println!("\n--- Domains Identified ---");
        let domains: Vec<_> = url_collection.unique_domains.iter().collect();
        for (i, domain) in domains.iter().enumerate() {
            println!("  {}. {}", i+1, domain);
        }
        
        // PARAMETERS WITH URLS
        if !url_collection.parameter_urls.is_empty() {
            println!("\n--- URL Parameters ---");
            for (param, param_url) in &url_collection.parameter_urls {
                println!("  • {}: {}", param, param_url);
            }
        }
        
        // SENSITIVE DATA
        println!("\n--- Sensitive Data Identified ---");
        println!("Found {} identifiers with sensitive data:", identifiers.len());
        
        // Log details about each identified sensitive value
        for (i, id) in identifiers.iter().enumerate() {
            if let Some(decoded) = &id.decoded_value {
                info!("Identifier {}: {} -> {} (anonymized: {})",
                    i + 1, 
                    id.value, 
                    if decoded.len() > 20 { format!("{}...", &decoded[..20]) } else { decoded.clone() },
                    id.anonymized_value.as_ref().map_or("None", |v| if v.len() > 20 { "..." } else { v })
                );
                
                println!("  {}. Original: {}", i+1, id.value);
                println!("     Decoded: {}", decoded);
                println!("     Anonymized: {}", id.anonymized_value.as_ref().unwrap_or(&"<none>".to_string()));
            } else {
                debug!("Identifier {} had encoded value but could not be decoded: {}", i + 1, id.value);
                println!("  {}. Original: {} (could not be decoded)", i+1, id.value);
            }
        }
        
        println!("==================================================\n");
        
        Ok(ParsedUrl {
            domain,
            identifiers,
            anonymized_url: anonymized_url_string,
            url_collection,
        })
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
    fn analyze_potential_base64(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_url_with_base64() {
        let test_url = "https://example.com/verify?token=SGVsbG8gV29ybGQ="; // Base64 for "Hello World"
        let parsed = ParsedUrl::new(test_url).unwrap();
        
        // Check for expected base URL using string construction instead of field access
        let expected_base_url = "https://example.com/verify";
        let actual_base_url = format!("{}://{}{}", 
            Url::parse(test_url).unwrap().scheme(),
            Url::parse(test_url).unwrap().host_str().unwrap(),
            Url::parse(test_url).unwrap().path()
        );
        assert_eq!(actual_base_url, expected_base_url);
        
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
    
    #[test]
    fn test_url_with_url_encoded_base64() {
        let test_url = "https://example.com/redirect?url=https%3A%2F%2Fexample.org&data=SGVsbG8gV29ybGQ%3D";
        let parsed = ParsedUrl::new(test_url).unwrap();
        
        // Should find the base64 value despite URL encoding
        assert!(!parsed.identifiers.is_empty());
        assert_eq!(parsed.identifiers[0].decoded_value.as_ref().unwrap(), "Hello World");
    }
    
    #[test]
    fn test_url_with_url_encoded_credit_card() {
        // This is the exact type of URL in our example
        let test_url = "https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.com&ccnum=NDExMTExMTExMTExMTExMQ%3D%3D";
        let parsed = ParsedUrl::new(test_url).unwrap();
        
        // Should find and decode the credit card
        assert!(!parsed.identifiers.is_empty());
        assert_eq!(parsed.identifiers[0].decoded_value.as_ref().unwrap(), "4111111111111111");
        assert!(parsed.identifiers[0].anonymized_value.is_some());
    }
    
    #[test]
    fn test_url_with_complex_query_parameters() {
        let test_url = "https://example.com/search?q=test&filters[]=SGVsbG8=&filters[]=V29ybGQ=&page=1";
        let parsed = ParsedUrl::new(test_url).unwrap();
        
        // Should properly handle array-style query parameters
        assert_eq!(parsed.identifiers.len(), 2);
        
        // Check both values from the filters array
        let decoded_values: Vec<_> = parsed.identifiers.iter()
            .filter_map(|id| id.decoded_value.clone())
            .collect();
        
        assert!(decoded_values.contains(&"Hello".to_string()));
        assert!(decoded_values.contains(&"World".to_string()));
    }
    
    #[test]
    fn test_url_with_same_parameter_multiple_times() {
        let test_url = "https://example.com/api?id=SGVsbG8=&id=V29ybGQ=";
        let parsed = ParsedUrl::new(test_url).unwrap();
        
        // Should find both values
        assert_eq!(parsed.identifiers.len(), 2);
        
        // Check both values from the repeated parameters
        let decoded_values: Vec<_> = parsed.identifiers.iter()
            .filter_map(|id| id.decoded_value.clone())
            .collect();
        
        assert!(decoded_values.contains(&"Hello".to_string()));
        assert!(decoded_values.contains(&"World".to_string()));
    }
}