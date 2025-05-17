use anyhow::{Result, Context};
use tracing::{debug, info, error, trace, instrument};
use url::Url;
use crate::utils::anonymizer::Anonymizer;
use std::collections::HashMap;

use super::url_collection::UrlCollection;
use super::identifier::Identifier;
use super::url_validator::validate_url;
use super::url_processor::{process_query_parameters, process_path_segments};
use super::url_reconstructor::reconstruct_url;

/// Represents a parsed URL with detected identifiers and their anonymized versions
/// 
/// This struct holds the results of URL parsing and analysis, including any
/// identified sensitive data in the URL and an anonymized version of the URL.
#[derive(Debug)]
pub struct ParsedUrl {
    pub domain: String,               // Domain name extracted from the URL
    pub identifiers: Vec<Identifier>, // Collection of sensitive data identifiers found
    pub url_collection: UrlCollection, // Collection of all related URLs
}

impl ParsedUrl {
    /// Creates a new ParsedUrl by analyzing the provided URL string asynchronously
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
    pub async fn new(url: &str) -> Result<Self> {
        trace!("Starting async URL parsing process");
        
        // First, create a URL collection and validate the URL
        let (mut url_collection, parsed_url) = Self::validate_and_parse_url(url).await?;
        
        // Extract domain from the URL
        let domain = Self::extract_domain(&parsed_url).await?;
        
        // Process the URL to find sensitive data and related URLs
        let (identifiers, anonymized_url) = Self::process_url_components(&parsed_url, &mut url_collection).await?;
        
        // Update the URL collection with the anonymized URL
        url_collection.set_anonymized_url(anonymized_url);
        
        // Log results
        Self::log_processing_results(&identifiers);
        
        Ok(ParsedUrl {
            domain,
            identifiers,
            url_collection,
        })
    }
    
    /// Validates and parses a URL string
    async fn validate_and_parse_url(url: &str) -> Result<(UrlCollection, Url)> {
        // Initialize URL collection to track all URLs found
        let url_collection = UrlCollection::new(url)?;
        
        // Basic validation
        validate_url(url).await?;
        
        info!("Parsing URL: {}", url);
        
        // Parse the URL into a structured form
        let parsed_url = match Url::parse(url) {
            Ok(parsed) => parsed,
            Err(e) => {
                let msg = format!("Failed to parse URL: {}", e);
                error!("Failed to parse URL '{}': {}", url, e);
                return Err(e).context(msg);
            }
        };
        
        Ok((url_collection, parsed_url))
    }
    
    /// Extracts the domain from a parsed URL
    async fn extract_domain(parsed_url: &Url) -> Result<String> {
        super::url_validator::extract_domain(parsed_url).await
    }
    
    /// Processes URL components to find sensitive data and related URLs
    async fn process_url_components(
        parsed_url: &Url, 
        url_collection: &mut UrlCollection
    ) -> Result<(Vec<Identifier>, String)> {
        // Initialize data structures
        let mut identifiers = Vec::new();
        let anonymizer = Anonymizer::new();
        let mut replacement_params = HashMap::new();
        
        // Process query parameters using structured URL library API
        info!("Checking query parameters for base64 encoded values");
        process_query_parameters(
            parsed_url, 
            &mut identifiers,
            &mut replacement_params,
            url_collection,
            &anonymizer
        ).await?;
        
        // Process path segments
        info!("Checking path segments for base64 encoded values");
        process_path_segments(
            parsed_url,
            &mut identifiers,
            &anonymizer
        ).await?;
        
        // Reconstruct the anonymized URL
        let anonymized_url = reconstruct_url(parsed_url, &replacement_params).await?;
        
        info!("URL parsing complete. Found {} identifiers", identifiers.len());
        
        Ok((identifiers, anonymized_url))
    }
    
    /// Logs details about the processing results
    fn log_processing_results(identifiers: &[Identifier]) {
        // Log details about each identified sensitive value
        for (i, id) in identifiers.iter().enumerate() {
            if let Some(decoded) = &id.decoded_value {
                info!("Identifier {}: {} -> {} (anonymized: {})",
                    i + 1, 
                    id.value, 
                    if decoded.len() > 20 { format!("{}...", &decoded[..20]) } else { decoded.clone() },
                    id.anonymized_value.as_ref().map_or("None", |v| if v.len() > 20 { "..." } else { v })
                );
            } else {
                debug!("Identifier {} had encoded value but could not be decoded: {}", i + 1, id.value);
            }
        }
    }
    
    /// Returns a reference to the anonymized URL
    pub fn anonymized_url(&self) -> &str {
        self.url_collection.anonymized_url()
    }

    /// Creates decoded and replacement URLs from the original URL
    ///
    /// This method applies the decoded and anonymized values from identifiers
    /// to create two variations of the original URL:
    /// 1. A decoded URL where encoded values are replaced with their decoded form
    /// 2. A replacement URL where sensitive values are replaced with anonymized versions
    ///
    /// # Arguments
    /// * `original_url` - The original URL to transform
    ///
    /// # Returns
    /// * `(String, String)` - The (decoded_url, replacement_url) tuple
    pub fn create_decoded_and_replacement_urls(&self, original_url: &str) -> (String, String) {
        let mut decoded_url = original_url.to_string();
        let mut replacement_url = original_url.to_string();
        
        for identifier in &self.identifiers {
            // Apply decoded values
            if let Some(decoded) = &identifier.decoded_value {
                decoded_url = decoded_url.replace(&identifier.value, decoded);
            }
            
            // Apply anonymized values
            if let Some(anonymized) = &identifier.anonymized_value {
                replacement_url = replacement_url.replace(&identifier.value, anonymized);
            }
        }
        
        debug!("Created decoded URL: {}", decoded_url);
        debug!("Created replacement URL: {}", replacement_url);
        
        (decoded_url, replacement_url)
    }

    /// Returns identifiers with their decoded values for classification
    ///
    /// This method provides a simplified view of the identifiers, focusing
    /// on the sensitive data for classification purposes.
    ///
    /// # Returns
    /// * `Vec<(String, String)>` - Vector of (original_value, decoded_value) pairs
    pub fn classify_identifiers(&self) -> Vec<(String, String)> {
        let mut classifications = Vec::new();
        
        for identifier in &self.identifiers {
            if let Some(decoded) = &identifier.decoded_value {
                classifications.push((identifier.value.clone(), decoded.clone()));
            }
        }
        
        classifications
    }
}