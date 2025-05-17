use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error, debug, trace, instrument};
use url;

use crate::api::models::ScreenshotRequest;
use crate::api::models::ScreenshotResponse;
use crate::api::config::ApiConfig;
use crate::url_parser::ParsedUrl;
use crate::url_crawler::crawl_redirect_chain;
use crate::screenshot::ScreenshotTaker;
use crate::utils::url_to_snake_case;
use crate::data_classifier::classifier::classify_sensitive;
use crate::ssl::get_certificate_info_from_parsed;
use crate::utils::whois::lookup_with_parsed;

/// Processes a screenshot request to generate a complete analysis
/// 
/// This function performs the following steps:
/// 1. Parses and analyzes the URL for sensitive data
///    - Identifies all URLs referenced in parameters
///    - Finds all unique domains in the URL and parameters
///    - Analyzes URL parameters that contain other URLs
/// 2. Follows the redirect chain to the final destination
/// 3. Captures screenshots of both the original and final URLs
/// 4. Collects SSL certificate and WHOIS information
/// 
/// # Arguments
/// * `request` - The screenshot request containing the URL
/// * `_config` - API configuration parameters
/// * `screenshot_taker` - Shared screenshot service instance
/// 
/// # Returns
/// * `Result<ScreenshotResponse>` - Complete analysis or an error
#[instrument(skip(screenshot_taker, _config), fields(url = %request.url))]
pub async fn process_request(
    request: ScreenshotRequest,
    _config: &ApiConfig,
    screenshot_taker: Arc<ScreenshotTaker>,
) -> Result<ScreenshotResponse> {
    info!("Processing screenshot request for URL: {}", request.url);
    let mut response = ScreenshotResponse::new(request.url.clone());
    
    // Step 1: Parse and anonymize the URL
    debug!("Parsing URL: {}", request.url);
    let parsed_url = match ParsedUrl::new(&request.url).await {
        Ok(parsed) => parsed,
        Err(e) => {
            error!("Failed to parse URL {}: {}", request.url, e);
            return Err(e);
        }
    };
    
    // Set URL metadata from the ParsedUrl
    response.anonymized_url = parsed_url.anonymized_url().to_string();
    response.referenced_urls = parsed_url.url_collection.referenced_urls().to_vec();
    response.unique_domains = parsed_url.url_collection.unique_domains().clone().into_iter().collect();
    
    // Get decoded and replacement URLs
    let (decoded_url, replacement_url) = parsed_url.create_decoded_and_replacement_urls(&request.url);
    response.decoded_url = decoded_url;
    response.replacement_url = replacement_url;
    
    // Add identifiers from classifications
    let classifications = parsed_url.classify_identifiers();
    for (identifier_index, classification) in classifications {
        let classification_type = if let Some(result) = classify_sensitive(&classification) {
            format!("{:?}", result).to_lowercase()
        } else {
            "unknown".to_string()
        };
        
        response.identifiers.push(crate::api::models::Identifier {
            value: identifier_index.clone(),
            decoded_value: Some(classification.clone()),
            value_classification: classification_type,
            replacement_value: Some(identifier_index.clone()), // Now properly wrapped in Some()
            encoded_replacement_value: Some(identifier_index.clone()), // Now properly wrapped in Some()
        });
    }
    
    // Step 2: Check redirect chain
    info!("Checking redirect chain for: {}", response.replacement_url);
    let redirect_result = match crawl_redirect_chain(&response.replacement_url).await {
        Ok(result) => {
            debug!("Found redirect chain with {} URLs and {} hops", result.chain.len(), result.hop_count);
            result
        },
        Err(e) => {
            error!("Failed to crawl redirect chain for {}: {}", response.replacement_url, e);
            // Fallback to anonymized URL if replacement URL fails
            match crawl_redirect_chain(parsed_url.anonymized_url()).await {
                Ok(fallback_result) => {
                    warn!("Recovered with fallback URL: {}", parsed_url.anonymized_url());
                    fallback_result
                },
                Err(fallback_e) => {
                    error!("Both primary and fallback redirect crawls failed: {} / {}", e, fallback_e);
                    return Err(e);
                }
            }
        }
    };
    
    response.redirect_chain = redirect_result.chain.clone();
    response.redirect_hop_count = redirect_result.hop_count;
    
    // Get final URL
    if let Some(final_url) = redirect_result.chain.last() {
        info!("Final URL after redirects: {}", final_url);
        response.final_url = final_url.clone();
    } else {
        // Fallback: use domain from original URL
        debug!("No redirects found, using original domain");
        response.final_url = response.replacement_url.clone();
    }
    
    // Step 2.5: Get domains for SSL and WHOIS checks
    let original_domain = if let Ok(url) = url::Url::parse(&response.replacement_url) {
        url.host_str().map(|s| s.to_string())
    } else {
        None
    };

    let final_domain = if let Some(final_url) = redirect_result.chain.last() {
        if let Ok(url) = url::Url::parse(final_url) {
            url.host_str().map(|s| s.to_string())
        } else {
            None
        }
    } else {
        None
    };

    debug!("Original domain: {:?}, Final domain: {:?}", original_domain, final_domain);

    // Step 2.6: Get SSL certificate info for original domain
    if let Some(domain) = &original_domain {
        let ssl_url = format!("https://{}", domain);
        debug!("Retrieving SSL certificate for original domain: {}", ssl_url);
        
        match ParsedUrl::new(&ssl_url).await {
            Ok(ssl_parsed_url) => {
                match get_certificate_info_from_parsed(&ssl_parsed_url) {
                    Ok(info) => {
                        debug!("SSL certificate info retrieved for original domain {}", domain);
                        response.original_ssl_info = Some(info);
                    },
                    Err(e) => {
                        warn!("Failed to get SSL certificate for original domain {}: {}", domain, e);
                    }
                }
            },
            Err(e) => {
                warn!("Failed to parse SSL URL for original domain certificate check: {}", e);
            }
        }
    }

    // Step 2.7: Get SSL certificate info for final domain (if different)
    if let Some(domain) = &final_domain {
        // Skip if domains are the same, to avoid duplicate work
        if original_domain.as_ref() != Some(domain) {
            let ssl_url = format!("https://{}", domain);
            debug!("Retrieving SSL certificate for final domain: {}", ssl_url);
            
            match ParsedUrl::new(&ssl_url).await {
                Ok(ssl_parsed_url) => {
                    match get_certificate_info_from_parsed(&ssl_parsed_url) {
                        Ok(info) => {
                            debug!("SSL certificate info retrieved for final domain {}", domain);
                            response.final_ssl_info = Some(info);
                        },
                        Err(e) => {
                            warn!("Failed to get SSL certificate for final domain {}: {}", domain, e);
                        }
                    }
                },
                Err(e) => {
                    warn!("Failed to parse SSL URL for final domain certificate check: {}", e);
                }
            }
        } else {
            debug!("Final domain is same as original, reusing SSL info");
            response.final_ssl_info = response.original_ssl_info.clone();
        }
    }
    
    // Step 2.8: WHOIS info for original domain
    if let Some(domain) = &original_domain {
        debug!("Performing WHOIS lookup for original domain: {}", domain);
        
        // Create a minimal ParsedUrl for WHOIS lookup
        let mut minimal_parsed = ParsedUrl::new(&format!("https://{}", domain)).await?;
        minimal_parsed.domain = domain.clone();
        
        match lookup_with_parsed(&minimal_parsed).await {
            Ok(info) => {
                debug!("WHOIS information retrieved for original domain");
                response.original_whois_info = Some(info);
            },
            Err(e) => {
                warn!("Failed to get WHOIS information for original domain: {}", e);
            }
        }
    }
    
    // Step 2.9: WHOIS info for final domain (if different)
    if let Some(domain) = &final_domain {
        // Skip if domains are the same, to avoid duplicate work
        if original_domain.as_ref() != Some(domain) {
            debug!("Performing WHOIS lookup for final domain: {}", domain);
            
            // Create a minimal ParsedUrl for WHOIS lookup
            let mut minimal_parsed = ParsedUrl::new(&format!("https://{}", domain)).await?;
            minimal_parsed.domain = domain.clone();
            
            match lookup_with_parsed(&minimal_parsed).await {
                Ok(info) => {
                    debug!("WHOIS information retrieved for final domain");
                    response.final_whois_info = Some(info);
                },
                Err(e) => {
                    warn!("Failed to get WHOIS information for final domain: {}", e);
                }
            }
        } else {
            debug!("Final domain is same as original, reusing WHOIS info");
            response.final_whois_info = response.original_whois_info.clone();
        }
    }
    
    // Step 3: Take screenshots
    let base_name = url_to_snake_case(&response.replacement_url);
    
    // Take screenshot of original URL (using replacement_url which preserves redirect URLs)
    info!("Taking screenshot of original URL: {}", response.replacement_url);
    let original_screenshot = match screenshot_taker.take_screenshot(
        &response.replacement_url,
        &format!("{}_original", base_name)
    ).await {
        Ok(screenshot) => {
            debug!("Successfully captured screenshot of original URL");
            screenshot
        },
        Err(e) => {
            error!("Failed to capture screenshot of original URL: {}", e);
            // Try fallback to anonymized URL if replacement URL fails
            match screenshot_taker.take_screenshot(
                parsed_url.anonymized_url(),
                &format!("{}_original_fallback", base_name)
            ).await {
                Ok(fallback) => {
                    warn!("Used fallback URL for original screenshot: {}", parsed_url.anonymized_url());
                    fallback
                },
                Err(fallback_e) => {
                    error!("Both primary and fallback screenshot attempts failed: {} / {}", e, fallback_e);
                    return Err(e);
                }
            }
        }
    };
    
    response.original_screenshot = Some(original_screenshot.image_data);
    
    // Take screenshot of final URL if different
    if let Some(final_url) = redirect_result.chain.last() {
        if final_url != &response.replacement_url {
            info!("Taking screenshot of final URL: {}", final_url);
            let dest_name = url_to_snake_case(final_url);
            match screenshot_taker.take_screenshot(
                final_url,
                &format!("{}_destination", dest_name)
            ).await {
                Ok(screenshot) => {
                    debug!("Successfully captured screenshot of final URL");
                    response.final_screenshot = Some(screenshot.image_data);
                },
                Err(e) => {
                    warn!("Failed to capture screenshot of final URL: {}", e);
                    // Continue anyway as we have the original screenshot
                }
            }
        } else {
            debug!("Final URL is same as original, skipping second screenshot");
        }
    }
    
    response.status = "success".to_string();
    info!("Successfully processed screenshot request for: {}", request.url);
    Ok(response)
} 