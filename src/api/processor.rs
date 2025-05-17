use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error, debug};
use url;
use futures::future::join;
use crate::api::models::ScreenshotRequest;
use crate::api::models::ScreenshotResponse;
use crate::api::config::ApiConfig;
use crate::url_parser::ParsedUrl;
use crate::url_crawler::{crawl_redirect_chain, RedirectResult};
use crate::screenshot::{ScreenshotTaker, Screenshot};
use crate::utils::url_to_snake_case;
use crate::data_classifier::classifier::classify_sensitive;
use crate::ssl::{get_certificate_info_from_parsed, CertificateInfo};
use crate::utils::whois::{lookup_with_parsed, WhoisResult};
use crate::utils::benchmarking::{OperationTimer, OperationType, time_operation};
/// Core processing logic trait - allows timing strategy to be swapped
trait ProcessingStrategy {
    /// Parse URL and extract identifiers
    async fn parse_url(&self, url: &str) -> Result<ParsedUrl>;
    
    /// Get redirect chain for URL
    async fn get_redirect_chain(&self, url: &str, fallback_url: &str) -> Result<RedirectResult>;
    
    /// Get SSL certificate for domain
    async fn get_ssl_info(&self, domain: &str) -> Option<CertificateInfo>;
    
    /// Get WHOIS info for domain
    async fn get_whois_info(&self, domain: &str) -> Option<WhoisResult>;
    
    /// Take a screenshot
    async fn take_screenshot(&self, url: &str, filename: &str, screenshot_taker: &Arc<ScreenshotTaker>) -> Result<Screenshot>;
}
/// Strategy for processing with benchmarking enabled
struct BenchmarkedProcessing<'a> {
    timer: &'a OperationTimer,
    parent_op: Option<&'a str>,
}
impl<'a> BenchmarkedProcessing<'a> {
    fn new(timer: &'a OperationTimer, parent_op: Option<&'a str>) -> Self {
        Self { timer, parent_op }
    }
}
impl<'a> ProcessingStrategy for BenchmarkedProcessing<'a> {
    async fn parse_url(&self, url: &str) -> Result<ParsedUrl> {
        time_operation(
            self.timer,
            "url_parsing",
            OperationType::Asynchronous,
            self.parent_op,
            async { ParsedUrl::new(url).await }
        ).await
    }
    
    async fn get_redirect_chain(&self, url: &str, fallback_url: &str) -> Result<RedirectResult> {
        time_operation(
            self.timer,
            "crawl_redirect_chain",
            OperationType::Asynchronous,
            self.parent_op,
            async {
                match crawl_redirect_chain(url).await {
                    Ok(result) => {
                        debug!("Found redirect chain with {} URLs and {} hops", 
                            result.chain.len(), result.hop_count);
                        Ok(result)
                    },
                    Err(e) => {
                        error!("Failed to crawl redirect chain for {}: {}", url, e);
                        // Fallback URL if original fails
                        match crawl_redirect_chain(fallback_url).await {
                            Ok(fallback_result) => {
                                warn!("Recovered with fallback URL: {}", fallback_url);
                                Ok(fallback_result)
                            },
                            Err(fallback_e) => {
                                error!("Both primary and fallback redirect crawls failed: {} / {}", 
                                    e, fallback_e);
                                Err(e)
                            }
                        }
                    }
                }
            }
        ).await
    }
    
    async fn get_ssl_info(&self, domain: &str) -> Option<CertificateInfo> {
        time_operation(
            self.timer,
            format!("get_ssl_cert_{}", domain).as_str(),
            OperationType::Asynchronous,
            self.parent_op,
            async move {
                let ssl_url = format!("https://{}", domain);
                debug!("Retrieving SSL certificate for domain: {}", ssl_url);
                
                match ParsedUrl::new(&ssl_url).await {
                    Ok(ssl_parsed_url) => {
                        match get_certificate_info_from_parsed(&ssl_parsed_url) {
                            Ok(info) => {
                                debug!("SSL certificate info retrieved for domain {}", domain);
                                Some(info)
                            },
                            Err(e) => {
                                warn!("Failed to get SSL certificate for domain {}: {}", domain, e);
                                None
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Failed to parse SSL URL for domain certificate check: {}", e);
                        None
                    }
                }
            }
        ).await
    }
    
    async fn get_whois_info(&self, domain: &str) -> Option<WhoisResult> {
        time_operation(
            self.timer,
            format!("get_whois_{}", domain).as_str(),
            OperationType::Asynchronous,
            self.parent_op,
            async move {
                debug!("Performing WHOIS lookup for domain: {}", domain);
                
                // Create a minimal ParsedUrl for WHOIS lookup
                let mut minimal_parsed = match ParsedUrl::new(&format!("https://{}", domain)).await {
                    Ok(parsed) => parsed,
                    Err(_) => return None,
                };
                minimal_parsed.domain = domain.to_string();
                
                match lookup_with_parsed(&minimal_parsed).await {
                    Ok(info) => {
                        debug!("WHOIS information retrieved for domain");
                        Some(info)
                    },
                    Err(e) => {
                        warn!("Failed to get WHOIS information for domain: {}", e);
                        None
                    }
                }
            }
        ).await
    }
    
    async fn take_screenshot(&self, url: &str, filename: &str, screenshot_taker: &Arc<ScreenshotTaker>) -> Result<Screenshot> {
        time_operation(
            self.timer,
            format!("take_screenshot_{}", url).as_str(),
            OperationType::Asynchronous,
            self.parent_op,
            async {
                info!("Taking screenshot of URL: {}", url);
                match screenshot_taker.take_screenshot(url, filename).await {
                    Ok(screenshot) => {
                        debug!("Successfully captured screenshot of URL");
                        Ok(screenshot)
                    },
                    Err(e) => Err(e)
                }
            }
        ).await
    }
}
/// Strategy for processing without benchmarking
#[allow(dead_code)]
struct StandardProcessing;
impl ProcessingStrategy for StandardProcessing {
    async fn parse_url(&self, url: &str) -> Result<ParsedUrl> {
        ParsedUrl::new(url).await
    }
    
    async fn get_redirect_chain(&self, url: &str, fallback_url: &str) -> Result<RedirectResult> {
        match crawl_redirect_chain(url).await {
            Ok(result) => Ok(result),
            Err(e) => {
                // Try fallback URL
                match crawl_redirect_chain(fallback_url).await {
                    Ok(result) => Ok(result),
                    Err(_) => Err(e)
                }
            }
        }
    }
    
    async fn get_ssl_info(&self, domain: &str) -> Option<CertificateInfo> {
        let ssl_url = format!("https://{}", domain);
        debug!("Retrieving SSL certificate for domain: {}", ssl_url);
        
        match ParsedUrl::new(&ssl_url).await {
            Ok(ssl_parsed_url) => {
                match get_certificate_info_from_parsed(&ssl_parsed_url) {
                    Ok(info) => Some(info),
                    Err(e) => {
                        warn!("Failed to get SSL certificate for domain {}: {}", domain, e);
                        None
                    }
                }
            },
            Err(e) => {
                warn!("Failed to parse SSL URL for domain certificate check: {}", e);
                None
            }
        }
    }
    
    async fn get_whois_info(&self, domain: &str) -> Option<WhoisResult> {
        debug!("Performing WHOIS lookup for domain: {}", domain);
        
        // Create a minimal ParsedUrl for WHOIS lookup
        let mut minimal_parsed = match ParsedUrl::new(&format!("https://{}", domain)).await {
            Ok(parsed) => parsed,
            Err(_) => return None,
        };
        minimal_parsed.domain = domain.to_string();
        
        match lookup_with_parsed(&minimal_parsed).await {
            Ok(info) => Some(info),
            Err(e) => {
                warn!("Failed to get WHOIS information for domain: {}", e);
                None
            }
        }
    }
    
    async fn take_screenshot(&self, url: &str, filename: &str, screenshot_taker: &Arc<ScreenshotTaker>) -> Result<Screenshot> {
        info!("Taking screenshot of URL: {}", url);
        screenshot_taker.take_screenshot(url, filename).await
    }
}
/// Extract domain from URL
fn extract_domain(url: &str) -> Option<String> {
    match url::Url::parse(url) {
        Ok(parsed) => parsed.host_str().map(|s| s.to_string()),
        Err(_) => None
    }
}
/// Process URL identifiers
async fn process_identifiers(
    parsed_url: &ParsedUrl, 
    original_url: &str,
    timer: Option<&OperationTimer>
) -> (Vec<crate::api::models::Identifier>, String, String) {
    // Get decoded and replacement URLs
    let (decoded_url, replacement_url) = match timer {
        Some(timer) => time_operation(
            timer,
            "create_decoded_urls",
            OperationType::Synchronous,
            Some("process_request"),
            async { parsed_url.create_decoded_and_replacement_urls(original_url) }
        ).await,
        None => parsed_url.create_decoded_and_replacement_urls(original_url),
    };
    
    // Process identifiers
    let classifications = match timer {
        Some(timer) => time_operation(
            timer,
            "classify_identifiers",
            OperationType::Synchronous,
            Some("process_request"),
            async { parsed_url.classify_identifiers() }
        ).await,
        None => parsed_url.classify_identifiers(),
    };
    
    let mut identifiers = Vec::new();
    for (value, decoded) in classifications {
        let classification_type = if let Some(timer) = timer {
            time_operation(
                timer,
                "classify_sensitive",
                OperationType::Synchronous,
                Some("process_request"),
                async {
                    if let Some(result) = classify_sensitive(&decoded) {
                        format!("{:?}", result).to_lowercase()
                    } else {
                        "unknown".to_string()
                    }
                }
            ).await
        } else {
            if let Some(result) = classify_sensitive(&decoded) {
                format!("{:?}", result).to_lowercase()
            } else {
                "unknown".to_string()
            }
        };
        
        // Fix: Clone the value here to avoid the moved value error
        let value_clone = value.clone();
        
        identifiers.push(crate::api::models::Identifier {
            value: value_clone.clone(),
            decoded_value: Some(decoded),
            value_classification: classification_type,
            replacement_value: Some(value_clone.clone()),
            encoded_replacement_value: Some(value),
        });
    }
    
    (identifiers, decoded_url, replacement_url)
}
/// Process original URL data
async fn process_original_url<T: ProcessingStrategy>(
    strategy: &T,
    replacement_url: &str,
    anonymized_url: &str,
    screenshot_taker: &Arc<ScreenshotTaker>
) -> Result<(RedirectResult, Screenshot, Option<CertificateInfo>, Option<WhoisResult>)> {
    // Get domain for domain-specific tasks
    let original_domain = extract_domain(replacement_url);
    
    // Prepare tasks that depend on the domain
    let mut ssl_future = None;
    let mut whois_future = None;
    
    if let Some(domain) = &original_domain {
        // Launch SSL certificate check
        ssl_future = Some(strategy.get_ssl_info(domain));
        
        // Launch WHOIS lookup
        whois_future = Some(strategy.get_whois_info(domain));
    }
    
    // Launch redirect chain crawler and screenshot tasks in parallel
    let redirect_task = strategy.get_redirect_chain(
        replacement_url, anonymized_url
    );
    
    // Take screenshot of original URL
    let base_name = url_to_snake_case(replacement_url);
    let filename = format!("{}_original", base_name);
    let original_screenshot_task = strategy.take_screenshot(
        replacement_url,
        &filename,
        screenshot_taker
    );
    
    // Await redirect chain and screenshot tasks in parallel
    let (redirect_result, original_screenshot) = join(
        redirect_task,
        original_screenshot_task
    ).await;
    
    // Prepare domain results
    let ssl_info = match ssl_future {
        Some(future) => future.await,
        None => None
    };
    
    let whois_info = match whois_future {
        Some(future) => future.await,
        None => None
    };
    
    Ok((redirect_result?, original_screenshot?, ssl_info, whois_info))
}
/// Process final URL data
async fn process_final_url<T: ProcessingStrategy>(
    strategy: &T,
    final_url: &str,
    original_domain: Option<&String>,
    original_ssl_info: Option<CertificateInfo>,
    original_whois_info: Option<WhoisResult>,
    screenshot_taker: &Arc<ScreenshotTaker>
) -> (Option<CertificateInfo>, Option<WhoisResult>, Option<String>) {
    let final_domain = extract_domain(final_url);
    
    // Skip domain processing if original and final domains are the same
    let same_domain = match (&final_domain, original_domain) {
        (Some(final_dom), Some(orig_dom)) => final_dom == orig_dom,
        _ => false
    };
    
    let mut ssl_info = None;
    let mut whois_info = None;
    
    if !same_domain {
        if let Some(domain) = &final_domain {
            // Run SSL and WHOIS lookups in parallel
            let ssl_task = strategy.get_ssl_info(domain);
            let whois_task = strategy.get_whois_info(domain);
            
            // Await both tasks
            let (ssl_result, whois_result) = join(ssl_task, whois_task).await;
            ssl_info = ssl_result;
            whois_info = whois_result;
        }
    } else {
        // Reuse the original domain info
        ssl_info = original_ssl_info;
        whois_info = original_whois_info;
    }
    
    // Take screenshot of final URL
    let dest_name = url_to_snake_case(final_url);
    let screenshot_result = strategy.take_screenshot(
        final_url,
        &format!("{}_destination", dest_name),
        screenshot_taker
    ).await;
    
    let final_screenshot = match screenshot_result {
        Ok(screenshot) => Some(screenshot.image_data),
        Err(e) => {
            warn!("Failed to capture screenshot of final URL: {}", e);
            None
        }
    };
    
    (ssl_info, whois_info, final_screenshot)
}
/// Process a screenshot request with benchmarking
pub async fn process_request(
    request: ScreenshotRequest,
    _config: &ApiConfig,
    screenshot_taker: Arc<ScreenshotTaker>,
) -> Result<ScreenshotResponse> {
    let timer = OperationTimer::new();
    let request_url = request.url.clone();
    
    // Fix: Added the None parameter for parent_op
    let result = process_request_with_strategy(
        request,
        &BenchmarkedProcessing::new(&timer, None),
        screenshot_taker,
        Some(&timer)
    ).await;
    
    // Generate and log timing report
    let report = timer.generate_report().await;
    info!("Timing report for request: {}\n{}", request_url, report);
    
    // Add timing report to response
    if let Ok(mut resp) = result {
        resp.timing_report = Some(report);
        Ok(resp)
    } else {
        result
    }
}
/// Process a screenshot request without benchmarking
#[allow(dead_code)]
pub async fn process_request_no_benchmarking(
    request: ScreenshotRequest,
    _config: &ApiConfig,
    screenshot_taker: Arc<ScreenshotTaker>,
) -> Result<ScreenshotResponse> {
    process_request_with_strategy(
        request,
        &StandardProcessing,
        screenshot_taker,
        None
    ).await
}
/// Core implementation that works with any processing strategy
async fn process_request_with_strategy<T: ProcessingStrategy>(
    request: ScreenshotRequest,
    strategy: &T,
    screenshot_taker: Arc<ScreenshotTaker>,
    timer: Option<&OperationTimer>
) -> Result<ScreenshotResponse> {
    let mut response = ScreenshotResponse::new(request.url.clone());
    
    // Step 1: Parse and analyze the URL
    debug!("Parsing URL: {}", request.url);
    let parsed_url = strategy.parse_url(&request.url).await?;
    
    // Set URL metadata from the ParsedUrl
    response.anonymized_url = parsed_url.anonymized_url().to_string();
    response.referenced_urls = parsed_url.url_collection.referenced_urls().to_vec();
    response.unique_domains = parsed_url.url_collection.unique_domains().clone().into_iter().collect();
    
    // Process URL identifiers
    let (identifiers, decoded_url, replacement_url) = process_identifiers(
        &parsed_url, &request.url, timer
    ).await;
    
    response.identifiers = identifiers;
    response.decoded_url = decoded_url;
    response.replacement_url = replacement_url;
    
    // Step 2: Start parallel processing for the original URL
    let _parent_op = timer.map(|_| "parallel_original_url_tasks");
    if let Some(t) = timer {
        t.start_operation("parallel_original_url_tasks", OperationType::Asynchronous, 
                         Some("process_request")).await;
    }
    
    // Process original URL data in parallel
    let (redirect_result, original_screenshot, ssl_info, whois_info) = process_original_url(
        strategy,
        &response.replacement_url,
        parsed_url.anonymized_url(),
        &screenshot_taker
    ).await?;
    
    if let Some(t) = timer {
        t.end_operation("parallel_original_url_tasks").await;
    }
    
    // Store the results
    response.original_ssl_info = ssl_info;
    response.original_whois_info = whois_info;
    response.original_screenshot = Some(original_screenshot.image_data);
    response.redirect_chain = redirect_result.chain.clone();
    response.redirect_hop_count = redirect_result.hop_count;
    
    // Get final URL and determine if we need additional processing
    let final_url = if let Some(url) = redirect_result.chain.last() {
        info!("Final URL after redirects: {}", url);
        url.clone()
    } else {
        // Fallback: use domain from original URL
        debug!("No redirects found, using original domain");
        response.replacement_url.clone()
    };
    
    response.final_url = final_url.clone();
    
    // Step 3: Perform parallel tasks for final URL (if different from original)
    let is_different_final_url = final_url != response.replacement_url;
    
    if is_different_final_url {
        if let Some(t) = timer {
            t.start_operation("parallel_final_url_tasks", OperationType::Asynchronous, 
                             Some("process_request")).await;
        }
        
        // Extract original domain
        let original_domain = extract_domain(&response.replacement_url);
        
        // Process the final URL data
        let (ssl_info, whois_info, final_screenshot) = process_final_url(
            strategy,
            &final_url,
            original_domain.as_ref(),
            response.original_ssl_info.clone(),
            response.original_whois_info.clone(),
            &screenshot_taker
        ).await;
        
        // Update response with final URL data
        response.final_ssl_info = ssl_info;
        response.final_whois_info = whois_info;
        response.final_screenshot = final_screenshot;
        
        if let Some(t) = timer {
            t.end_operation("parallel_final_url_tasks").await;
        }
    } else {
        debug!("Final URL is same as original, skipping additional processing");
    }
    
    response.status = "success".to_string();
    info!("Successfully processed screenshot request for: {}", request.url);
    Ok(response)
}