use anyhow::{Result, Context, bail};
use tracing::{info, warn, debug, error, trace};
use reqwest::{Client, header::{HeaderMap, HeaderValue, USER_AGENT}};
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

// Constants for crawler configuration
const MAX_HOPS: usize = 10;
const MAX_URL_LENGTH: usize = 2048;
const REQUEST_TIMEOUT: u64 = 30; // seconds
const RATE_LIMIT_DELAY: u64 = 1; // seconds

/// Configuration for URL crawler behavior
/// 
/// Allows customization of crawler constraints and behavior including
/// hop limits, URL validation, timeouts, and rate limiting.
pub struct CrawlerConfig {
    pub max_hops: usize,
    pub max_url_length: usize,
    pub request_timeout: Duration,
    pub rate_limit_delay: Duration,
    pub allowed_schemes: Vec<String>,
    pub user_agent: String,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_hops: MAX_HOPS,
            max_url_length: MAX_URL_LENGTH,
            request_timeout: Duration::from_secs(REQUEST_TIMEOUT),
            rate_limit_delay: Duration::from_secs(RATE_LIMIT_DELAY),
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            user_agent: "ScreenshotAPI/1.0".to_string(),
        }
    }
}

/// Crawls a URL's redirect chain using default configuration
/// 
/// Follows redirects from the starting URL and returns all URLs in the chain.
/// Uses default crawler configuration settings.
/// 
/// # Arguments
/// * `start_url` - The initial URL to begin crawling from
/// 
/// # Returns
/// * `Result<Vec<String>>` - A vector of URLs in the redirect chain or an error
pub async fn crawl_redirect_chain(start_url: &str) -> Result<Vec<String>> {
    trace!("crawl_redirect_chain called with URL: {}", start_url);
    crawl_redirect_chain_with_config(start_url, &CrawlerConfig::default()).await
}

/// Crawls a URL's redirect chain with custom configuration
/// 
/// Follows redirects from the starting URL and returns all URLs in the chain.
/// Allows custom crawler behavior through provided configuration.
/// 
/// This function performs the following steps:
/// 1. Validates the input URL format and constraints
/// 2. Creates an HTTP client that doesn't auto-follow redirects
/// 3. Follows redirect chain manually, collecting URLs
/// 4. Enforces configured limits on hops, schemes, etc.
/// 
/// # Arguments
/// * `start_url` - The initial URL to begin crawling from
/// * `config` - Custom crawler configuration parameters
/// 
/// # Returns
/// * `Result<Vec<String>>` - A vector of URLs in the redirect chain or an error
pub async fn crawl_redirect_chain_with_config(start_url: &str, config: &CrawlerConfig) -> Result<Vec<String>> {
    debug!("Starting URL crawl with config: max_hops={}, max_url_length={}, timeout={:?}, rate_limit={:?}",
        config.max_hops, config.max_url_length, config.request_timeout, config.rate_limit_delay);

    // Validate input URL
    if start_url.is_empty() {
        error!("Empty URL provided");
        bail!("URL cannot be empty");
    }
    if start_url.len() > config.max_url_length {
        error!("URL length {} exceeds maximum allowed length of {}", start_url.len(), config.max_url_length);
        bail!("URL exceeds maximum length of {} characters", config.max_url_length);
    }

    trace!("Parsing URL: {}", start_url);
    let parsed_url = match Url::parse(start_url) {
        Ok(url) => url,
        Err(e) => {
            error!("Failed to parse URL '{}': {}", start_url, e);
            return Err(e).context("Failed to parse URL");
        }
    };

    // Validate URL scheme
    if !config.allowed_schemes.contains(&parsed_url.scheme().to_string()) {
        error!("Disallowed URL scheme: {}", parsed_url.scheme());
        bail!("URL scheme '{}' is not allowed", parsed_url.scheme());
    }

    debug!("Initializing HTTP client with user agent: {}", config.user_agent);
    // Configure client with custom settings
    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(&config.user_agent) {
        Ok(value) => { headers.insert(USER_AGENT, value); }
        Err(e) => {
            error!("Invalid user agent string '{}': {}", config.user_agent, e);
            return Err(e).context("Failed to create User-Agent header");
        }
    }

    let client = match Client::builder()
        .redirect(reqwest::redirect::Policy::none())  // Don't auto-follow redirects
        .timeout(config.request_timeout)
        .default_headers(headers)
        .pool_idle_timeout(Duration::from_secs(90))
        .build() {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to build HTTP client: {}", e);
                return Err(e).context("Failed to build HTTP client");
            }
        };

    let mut chain = Vec::new();
    let mut visited_urls = HashSet::new();
    let mut current_url = start_url.to_string();
    let mut hops = 0;

    trace!("Beginning redirect chain traversal from {}", current_url);
    loop {
        // Check for redirect loops
        if !visited_urls.insert(current_url.clone()) {
            error!("Redirect loop detected at {}", current_url);
            break;
        }

        info!("Crawling URL: {} (hop {}/{})", current_url, hops + 1, config.max_hops);
        chain.push(current_url.clone());

        // Rate limiting
        if hops > 0 {
            debug!("Rate limiting: waiting for {:?}", config.rate_limit_delay);
            tokio::time::sleep(config.rate_limit_delay).await;
        }

        debug!("Sending request to {}", current_url);
        let resp = match client.get(&current_url).send().await {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to send request to {}: {}", current_url, e);
                return Err(e).context(format!("Failed to send request to {}", current_url));
            }
        };

        debug!("Response status: {}", resp.status());
        trace!("Response headers: {:?}", resp.headers());

        if let Some(location) = resp.headers().get(reqwest::header::LOCATION) {
            if hops >= config.max_hops {
                warn!("Max redirect hops ({}) reached at {}", config.max_hops, current_url);
                break;
            }

            let location_str = match location.to_str() {
                Ok(s) => s,
                Err(e) => {
                    error!("Invalid redirect location header: {}", e);
                    return Err(e).context("Failed to parse redirect location header");
                }
            };
            debug!("Found redirect location: {}", location_str);
            
            // Determine the next URL, resolving relative URLs if needed
            let next_url = if location_str.starts_with("http") {
                location_str.to_string()
            } else {
                // Handle relative redirects
                trace!("Handling relative redirect: {}", location_str);
                let base = match Url::parse(&current_url) {
                    Ok(url) => url,
                    Err(e) => {
                        error!("Failed to parse current URL '{}' as base for relative redirect: {}", current_url, e);
                        return Err(e).context("Failed to parse current URL for relative redirect");
                    }
                };
                
                match base.join(location_str) {
                    Ok(url) => url.to_string(),
                    Err(e) => {
                        error!("Failed to join relative URL '{}' with base '{}': {}", location_str, current_url, e);
                        return Err(e).context("Failed to resolve relative redirect URL");
                    }
                }
            };

            // Validate redirect URL
            let next_parsed = match Url::parse(&next_url) {
                Ok(url) => url,
                Err(e) => {
                    error!("Failed to parse redirect URL '{}': {}", next_url, e);
                    return Err(e).context("Failed to parse redirect URL");
                }
            };

            // Check scheme
            if !config.allowed_schemes.contains(&next_parsed.scheme().to_string()) {
                warn!("Redirect to disallowed scheme: {} (from {})", next_parsed.scheme(), current_url);
                break;
            }

            info!("Redirected to: {} (hop {}/{})", next_url, hops + 1, config.max_hops);
            current_url = next_url;
            hops += 1;
        } else {
            debug!("No more redirects found, ending crawl");
            break;
        }
    }

    info!("Completed URL crawl: found {} URLs in chain", chain.len());
    trace!("Complete redirect chain: {:?}", chain);
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_crawl_redirect_chain() {
        let chain = crawl_redirect_chain("http://httpbin.org/redirect/1").await.unwrap();
        assert!(chain.len() >= 2);
    }

    #[tokio::test]
    async fn test_crawl_with_custom_config() {
        let config = CrawlerConfig {
            max_hops: 2,
            ..Default::default()
        };
        let chain = crawl_redirect_chain_with_config("http://httpbin.org/redirect/3", &config)
            .await
            .unwrap();
        assert!(chain.len() <= 3); // Should stop at max_hops
    }

    #[tokio::test]
    async fn test_invalid_scheme() {
        let config = CrawlerConfig {
            allowed_schemes: vec!["https".to_string()],
            ..Default::default()
        };
        let result = crawl_redirect_chain_with_config("http://example.com", &config).await;
        assert!(result.is_err());
    }
} 