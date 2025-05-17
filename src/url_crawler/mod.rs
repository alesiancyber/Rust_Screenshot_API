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

/// Result of a redirect chain crawl, including URLs and hop count
#[derive(Debug, Clone)]
pub struct RedirectResult {
    pub chain: Vec<String>,
    pub hop_count: usize,
}

/// Configuration for URL crawler behavior
/// 
/// Allows customization of crawler constraints and behavior including
/// hop limits, URL validation, timeouts, and rate limiting.
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    // URL and redirect configuration
    pub max_hops: usize,
    pub max_url_length: usize,
    pub allowed_schemes: Vec<String>,
    
    // Rate limiting and timing
    pub request_timeout: Duration,
    pub rate_limit_delay: Duration,
    
    // HTTP client configuration
    pub user_agent: String,
    pub connection_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    pub follow_hostname_redirects_only: bool,
}

impl CrawlerConfig {
    /// Creates a new crawler configuration with default values
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Checks if a URL scheme is allowed by this configuration
    #[inline]
    pub fn is_scheme_allowed(&self, scheme: &str) -> bool {
        self.allowed_schemes.iter().any(|s| s == scheme)
    }
}

#[cfg(test)]
mod builder {
    use super::*;
    
    impl CrawlerConfig {
        /// Sets the maximum number of redirect hops to follow
        pub fn with_max_hops(mut self, max_hops: usize) -> Self {
            self.max_hops = max_hops;
            self
        }
        
        /// Sets the maximum allowed URL length
        pub fn with_max_url_length(mut self, max_url_length: usize) -> Self {
            self.max_url_length = max_url_length;
            self
        }
        
        /// Sets the request timeout duration
        pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
            self.request_timeout = timeout;
            self
        }
        
        /// Sets the rate limiting delay between requests
        pub fn with_rate_limit_delay(mut self, delay: Duration) -> Self {
            self.rate_limit_delay = delay;
            self
        }
        
        /// Sets the allowed URL schemes
        pub fn with_allowed_schemes<I, S>(mut self, schemes: I) -> Self 
        where 
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            self.allowed_schemes = schemes.into_iter().map(|s| s.into()).collect();
            self
        }
        
        /// Sets the user agent string
        pub fn with_user_agent<S: Into<String>>(mut self, user_agent: S) -> Self {
            self.user_agent = user_agent.into();
            self
        }
        
        /// Sets the connection timeout for establishing new connections
        pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
            self.connection_timeout = timeout;
            self
        }
        
        /// Sets the idle timeout for connection pool
        pub fn with_pool_idle_timeout(mut self, timeout: Duration) -> Self {
            self.pool_idle_timeout = timeout;
            self
        }
        
        /// Sets the maximum number of idle connections per host
        pub fn with_pool_max_idle_per_host(mut self, max: usize) -> Self {
            self.pool_max_idle_per_host = max;
            self
        }
        
        /// Sets whether to follow redirects only to the same hostname
        pub fn with_follow_hostname_redirects_only(mut self, only_same_host: bool) -> Self {
            self.follow_hostname_redirects_only = only_same_host;
            self
        }
    }
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        let allowed_schemes = vec![
            "http".to_string(),
            "https".to_string(),
        ];
        
        Self {
            // URL and redirect configuration
            max_hops: MAX_HOPS,
            max_url_length: MAX_URL_LENGTH,
            allowed_schemes,
            
            // Rate limiting and timing
            request_timeout: Duration::from_secs(REQUEST_TIMEOUT),
            rate_limit_delay: Duration::from_secs(RATE_LIMIT_DELAY),
            
            // HTTP client configuration
            user_agent: "ScreenshotAPI/1.0".to_string(),
            connection_timeout: Duration::from_secs(30),
            pool_idle_timeout: Duration::from_secs(90),
            pool_max_idle_per_host: 10,
            follow_hostname_redirects_only: false,
        }
    }
}

/// Crawls a URL's redirect chain using default configuration
/// 
/// Follows redirects from the starting URL and returns all URLs in the chain
/// along with the hop count.
/// Uses default crawler configuration settings.
/// 
/// # Arguments
/// * `start_url` - The initial URL to begin crawling from
/// 
/// # Returns
/// * `Result<RedirectResult>` - URLs in the redirect chain and hop count or an error
pub async fn crawl_redirect_chain(start_url: &str) -> Result<RedirectResult> {
    trace!("crawl_redirect_chain called with URL: {}", start_url);
    let config = CrawlerConfig::new(); // Make usage explicit
    crawl_redirect_chain_with_config(start_url, &config).await
}

/// Crawls a URL's redirect chain with custom configuration
/// 
/// Follows redirects from the starting URL and returns all URLs in the chain
/// along with the hop count.
/// Allows custom crawler behavior through provided configuration.
/// 
/// This function performs the following steps:
/// 1. Validates the input URL format and constraints
/// 2. Creates an HTTP client that doesn't auto-follow redirects
/// 3. Follows redirect chain manually, collecting URLs
/// 4. Enforces configured limits on hops, schemes, etc.
/// 5. Returns both the chain and hop count
/// 
/// # Arguments
/// * `start_url` - The initial URL to begin crawling from
/// * `config` - Custom crawler configuration parameters
/// 
/// # Returns
/// * `Result<RedirectResult>` - URLs in the redirect chain and hop count or an error
pub async fn crawl_redirect_chain_with_config(start_url: &str, config: &CrawlerConfig) -> Result<RedirectResult> {
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
    if !config.is_scheme_allowed(parsed_url.scheme()) { // Make usage explicit
        error!("Disallowed URL scheme: {}", parsed_url.scheme());
        bail!("URL scheme '{}' is not allowed", parsed_url.scheme());
    }

    debug!("Initializing HTTP client with user agent: {}", config.user_agent);
    // Configure client with custom settings - optimize header creation
    let client = {
        let mut headers = HeaderMap::with_capacity(1); // Pre-allocate with expected size
        match HeaderValue::from_str(&config.user_agent) {
            Ok(value) => { headers.insert(USER_AGENT, value); }
            Err(e) => {
                error!("Invalid user agent string '{}': {}", config.user_agent, e);
                return Err(e).context("Failed to create User-Agent header");
            }
        }

        match Client::builder()
            .redirect(reqwest::redirect::Policy::none())  // Don't auto-follow redirects
            .timeout(config.request_timeout)
            .connect_timeout(config.connection_timeout)
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .default_headers(headers)
            .build() {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to build HTTP client: {}", e);
                    return Err(e).context("Failed to build HTTP client");
                }
            }
    };

    // Pre-allocate vectors with a reasonable capacity to avoid reallocations
    let mut chain = Vec::with_capacity(config.max_hops + 1);
    let mut visited_urls = HashSet::with_capacity(config.max_hops + 1);
    let mut current_url = start_url.to_owned();
    let mut current_parsed_url = parsed_url;  // Store the initially parsed URL
    let mut hops = 0;

    trace!("Beginning redirect chain traversal from {}", current_url);
    loop {
        // Check for redirect loops - reference strings where possible instead of cloning
        if !visited_urls.insert(current_url.clone()) {
            error!("Redirect loop detected at {}", current_url);
            break;
        }

        info!("Crawling URL: {} (hop {}/{})", current_url, hops + 1, config.max_hops);
        chain.push(current_url.clone());

        // Early check for max hops to avoid unnecessary request
        if hops >= config.max_hops {
            warn!("Max redirect hops ({}) reached at {}", config.max_hops, current_url);
            break;
        }

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

        // Check if it's a redirect response (300-399 status code)
        let status = resp.status().as_u16();
        let is_redirect = status >= 300 && status < 400 && status != 304;

        if is_redirect {
            // Check for location header
            let location_opt = resp.headers().get(reqwest::header::LOCATION);
            
            // Special handling for httpbin.org/redirect-to which might not have a Location header
            // but has a URL parameter that indicates the redirect target
            let location_str = if location_opt.is_none() && current_url.contains("httpbin.org/redirect-to") {
                // Try to extract the url parameter from the current URL - we can use current_parsed_url here
                // Use a more efficient extraction for query parameters
                if let Some(param_value) = current_parsed_url.query_pairs()
                    .find(|(name, _)| name == "url")
                    .map(|(_, value)| value.into_owned())
                {
                    debug!("Extracted redirect URL from httpbin: {}", param_value);
                    param_value
                } else {
                    // No location header and no url parameter
                    warn!("Redirect status {} without Location header at {} and no URL parameter", status, current_url);
                    break;
                }
            } else if let Some(location) = location_opt {
                // Normal case - use the Location header
                match location.to_str() {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        error!("Invalid redirect location header: {}", e);
                        return Err(e).context("Failed to parse redirect location header");
                    }
                }
            } else {
                // No location header
                warn!("Redirect status {} without Location header at {}", status, current_url);
                break;
            };
            
            debug!("Found redirect location: {}", location_str);
            
            // Determine the next URL, resolving relative URLs if needed
            let next_url = if location_str.starts_with("http") {
                location_str
            } else {
                // Handle relative redirects using our current parsed URL
                trace!("Handling relative redirect: {}", location_str);
                match current_parsed_url.join(&location_str) {
                    Ok(url) => url.to_string(),
                    Err(e) => {
                        error!("Failed to join relative URL '{}' with base '{}': {}", location_str, current_url, e);
                        return Err(e).context("Failed to resolve relative redirect URL");
                    }
                }
            };

            // Parse the next URL once
            let next_parsed_url = match Url::parse(&next_url) {
                Ok(url) => url,
                Err(e) => {
                    error!("Failed to parse redirect URL '{}': {}", next_url, e);
                    return Err(e).context("Failed to parse redirect URL");
                }
            };

            // Check scheme - use as_str() to avoid string allocation
            let scheme = next_parsed_url.scheme();
            if !config.allowed_schemes.iter().any(|s| s == scheme) {
                warn!("Redirect to disallowed scheme: {} (from {})", scheme, current_url);
                break;
            }

            // Check if we should enforce same-host policy
            if config.follow_hostname_redirects_only {
                let current_host = current_parsed_url.host_str().unwrap_or("");
                let next_host = next_parsed_url.host_str().unwrap_or("");
                
                if current_host != next_host {
                    warn!("Cross-host redirect from {} to {} not allowed", current_host, next_host);
                    break;
                }
            }

            info!("Redirected to: {} (hop {}/{})", next_url, hops + 2, config.max_hops);
            current_url = next_url;
            current_parsed_url = next_parsed_url;  // Update the parsed URL
            hops += 1;
        } else {
            debug!("No more redirects found, ending crawl");
            break;
        }
    }

    info!("Completed URL crawl: found {} URLs in chain with {} hops", chain.len(), hops);
    trace!("Complete redirect chain: {:?}", chain);
    
    Ok(RedirectResult {
        chain,
        hop_count: hops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_config_builder() {
        let config = CrawlerConfig::new()
            .with_max_hops(5)
            .with_max_url_length(1000)
            .with_request_timeout(Duration::from_secs(10))
            .with_rate_limit_delay(Duration::from_millis(500))
            .with_allowed_schemes(vec!["https".to_string()])
            .with_user_agent("Test/1.0");
        
        assert_eq!(config.max_hops, 5);
        assert_eq!(config.max_url_length, 1000);
        assert_eq!(config.request_timeout, Duration::from_secs(10));
        assert_eq!(config.rate_limit_delay, Duration::from_millis(500));
        assert_eq!(config.allowed_schemes, vec!["https".to_string()]);
        assert_eq!(config.user_agent, "Test/1.0");
    }

    #[tokio::test]
    async fn test_simple_url_fetch() {
        // This is a basic integration test that verifies the API works
        // We use a well-known URL that should be stable
        let result = crawl_redirect_chain("https://example.com").await;
        assert!(result.is_ok());
        
        let redirect_result = result.unwrap();
        assert!(!redirect_result.chain.is_empty());
        
        // Example.com shouldn't redirect, so hop count should be 0
        assert_eq!(redirect_result.hop_count, 0);
    }

    #[tokio::test]
    #[ignore]  // Run only when needed, may hit real services
    async fn test_redirect_chain() {
        // Test URL with redirects (httpbin)
        let config = CrawlerConfig::new()
            .with_max_hops(5);
        
        let result = crawl_redirect_chain_with_config(
            "https://httpbin.org/redirect/2", 
            &config
        ).await;
        
        assert!(result.is_ok());
        let redirect_result = result.unwrap();
        
        // Should have 3 URLs: original + 2 redirects
        assert_eq!(redirect_result.chain.len(), 3);
        assert_eq!(redirect_result.hop_count, 2);
    }
} 