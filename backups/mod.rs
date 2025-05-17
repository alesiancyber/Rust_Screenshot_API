// Module organization
mod config;
mod client;
mod core;
mod redirect;   // Rename from parser to redirect to clarify its role
mod pool;
mod util;

// Re-export main types and functions for public API
pub use config::CrawlerConfig;
pub use core::{crawl_redirect_chain, crawl_redirect_chain_with_config, crawl_multiple_urls, RedirectResult};

#[cfg(test)]
mod tests;

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
    pub detect_meta_refresh: bool,
}

impl CrawlerConfig {
    /// Creates a new crawler configuration with default values
    pub fn new() -> Self {
        Self::default()
    }
    
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
    pub fn with_allowed_schemes(mut self, schemes: Vec<String>) -> Self {
        self.allowed_schemes = schemes;
        self
    }
    
    /// Sets the user agent string
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
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
    
    /// Sets whether to detect meta refresh redirects
    pub fn with_detect_meta_refresh(mut self, detect: bool) -> Self {
        self.detect_meta_refresh = detect;
        self
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
            detect_meta_refresh: false,
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
    crawl_redirect_chain_with_config(start_url, &CrawlerConfig::default()).await
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

    // Validate the URL (we only need validation, not the URL object)
    validate_url(start_url, config)?;
    
    // Build HTTP client
    let client = build_http_client(config)?;
    
    // Perform the crawl
    follow_redirect_chain(start_url, &client, config).await
}

/// Validates a URL against configuration constraints
fn validate_url(url: &str, config: &CrawlerConfig) -> Result<Url> {
    // Validate input URL
    if url.is_empty() {
        error!("Empty URL provided");
        bail!("URL cannot be empty");
    }
    
    if url.len() > config.max_url_length {
        error!("URL length {} exceeds maximum allowed length of {}", url.len(), config.max_url_length);
        bail!("URL exceeds maximum length of {} characters", config.max_url_length);
    }

    trace!("Parsing URL: {}", url);
    let parsed_url = Url::parse(url)
        .context(format!("Failed to parse URL: {}", url))?;

    // Validate URL scheme
    if !config.allowed_schemes.contains(&parsed_url.scheme().to_string()) {
        error!("Disallowed URL scheme: {}", parsed_url.scheme());
        bail!("URL scheme '{}' is not allowed", parsed_url.scheme());
    }
    
    Ok(parsed_url)
}

/// Creates an HTTP client for following redirects
fn build_http_client(config: &CrawlerConfig) -> Result<Client> {
    debug!("Initializing HTTP client with user agent: {}", config.user_agent);
    
    // Configure client with custom settings
    let mut headers = HeaderMap::new();
    let user_agent = HeaderValue::from_str(&config.user_agent)
        .context("Failed to create User-Agent header")?;
    
    headers.insert(USER_AGENT, user_agent);

    // Start building the client with our configuration
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())  // Don't auto-follow redirects
        .timeout(config.request_timeout)
        .connect_timeout(config.connection_timeout)
        .pool_idle_timeout(config.pool_idle_timeout)
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .default_headers(headers);
    
    // Optional: Configure TLS
    // builder = builder.danger_accept_invalid_certs(config.accept_invalid_certs);
    
    builder.build()
        .context("Failed to build HTTP client")
}

/// Resolves a potentially relative URL against a base URL
fn resolve_redirect_url(location: &str, current_url: &str) -> Result<String> {
    // Handle absolute URLs
    if location.starts_with("http") {
        return Ok(location.to_owned());
    }
    
    // Handle relative redirects
    trace!("Handling relative redirect: {}", location);
    let base = Url::parse(current_url)
        .context(format!("Failed to parse current URL '{}' as base for relative redirect", current_url))?;
    
    let resolved = base.join(location)
        .context(format!("Failed to resolve relative redirect URL '{}' with base '{}'", location, current_url))?;
    
    // Convert to String without using deprecated method
    Ok(resolved.to_string())
}

/// Follows a redirect chain from a starting URL
async fn follow_redirect_chain(start_url: &str, client: &Client, config: &CrawlerConfig) -> Result<RedirectResult> {
    // Pre-allocate vectors with a reasonable capacity to avoid reallocations
    let mut chain = Vec::with_capacity(config.max_hops + 1);
    let mut visited_urls = HashSet::with_capacity(config.max_hops + 1);
    let mut current_url = start_url.to_owned();
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
        
        // Apply rate limiting if needed
        apply_rate_limiting(hops, config).await;

        // Make the request and get response
        let resp = make_request(&current_url, client).await?;
        
        // Process the response and get the next URL if it's a redirect
        match process_response(&resp, &current_url, hops, config).await? {
            Some(next_url) => {
                current_url = next_url;
                hops += 1;
            },
            None => {
                debug!("No more redirects found, ending crawl");
                break;
            }
        }
    }

    info!("Completed URL crawl: found {} URLs in chain with {} hops", chain.len(), hops);
    trace!("Complete redirect chain: {:?}", chain);
    
    Ok(RedirectResult {
        chain,
        hop_count: hops,
    })
}

/// Applies rate limiting between requests if needed
async fn apply_rate_limiting(hops: usize, config: &CrawlerConfig) {
    if hops > 0 {
        debug!("Rate limiting: waiting for {:?}", config.rate_limit_delay);
        tokio::time::sleep(config.rate_limit_delay).await;
    }
}

/// Makes an HTTP request to the specified URL
async fn make_request(url: &str, client: &Client) -> Result<reqwest::Response> {
    debug!("Sending request to {}", url);
    let resp = client.get(url).send().await
        .context(format!("Failed to send request to {}", url))?;

    debug!("Response status: {}", resp.status());
    trace!("Response headers: {:?}", resp.headers());
    
    Ok(resp)
}

/// Processes an HTTP response to determine if it's a redirect
/// Returns Some(next_url) if it's a redirect, None otherwise
async fn process_response(
    resp: &reqwest::Response, 
    current_url: &str,
    hops: usize,
    config: &CrawlerConfig
) -> Result<Option<String>> {
    // First check if the status code is a redirect
    let status = resp.status().as_u16();
    let is_redirect = match status {
        301 | 302 | 303 | 307 | 308 => true,
        _ => false
    };
    
    // Handle standard HTTP redirects via Location header
    if is_redirect {
        return process_http_redirect(resp, current_url, hops, config);
    }
    
    // If not a standard redirect but we got a 200 OK, check for meta refresh or JS redirects
    if status == 200 && config.detect_meta_refresh {
        return process_html_redirect(resp, current_url, hops, config).await;
    }
    
    // Not a redirect
    Ok(None)
}

/// Processes a standard HTTP redirect with Location header
fn process_http_redirect(
    resp: &reqwest::Response,
    current_url: &str,
    hops: usize,
    config: &CrawlerConfig
) -> Result<Option<String>> {
    // Check for Location header
    if let Some(location) = resp.headers().get(reqwest::header::LOCATION) {
        // Check if we've reached the maximum hop count
        if hops >= config.max_hops {
            warn!("Max redirect hops ({}) reached at {}", config.max_hops, current_url);
            return Ok(None);
        }

        let location_str = location.to_str()
            .context("Failed to parse redirect location header")?;
            
        debug!("Found HTTP redirect (status: {}) with Location: {}", 
               resp.status(), location_str);
        
        // Handle the redirect
        handle_redirect(location_str, current_url, hops, config)
    } else {
        // No Location header despite redirect status
        warn!("Redirect status {} without Location header at {}", resp.status(), current_url);
        Ok(None)
    }
}

/// Looks for meta refresh or JavaScript redirects in HTML content
async fn process_html_redirect(
    resp: &reqwest::Response,
    current_url: &str,
    hops: usize,
    config: &CrawlerConfig
) -> Result<Option<String>> {
    // Check if we've reached the maximum hop count
    if hops >= config.max_hops {
        warn!("Max redirect hops ({}) reached at {}", config.max_hops, current_url);
        return Ok(None);
    }
    
    // Only try to parse text/html content
    let content_type = resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
        
    if !content_type.contains("text/html") {
        trace!("Skipping meta refresh detection for non-HTML content: {}", content_type);
        return Ok(None);
    }
    
    // Clone the response so we can read the body
    let text = resp.text().await
        .context("Failed to read response body for meta refresh detection")?;
    
    // Look for meta refresh tags
    if let Some(url) = extract_meta_refresh(&text) {
        debug!("Found meta refresh redirect to: {}", url);
        return handle_redirect(url, current_url, hops, config);
    }
    
    // Look for JavaScript redirects (simple cases only)
    if let Some(url) = extract_js_redirect(&text) {
        debug!("Found JavaScript redirect to: {}", url);
        return handle_redirect(url, current_url, hops, config);
    }
    
    // No HTML-based redirects found
    Ok(None)
}

/// Extracts a URL from a meta refresh tag in HTML content
fn extract_meta_refresh(html: &str) -> Option<&str> {
    // Basic regex to extract meta refresh URL
    // This is a simplified implementation - a proper solution would use an HTML parser
    let re = regex::Regex::new(r#"(?i)<meta\s+http-equiv=["']?refresh["']?\s+content=["']?\d+;\s*url=([^"'>]+)["']?"#)
        .ok()?;
    
    re.captures(html)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str())
}

/// Extracts a URL from common JavaScript redirect patterns
fn extract_js_redirect(html: &str) -> Option<&str> {
    // Very basic detection of common JS redirect patterns
    // This is highly simplified - a proper solution would use a JS parser
    
    // Look for window.location patterns
    let re1 = regex::Regex::new(r#"(?i)window\.location(?:\.href)?\s*=\s*["']([^"']+)["']"#)
        .ok()?;
    
    if let Some(cap) = re1.captures(html) {
        return cap.get(1).map(|m| m.as_str());
    }
    
    // Look for location.replace patterns
    let re2 = regex::Regex::new(r#"(?i)location\.replace\(\s*["']([^"']+)["']\s*\)"#)
        .ok()?;
    
    re2.captures(html)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str())
}

/// Handles a redirect by resolving and validating the next URL
fn handle_redirect(
    location: &str, 
    current_url: &str,
    hops: usize,
    config: &CrawlerConfig
) -> Result<Option<String>> {
    // Resolve the next URL
    let next_url = resolve_redirect_url(location, current_url)?;

    // Validate the redirect URL
    let next_parsed = Url::parse(&next_url)
        .context(format!("Failed to parse redirect URL '{}'", next_url))?;

    // Check scheme
    if !config.allowed_schemes.contains(&next_parsed.scheme().to_string()) {
        warn!("Redirect to disallowed scheme: {} (from {})", next_parsed.scheme(), current_url);
        return Ok(None);
    }

    info!("Redirected to: {} (hop {}/{})", next_url, hops + 2, config.max_hops);
    Ok(Some(next_url))
}

/// Follows multiple URLs in parallel with concurrency control
/// 
/// Crawls multiple URLs concurrently while respecting rate limits
/// and restricting the number of simultaneous connections.
/// 
/// # Arguments
/// * `urls` - List of URLs to crawl
/// * `config` - Custom crawler configuration parameters
/// * `max_concurrent` - Maximum number of concurrent requests
/// 
/// # Returns
/// * `Result<Vec<RedirectResult>>` - Results for each URL in the same order
pub async fn crawl_multiple_urls(
    urls: &[String], 
    config: &CrawlerConfig,
    max_concurrent: usize
) -> Result<Vec<RedirectResult>> {
    debug!("Starting parallel crawl of {} URLs with max concurrency {}", 
           urls.len(), max_concurrent);
    
    // Create a shared HTTP client for all requests
    let client = build_http_client(config)?;
    
    // Use a semaphore to limit concurrency
    let semaphore = tokio::sync::Semaphore::new(max_concurrent);
    let mut handles = Vec::with_capacity(urls.len());
    
    // Start tasks for each URL
    for url in urls {
        // Clone what we need to move into the task
        let url = url.clone();
        let client = client.clone();
        let config = config.clone();
        let permit = semaphore.acquire_owned().await
            .context("Failed to acquire semaphore permit")?;
        
        // Spawn a task for this URL
        let handle = tokio::spawn(async move {
            // Ensure the permit is held for the duration and released after
            let _permit = permit;
            
            match crawl_redirect_chain_with_config(&url, &config).await {
                Ok(result) => Ok(result),
                Err(e) => Err(anyhow::anyhow!("Failed to crawl {}: {}", url, e)),
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks to complete and collect results
    let mut results = Vec::with_capacity(urls.len());
    for handle in handles {
        // Await the JoinHandle, then unwrap the inner Result
        let result = handle.await
            .context("Crawl task panicked")?
            .context("Crawl task returned error")?;
            
        results.push(result);
    }
    
    info!("Completed parallel crawl of {} URLs", urls.len());
    Ok(results)
}
