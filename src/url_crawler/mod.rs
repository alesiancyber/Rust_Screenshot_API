use anyhow::{Result, Context, bail};
use log::{info, warn, debug, error};
use reqwest::{Client, header::{HeaderMap, HeaderValue, USER_AGENT}};
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

const MAX_HOPS: usize = 10;
const MAX_URL_LENGTH: usize = 2048;
const REQUEST_TIMEOUT: u64 = 30; // seconds
const RATE_LIMIT_DELAY: u64 = 1; // seconds

pub struct CrawlerConfig {
    pub max_hops: usize,
    pub max_url_length: usize,
    pub request_timeout: Duration,
    pub rate_limit_delay: Duration,
    pub allowed_schemes: Vec<String>,
    pub allowed_domains: Option<Vec<String>>,
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
            allowed_domains: None,
            user_agent: "ScreenshotAPI/1.0".to_string(),
        }
    }
}

pub async fn crawl_redirect_chain(start_url: &str) -> Result<Vec<String>> {
    crawl_redirect_chain_with_config(start_url, &CrawlerConfig::default()).await
}

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

    let parsed_url = Url::parse(start_url)
        .context("Failed to parse URL")?;

    // Validate URL scheme
    if !config.allowed_schemes.contains(&parsed_url.scheme().to_string()) {
        error!("Disallowed URL scheme: {}", parsed_url.scheme());
        bail!("URL scheme '{}' is not allowed", parsed_url.scheme());
    }

    debug!("Initializing HTTP client with user agent: {}", config.user_agent);
    // Configure client with custom settings
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_str(&config.user_agent)?);

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.request_timeout)
        .default_headers(headers)
        .pool_idle_timeout(Duration::from_secs(90))
        .build()?;

    let mut chain = Vec::new();
    let mut visited_urls = HashSet::new();
    let mut current_url = start_url.to_string();
    let mut hops = 0;

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
        let resp = client.get(&current_url)
            .send()
            .await
            .context("Failed to send request")?;

        debug!("Response status: {}", resp.status());

        if let Some(location) = resp.headers().get(reqwest::header::LOCATION) {
            if hops >= config.max_hops {
                warn!("Max redirect hops ({}) reached at {}", config.max_hops, current_url);
                break;
            }

            let location_str = location.to_str()?;
            debug!("Found redirect location: {}", location_str);
            let next_url = if location_str.starts_with("http") {
                location_str.to_string()
            } else {
                // Handle relative redirects
                let base = Url::parse(&current_url)?;
                base.join(location_str)?.to_string()
            };

            // Validate redirect URL
            let next_parsed = Url::parse(&next_url)
                .context("Failed to parse redirect URL")?;

            // Check scheme
            if !config.allowed_schemes.contains(&next_parsed.scheme().to_string()) {
                warn!("Redirect to disallowed scheme: {} (from {})", next_parsed.scheme(), current_url);
                break;
            }

            // Check domain if whitelist is configured
            if let Some(allowed_domains) = &config.allowed_domains {
                if let Some(host) = next_parsed.host_str() {
                    if !allowed_domains.iter().any(|d| host.ends_with(d)) {
                        error!("Redirect to disallowed domain: {} (from {})", host, current_url);
                        bail!("Redirect to disallowed domain: {}", host);
                    }
                }
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

    #[tokio::test]
    async fn test_domain_whitelist() {
        let config = CrawlerConfig {
            allowed_domains: Some(vec!["example.com".to_string()]),
            ..Default::default()
        };
        let result = crawl_redirect_chain_with_config("http://httpbin.org/redirect/1", &config).await;
        assert!(result.is_err());
    }
} 