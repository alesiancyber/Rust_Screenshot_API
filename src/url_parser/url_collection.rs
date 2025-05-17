use std::collections::{HashMap, HashSet};
use url::Url;
use anyhow::{Result, anyhow};

/// Collection of URLs discovered during parsing and analysis
/// 
/// Tracks all URLs found during the parsing process, including:
/// - Anonymized URLs
/// - Referenced URLs in parameters
/// - All unique domains encountered
#[derive(Debug, Clone)]
pub struct UrlCollection {
    // Keeping only fields that are actually used
    anonymized_url: String,             // The URL with sensitive data anonymized
    referenced_urls: Vec<String>,       // URLs found in parameters or path segments
    unique_domains: HashSet<String>,    // All unique domains found
    parameter_urls: HashMap<String, String>, // URLs found in specific parameters, by param name
}

/// Detailed information about a domain extracted from a URL
#[derive(Debug, Clone)]
pub struct DomainInfo {
    pub full_host: Option<String>,      // Complete hostname
    pub domain_name: Option<String>,    // Domain name (without www.)
    pub is_ip_address: bool,            // Whether it's an IP address
    pub tld: Option<String>,            // Top-level domain (public suffix)
    pub registrable_domain: Option<String>, // Registrable domain (eTLD+1)
}

impl UrlCollection {
    /// Creates a new empty URL collection with just the original URL
    pub fn new(original_url: &str) -> Result<Self> {
        // Just validate the URL without storing the result
        Url::parse(original_url)
            .map_err(|e| anyhow!("Invalid original URL: {}", e))?;
        
        let mut unique_domains = HashSet::new();
        let domain_info = Self::extract_domain_info(original_url)?;
        
        // Add domain to unique domains if available
        if let Some(domain) = &domain_info.domain_name {
            unique_domains.insert(domain.to_owned());
        } else if let Some(host) = &domain_info.full_host {
            unique_domains.insert(host.to_owned());
        }
        
        Ok(UrlCollection {
            anonymized_url: original_url.to_owned(),
            referenced_urls: Vec::new(),
            unique_domains,
            parameter_urls: HashMap::new(),
        })
    }
    
    /// Adds a referenced URL found in a parameter or path segment
    pub fn add_referenced_url(&mut self, url: &str, parameter_name: Option<&str>) -> Result<()> {
        // Parse the URL and extract domain information
        let domain_info = Self::extract_domain_info(url)?;
        
        // Add to referenced URLs
        self.referenced_urls.push(url.to_owned());
        
        // Add domain to unique domains set
        if let Some(domain) = &domain_info.domain_name {
            self.unique_domains.insert(domain.to_owned());
        } else if let Some(host) = &domain_info.full_host {
            self.unique_domains.insert(host.to_owned());
        }
        
        // If from a specific parameter, track it
        if let Some(param) = parameter_name {
            self.parameter_urls.insert(param.to_owned(), url.to_owned());
        }
        
        Ok(())
    }

    
    /// Extract detailed domain information from a URL string
    pub fn extract_domain_info(url_str: &str) -> Result<DomainInfo> {
        let parsed_url = Url::parse(url_str)?;
        
        // Create a DomainInfo struct to hold detailed information
        let mut info = DomainInfo {
            full_host: None,
            domain_name: None,
            is_ip_address: false,
            tld: None,
            registrable_domain: None,
        };
        
        // Process host information if available
        if let Some(host) = parsed_url.host_str() {
            info.full_host = Some(host.to_owned());
            Self::process_host(&mut info, parsed_url.host());
        }
        
        Ok(info)
    }

    // Helper method to process host information
    fn process_host(info: &mut DomainInfo, host: Option<url::Host<&str>>) {
        if let Some(host) = host {
            match host {
                url::Host::Domain(domain) => {
                    // Remove www prefix if present
                    let normalized = if domain.starts_with("www.") {
                        &domain[4..]
                    } else {
                        domain
                    };
                    
                    info.domain_name = Some(normalized.to_owned());
                    
                    // Simplistic TLD extraction
                    Self::extract_domain_parts(info, normalized);
                },
                url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
                    info.is_ip_address = true;
                }
            }
        }
    }

    // Extract domain parts using a simple approach
    fn extract_domain_parts(info: &mut DomainInfo, domain: &str) {
        // Handle special compound TLD cases (hardcoded commonly used ones)
        let common_compound_tlds = ["co.uk", "com.au", "co.nz", "org.uk", "net.uk"];
        
        for tld in &common_compound_tlds {
            if domain.ends_with(tld) {
                let domain_without_tld = &domain[..domain.len() - tld.len() - 1]; // -1 for the dot
                if !domain_without_tld.is_empty() {
                    info.tld = Some(tld.to_string());
                    info.registrable_domain = Some(format!("{}.{}", domain_without_tld, tld));
                    return;
                }
            }
        }
        
        // Regular TLD extraction
        if let Some(last_dot) = domain.rfind('.') {
            let tld = &domain[last_dot + 1..];
            info.tld = Some(tld.to_owned());
            
            // For simple domains like example.com, the registrable domain is the full domain
            info.registrable_domain = Some(domain.to_owned());
        }
    }
    
    /// Sets the anonymized URL
    pub fn set_anonymized_url(&mut self, url: String) {
        self.anonymized_url = url;
    }
    
    /// Get the anonymized URL
    pub fn anonymized_url(&self) -> &str {
        &self.anonymized_url
    }
    
    /// Get all referenced URLs
    pub fn referenced_urls(&self) -> &[String] {
        &self.referenced_urls
    }
    
    /// Get all unique domains
    pub fn unique_domains(&self) -> &HashSet<String> {
        &self.unique_domains
    }

}

// Implement conversions
impl TryFrom<&str> for UrlCollection {
    type Error = anyhow::Error;
    
    fn try_from(url_str: &str) -> Result<Self, Self::Error> {
        UrlCollection::new(url_str)
    }
}

impl TryFrom<Url> for UrlCollection {
    type Error = anyhow::Error;
    
    fn try_from(url: Url) -> Result<Self, Self::Error> {
        UrlCollection::new(url.as_str())
    }
}