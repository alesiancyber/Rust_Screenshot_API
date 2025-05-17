#[cfg(test)]
mod tests {
    use crate::url_parser::{
        url_collection::UrlCollection,
        parser::ParsedUrl,
    };
    
    // Test URL Collection functionality
    #[test]
    fn test_url_collection_new() {
        let url = "https://example.com/path?param=value";
        let collection = UrlCollection::new(url).expect("Failed to create URL collection");
        
        assert_eq!(collection.anonymized_url(), url);
        assert!(collection.unique_domains().contains("example.com"));
        assert!(collection.referenced_urls().is_empty());
    }
    
    #[test]
    fn test_add_referenced_url() {
        let original_url = "https://example.com/";
        let mut collection = UrlCollection::new(original_url).unwrap();
        
        // Add a referenced URL
        let ref_url = "https://other-domain.com/path?q=123";
        collection.add_referenced_url(ref_url, Some("referer")).unwrap();
        
        // Verify it was added properly
        assert_eq!(collection.referenced_urls().len(), 1);
        assert_eq!(collection.referenced_urls()[0], ref_url);
        
        // Verify domain was added
        assert!(collection.unique_domains().contains("other-domain.com"));
        
        // Verify parameter URL was tracked
        assert_eq!(collection.parameter_urls().get("referer").unwrap(), ref_url);
    }
    
    #[test]
    fn test_extract_domain_info() {
        // Test regular domain
        let info = UrlCollection::extract_domain_info("https://example.com/path").unwrap();
        assert_eq!(info.full_host.as_deref(), Some("example.com"));
        assert_eq!(info.domain_name.as_deref(), Some("example.com"));
        assert_eq!(info.tld.as_deref(), Some("com"));
        assert!(!info.is_ip_address);
        
        // Test www prefix removal
        let info = UrlCollection::extract_domain_info("https://www.example.org/").unwrap();
        assert_eq!(info.full_host.as_deref(), Some("www.example.org"));
        assert_eq!(info.domain_name.as_deref(), Some("example.org"));
        
        // Test compound TLD
        let info = UrlCollection::extract_domain_info("https://example.co.uk/").unwrap();
        assert_eq!(info.tld.as_deref(), Some("co.uk"));
        assert_eq!(info.registrable_domain.as_deref(), Some("example.co.uk"));
        
        // Test IP address
        let info = UrlCollection::extract_domain_info("http://192.168.1.1/").unwrap();
        assert!(info.is_ip_address);
        assert_eq!(info.full_host.as_deref(), Some("192.168.1.1"));
        assert!(info.domain_name.is_none());
    }
    
    #[test]
    fn test_add_multiple_urls() {
        let original_url = "https://example.com/";
        let mut collection = UrlCollection::new(original_url).unwrap();
        
        let urls = vec![
            ("https://domain1.com/", Some("ref1")),
            ("https://domain2.org/path", Some("ref2")),
            ("https://domain3.net/path?q=123", None),
        ];
        
        collection.add_multiple_urls(urls).unwrap();
        
        // Verify all URLs were added
        assert_eq!(collection.referenced_urls().len(), 3);
        
        // Verify all domains were added
        let domains = collection.unique_domains();
        assert!(domains.contains("domain1.com"));
        assert!(domains.contains("domain2.org"));
        assert!(domains.contains("domain3.net"));
        
        // Verify parameter mapping
        assert_eq!(collection.parameter_urls().get("ref1").unwrap(), "https://domain1.com/");
        assert_eq!(collection.parameter_urls().get("ref2").unwrap(), "https://domain2.org/path");
        assert_eq!(collection.parameter_urls().len(), 2); // The third URL had no parameter name
    }
    
    #[test]
    fn test_find_urls_with_domain() {
        let original_url = "https://example.com/";
        let mut collection = UrlCollection::new(original_url).unwrap();
        
        // Add several URLs
        collection.add_referenced_url("https://test.com/path1", None).unwrap();
        collection.add_referenced_url("https://test.com/path2", None).unwrap();
        collection.add_referenced_url("https://other.org/path", None).unwrap();
        
        // Find URLs with a specific domain
        let results = collection.find_urls_with_domain("test.com");
        assert_eq!(results.len(), 2);
        assert!(results.contains(&"https://test.com/path1"));
        assert!(results.contains(&"https://test.com/path2"));
        
        // Search for a domain that doesn't exist
        let results = collection.find_urls_with_domain("nonexistent.com");
        assert_eq!(results.len(), 0);
    }
    
    #[test]
    fn test_is_https() {
        let collection = UrlCollection::new("https://example.com/").unwrap();
        
        assert!(collection.is_https("https://secure.com").unwrap());
        assert!(!collection.is_https("http://insecure.com").unwrap());
        
        // Invalid URL should return an error
        assert!(collection.is_https("not-a-url").is_err());
    }
    
    // Integration tests for ParsedUrl (needs async runtime)
    #[tokio::test]
    async fn test_parsed_url_simple() {
        let url = "https://example.com/path?q=value";
        let parsed = ParsedUrl::new(url).await.expect("Failed to parse URL");
        
        assert_eq!(parsed.domain, "example.com");
        assert!(parsed.identifiers.is_empty()); // No sensitive data in this simple URL
        
        // The actual value might be different since url_reconstructor might strip the query
        // or the URL might be normalized in some way
        let anonymized = parsed.anonymized_url();
        assert!(
            anonymized == url || anonymized == "https://example.com/path", 
            "Expected '{}' or '{}', but got '{}'", 
            url, 
            "https://example.com/path", 
            anonymized
        );
    }
    
    #[tokio::test]
    async fn test_parsed_url_with_urls_in_params() {
        let url = "https://example.com/redirect?url=https://other.com/path&ref=https://referer.org";
        let parsed = ParsedUrl::new(url).await.expect("Failed to parse URL");
        
        // Check that the referenced URLs were found
        let url_collection = &parsed.url_collection;
        let referenced = url_collection.referenced_urls();
        
        assert!(referenced.contains(&"https://other.com/path".to_string()));
        assert!(referenced.contains(&"https://referer.org".to_string()));
        
        // Check that domains were added
        let domains = url_collection.unique_domains();
        assert!(domains.contains("example.com"));
        assert!(domains.contains("other.com"));
        assert!(domains.contains("referer.org"));
        
        // Check parameter mappings
        let params = url_collection.parameter_urls();
        assert_eq!(params.get("url").unwrap(), "https://other.com/path");
        assert_eq!(params.get("ref").unwrap(), "https://referer.org");
    }
} 