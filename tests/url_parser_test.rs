#[cfg(test)]
mod tests {
    use anyhow::Result;
    use screenshot_api::url_parser::ParsedUrl;

    #[tokio::test]
    async fn test_basic_url_parsing() -> Result<()> {
        // Test a simple URL
        let url = "https://example.com/path?query=value";
        let parsed = ParsedUrl::new(url).await?;
        
        assert_eq!(parsed.domain, "example.com");
        // Just check that the anonymized URL contains the original domain
        assert!(parsed.anonymized_url().contains("example.com"));
        assert_eq!(parsed.identifiers.len(), 0);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_with_base64_param() -> Result<()> {
        // Create a URL with a base64-encoded email (john@example.com)
        let url = "https://example.com/api?token=am9obkBleGFtcGxlLmNvbQ==";
        let parsed = ParsedUrl::new(url).await?;
        
        // Should have found the base64-encoded email
        assert!(parsed.identifiers.len() > 0);
        
        // Anonymized URL should be different from original
        assert_ne!(parsed.anonymized_url(), url);
        
        // Check if the domain was correctly parsed
        assert_eq!(parsed.domain, "example.com");
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_url_with_embedded_url() -> Result<()> {
        // Test URL with another URL as a parameter
        let url = "https://example.com/redirect?url=https://other-site.com";
        let parsed = ParsedUrl::new(url).await?;
        
        // Check domain
        assert_eq!(parsed.domain, "example.com");
        
        // Check if the URL collection has the referenced URL
        let url_collection = parsed.url_collection;
        assert!(url_collection.referenced_urls().len() > 0);
        assert!(url_collection.unique_domains().contains("other-site.com"));
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_complex_url() -> Result<()> {
        // Test a more complex URL
        let url = "https://api.example.com:8443/v1/users?id=12345&token=c2VjcmV0X3Rva2VuX3ZhbHVl";
        let parsed = ParsedUrl::new(url).await?;
        
        // Check domain and port
        assert_eq!(parsed.domain, "api.example.com");
        
        // The token is base64-encoded, should be anonymized
        assert_ne!(parsed.anonymized_url(), url);
        
        Ok(())
    }
} 