use screenshot_api::url_parser::ParsedUrl;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging (optional)
    tracing_subscriber::fmt::init();
    
    // Test URL with base64-encoded data
    let test_url = "https://example.com/verify?email=dGVzdEBleGFtcGxlLmNvbQ==";
    
    println!("Parsing URL: {}", test_url);
    
    // Use the async version of ParsedUrl::new
    let parsed = ParsedUrl::new(test_url).await?;
    
    // Display the results
    println!("\nResults:");
    println!("Domain: {}", parsed.domain);
    println!("Anonymized URL: {}", parsed.anonymized_url());
    println!("Found {} identifiers", parsed.identifiers.len());
    
    for (i, id) in parsed.identifiers.iter().enumerate() {
        println!("\nIdentifier {}:", i + 1);
        println!("  Original value: {}", id.value);
        
        if let Some(decoded) = &id.decoded_value {
            println!("  Decoded value: {}", decoded);
        }
        
        if let Some(anonymized) = &id.anonymized_value {
            println!("  Anonymized as: {}", anonymized);
        }
    }
    
    Ok(())
}