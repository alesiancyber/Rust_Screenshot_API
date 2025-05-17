use anyhow::{Result, anyhow};
use screenshot_api::url_parser::ParsedUrl;
use std::env;
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    // Get URL from command line argument
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <url> [--batch <file>]", args[0]);
        return Err(anyhow!("Missing URL argument"));
    }
    
    // Check if --batch mode is specified
    if args.len() >= 3 && args[1] == "--batch" {
        if args.len() < 3 {
            eprintln!("Usage: {} --batch <file>", args[0]);
            return Err(anyhow!("Missing file path for batch processing"));
        }
        
        let file_path = &args[2];
        process_url_batch(file_path).await?;
    } else {
        // Process single URL
        let url = &args[1];
        process_single_url(url).await?;
    }
    
    Ok(())
}

async fn process_single_url(url: &str) -> Result<()> {
    println!("Processing URL: {}", url);
    
    // Parse the URL
    let start = std::time::Instant::now();
    let parsed_url = ParsedUrl::new(url).await?;
    let duration = start.elapsed();
    
    println!("\nResults:");
    println!("Domain: {}", parsed_url.domain);
    println!("Anonymized URL: {}", parsed_url.anonymized_url());
    println!("Identifiers found: {}", parsed_url.identifiers.len());
    
    // Print identifiers if found
    if !parsed_url.identifiers.is_empty() {
        println!("\nIdentified sensitive data:");
        for (i, id) in parsed_url.identifiers.iter().enumerate() {
            println!("  {}. Original: {}", i+1, id.value);
            if let Some(decoded) = &id.decoded_value {
                println!("     Decoded: {}", decoded);
            }
            if let Some(anonymized) = &id.anonymized_value {
                println!("     Anonymized: {}", anonymized);
            }
        }
    }
    
    // Print referenced URLs if found
    let url_collection = parsed_url.url_collection;
    if !url_collection.referenced_urls().is_empty() {
        println!("\nReferenced URLs:");
        for (i, url) in url_collection.referenced_urls().iter().enumerate() {
            println!("  {}. {}", i+1, url);
        }
    }
    
    // Print unique domains
    println!("\nUnique domains found:");
    for domain in url_collection.unique_domains() {
        println!("  - {}", domain);
    }
    
    println!("\nProcessing time: {:?}", duration);
    
    Ok(())
}

async fn process_url_batch(file_path: &str) -> Result<()> {
    // Read URLs from file (one per line)
    let content = std::fs::read_to_string(file_path)?;
    let urls: Vec<&str> = content.lines()
        .filter(|line| !line.trim().is_empty() && !line.trim().starts_with("#"))
        .collect();
    
    println!("Processing {} URLs from file: {}", urls.len(), file_path);
    
    // Start timer
    let start = std::time::Instant::now();
    
    // Process URLs concurrently (with controlled concurrency)
    const MAX_CONCURRENT: usize = 10;
    let mut results = Vec::new();
    
    for chunk in urls.chunks(MAX_CONCURRENT) {
        let futures = chunk.iter().map(|url| ParsedUrl::new(url));
        let chunk_results = futures::future::join_all(futures).await;
        results.extend(chunk_results);
    }
    
    let duration = start.elapsed();
    
    // Count successful parses and identifiers found
    let successful = results.iter().filter(|r| r.is_ok()).count();
    let total_identifiers: usize = results.iter()
        .filter_map(|r| r.as_ref().ok())
        .map(|parsed| parsed.identifiers.len())
        .sum();
    
    println!("\nSummary:");
    println!("Processed: {} URLs", urls.len());
    println!("Successful: {} URLs", successful);
    println!("Failed: {} URLs", urls.len() - successful);
    println!("Total identifiers found: {}", total_identifiers);
    println!("Total processing time: {:?}", duration);
    println!("Average time per URL: {:?}", duration / urls.len() as u32);
    
    // Report errors
    let errors: Vec<(&&str, &anyhow::Error)> = urls.iter()
        .zip(results.iter())
        .filter_map(|(url, result)| {
            if let Err(err) = result {
                Some((url, err))
            } else {
                None
            }
        })
        .collect();
    
    if !errors.is_empty() {
        println!("\nErrors:");
        for (url, err) in errors {
            println!("  URL: {}", url);
            println!("  Error: {}", err);
        }
    }
    
    Ok(())
} 