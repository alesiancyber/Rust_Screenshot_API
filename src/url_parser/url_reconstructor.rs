use anyhow::Result;
use std::collections::HashMap;
use url::Url;

/// Reconstructs a URL with replacement parameters
pub async fn reconstruct_url(
    original_url: &Url,
    replacement_params: &HashMap<String, String>
) -> Result<String> {
    // For CPU-bound operations like this, we can spawn a blocking task
    // This prevents blocking the async runtime with CPU-intensive operations
    let original_url_clone = original_url.clone();
    let params_clone = replacement_params.clone();
    
    tokio::task::spawn_blocking(move || {
        // Create a new URL from the original, removing query
        let mut new_url = original_url_clone;
        new_url.set_query(None);
        
        // Add the replacement parameters
        if !params_clone.is_empty() {
            let mut query_pairs = new_url.query_pairs_mut();
            for (key, value) in params_clone {
                query_pairs.append_pair(&key, &value);
            }
            // Release the borrow on new_url
            drop(query_pairs);
        }
        
        Ok(new_url.to_string())
    }).await?
}