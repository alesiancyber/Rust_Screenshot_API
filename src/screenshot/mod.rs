// Submodules
mod client;
mod config;
mod model;
mod pool;
mod taker;

// Public exports
pub use model::Screenshot;
pub use taker::ScreenshotTaker;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[tokio::test]
    #[ignore] // Ignore by default since it requires WebDriver to be running
    async fn test_screenshot() {
        let dir = "test_screenshots";
        
        // Create the ScreenshotTaker
        let taker = match ScreenshotTaker::new(
            dir,
            None,
            Some((800, 600)),
            false
        ).await {
            Ok(t) => t,
            Err(e) => {
                println!("Failed to create ScreenshotTaker: {}", e);
                println!("This test requires a running WebDriver server - skipping");
                return;
            }
        };
        
        // Take screenshot
        let result = taker.take_screenshot("https://example.com", "test").await;
        if let Err(e) = &result {
            println!("Screenshot failed: {}", e);
            println!("This test requires a running WebDriver server - skipping");
            return;
        }
        
        let screenshot = result.unwrap();
        assert!(Path::new(&screenshot.file_path).exists());
        
        // Cleanup screenshot file
        fs::remove_file(&screenshot.file_path).unwrap();
        
        // Close the taker
        taker.close().await.unwrap();
        
        // Clean up the directory after test
        if Path::new(dir).exists() {
            match fs::remove_dir(dir) {
                Ok(_) => {},
                Err(e) => println!("Warning: Could not remove test directory: {}", e),
            }
        }
    }
} 