use anyhow::{Context, Result};
use fantoccini::{ClientBuilder, wd::Capabilities, wd::Locator};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use std::path::Path;
use chrono::Local;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScreenshotRequest {
    pub url: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub wait_for: Option<String>,
    pub wait_timeout: Option<u64>,
}

pub struct DockerScreenshotService {
    container_name: String,
    webdriver_url: String,
    screenshot_dir: String,
}

impl DockerScreenshotService {
    pub fn new(container_name: &str, webdriver_url: &str, screenshot_dir: &str) -> Self {
        // Ensure screenshot directory exists
        fs::create_dir_all(screenshot_dir).expect("Failed to create screenshot directory");
        
        Self {
            container_name: container_name.to_string(),
            webdriver_url: webdriver_url.to_string(),
            screenshot_dir: screenshot_dir.to_string(),
        }
    }

    pub async fn take_screenshot(&self, request: ScreenshotRequest) -> Result<Vec<u8>> {
        // Create a new ChromeDriver client
        let client = ClientBuilder::native()
            .capabilities(Capabilities::new())
            .connect(&self.webdriver_url)
            .await
            .context("Failed to connect to ChromeDriver")?;

        // Navigate to the URL
        client.goto(&request.url).await?;

        // Set viewport size if specified
        if let (Some(width), Some(height)) = (request.width, request.height) {
            client.set_window_size(width, height).await?;
        }

        // Wait for element if specified
        if let Some(selector) = request.wait_for {
            let timeout = request.wait_timeout.unwrap_or(30);
            let locator = Locator::Css(&selector);
            client
                .wait()
                .for_element(locator)
                .await?;
        }

        // Take screenshot
        let screenshot = client.screenshot().await?;

        // Save screenshot to file
        let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("docker_screenshot_{}.png", timestamp);
        let filepath = Path::new(&self.screenshot_dir).join(&filename);
        fs::write(&filepath, &screenshot)?;
        println!("Screenshot saved to: {}", filepath.display());

        // Close the session
        client.close().await?;

        Ok(screenshot)
    }

    pub async fn ensure_container_running(&self) -> Result<()> {
        // Check if container is running
        let output = Command::new("docker")
            .args(["ps", "-q", "-f", &format!("name={}", self.container_name)])
            .output()
            .await?;

        if output.stdout.is_empty() {
            // Start the container
            Command::new("docker")
                .args([
                    "run",
                    "-d",
                    "--name",
                    &self.container_name,
                    "-p",
                    "4444:4444",
                    "chromium:minimal",
                ])
                .output()
                .await?;

            // Wait for ChromeDriver to be ready
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        Ok(())
    }

    pub async fn cleanup(&self) -> Result<()> {
        Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .output()
            .await?;
        Ok(())
    }
} 