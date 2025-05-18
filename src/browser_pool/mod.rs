use anyhow::{Result, Context};
use bollard::container::{Config, CreateContainerOptions, StartContainerOptions};
use bollard::Docker;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

const CHROME_IMAGE: &str = "chromium:latest";
const WEBDRIVER_PORT: u16 = 4444;

#[derive(Debug, Clone)]
pub struct BrowserContainer {
    pub id: String,
    pub webdriver_url: String,
}

pub struct BrowserPool {
    docker: Docker,
    containers: Arc<Mutex<HashMap<String, BrowserContainer>>>,
    min_containers: usize,
    max_containers: usize,
}

impl BrowserPool {
    pub async fn new(min_containers: usize, max_containers: usize) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        
        let pool = Self {
            docker,
            containers: Arc::new(Mutex::new(HashMap::new())),
            min_containers,
            max_containers,
        };

        // Initialize the pool with minimum containers
        pool.initialize_pool().await?;
        
        Ok(pool)
    }

    async fn initialize_pool(&self) -> Result<()> {
        info!("Initializing browser pool with {} containers", self.min_containers);
        
        for i in 0..self.min_containers {
            self.create_container().await?;
        }

        Ok(())
    }

    async fn create_container(&self) -> Result<BrowserContainer> {
        let container_name = format!("browser-chrome-{}", uuid::Uuid::new_v4());

        // Configure the container with minimal settings
        let config = Config {
            image: Some(CHROME_IMAGE),
            hostname: Some(&container_name),
            exposed_ports: Some(HashMap::from([(
                format!("{}/tcp", WEBDRIVER_PORT),
                HashMap::new(),
            )])),
            host_config: Some(bollard::service::HostConfig {
                port_bindings: Some(HashMap::from([(
                    format!("{}/tcp", WEBDRIVER_PORT),
                    Some(vec![bollard::service::PortBinding {
                        host_ip: Some("0.0.0.0".to_string()),
                        host_port: Some("0".to_string()),
                    }]),
                )])),
                // Add memory limits
                memory: Some(512 * 1024 * 1024), // 512MB
                memory_swap: Some(512 * 1024 * 1024), // No swap
                ..Default::default()
            }),
            ..Default::default()
        };

        // Create and start the container
        let create_opts = CreateContainerOptions {
            name: &container_name,
            ..Default::default()
        };

        let id = self.docker
            .create_container(Some(create_opts), config)
            .await?
            .id;

        self.docker
            .start_container(&id, None::<StartContainerOptions<String>>)
            .await?;

        // Get the assigned port
        let container_info = self.docker.inspect_container(&id, None).await?;
        let port_bindings = container_info
            .host_config
            .and_then(|hc| hc.port_bindings)
            .unwrap_or_default();

        let host_port = port_bindings
            .get(&format!("{}/tcp", WEBDRIVER_PORT))
            .and_then(|bindings| bindings.first())
            .and_then(|binding| binding.host_port.clone())
            .unwrap_or_else(|| WEBDRIVER_PORT.to_string());

        let webdriver_url = format!("http://localhost:{}", host_port);

        let container = BrowserContainer {
            id,
            webdriver_url,
        };

        // Add to our pool
        let mut containers = self.containers.lock().await;
        containers.insert(container_name, container.clone());

        info!("Created new browser container: {}", container_name);
        Ok(container)
    }

    pub async fn get_container(&self) -> Result<BrowserContainer> {
        let containers = self.containers.lock().await;
        
        // Find an available container
        if let Some(container) = containers.values().next() {
            return Ok(container.clone());
        }

        // If no container is available, create a new one if we haven't hit the max
        if containers.len() < self.max_containers {
            drop(containers); // Release the lock before creating a new container
            self.create_container().await
        } else {
            Err(anyhow::anyhow!("No available containers and pool is at maximum capacity"))
        }
    }

    pub async fn cleanup(&self) -> Result<()> {
        info!("Cleaning up browser pool");
        let containers = self.containers.lock().await;
        
        for (name, container) in containers.iter() {
            if let Err(e) = self.docker.stop_container(&container.id, None).await {
                warn!("Failed to stop container {}: {}", name, e);
            }
            
            if let Err(e) = self.docker.remove_container(&container.id, None).await {
                warn!("Failed to remove container {}: {}", name, e);
            }
        }

        Ok(())
    }
}

impl Drop for BrowserPool {
    fn drop(&mut self) {
        // We can't do async operations in drop, so we'll just log a warning
        warn!("BrowserPool is being dropped - containers may not be properly cleaned up");
    }
} 