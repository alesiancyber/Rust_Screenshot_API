use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn, debug, trace};

use crate::api::models::ScreenshotJob;
use crate::api::config::ApiConfig;
use crate::api::processor::process_request;
use crate::screenshot::{ScreenshotTaker, MAX_CONNECTIONS};

/// Starts worker threads to process jobs from the queue
/// 
/// Each worker thread pulls jobs from the shared queue and processes them
/// using the screenshot service.
/// 
/// # Arguments
/// * `job_rx` - Shared job receiver channel
/// * `screenshot_taker` - Shared screenshot service
/// * `config` - API configuration
pub async fn start_workers(
    job_rx: mpsc::Receiver<ScreenshotJob>,
    screenshot_taker: Arc<ScreenshotTaker>,
    config: ApiConfig,
) {
    // Wrap the job receiver in a mutex so multiple workers can access it
    let job_rx = Arc::new(Mutex::new(job_rx));
    
    // Spawn worker tasks (all share the same receiver)
    info!("Spawning {} worker threads", MAX_CONNECTIONS);
    
    for worker_id in 0..MAX_CONNECTIONS {
        let screenshot_taker = screenshot_taker.clone();
        let job_rx = job_rx.clone();
        let config = config.clone();
        
        tokio::spawn(async move {
            debug!("Worker thread {} started", worker_id);
            loop {
                trace!("Worker {} waiting for job", worker_id);
                let job_opt = { job_rx.lock().await.recv().await };
                
                match job_opt {
                    Some(job) => {
                        debug!("Worker {} processing job for URL: {}", worker_id, job.request.url);
                        let result = process_request(job.request, &config, screenshot_taker.clone()).await;
                        
                        match &result {
                            Ok(_) => debug!("Worker {} completed job successfully", worker_id),
                            Err(e) => warn!("Worker {} job failed: {}", worker_id, e),
                        }
                        
                        if let Err(_) = job.response_tx.send(result.map_err(|e| e.to_string())) {
                            warn!("Worker {} failed to send response - receiver dropped", worker_id);
                        }
                    },
                    None => {
                        info!("Worker {} shutting down - channel closed", worker_id);
                        break;
                    }
                }
            }
        });
    }
} 