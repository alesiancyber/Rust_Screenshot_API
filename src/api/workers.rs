use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn, instrument};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use crate::api::config::ApiConfig;
use crate::api::models::ScreenshotJob;
use crate::api::processor::process_request;
use crate::screenshot::ScreenshotTaker;
use crate::utils::benchmarking::{OperationTimer, OperationType};
/// Default number of workers to spawn
const DEFAULT_WORKER_COUNT: usize = 4;
/// Default channel capacity for job queue
const DEFAULT_CHANNEL_CAPACITY: usize = 100;
/// Default timeout for job processing (5 minutes)
const DEFAULT_JOB_TIMEOUT: Duration = Duration::from_secs(300);
/// Worker metrics for monitoring
#[derive(Debug, Default)]
struct WorkerMetrics {
    jobs_processed: AtomicUsize,
    jobs_failed: AtomicUsize,
    total_processing_time: AtomicUsize, // in milliseconds
}
impl WorkerMetrics {
    fn new() -> Self {
        Self::default()
    }
    
    fn record_job(&self, success: bool, processing_time_ms: u64) {
        if success {
            self.jobs_processed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.jobs_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.total_processing_time.fetch_add(processing_time_ms as usize, Ordering::Relaxed);
    }
    
    fn get_metrics(&self) -> HashMap<String, String> {
        let processed = self.jobs_processed.load(Ordering::Relaxed);
        let failed = self.jobs_failed.load(Ordering::Relaxed);
        let total_time = self.total_processing_time.load(Ordering::Relaxed);
        let avg_time = if processed > 0 {
            total_time / processed
        } else {
            0
        };
        
        let mut metrics = HashMap::new();
        metrics.insert("jobs_processed".to_string(), processed.to_string());
        metrics.insert("jobs_failed".to_string(), failed.to_string());
        metrics.insert("avg_processing_time_ms".to_string(), avg_time.to_string());
        
        metrics
    }
}
/// Starts multiple worker tasks to process screenshot jobs
/// 
/// Creates a configurable number of worker tasks that listen to the job queue and
/// process incoming screenshot requests in parallel.
/// 
/// # Arguments
/// * `job_rx` - Receiver for the job queue
/// * `screenshot_taker` - Shared screenshot service instance
/// * `config` - API configuration
/// * `worker_count` - Number of worker tasks to spawn (defaults to DEFAULT_WORKER_COUNT)
/// * `shutdown_rx` - Channel to receive shutdown signal
/// 
/// # Returns
/// * `()` - This function does not return a value
#[instrument(skip(job_rx, screenshot_taker, config, shutdown_rx), fields(worker_count = worker_count))]
pub async fn start_workers(
    mut job_rx: mpsc::Receiver<ScreenshotJob>,
    screenshot_taker: Arc<ScreenshotTaker>,
    config: ApiConfig,
    worker_count: Option<usize>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let worker_count = worker_count.unwrap_or(DEFAULT_WORKER_COUNT);
    info!("Starting {} screenshot worker tasks", worker_count);
    
    // Create a channel for each worker
    let mut worker_txs = Vec::with_capacity(worker_count);
    let mut worker_rxs = Vec::with_capacity(worker_count);
    
    for _ in 0..worker_count {
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        worker_txs.push(tx);
        worker_rxs.push(rx);
    }
    
    // Create metrics for monitoring
    let metrics = Arc::new(WorkerMetrics::new());
    
    // Spawn worker tasks
    let mut worker_handles = Vec::with_capacity(worker_count);
    
    for worker_id in 0..worker_count {
        let worker_rx = worker_rxs.remove(0);
        let worker_screenshot_taker = Arc::clone(&screenshot_taker);
        let worker_config = config.clone();
        let worker_metrics = Arc::clone(&metrics);
        
        let handle = tokio::spawn(async move {
            worker_task(
                worker_id,
                worker_rx,
                worker_screenshot_taker,
                worker_config,
                worker_metrics,
            ).await
        });
        
        worker_handles.push(handle);
    }
    
    // Main loop to distribute jobs to workers using round-robin
    let mut current_worker = 0;
    let mut shutdown_requested = false;
    
    while !shutdown_requested {
        tokio::select! {
            Some(job) = job_rx.recv() => {
                // Round-robin job distribution
                if let Err(e) = worker_txs[current_worker].send(job).await {
                    error!("Failed to send job to worker {}: {}", current_worker, e);
                }
                current_worker = (current_worker + 1) % worker_count;
            },
            _ = &mut shutdown_rx => {
                info!("Received shutdown signal, stopping job distribution");
                shutdown_requested = true;
            }
        }
    }
    
    // Close all worker channels
    for tx in worker_txs {
        let _ = tx.send(ScreenshotJob {
            request: crate::api::models::ScreenshotRequest {
                url: "SHUTDOWN".to_string(),
            },
            response_tx: oneshot::channel().0,
            timer: None,
        }).await;
    }
    
    // Wait for all workers to complete
    info!("Waiting for worker tasks to complete...");
    for (i, handle) in worker_handles.into_iter().enumerate() {
        if let Err(e) = handle.await {
            error!("Worker {} failed: {}", i, e);
        }
    }
    
    // Log final metrics
    let final_metrics = metrics.get_metrics();
    info!("Worker metrics: {:?}", final_metrics);
}
/// Individual worker task implementation
#[instrument(skip(worker_rx, screenshot_taker, config, metrics), fields(worker_id = worker_id))]
async fn worker_task(
    worker_id: usize,
    mut worker_rx: mpsc::Receiver<ScreenshotJob>,
    screenshot_taker: Arc<ScreenshotTaker>,
    config: ApiConfig,
    metrics: Arc<WorkerMetrics>,
) {
    info!("Worker {} started", worker_id);
    
    // Process jobs until the channel is closed
    while let Some(job) = worker_rx.recv().await {
        // Check for shutdown signal
        if job.request.url == "SHUTDOWN" {
            break;
        }
        
        let start_time = Instant::now();
        let job_url = job.request.url.clone();
        
        debug!("Worker {} processing job for URL: {}", worker_id, job_url);
        
        // Create or use existing timer
        let timer = match job.timer {
            Some(t) => t,
            None => OperationTimer::new(),
        };
        
        // Start timing the job
        timer.start_operation("process_job", OperationType::Asynchronous, None).await;
        
        // Process the request with timeout
        let result = match timeout(DEFAULT_JOB_TIMEOUT, process_request(
            job.request, 
            &config, 
            Arc::clone(&screenshot_taker)
        )).await {
            Ok(result) => result,
            Err(_) => {
                let error_msg = format!("Job processing timed out after {} seconds", 
                    DEFAULT_JOB_TIMEOUT.as_secs());
                error!("{} for URL: {}", error_msg, job_url);
                Err(anyhow::anyhow!(error_msg))
            }
        };
        
        // End timing
        timer.end_operation("process_job").await;
        
        // Record metrics
        let processing_time = start_time.elapsed().as_millis() as u64;
        let success = result.is_ok();
        metrics.record_job(success, processing_time);
        
        // Send result back through channel
        match result {
            Ok(mut response) => {
                // Add timing report if available
                // FIXED: timer.generate_report().await returns a String directly, not a Result
                response.timing_report = Some(timer.generate_report().await);
                
                if let Err(e) = job.response_tx.send(Ok(response)) {
                    warn!("Worker {} failed to send response: {:?}", worker_id, e);
                }
            },
            Err(e) => {
                error!("Worker {} error processing URL {}: {}", worker_id, job_url, e);
                if let Err(send_err) = job.response_tx.send(Err(format!("{}", e))) {
                    warn!("Worker {} failed to send error response: {:?}", worker_id, send_err);
                }
            }
        }
    }
    
    info!("Worker {} shutting down - channel closed", worker_id);
}

/// Creates a shutdown channel for graceful termination
/// 
/// # Returns
/// * `(oneshot::Sender<()>, oneshot::Receiver<()>)` - Shutdown channel endpoints
pub fn create_shutdown_channel() -> (oneshot::Sender<()>, oneshot::Receiver<()>) {
    oneshot::channel()
}
/// Creates a bounded channel for job processing
/// 
/// # Arguments
/// * `capacity` - Channel capacity (defaults to DEFAULT_CHANNEL_CAPACITY)
/// 
/// # Returns
/// * `(mpsc::Sender<ScreenshotJob>, mpsc::Receiver<ScreenshotJob>)` - Channel endpoints
#[allow(dead_code)]
pub fn create_job_channel(capacity: Option<usize>) -> (mpsc::Sender<ScreenshotJob>, mpsc::Receiver<ScreenshotJob>) {
    let capacity = capacity.unwrap_or(DEFAULT_CHANNEL_CAPACITY);
    mpsc::channel(capacity)
}