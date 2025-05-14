use anyhow::Result;
use std::path::Path;
use std::fs;
use chrono::Local;
use tracing::info;
use tracing_subscriber::{FmtSubscriber, EnvFilter};

pub fn init_logger(log_dir: &str) -> Result<()> {
    // Create log directory if it doesn't exist
    if !Path::new(log_dir).exists() {
        fs::create_dir_all(log_dir)?;
    }

    // Create log file with timestamp
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_file = format!("{}/screenshot_api_{}.log", log_dir, timestamp);

    // Initialize tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(false)
        .with_ansi(false)
        .with_writer(std::fs::File::create(log_file)?)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;
    info!("Logger initialized");

    Ok(())
} 