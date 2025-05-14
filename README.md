# Screenshot API

A Rust-based API service that takes screenshots of web pages while handling URL parsing, base64 decoding, and anonymization of sensitive information.

## Features

- URL parsing with base64 detection and decoding
- Automatic anonymization of sensitive data (emails, phone numbers, etc.)
- Screenshot capture of both original and final (after redirects) pages
- Redirect chain tracking
- Health check endpoint
- Configurable viewport size and WebDriver settings
- Request queue and connection pool for safe concurrency

## Components

### URL Parser (`url_parser/mod.rs`)
- Parses URLs to detect base64 encoded values
- Decodes base64 values and identifies their type (email, phone, etc.)
- Anonymizes sensitive information
- Handles both query parameters and path segments

### URL Crawler (`url_crawler/mod.rs`)
- Follows redirect chains
- Handles HTTP/HTTPS redirects
- Tracks the complete redirect path
- Returns the final destination URL

### Screenshot Taker (`screenshot/mod.rs`)
- Takes screenshots using a headless browser
- Configurable viewport size
- Supports both original and final page screenshots
- Handles WebDriver initialization and cleanup

### API (`api/mod.rs`)
- RESTful API endpoints
- Request validation
- Response formatting
- Error handling
- Configuration management

## Configuration

The API can be configured using the `ApiConfig` struct:

```rust
pub struct ApiConfig {
    pub screenshot_dir: String,      // Directory to save screenshots
    pub viewport_width: u32,         // Browser viewport width
    pub viewport_height: u32,        // Browser viewport height
    pub headless: bool,              // Run browser in headless mode
    pub webdriver_url: Option<String>, // Custom WebDriver URL
    pub request_timeout: Duration,   // Timeout for each request
}
```

Concurrency is managed by a queue and a connection pool. You can adjust the queue size and pool size in the code (`QUEUE_SIZE` and `MAX_CONNECTIONS`).

## API Documentation

### Health Check
```http
GET /health
```
Returns the API health status.

Response:
```json
{
    "status": "healthy",
    "active_connections": 0,
    "total_connections": 2,
    "uptime": 0
}
```

### Take Screenshot
```http
POST /screenshot
Content-Type: application/json

{
    "url": "https://example.com/verify?email=ZXhhbXBsZUBleGFtcGxlLmNvbQ=="
}
```

Response:
```json
{
    "original_url": "https://example.com/verify?email=ZXhhbXBsZUBleGFtcGxlLmNvbQ==",
    "anonymized_url": "https://example.com/verify?email=anonymized_value",
    "final_url": "https://example.com/verify-success",
    "identifiers": [
        {
            "value": "ZXhhbXBsZUBleGFtcGxlLmNvbQ==",
            "decoded_value": "example@example.com",
            "anonymized_value": "anonymized_value"
        }
    ],
    "original_screenshot": "base64_encoded_image_data",
    "final_screenshot": "base64_encoded_image_data",
    "status": "success",
    "message": null
}
```

#### Error Response Example
```json
{
    "original_url": "https://example.com/invalid",
    "anonymized_url": "",
    "final_url": "",
    "identifiers": [],
    "original_screenshot": null,
    "final_screenshot": null,
    "status": "error",
    "message": "Error message here"
}
```

## Logging

- Logging is handled by `tracing` and `tracing-subscriber` (with `log` compatibility).
- Log files are written to the `logs/` directory, with a timestamped filename.
- Log levels can be controlled with the `RUST_LOG` environment variable.

## Dependencies

- `actix-web`: Web framework
- `serde`: Serialization/deserialization
- `log`, `tracing`, `tracing-subscriber`: Logging
- `anyhow`: Error handling
- `fantoccini`: WebDriver client
- `base64`: Base64 encoding/decoding
- `url`: URL parsing

## Building and Running

```bash
cargo build
cargo run
```

The API will be available at `http://localhost:8080`

## Testing

```bash
cargo test
```

## Performance and Concurrency

- The API uses a queue and connection pool to safely handle concurrent requests.
- If the queue is full, the API returns a 429 error.
- The number of concurrent browser sessions is limited by `MAX_CONNECTIONS`.

## Security Considerations

- URL validation and sanitization
- Base64 decoding safety
- WebDriver security settings
- File system permissions
- Error message sanitization

## Troubleshooting

- Check the `logs/` directory for detailed logs.
- Ensure ChromeDriver is running and accessible.
- Adjust `QUEUE_SIZE` and `MAX_CONNECTIONS` as needed for your environment.

## Project Structure
```
screenshot_api/
├── src/
│   ├── api/
│   │   └── mod.rs
│   ├── url_parser/
│   │   └── mod.rs
│   ├── url_crawler/
│   │   └── mod.rs
│   ├── screenshot/
│   │   └── mod.rs
│   ├── utils/
│   │   └── logger.rs
│   │   └── anonymizer.rs
│   │   └── mod.rs
│   └── main.rs
├── logs/
├── screenshots/
├── Cargo.toml
└── README.md
```

## Development Setup

### Prerequisites
- Rust 1.70 or higher
- Chrome/Chromium browser (for WebDriver)
- ChromeDriver matching your browser version

### Environment Variables
```bash
# API Configuration
SCREENSHOT_DIR=screenshots
VIEWPORT_WIDTH=1280
VIEWPORT_HEIGHT=800
HEADLESS=true
WEBDRIVER_URL=http://localhost:9515

# Logging
RUST_LOG=debug
```

### Development Tools
- `rustfmt` for code formatting
- `clippy` for linting
- `cargo-watch` for development

Install development tools:
```bash
# Install rustfmt and clippy
rustup component add rustfmt clippy

# Install cargo-watch
cargo install cargo-watch

# Format code
cargo fmt

# Run linter
cargo clippy

# Watch for changes
cargo watch -x test -x run
```

## Troubleshooting

### Common Issues

1. **WebDriver Connection Issues**
   - Ensure ChromeDriver is running and accessible
   - Check WebDriver URL configuration
   - Verify Chrome/Chromium version matches ChromeDriver

2. **Screenshot Failures**
   - Check screenshot directory permissions
   - Verify viewport size settings
   - Ensure headless mode is properly configured

3. **URL Parsing Issues**
   - Verify base64 encoding format
   - Check URL encoding/decoding
   - Validate URL structure

### Debugging

Enable debug logging:
```bash
RUST_LOG=debug cargo run
```

Check logs in:
- Console output
- `logs/` directory (if configured)

## Performance Considerations

- Viewport size affects memory usage
- Large redirect chains may impact performance
- Screenshot size and format affect response time
- WebDriver connection pooling for high load

## Security Considerations

- URL validation and sanitization
- Base64 decoding safety
- WebDriver security settings
- File system permissions
- Error message sanitization

## Monitoring

The API provides health metrics at `/health`:
```json
{
    "status": "healthy",
    "active_connections": 0,
    "total_connections": 2,
    "uptime": 0
}
```

## Deployment

### Docker
```bash
# Build image
docker build -t screenshot-api .

# Run container
docker run -p 8080:8080 screenshot-api
```

### Systemd Service
```ini
[Unit]
Description=Screenshot API Service
After=network.target

[Service]
Type=simple
User=screenshot-api
WorkingDirectory=/opt/screenshot-api
ExecStart=/usr/local/bin/screenshot-api
Restart=always

[Install]
WantedBy=multi-user.target
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 