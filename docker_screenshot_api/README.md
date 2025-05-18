# Docker Screenshot API

A standalone screenshot service that uses Docker containers to capture screenshots of web pages using Chrome.

## Prerequisites

- Docker installed and running
- Rust toolchain installed
- Chrome Docker image built (see below)

## Building the Chrome Docker Image

First, build the Chrome Docker image:

```bash
cd docker/chrome
docker build -t chromium:minimal .
```

## Running the Service

1. Build and run the service:

```bash
cargo run
```

The service will start on `http://127.0.0.1:8081`.

## API Usage

### Take a Screenshot

Send a POST request to `/screenshot` with the following JSON body:

```json
{
    "url": "https://example.com",
    "width": 1920,
    "height": 1080,
    "wait_for": "#main-content",
    "wait_timeout": 30
}
```

All fields except `url` are optional:
- `width`: Viewport width in pixels
- `height`: Viewport height in pixels
- `wait_for`: CSS selector to wait for before taking screenshot
- `wait_timeout`: Maximum time to wait for element in seconds

The response will be a PNG image.

## Example

Using curl:

```bash
curl -X POST http://127.0.0.1:8081/screenshot \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "width": 1920, "height": 1080}' \
  --output screenshot.png
```

## Screenshots

Screenshots are saved to the `screenshots/docker` directory with timestamps in the filename.

## Error Handling

The service will return:
- 200 OK with the screenshot on success
- 500 Internal Server Error with an error message on failure

## Cleanup

The service automatically manages the Chrome container lifecycle. When the service stops, you can manually clean up the container:

```bash
docker rm -f screenshot-chrome
``` 