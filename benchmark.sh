#!/bin/bash

echo "Starting benchmark..."

# Clean up any existing container
docker rm -f test-chrome 2>/dev/null

# Start timing container creation
START_TIME=$(date +%s.%N)
echo "Starting container..."
docker run -d -p 4444:4444 --name test-chrome chromium:latest
CONTAINER_START_TIME=$(date +%s.%N)
CONTAINER_DURATION=$(echo "$CONTAINER_START_TIME - $START_TIME" | bc)
echo "Container started in ${CONTAINER_DURATION} seconds"

# Wait for ChromeDriver to be ready
echo "Waiting for ChromeDriver to be ready..."
while true; do
    if curl -s http://localhost:4444/status > /dev/null; then
        break
    fi
    sleep 0.1
done
DRIVER_READY_TIME=$(date +%s.%N)
DRIVER_DURATION=$(echo "$DRIVER_READY_TIME - $CONTAINER_START_TIME" | bc)
echo "ChromeDriver ready in ${DRIVER_DURATION} seconds"

# Create a new session
echo "Creating new session..."
SESSION_START=$(date +%s.%N)
SESSION_RESPONSE=$(curl -s -X POST http://localhost:4444/session \
    -H "Content-Type: application/json" \
    -d '{"capabilities": {"browserName": "chrome", "goog:chromeOptions": {"args": ["--ignore-certificate-errors"]}}}')
SESSION_ID=$(echo $SESSION_RESPONSE | grep -o '"sessionId":"[^"]*' | cut -d'"' -f4)
if [ -z "$SESSION_ID" ]; then
    echo "Failed to create session. Response: $SESSION_RESPONSE"
    docker rm -f test-chrome
    exit 1
fi
SESSION_END=$(date +%s.%N)
SESSION_DURATION=$(echo "$SESSION_END - $SESSION_START" | bc)
echo "Session created in ${SESSION_DURATION} seconds"

# Navigate to a website
echo "Navigating to example.com..."
NAV_START=$(date +%s.%N)
NAV_RESPONSE=$(curl -s -X POST "http://localhost:4444/session/$SESSION_ID/url" \
    -H "Content-Type: application/json" \
    -d '{"url": "http://example.com"}')
if [ "$NAV_RESPONSE" != '{"value":null}' ]; then
    echo "Navigation failed. Response: $NAV_RESPONSE"
    docker rm -f test-chrome
    exit 1
fi
NAV_END=$(date +%s.%N)
NAV_DURATION=$(echo "$NAV_END - $NAV_START" | bc)
echo "Navigation completed in ${NAV_DURATION} seconds"

# Get page title to verify navigation
echo "Getting page title..."
TITLE_START=$(date +%s.%N)
TITLE_RESPONSE=$(curl -s -X GET "http://localhost:4444/session/$SESSION_ID/title")
TITLE_END=$(date +%s.%N)
TITLE_DURATION=$(echo "$TITLE_END - $TITLE_START" | bc)
echo "Title retrieved in ${TITLE_DURATION} seconds"
echo "Page title: $TITLE_RESPONSE"

# Calculate total time
TOTAL_DURATION=$(echo "$TITLE_END - $START_TIME" | bc)

echo "----------------------------------------"
echo "Benchmark Results:"
echo "Container startup: ${CONTAINER_DURATION} seconds"
echo "ChromeDriver ready: ${DRIVER_DURATION} seconds"
echo "Session creation: ${SESSION_DURATION} seconds"
echo "Navigation: ${NAV_DURATION} seconds"
echo "Title retrieval: ${TITLE_DURATION} seconds"
echo "----------------------------------------"
echo "Total time: ${TOTAL_DURATION} seconds"

# Clean up
echo "Cleaning up..."
docker rm -f test-chrome 