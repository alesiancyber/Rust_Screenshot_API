#!/bin/sh

# Start Xvfb
Xvfb :99 -screen 0 1280x1024x24 -ac &
export DISPLAY=:99

# Start ChromeDriver with minimal configuration
chromedriver \
    --port=4444 \
    --whitelisted-ips="" \
    --allowed-origins="*" \
    --allowed-ips="" \
    --log-path=/dev/stdout \
    --verbose 