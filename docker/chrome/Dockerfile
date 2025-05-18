FROM alpine:3.19

# Install only the essential dependencies
RUN apk add --no-cache \
    chromium \
    chromium-chromedriver \
    xvfb \
    dbus \
    ttf-freefont \
    # Minimal dependencies for Chrome
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    tzdata \
    # Clean up
    && rm -rf /var/cache/apk/*

# Create a non-root user
RUN addgroup -S chrome && adduser -S chrome -G chrome

# Set up the working directory
WORKDIR /home/chrome

# Copy the startup script
COPY start.sh /home/chrome/start.sh
RUN chmod +x /home/chrome/start.sh

# Switch to non-root user
USER chrome

# Expose the ChromeDriver port
EXPOSE 4444

# Start ChromeDriver with minimal configuration
CMD ["/home/chrome/start.sh"] 