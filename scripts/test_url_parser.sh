#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing URL Parser Module${NC}"
echo "=================================="

# Create directory for test results
mkdir -p test_results

# Run unit tests
echo -e "\n${YELLOW}Running unit tests...${NC}"
RUST_BACKTRACE=1 cargo test --test url_parser_test -- --nocapture

# Run example CLI with sample URLs
echo -e "\n${YELLOW}Running CLI example with sample URLs...${NC}"

# Create sample URL file
echo "Creating sample URL file..."
cat > test_urls.txt << EOL
# Sample URLs for testing
https://example.com/path?query=value
https://example.com/api?token=am9obkBleGFtcGxlLmNvbQ==
https://example.com/redirect?url=https://other-site.com
https://api.example.com:8443/v1/users?id=12345&token=c2VjcmV0X3Rva2VuX3ZhbHVl
https://login.example.com?token=c2VjcmV0X3Rva2VuX3ZhbHVl
https://example.org/search?q=test
https://example.net/profile/12345
https://data.example.com/export?format=json
https://cdn.example.com/images/logo.png
https://api.example.org/v2/products?category=electronics
EOL

# Run CLI example with batch mode
echo -e "\n${YELLOW}Testing batch URL processing...${NC}"
time cargo run --example url_parser_cli -- --batch test_urls.txt | tee test_results/batch_results.txt

# Run performance benchmark (if criterion is available)
if cargo bench --bench url_parser_bench --no-run 2>/dev/null; then
    echo -e "\n${YELLOW}Running performance benchmarks...${NC}"
    cargo bench --bench url_parser_bench | tee test_results/benchmark_results.txt
else
    echo -e "\n${YELLOW}Skipping benchmarks (criterion might not be installed)${NC}"
fi

echo -e "\n${GREEN}All tests completed successfully!${NC}"
echo "Results saved in test_results directory" 