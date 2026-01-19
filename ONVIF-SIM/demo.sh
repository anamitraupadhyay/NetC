#!/bin/bash
# ONVIF WS-Discovery Demo Script
# Demonstrates fake camera discovery in a single terminal

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  ONVIF WS-Discovery Educational Demo${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Build if needed
if [ ! -f "build/discovery_server" ] || [ ! -f "build/onvif_discoverer" ]; then
    echo -e "${YELLOW}Building tools...${NC}"
    make -s clean
    make -s
    echo -e "${GREEN}✓ Build complete${NC}"
    echo ""
fi

# Check for port conflicts
if ss -ulnp 2>/dev/null | grep -q ":3702 "; then
    echo -e "${RED}✗ Port 3702 already in use${NC}"
    echo "  Another process is using the WS-Discovery port."
    echo "  Find it with: ss -ulnp | grep 3702"
    exit 1
fi

echo -e "${BLUE}═══ Step 1: Starting Fake Camera Server ═══${NC}"
echo ""

# Start server in background
./build/discovery_server > /tmp/onvif_server.log 2>&1 &
SERVER_PID=$!
echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
echo "  Logs: /tmp/onvif_server.log"
echo ""

# Wait for server to initialize
sleep 2

# Check if server is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Server failed to start${NC}"
    echo "  Check logs: cat /tmp/onvif_server.log"
    exit 1
fi

echo -e "${BLUE}═══ Step 2: Running Discovery Client ═══${NC}"
echo ""

# Run client and capture output
if ./build/onvif_discoverer > /tmp/onvif_client.log 2>&1; then
    # Check if devices were found
    if grep -q "Device #1" /tmp/onvif_client.log; then
        echo -e "${GREEN}✓ Discovery successful!${NC}"
        echo ""
        echo -e "${YELLOW}Discovered device:${NC}"
        grep -A3 "Device #1:" /tmp/onvif_client.log | sed 's/^/  /'
    else
        echo -e "${YELLOW}⚠ No devices found${NC}"
        echo "  This may be expected in restricted network environments."
    fi
else
    echo -e "${YELLOW}⚠ Client completed with warnings${NC}"
    echo "  Check logs: cat /tmp/onvif_client.log"
fi

echo ""
echo -e "${BLUE}═══ Step 3: Cleanup ═══${NC}"
echo ""

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
echo -e "${GREEN}✓ Server stopped${NC}"

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo Complete${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Full logs available at:"
echo "  Server: /tmp/onvif_server.log"
echo "  Client: /tmp/onvif_client.log"
echo ""
echo "To run manually (in separate terminals):"
echo "  Terminal 1: make run-server"
echo "  Terminal 2: make run-client"
echo ""
echo "For more information:"
echo "  README.md  - Comprehensive networking guide"
echo "  USAGE.md   - Quick start and troubleshooting"
echo ""
