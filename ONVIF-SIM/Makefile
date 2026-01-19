# Makefile for ONVIF WS-Discovery Tools
# Educational low-level networking implementations

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c99 -O2
LDFLAGS =

# Output directory
BUILD_DIR = build

# Targets
DISCOVERER = $(BUILD_DIR)/onvif_discoverer
FAKE_CAMERA = $(BUILD_DIR)/discovery_server

# Default target
.PHONY: all
all: $(BUILD_DIR) $(DISCOVERER) $(FAKE_CAMERA)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
	@echo "Created build directory"

# Build ONVIF discoverer client
$(DISCOVERER): onvif_discoverer.c
	@echo "Building ONVIF discoverer..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✓ Built: $@"

# Build fake camera server
$(FAKE_CAMERA): fakecamera/discovery_server.c
	@echo "Building fake camera server..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✓ Built: $@"

# Install to system (optional)
.PHONY: install
install: all
	@echo "Installing to /usr/local/bin..."
	@sudo install -m 755 $(DISCOVERER) /usr/local/bin/
	@sudo install -m 755 $(FAKE_CAMERA) /usr/local/bin/
	@echo "✓ Installed"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Clean"

# Run fake camera server
.PHONY: run-server
run-server: $(FAKE_CAMERA)
	@echo "Starting fake camera server..."
	@echo "Press Ctrl+C to stop"
	@$(FAKE_CAMERA)

# Run discovery client
.PHONY: run-client
run-client: $(DISCOVERER)
	@echo "Running ONVIF discovery client..."
	@$(DISCOVERER)

# Run both (requires terminal multiplexer or two terminals)
.PHONY: demo
demo: all
	@echo "=== ONVIF Discovery Demo ==="
	@echo "Starting fake camera in background..."
	@$(FAKE_CAMERA) &
	@sleep 2
	@echo ""
	@echo "Running discovery client..."
	@$(DISCOVERER)
	@pkill -f discovery_server || true

# Debug build
.PHONY: debug
debug: CFLAGS += -g -DDEBUG -O0
debug: clean all
	@echo "✓ Debug build complete"

# Check for common issues
.PHONY: check
check:
	@echo "Checking for common issues..."
	@echo -n "✓ gcc installed: "
	@which gcc >/dev/null && echo "yes" || echo "NO - run: sudo apt-get install build-essential"
	@echo -n "✓ Multicast routing enabled: "
	@grep -q "^1$$" /proc/sys/net/ipv4/ip_forward 2>/dev/null && echo "yes" || echo "no (usually ok for local subnet)"
	@echo -n "✓ Firewall allows UDP 3702: "
	@(sudo iptables -L INPUT -n | grep -q "udp dpt:3702" && echo "yes") || echo "no (may need: sudo iptables -I INPUT -p udp --dport 3702 -j ACCEPT)"
	@echo ""
	@echo "Network interfaces:"
	@ip addr show | grep -E '^[0-9]+:|inet ' | grep -v '127.0.0.1'

# Help target
.PHONY: help
help:
	@echo "ONVIF WS-Discovery Tools - Makefile Help"
	@echo "========================================"
	@echo ""
	@echo "Targets:"
	@echo "  make              - Build all tools"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make run-server   - Run fake camera server"
	@echo "  make run-client   - Run discovery client"
	@echo "  make demo         - Run both (automated demo)"
	@echo "  make debug        - Build with debug symbols"
	@echo "  make install      - Install to /usr/local/bin"
	@echo "  make check        - Check for common issues"
	@echo "  make help         - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  1. Build: make"
	@echo "  2. Terminal 1: make run-server"
	@echo "  3. Terminal 2: make run-client"
	@echo ""
	@echo "Or run automated demo:"
	@echo "  make demo"
