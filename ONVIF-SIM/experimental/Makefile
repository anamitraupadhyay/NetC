# Makefile for Experimental Low-Level Networking Examples

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O2 -g
LDFLAGS =

# Output directory
BUILD_DIR = build

# Targets
RAW_UDP = $(BUILD_DIR)/raw_udp_syscall
RAW_TCP = $(BUILD_DIR)/raw_tcp_syscall
MEMORY = $(BUILD_DIR)/memory_explicit

# All targets
.PHONY: all
all: $(BUILD_DIR) $(RAW_UDP) $(RAW_TCP) $(MEMORY)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
	@echo "Created $(BUILD_DIR)/ directory"

# Build raw UDP syscall example
$(RAW_UDP): raw_udp_syscall.c
	@echo "Building raw_udp_syscall..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✓ Built: $@"

# Build raw TCP syscall example
$(RAW_TCP): raw_tcp_syscall.c
	@echo "Building raw_tcp_syscall..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✓ Built: $@"

# Build memory management example
$(MEMORY): memory_explicit.c
	@echo "Building memory_explicit..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✓ Built: $@"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Clean"

# Run all examples (for testing)
.PHONY: test
test: all
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  Running raw_udp_syscall"
	@echo "═══════════════════════════════════════════════════════════"
	@$(RAW_UDP)
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  Running raw_tcp_syscall"
	@echo "═══════════════════════════════════════════════════════════"
	@$(RAW_TCP)
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  Running memory_explicit"
	@echo "═══════════════════════════════════════════════════════════"
	@$(MEMORY)

# Trace syscalls for educational purposes
.PHONY: trace-udp
trace-udp: $(RAW_UDP)
	@echo "Tracing UDP syscalls (socket, sendto, close)..."
	strace -e socket,sendto,close $(RAW_UDP)

.PHONY: trace-tcp
trace-tcp: $(RAW_TCP)
	@echo "Tracing TCP syscalls (socket, bind, listen, close)..."
	strace -e socket,bind,listen,close $(RAW_TCP)

.PHONY: trace-memory
trace-memory: $(MEMORY)
	@echo "Tracing memory syscalls (mmap, madvise, munmap)..."
	strace -e mmap,madvise,munmap $(MEMORY)

# Help target
.PHONY: help
help:
	@echo "Experimental Low-Level Networking - Makefile"
	@echo "============================================="
	@echo ""
	@echo "Targets:"
	@echo "  make              - Build all examples"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make test         - Build and run all examples"
	@echo "  make trace-udp    - Run UDP example with strace"
	@echo "  make trace-tcp    - Run TCP example with strace"
	@echo "  make trace-memory - Run memory example with strace"
	@echo "  make help         - Show this help"
	@echo ""
	@echo "Individual builds:"
	@echo "  make $(RAW_UDP)"
	@echo "  make $(RAW_TCP)"
	@echo "  make $(MEMORY)"
	@echo ""
	@echo "Learning order:"
	@echo "  1. $(RAW_UDP)    - Simplest (UDP + syscalls)"
	@echo "  2. $(MEMORY)     - Memory management"
	@echo "  3. $(RAW_TCP)    - Complex (TCP state machine)"
