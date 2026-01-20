# Makefile for ONVIF authentication example

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
LDFLAGS = -lssl -lcrypto

# Source files
AUTH_SRC = auth.c
AUTH_EXAMPLE_SRC = auth_example.c
INTEGRATION_EXAMPLE_SRC = integration_example.c

# Object files
AUTH_OBJ = $(AUTH_SRC:.c=.o)
AUTH_EXAMPLE_OBJ = $(AUTH_EXAMPLE_SRC:.c=.o)
INTEGRATION_EXAMPLE_OBJ = $(INTEGRATION_EXAMPLE_SRC:.c=.o)

# Executables
AUTH_EXAMPLE = auth_example
INTEGRATION_EXAMPLE = integration_example

# Default target
all: $(AUTH_EXAMPLE) $(INTEGRATION_EXAMPLE)

# Build authentication example
$(AUTH_EXAMPLE): $(AUTH_OBJ) $(AUTH_EXAMPLE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build integration example
$(INTEGRATION_EXAMPLE): $(AUTH_OBJ) $(INTEGRATION_EXAMPLE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(AUTH_OBJ) $(AUTH_EXAMPLE_OBJ) $(INTEGRATION_EXAMPLE_OBJ) $(AUTH_EXAMPLE) $(INTEGRATION_EXAMPLE)

# Run the basic example
run: $(AUTH_EXAMPLE)
	./$(AUTH_EXAMPLE)

# Run the integration example
run-integration: $(INTEGRATION_EXAMPLE)
	./$(INTEGRATION_EXAMPLE)

.PHONY: all clean run run-integration
