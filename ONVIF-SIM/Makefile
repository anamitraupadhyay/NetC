# Makefile for ONVIF authentication example

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
LDFLAGS = -lssl -lcrypto

# Source files
AUTH_SRC = auth.c
AUTH_EXAMPLE_SRC = auth_example.c

# Object files
AUTH_OBJ = $(AUTH_SRC:.c=.o)
AUTH_EXAMPLE_OBJ = $(AUTH_EXAMPLE_SRC:.c=.o)

# Executables
AUTH_EXAMPLE = auth_example

# Default target
all: $(AUTH_EXAMPLE)

# Build authentication example
$(AUTH_EXAMPLE): $(AUTH_OBJ) $(AUTH_EXAMPLE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(AUTH_OBJ) $(AUTH_EXAMPLE_OBJ) $(AUTH_EXAMPLE)

# Run the example
run: $(AUTH_EXAMPLE)
	./$(AUTH_EXAMPLE)

.PHONY: all clean run
