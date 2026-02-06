# OpenSSL in C - Comprehensive Guide for ONVIF Authentication

## Table of Contents
1. [Introduction to OpenSSL](#introduction-to-openssl)
2. [Why OpenSSL for ONVIF?](#why-openssl-for-onvif)
3. [Installation and Setup](#installation-and-setup)
4. [Core OpenSSL Concepts](#core-openssl-concepts)
5. [EVP Digest API](#evp-digest-api)
6. [Hash Functions Deep Dive](#hash-functions-deep-dive)
7. [BIO System](#bio-system)
8. [Base64 Encoding/Decoding](#base64-encodingdecoding)
9. [ONVIF-Specific Implementations](#onvif-specific-implementations)
10. [Best Practices](#best-practices)
11. [Common Pitfalls](#common-pitfalls)
12. [Performance Optimization](#performance-optimization)
13. [Security Considerations](#security-considerations)

## Introduction to OpenSSL

**OpenSSL** is a robust, commercial-grade, full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols. It also provides a general-purpose cryptography library.

### What is OpenSSL?

```
┌─────────────────────────────────────┐
│         OpenSSL Library             │
├─────────────────────────────────────┤
│  • Cryptographic Functions          │
│    - Hash: MD5, SHA-1, SHA-256, etc │
│    - Symmetric: AES, DES, etc       │
│    - Asymmetric: RSA, ECC, etc      │
│  • SSL/TLS Implementation           │
│  • Certificate Management           │
│  • Random Number Generation         │
│  • Base64 Encoding/Decoding         │
│  • Many more utilities              │
└─────────────────────────────────────┘
```

### Key Features

✅ **Industry Standard**: Used by millions of applications
✅ **Peer-Reviewed**: Security audited by experts
✅ **Hardware Acceleration**: Supports CPU crypto extensions
✅ **Cross-Platform**: Works on Linux, Windows, macOS, etc.
✅ **Open Source**: Free to use, well-documented
✅ **FIPS Compliance**: Meets government security standards

## Why OpenSSL for ONVIF?

ONVIF authentication requires several cryptographic operations:

### 1. HTTP Digest Authentication
- **MD5 hashing**: For computing HA1, HA2, and response
- **MD5-sess**: Session-based MD5 variant
- **Hex encoding**: Converting binary hashes to hexadecimal

### 2. WS-UsernameToken Authentication
- **SHA-1 hashing**: For password digest computation
- **Base64 encoding/decoding**: For nonce and password digest
- **Binary operations**: Handling raw nonce data

### 3. Secure Communication
- **TLS/SSL**: Encrypting ONVIF traffic (HTTPS)
- **Certificate validation**: Verifying server identity
- **Random number generation**: Creating nonces

### Why Not Implement Crypto Yourself?

❌ **DON'T:**
- Implement your own MD5/SHA-1
- Write custom Base64 encoder
- Create your own random number generator

✅ **DO:**
- Use OpenSSL (or another reputable library)
- Leverage hardware acceleration
- Benefit from security audits
- Avoid crypto implementation bugs

> **"Don't roll your own crypto!"** - Every security expert

## Installation and Setup

### Linux (Ubuntu/Debian)

```bash
# Install development libraries
sudo apt-get update
sudo apt-get install libssl-dev

# Check version
openssl version
# Output: OpenSSL 1.1.1f  31 Mar 2020 (or newer)
```

### Linux (RedHat/CentOS/Fedora)

```bash
sudo yum install openssl-devel
# or
sudo dnf install openssl-devel
```

### macOS

```bash
# Using Homebrew
brew install openssl

# Add to PATH (if needed)
export PATH="/usr/local/opt/openssl/bin:$PATH"
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

### Windows

1. Download from: https://slproweb.com/products/Win32OpenSSL.html
2. Install to `C:\OpenSSL-Win64\`
3. Add to Visual Studio project:
   ```
   Include Directories: C:\OpenSSL-Win64\include
   Library Directories: C:\OpenSSL-Win64\lib
   Linker Input: libssl.lib libcrypto.lib
   ```

### Compilation

```bash
# Simple compilation
gcc -o myprogram myprogram.c -lssl -lcrypto

# With optimization
gcc -O2 -o myprogram myprogram.c -lssl -lcrypto

# With debugging symbols
gcc -g -o myprogram myprogram.c -lssl -lcrypto

# Full flags
gcc -Wall -Wextra -O2 -o myprogram myprogram.c -I/usr/include/openssl -L/usr/lib -lssl -lcrypto
```

### Verify Installation

```c
#include <stdio.h>
#include <openssl/opensslv.h>

int main() {
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    return 0;
}
```

```bash
gcc -o check_openssl check_openssl.c -lssl -lcrypto
./check_openssl
# Output: OpenSSL version: OpenSSL 1.1.1f  31 Mar 2020
```

## Core OpenSSL Concepts

### 1. The EVP Interface

**EVP** = **En**elope = High-level cryptographic interface

```
┌─────────────────────────────────────┐
│     Application Code                │
├─────────────────────────────────────┤
│  EVP Interface (High-Level)         │  ← Use this!
│  • Algorithm-independent            │
│  • Easy to switch algorithms        │
├─────────────────────────────────────┤
│  Low-Level Algorithms               │  ← Don't use directly
│  • MD5_Init, SHA1_Init, etc.        │
│  • Harder to maintain               │
└─────────────────────────────────────┘
```

### Why Use EVP?

✅ **Algorithm Independence**: Easy to switch from MD5 to SHA-256
✅ **Hardware Acceleration**: Automatically uses CPU extensions
✅ **Future-Proof**: New algorithms added to EVP interface
✅ **Recommended**: Official OpenSSL documentation recommends EVP

### 2. Contexts (CTX)

Most OpenSSL operations use **contexts** to maintain state:

```c
EVP_MD_CTX *ctx = EVP_MD_CTX_new();  // Create
// ... use context ...
EVP_MD_CTX_free(ctx);                 // Free (IMPORTANT!)
```

**Why contexts?**
- Maintain state across multiple operations
- Thread-safe when each thread has own context
- Can be reused (with reset) for efficiency

### 3. Message Digests (Hashes)

OpenSSL provides many hash algorithms:

```c
const EVP_MD *EVP_md5();        // MD5 (16 bytes)
const EVP_MD *EVP_sha1();       // SHA-1 (20 bytes)
const EVP_MD *EVP_sha224();     // SHA-224 (28 bytes)
const EVP_MD *EVP_sha256();     // SHA-256 (32 bytes)
const EVP_MD *EVP_sha384();     // SHA-384 (48 bytes)
const EVP_MD *EVP_sha512();     // SHA-512 (64 bytes)
```

### 4. BIO (Binary I/O)

BIO is OpenSSL's I/O abstraction:

```c
BIO *bio = BIO_new(BIO_s_file());     // File BIO
BIO *bio = BIO_new(BIO_s_mem());      // Memory BIO
BIO *bio = BIO_new(BIO_f_base64());   // Base64 filter BIO
BIO *bio = BIO_new(BIO_s_socket());   // Socket BIO
```

**BIO Chains**: Connect multiple BIOs for data transformation

```
Data → [Base64 BIO] → [Memory BIO] → Output
```

## EVP Digest API

### Basic Digest Workflow

```c
#include <openssl/evp.h>

void compute_hash_example() {
    // 1. Create context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    
    // 2. Initialize with algorithm
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    
    // 3. Feed data (can call multiple times)
    EVP_DigestUpdate(ctx, "Hello", 5);
    EVP_DigestUpdate(ctx, "World", 5);
    
    // 4. Finalize and get hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    
    // 5. Free context
    EVP_MD_CTX_free(ctx);
    
    // hash now contains MD5("HelloWorld")
}
```

### API Functions Explained

#### EVP_MD_CTX_new()
```c
EVP_MD_CTX *EVP_MD_CTX_new(void);
```
- **Purpose**: Allocate new context
- **Returns**: Pointer to context, or NULL on error
- **Must**: Call `EVP_MD_CTX_free()` when done

#### EVP_DigestInit_ex()
```c
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
```
- **Purpose**: Initialize digest context
- **Parameters**:
  - `ctx`: Context to initialize
  - `type`: Hash algorithm (EVP_md5(), EVP_sha1(), etc.)
  - `impl`: Engine to use (usually NULL)
- **Returns**: 1 on success, 0 on error

#### EVP_DigestUpdate()
```c
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
```
- **Purpose**: Feed data to hash
- **Parameters**:
  - `ctx`: Context
  - `d`: Data pointer
  - `cnt`: Data length in bytes
- **Can**: Call multiple times to hash data incrementally

#### EVP_DigestFinal_ex()
```c
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
```
- **Purpose**: Finalize hash and get result
- **Parameters**:
  - `ctx`: Context
  - `md`: Output buffer (at least EVP_MAX_MD_SIZE bytes)
  - `s`: Pointer to receive actual hash length
- **Note**: Context is invalid after this; use `EVP_MD_CTX_reset()` to reuse

#### EVP_MD_CTX_reset()
```c
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
```
- **Purpose**: Reset context for reuse
- **Use**: When you want to compute another hash with same context

#### EVP_MD_CTX_free()
```c
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
```
- **Purpose**: Free context and all associated memory
- **Critical**: Always call this to prevent memory leaks!

### Complete Example: MD5 Hash

```c
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

void compute_md5(const char *input) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return;
    }
    
    // Initialize for MD5
    if (!EVP_DigestInit_ex(ctx, EVP_md5(), NULL)) {
        fprintf(stderr, "Failed to initialize MD5\n");
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    // Hash the input
    if (!EVP_DigestUpdate(ctx, input, strlen(input))) {
        fprintf(stderr, "Failed to update digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    // Get the hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        fprintf(stderr, "Failed to finalize digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    // Print as hex
    printf("MD5(\"%s\") = ", input);
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    EVP_MD_CTX_free(ctx);
}

int main() {
    compute_md5("Hello World");
    // Output: MD5("Hello World") = b10a8db164e0754105b7a99be72e3fe5
    return 0;
}
```

## Hash Functions Deep Dive

### MD5 (Message Digest 5)

```c
const EVP_MD *EVP_md5(void);
```

**Specifications:**
- Output: 128 bits (16 bytes)
- Speed: Very fast
- Security: **BROKEN** (collision attacks exist)

**Use Cases:**
- ✅ HTTP Digest authentication (legacy)
- ✅ Checksums (non-security)
- ❌ Password hashing (use bcrypt/Argon2)
- ❌ Digital signatures (use SHA-256+)

**Example:**
```c
unsigned char md5_hash[16];
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
EVP_DigestUpdate(ctx, "data", 4);
unsigned int len;
EVP_DigestFinal_ex(ctx, md5_hash, &len);
EVP_MD_CTX_free(ctx);
// len = 16
```

**Converting to Hex String:**
```c
char hex[33];
for (int i = 0; i < 16; i++) {
    sprintf(&hex[i*2], "%02x", md5_hash[i]);
}
hex[32] = '\0';
```

### SHA-1 (Secure Hash Algorithm 1)

```c
const EVP_MD *EVP_sha1(void);
```

**Specifications:**
- Output: 160 bits (20 bytes)
- Speed: Fast
- Security: **DEPRECATED** (collision attacks demonstrated)

**Use Cases:**
- ✅ WS-UsernameToken (ONVIF specification)
- ✅ Legacy systems
- ❌ New applications (use SHA-256+)
- ❌ Certificate signing (use SHA-256+)

**Example:**
```c
unsigned char sha1_hash[20];
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
EVP_DigestUpdate(ctx, "data", 4);
unsigned int len;
EVP_DigestFinal_ex(ctx, sha1_hash, &len);
EVP_MD_CTX_free(ctx);
// len = 20
```

### SHA-256 (Secure Hash Algorithm 256)

```c
const EVP_MD *EVP_sha256(void);
```

**Specifications:**
- Output: 256 bits (32 bytes)
- Speed: Fast (with hardware acceleration)
- Security: **SECURE** (no practical attacks)

**Use Cases:**
- ✅ Modern authentication
- ✅ Password hashing (with proper salting)
- ✅ Digital signatures
- ✅ Blockchain

**Example:**
```c
unsigned char sha256_hash[32];
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
EVP_DigestUpdate(ctx, "data", 4);
unsigned int len;
EVP_DigestFinal_ex(ctx, sha256_hash, &len);
EVP_MD_CTX_free(ctx);
// len = 32
```

### Hash Comparison Table

| Algorithm | Output Size | Speed | Security Status | ONVIF Usage |
|-----------|-------------|-------|----------------|-------------|
| MD5 | 16 bytes | ⚡⚡⚡ | ❌ Broken | HTTP Digest |
| SHA-1 | 20 bytes | ⚡⚡ | ⚠️ Deprecated | WS-UsernameToken |
| SHA-224 | 28 bytes | ⚡⚡ | ✅ Secure | Not used |
| SHA-256 | 32 bytes | ⚡⚡ | ✅ Secure | Recommended |
| SHA-384 | 48 bytes | ⚡ | ✅ Secure | Not used |
| SHA-512 | 64 bytes | ⚡ | ✅ Secure | Not used |

### Multi-Part Hashing

Hash data incrementally:

```c
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

// Hash data in chunks
EVP_DigestUpdate(ctx, "Part 1", 6);
EVP_DigestUpdate(ctx, "Part 2", 6);
EVP_DigestUpdate(ctx, "Part 3", 6);

unsigned char hash[32];
unsigned int len;
EVP_DigestFinal_ex(ctx, hash, &len);
EVP_MD_CTX_free(ctx);

// Same as hashing "Part 1Part 2Part 3" at once
```

**Use Cases:**
- Hashing large files (read chunks)
- Streaming data
- Network packets

### Reusing Contexts

```c
EVP_MD_CTX *ctx = EVP_MD_CTX_new();

// Compute hash 1
EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
EVP_DigestUpdate(ctx, "data1", 5);
unsigned char hash1[16];
unsigned int len1;
EVP_DigestFinal_ex(ctx, hash1, &len1);

// Reset and compute hash 2
EVP_MD_CTX_reset(ctx);  // Reuse same context
EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
EVP_DigestUpdate(ctx, "data2", 5);
unsigned char hash2[16];
unsigned int len2;
EVP_DigestFinal_ex(ctx, hash2, &len2);

EVP_MD_CTX_free(ctx);
```

## BIO System

### What is BIO?

**BIO** = **B**inary **I/O**

BIO is OpenSSL's I/O abstraction layer:
- Unified interface for different I/O types
- Support for filters (transformations)
- Chainable for complex operations

### BIO Types

#### Source/Sink BIOs

```c
// Memory BIO (buffer in memory)
BIO *bio = BIO_new(BIO_s_mem());

// File BIO
BIO *bio = BIO_new_file("file.txt", "r");
BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

// Socket BIO
BIO *bio = BIO_new_socket(socket_fd, BIO_CLOSE);

// String BIO (read-only memory)
BIO *bio = BIO_new_mem_buf("data", 4);
```

#### Filter BIOs

```c
// Base64 encoding/decoding
BIO *bio = BIO_new(BIO_f_base64());

// Cipher (encryption/decryption)
BIO *bio = BIO_new(BIO_f_cipher());

// Message digest
BIO *bio = BIO_new(BIO_f_md());

// Buffering
BIO *bio = BIO_new(BIO_f_buffer());
```

### BIO Chains

Connect BIOs to create data pipelines:

```
┌──────────┐    ┌───────────┐    ┌───────────┐
│  Input   │ -> │  Filter   │ -> │  Output   │
│   BIO    │    │    BIO    │    │    BIO    │
└──────────┘    └───────────┘    └───────────┘
```

**Example: Base64 Encoding**
```
Data → [Base64 Filter] → [Memory Buffer] → Encoded Result
```

```c
// Create chain
BIO *b64 = BIO_new(BIO_f_base64());
BIO *mem = BIO_new(BIO_s_mem());
BIO_push(b64, mem);  // Chain them

// Write data (automatically Base64 encoded)
BIO_write(b64, "Hello", 5);
BIO_flush(b64);

// Get encoded result
BUF_MEM *bptr;
BIO_get_mem_ptr(b64, &bptr);
// bptr->data contains Base64-encoded data

BIO_free_all(b64);  // Frees both BIOs
```

### BIO Operations

#### Create and Free

```c
// Create
BIO *bio = BIO_new(BIO_s_mem());

// Free
BIO_free(bio);

// Free chain (all BIOs in chain)
BIO_free_all(bio);
```

#### Read and Write

```c
// Write
int written = BIO_write(bio, "data", 4);

// Read
char buffer[1024];
int read = BIO_read(bio, buffer, sizeof(buffer));

// Flush
BIO_flush(bio);
```

#### Chain Management

```c
// Push (add to chain)
BIO *chain = BIO_push(bio1, bio2);

// Pop (remove from chain)
BIO *popped = BIO_pop(bio);
```

## Base64 Encoding/Decoding

### Why Base64?

Base64 encodes binary data as ASCII text:
- **Use Case**: Transmit binary data over text protocols (HTTP, XML)
- **Encoding**: 3 bytes → 4 ASCII characters
- **Overhead**: ~33% size increase

### Base64 Encoding with BIO

```c
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>

void base64_encode(const unsigned char *input, int input_len, char *output) {
    // Create Base64 filter BIO
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    
    // Create memory BIO
    BIO *mem = BIO_new(BIO_s_mem());
    
    // Chain: b64 → mem
    BIO_push(b64, mem);
    
    // Write data (automatically encoded)
    BIO_write(b64, input, input_len);
    BIO_flush(b64);
    
    // Get encoded result
    BUF_MEM *buffer_ptr;
    BIO_get_mem_ptr(b64, &buffer_ptr);
    
    // Copy to output
    memcpy(output, buffer_ptr->data, buffer_ptr->length);
    output[buffer_ptr->length] = '\0';
    
    // Cleanup
    BIO_free_all(b64);
}

int main() {
    unsigned char data[] = "Hello World";
    char encoded[64];
    base64_encode(data, strlen((char*)data), encoded);
    printf("Encoded: %s\n", encoded);
    // Output: SGVsbG8gV29ybGQ=
    return 0;
}
```

### Base64 Decoding with BIO

```c
int base64_decode(const char *input, int input_len, unsigned char *output) {
    // Create Base64 filter BIO
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    // Create memory BIO with input data
    BIO *mem = BIO_new_mem_buf(input, input_len);
    
    // Chain: b64 → mem
    BIO_push(b64, mem);
    
    // Read decoded data
    int decoded_len = BIO_read(b64, output, input_len);
    
    // Cleanup
    BIO_free_all(b64);
    
    return decoded_len;
}

int main() {
    char encoded[] = "SGVsbG8gV29ybGQ=";
    unsigned char decoded[64];
    int len = base64_decode(encoded, strlen(encoded), decoded);
    decoded[len] = '\0';
    printf("Decoded: %s\n", decoded);
    // Output: Hello World
    return 0;
}
```

### Important BIO Flags

```c
// No newlines in Base64 output (important!)
BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

// With newlines (default, usually NOT wanted)
// Results in:
// SGVs
// bG8g
// V29y
// bGQ=
```

### Common Base64 Pitfalls

❌ **Forgetting BIO_FLAGS_BASE64_NO_NL**
```c
BIO *b64 = BIO_new(BIO_f_base64());
// Missing: BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
// Result: Output has newlines every 64 chars!
```

❌ **Not null-terminating output**
```c
base64_encode(data, len, output);
// Missing: output[result_len] = '\0';
// Result: String not null-terminated!
```

❌ **Buffer too small**
```c
char output[10];  // Too small!
base64_encode(long_data, 100, output);  // Buffer overflow!

// Correct size: (input_len * 4 / 3) + 4
```

## ONVIF-Specific Implementations

### HTTP Digest: Computing HA1

```c
void compute_ha1(const char *username, const char *realm, 
                 const char *password, char *ha1_hex) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[16];  // MD5 = 16 bytes
    unsigned int len;
    
    // Compute MD5(username:realm:password)
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, username, strlen(username));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, realm, strlen(realm));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    
    // Convert to hex
    for (int i = 0; i < 16; i++) {
        sprintf(&ha1_hex[i*2], "%02x", hash[i]);
    }
    ha1_hex[32] = '\0';
}

// Example usage
char ha1[33];
compute_ha1("admin", "ONVIF_Device", "password123", ha1);
printf("HA1: %s\n", ha1);
```

### HTTP Digest: Computing Response

```c
void compute_response(const char *ha1, const char *nonce,
                      const char *nc, const char *cnonce,
                      const char *qop, const char *ha2,
                      char *response_hex) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[16];
    unsigned int len;
    
    // Compute MD5(HA1:nonce:nc:cnonce:qop:HA2)
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, ha1, 32);
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, nonce, strlen(nonce));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, nc, strlen(nc));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, cnonce, strlen(cnonce));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, qop, strlen(qop));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, ha2, 32);
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    
    // Convert to hex
    for (int i = 0; i < 16; i++) {
        sprintf(&response_hex[i*2], "%02x", hash[i]);
    }
    response_hex[32] = '\0';
}
```

### WS-UsernameToken: Computing Password Digest

```c
void compute_ws_password_digest(const unsigned char *nonce_raw, int nonce_len,
                                const char *created, const char *password,
                                char *digest_b64) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char sha1_hash[20];  // SHA-1 = 20 bytes
    unsigned int len;
    
    // Compute SHA1(nonce + created + password)
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, nonce_raw, nonce_len);
    EVP_DigestUpdate(ctx, created, strlen(created));
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, sha1_hash, &len);
    EVP_MD_CTX_free(ctx);
    
    // Base64 encode
    base64_encode(sha1_hash, 20, digest_b64);
}

// Example usage
unsigned char nonce_raw[16] = {0x01, 0x02, ...};  // 16 random bytes
char created[] = "2024-01-31T10:15:30Z";
char password[] = "password123";
char digest[64];

compute_ws_password_digest(nonce_raw, 16, created, password, digest);
printf("Password Digest: %s\n", digest);
```

### Generating Random Nonce

```c
#include <openssl/rand.h>

void generate_random_nonce(unsigned char *nonce, int nonce_len) {
    // Generate cryptographically secure random bytes
    if (RAND_bytes(nonce, nonce_len) != 1) {
        fprintf(stderr, "Failed to generate random nonce\n");
        // Fallback or error handling
    }
}

// Usage
unsigned char nonce[16];
generate_random_nonce(nonce, 16);

// Convert to Base64 for transmission
char nonce_b64[64];
base64_encode(nonce, 16, nonce_b64);
```

## Best Practices

### 1. Always Check Return Values

```c
// ❌ Bad
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

// ✓ Good
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
if (!ctx) {
    fprintf(stderr, "Failed to create context\n");
    return -1;
}

if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
    fprintf(stderr, "Failed to initialize digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
}
```

### 2. Free Resources

```c
// ❌ Memory leak
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
// ... use context ...
return;  // Forgot to free!

// ✓ Always free
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
// ... use context ...
EVP_MD_CTX_free(ctx);  // Always!
```

### 3. Use EVP_MAX_MD_SIZE

```c
// ✓ Safe - works for any hash algorithm
unsigned char hash[EVP_MAX_MD_SIZE];
unsigned int hash_len;
EVP_DigestFinal_ex(ctx, hash, &hash_len);

// ❌ Unsafe - what if algorithm changes?
unsigned char hash[16];  // Assumes MD5!
```

### 4. Zero Sensitive Data

```c
char password[64];
// ... use password ...

// Zero before freeing
memset(password, 0, sizeof(password));
```

### 5. Use Constant-Time Comparison

```c
#include <openssl/crypto.h>

// ✓ Constant-time comparison (prevents timing attacks)
if (CRYPTO_memcmp(computed_hash, received_hash, 16) == 0) {
    // Valid
}

// ❌ Variable-time (vulnerable to timing attacks)
if (memcmp(computed_hash, received_hash, 16) == 0) {
    // Valid
}
```

### 6. Initialize OpenSSL (OpenSSL 1.0.x)

```c
// OpenSSL 1.0.x requires initialization
#include <openssl/ssl.h>

SSL_library_init();
SSL_load_error_strings();
OpenSSL_add_all_algorithms();

// OpenSSL 1.1.0+ initializes automatically
// No initialization needed!
```

## Common Pitfalls

### 1. Not Linking OpenSSL Libraries

```bash
# ❌ Error: undefined reference to EVP_MD_CTX_new
gcc -o program program.c

# ✓ Correct
gcc -o program program.c -lssl -lcrypto
```

### 2. Using Deprecated Functions

```c
// ❌ Deprecated (OpenSSL 1.0.x)
MD5_Init(&ctx);
MD5_Update(&ctx, data, len);
MD5_Final(hash, &ctx);

// ✓ Modern EVP API
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
EVP_DigestUpdate(ctx, data, len);
EVP_DigestFinal_ex(ctx, hash, &len);
EVP_MD_CTX_free(ctx);
```

### 3. Buffer Overflows

```c
// ❌ Potential overflow
char output[10];
base64_encode(long_input, 100, output);

// ✓ Correctly sized
int output_len = (input_len * 4 / 3) + 4;
char *output = malloc(output_len);
base64_encode(input, input_len, output);
free(output);
```

### 4. Not Handling Errors

```c
// ❌ Ignoring errors
int len = base64_decode(input, input_len, output);
output[len] = '\0';  // What if len is -1 (error)?

// ✓ Check for errors
int len = base64_decode(input, input_len, output);
if (len < 0) {
    fprintf(stderr, "Base64 decode failed\n");
    return -1;
}
output[len] = '\0';
```

### 5. Thread Safety

```c
// ❌ Sharing context across threads
EVP_MD_CTX *global_ctx;  // Shared!

void thread_function() {
    EVP_DigestUpdate(global_ctx, data, len);  // Race condition!
}

// ✓ Each thread has own context
void thread_function() {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestUpdate(ctx, data, len);
    EVP_MD_CTX_free(ctx);
}
```

## Performance Optimization

### 1. Reuse Contexts

```c
// ❌ Slow: Creating/destroying repeatedly
for (int i = 0; i < 1000; i++) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    // ... compute hash ...
    EVP_MD_CTX_free(ctx);
}

// ✓ Fast: Reuse context
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
for (int i = 0; i < 1000; i++) {
    EVP_MD_CTX_reset(ctx);
    // ... compute hash ...
}
EVP_MD_CTX_free(ctx);
```

### 2. Use Hardware Acceleration

```c
// OpenSSL automatically uses CPU extensions when available:
// - AES-NI (AES encryption)
// - SHA extensions
// - AVX/AVX2

// Check if hardware acceleration is available
#include <openssl/engine.h>

ENGINE_load_builtin_engines();
ENGINE *e = ENGINE_by_id("aesni");
if (e) {
    printf("AES-NI acceleration available\n");
    ENGINE_free(e);
}
```

### 3. Minimize Allocations

```c
// ✓ Stack allocation for small buffers
unsigned char hash[EVP_MAX_MD_SIZE];

// ✓ Pool allocation for frequent operations
typedef struct {
    EVP_MD_CTX *ctx;
    unsigned char buffer[4096];
} HashContext;

HashContext pool[10];
// Initialize pool once, reuse many times
```

## Security Considerations

### 1. Use Strong Algorithms

```c
// ❌ MD5 for security
EVP_md5()  // Broken, don't use for new applications

// ✓ SHA-256 or better
EVP_sha256()
EVP_sha384()
EVP_sha512()
```

### 2. Secure Random Numbers

```c
// ❌ Weak randomness
srand(time(NULL));
int random = rand();

// ✓ Cryptographically secure
unsigned char random_bytes[32];
RAND_bytes(random_bytes, 32);
```

### 3. Constant-Time Operations

```c
// Prevent timing attacks
#include <openssl/crypto.h>

if (CRYPTO_memcmp(hash1, hash2, hash_len) == 0) {
    // Valid
}
```

### 4. Clear Sensitive Data

```c
char password[64];
get_password(password);
// ... use password ...
OPENSSL_cleanse(password, sizeof(password));  // Secure clear
```

### 5. Validate All Inputs

```c
// Check buffer sizes
if (input_len > MAX_INPUT_LEN) {
    return ERROR_TOO_LARGE;
}

// Validate Base64
if (!is_valid_base64(input)) {
    return ERROR_INVALID_FORMAT;
}
```

## Debugging OpenSSL

### Enable Error Messages

```c
#include <openssl/err.h>

void print_openssl_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "OpenSSL Error: %s\n", err_buf);
    }
}

// Usage
if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
    print_openssl_errors();
}
```

### Check OpenSSL Version

```c
printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
printf("Built on: %s\n", OpenSSL_version(OPENSSL_BUILT_ON));
printf("Platform: %s\n", OpenSSL_version(OPENSSL_PLATFORM));
```

## Complete Example: ONVIF Authentication

```c
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Base64 encode (from auth_utils.h)
void base64_encode(const unsigned char *in, int in_len, char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_write(b64, in, in_len);
    BIO_flush(b64);
    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);
    memcpy(out, bufferPtr->data, bufferPtr->length);
    out[bufferPtr->length] = '\0';
    BIO_free_all(b64);
}

// Compute HTTP Digest HA1
void compute_digest_ha1(const char *user, const char *realm, const char *pass, char *ha1) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[16];
    unsigned int len;
    
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, user, strlen(user));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, realm, strlen(realm));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, pass, strlen(pass));
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    
    for (int i = 0; i < 16; i++) {
        sprintf(&ha1[i*2], "%02x", hash[i]);
    }
    ha1[32] = '\0';
}

int main() {
    // Example: Compute HTTP Digest HA1
    char ha1[33];
    compute_digest_ha1("admin", "ONVIF_Device", "password123", ha1);
    printf("HTTP Digest HA1: %s\n", ha1);
    
    // Example: Compute WS-Security password digest
    unsigned char nonce[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const char *created = "2024-01-31T10:15:30Z";
    const char *password = "password123";
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char sha1_hash[20];
    unsigned int len;
    
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, nonce, 16);
    EVP_DigestUpdate(ctx, created, strlen(created));
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, sha1_hash, &len);
    EVP_MD_CTX_free(ctx);
    
    char digest_b64[64];
    base64_encode(sha1_hash, 20, digest_b64);
    printf("WS-Security Password Digest: %s\n", digest_b64);
    
    return 0;
}
```

```bash
# Compile
gcc -o onvif_auth onvif_auth.c -lssl -lcrypto

# Run
./onvif_auth
```

## Conclusion

OpenSSL is essential for ONVIF authentication:

✅ **Production-grade cryptography**
✅ **Hardware acceleration**
✅ **Well-tested and audited**
✅ **Easy to use with EVP API**
✅ **Cross-platform support**

**Key Takeaways:**
1. Always use EVP API (not low-level functions)
2. Check return values and handle errors
3. Free all allocated resources
4. Use secure random numbers (RAND_bytes)
5. Clear sensitive data after use
6. Link with `-lssl -lcrypto`

For ONVIF-specific usage, see:
- README_ONVIF_AUTHENTICATION.md
- README_AUTH_UTILS.md
- README_HTTP_HEADERS.md

## Further Reading

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [OpenSSL Wiki](https://wiki.openssl.org/)
- [EVP API Guide](https://wiki.openssl.org/index.php/EVP)
- [OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/)
