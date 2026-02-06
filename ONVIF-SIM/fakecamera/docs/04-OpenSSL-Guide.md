# OpenSSL Library Guide for C Developers

> A comprehensive guide to using OpenSSL for cryptographic operations in ONVIF authentication

## Table of Contents

1. [Introduction to OpenSSL](#introduction-to-openssl)
2. [Installation and Setup](#installation-and-setup)
3. [Core Concepts](#core-concepts)
4. [Message Digests (Hashing)](#message-digests-hashing)
5. [Base64 Encoding/Decoding](#base64-encodingdecoding)
6. [EVP API (Recommended)](#evp-api-recommended)
7. [Memory Management](#memory-management)
8. [Complete Examples](#complete-examples)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)

---

## Introduction to OpenSSL

OpenSSL is a robust, full-featured open-source toolkit implementing the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols, as well as a general-purpose cryptography library.

### Why OpenSSL for ONVIF?

| Feature | Use in ONVIF |
|---------|--------------|
| MD5 hashing | HTTP Digest Authentication |
| SHA-1 hashing | WS-UsernameToken |
| Base64 encoding | Nonce and digest encoding |
| Random generation | Nonce creation |

### OpenSSL Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      OpenSSL Library                           │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    EVP (Envelope)                        │  │
│  │        High-level interface to cryptographic operations  │  │
│  │                                                          │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │  │
│  │  │  Digest  │ │  Cipher  │ │  Sign    │ │  Verify  │    │  │
│  │  │  (Hash)  │ │  (Enc)   │ │          │ │          │    │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                       BIO (I/O)                          │  │
│  │            Abstraction for I/O operations                │  │
│  │                                                          │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │  │
│  │  │  Memory  │ │  File    │ │  Socket  │ │  Base64  │    │  │
│  │  │  Buffer  │ │          │ │          │ │  Filter  │    │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Low-level Algorithm Libraries               │  │
│  │                                                          │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │  │
│  │  │   MD5    │ │  SHA1    │ │   AES    │ │   RSA    │    │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Installation and Setup

### Ubuntu/Debian

```bash
# Install OpenSSL development package
sudo apt-get update
sudo apt-get install libssl-dev

# Verify installation
openssl version
pkg-config --cflags --libs openssl
```

### Fedora/RHEL/CentOS

```bash
sudo dnf install openssl-devel
# or
sudo yum install openssl-devel
```

### macOS

```bash
# Using Homebrew
brew install openssl

# Set environment variables
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

### Compilation

```bash
# Basic compilation
gcc -o program program.c -lssl -lcrypto

# With all warnings and debugging
gcc -Wall -Wextra -g -o program program.c -lssl -lcrypto

# Using pkg-config
gcc -o program program.c $(pkg-config --cflags --libs openssl)
```

### Required Headers

```c
// Main OpenSSL headers for our purposes
#include <openssl/evp.h>      // EVP (high-level) API
#include <openssl/bio.h>      // BIO (I/O abstraction)
#include <openssl/buffer.h>   // Buffer management
#include <openssl/md5.h>      // MD5 (deprecated, use EVP)
#include <openssl/sha.h>      // SHA (deprecated, use EVP)
#include <openssl/rand.h>     // Random number generation
```

---

## Core Concepts

### The EVP Interface

EVP (Envelope) is the recommended high-level interface for all cryptographic operations:

- **Algorithm-agnostic** - Same API for MD5, SHA-1, SHA-256, etc.
- **Future-proof** - Easy to switch algorithms
- **Consistent** - Same pattern for all operations

### The BIO Interface

BIO (Basic I/O) provides an abstraction for I/O operations:

- **Chainable** - Can stack filters (Base64 → Memory)
- **Flexible** - Works with files, memory, sockets
- **Reusable** - Common interface for different sources

### Context Objects

OpenSSL uses context objects to maintain state:

```c
EVP_MD_CTX *ctx;    // Message digest context
BIO *bio;           // BIO object
```

**Important:** Always free context objects to prevent memory leaks!

---

## Message Digests (Hashing)

### EVP Digest API Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    EVP Digest Workflow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. Create Context                                             │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  EVP_MD_CTX *ctx = EVP_MD_CTX_new();                    │  │
│   └─────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                          ▼                                      │
│   2. Initialize with Algorithm                                  │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  EVP_DigestInit_ex(ctx, EVP_md5(), NULL);               │  │
│   │  // or EVP_sha1(), EVP_sha256(), etc.                   │  │
│   └─────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                          ▼                                      │
│   3. Update with Data (can call multiple times)                 │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  EVP_DigestUpdate(ctx, data1, len1);                    │  │
│   │  EVP_DigestUpdate(ctx, data2, len2);                    │  │
│   │  EVP_DigestUpdate(ctx, data3, len3);                    │  │
│   └─────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                          ▼                                      │
│   4. Finalize and Get Result                                    │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  unsigned char hash[EVP_MAX_MD_SIZE];                   │  │
│   │  unsigned int len;                                      │  │
│   │  EVP_DigestFinal_ex(ctx, hash, &len);                   │  │
│   └─────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                          ▼                                      │
│   5. Free Context                                               │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  EVP_MD_CTX_free(ctx);                                  │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### MD5 Digest Example (HTTP Digest Auth)

```c
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

void compute_md5(const char *input, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;
    
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, input, strlen(input));
    EVP_DigestFinal_ex(ctx, output, &len);
    
    EVP_MD_CTX_free(ctx);
}

void md5_to_hex(unsigned char *md5, char *hex_output) {
    for (int i = 0; i < 16; i++) {
        sprintf(&hex_output[i * 2], "%02x", md5[i]);
    }
    hex_output[32] = '\0';
}

// Example usage for HTTP Digest HA1 = MD5(username:realm:password)
void compute_ha1(const char *user, const char *realm, const char *pass, 
                 char *ha1_hex) {
    char input[256];
    unsigned char md5_result[16];
    
    // Build "username:realm:password"
    snprintf(input, sizeof(input), "%s:%s:%s", user, realm, pass);
    
    // Compute MD5
    compute_md5(input, md5_result);
    
    // Convert to hex string
    md5_to_hex(md5_result, ha1_hex);
}
```

### SHA-1 Digest Example (WS-UsernameToken)

```c
#include <openssl/evp.h>

void compute_sha1_for_ws_auth(
    const unsigned char *nonce, int nonce_len,
    const char *created,
    const char *password,
    unsigned char *sha1_output
) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;
    
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    
    // Note: Order matters! nonce + created + password
    EVP_DigestUpdate(ctx, nonce, nonce_len);
    EVP_DigestUpdate(ctx, created, strlen(created));
    EVP_DigestUpdate(ctx, password, strlen(password));
    
    EVP_DigestFinal_ex(ctx, sha1_output, &len);
    
    EVP_MD_CTX_free(ctx);
}
```

### Reusing Context (for multiple calculations)

```c
void compute_multiple_hashes(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    
    // First hash
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, "first input", 11);
    EVP_DigestFinal_ex(ctx, hash, &len);
    // hash now contains MD5 of "first input"
    
    // Reset for second hash (important!)
    EVP_MD_CTX_reset(ctx);
    
    // Second hash
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, "second input", 12);
    EVP_DigestFinal_ex(ctx, hash, &len);
    // hash now contains MD5 of "second input"
    
    EVP_MD_CTX_free(ctx);
}
```

### Available Digest Algorithms

| Function | Algorithm | Output Size | Use Case |
|----------|-----------|-------------|----------|
| `EVP_md5()` | MD5 | 16 bytes | HTTP Digest Auth |
| `EVP_sha1()` | SHA-1 | 20 bytes | WS-UsernameToken |
| `EVP_sha256()` | SHA-256 | 32 bytes | Modern applications |
| `EVP_sha384()` | SHA-384 | 48 bytes | High security |
| `EVP_sha512()` | SHA-512 | 64 bytes | High security |

---

## Base64 Encoding/Decoding

### BIO-Based Base64 Operations

OpenSSL uses BIO chains for Base64:

```
┌────────────────────────────────────────────────────────────────┐
│                   BIO Chain for Base64                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│   Encoding:                                                    │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐                │
│   │  Binary  │───>│  Base64  │───>│  Memory  │                │
│   │   Data   │    │  Filter  │    │  Buffer  │                │
│   └──────────┘    └──────────┘    └──────────┘                │
│                                                                │
│   Decoding:                                                    │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐                │
│   │  Base64  │───>│  Base64  │───>│  Binary  │                │
│   │  String  │    │  Filter  │    │  Output  │                │
│   └──────────┘    └──────────┘    └──────────┘                │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Base64 Encode

```c
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>

void base64_encode(const unsigned char *input, int input_len, char *output) {
    // Create Base64 filter BIO
    BIO *b64 = BIO_new(BIO_f_base64());
    
    // Disable newlines (important for single-line output)
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    // Create memory BIO for output
    BIO *bio = BIO_new(BIO_s_mem());
    
    // Chain: b64 -> bio
    BIO_push(b64, bio);
    
    // Write data through the chain
    BIO_write(b64, input, input_len);
    BIO_flush(b64);
    
    // Get the output
    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);
    
    // Copy to output
    memcpy(output, bufferPtr->data, bufferPtr->length);
    output[bufferPtr->length] = '\0';
    
    // Free the entire chain
    BIO_free_all(b64);
}
```

### Base64 Decode

```c
int base64_decode(const char *input, int input_len, unsigned char *output) {
    // Create Base64 filter BIO
    BIO *b64 = BIO_new(BIO_f_base64());
    
    // Disable newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    // Create memory BIO with input data
    BIO *bio = BIO_new_mem_buf(input, input_len);
    
    // Chain: b64 <- bio
    bio = BIO_push(b64, bio);
    
    // Read decoded data
    int output_len = BIO_read(bio, output, input_len);
    
    // Free the chain
    BIO_free_all(bio);
    
    return output_len;
}
```

### Example Usage

```c
int main() {
    // Original binary data (could be hash output)
    unsigned char binary_data[] = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64
    };  // "Hello World"
    
    // Encode
    char encoded[100];
    base64_encode(binary_data, 11, encoded);
    printf("Encoded: %s\n", encoded);  // "SGVsbG8gV29ybGQ="
    
    // Decode
    unsigned char decoded[100];
    int decoded_len = base64_decode(encoded, strlen(encoded), decoded);
    decoded[decoded_len] = '\0';
    printf("Decoded: %s\n", decoded);  // "Hello World"
    
    return 0;
}
```

---

## EVP API (Recommended)

### Why Use EVP Instead of Direct Calls?

| Direct API (Deprecated) | EVP API (Recommended) |
|------------------------|------------------------|
| `MD5()` | `EVP_Digest()` with `EVP_md5()` |
| `SHA1()` | `EVP_Digest()` with `EVP_sha1()` |
| Algorithm-specific | Algorithm-agnostic |
| No error handling | Consistent error handling |
| May be removed | Long-term support |

### One-Shot Digest with EVP

```c
#include <openssl/evp.h>

int compute_digest_oneshot(
    const EVP_MD *type,      // EVP_md5(), EVP_sha1(), etc.
    const void *data,
    size_t data_len,
    unsigned char *output,
    unsigned int *output_len
) {
    return EVP_Digest(data, data_len, output, output_len, type, NULL);
}

// Usage
unsigned char hash[EVP_MAX_MD_SIZE];
unsigned int hash_len;
EVP_Digest("Hello", 5, hash, &hash_len, EVP_sha256(), NULL);
```

### Generic Digest Function

```c
// Generic digest function that works with any algorithm
void compute_digest(
    const EVP_MD *type,
    const void *d1, size_t l1,
    const void *d2, size_t l2,
    const void *d3, size_t l3,
    unsigned char *output
) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;
    
    EVP_DigestInit_ex(ctx, type, NULL);
    
    if (d1) EVP_DigestUpdate(ctx, d1, l1);
    if (d2) EVP_DigestUpdate(ctx, d2, l2);
    if (d3) EVP_DigestUpdate(ctx, d3, l3);
    
    EVP_DigestFinal_ex(ctx, output, &len);
    EVP_MD_CTX_free(ctx);
}

// Usage
unsigned char hash[20];
compute_digest(EVP_sha1(), nonce, 16, created, 20, password, 4, hash);
```

---

## Memory Management

### Critical Rules

1. **Always free what you allocate**
2. **Use matching free functions**
3. **Check for NULL before using**

### Memory Functions

| Allocate | Free | Purpose |
|----------|------|---------|
| `EVP_MD_CTX_new()` | `EVP_MD_CTX_free()` | Digest context |
| `BIO_new()` | `BIO_free()` | Single BIO |
| `BIO_push()` | `BIO_free_all()` | BIO chain |
| `OPENSSL_malloc()` | `OPENSSL_free()` | General memory |

### Safe Pattern

```c
int safe_hash_function(const char *input, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    
    if (ctx == NULL) {
        // Handle allocation failure
        return -1;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    unsigned int len;
    if (EVP_DigestFinal_ex(ctx, output, &len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    return (int)len;
}
```

---

## Complete Examples

### Example 1: HTTP Digest Authentication

```c
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void md5_hex(const char *input, char *output_hex) {
    unsigned char md5_result[16];
    unsigned int len;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, input, strlen(input));
    EVP_DigestFinal_ex(ctx, md5_result, &len);
    EVP_MD_CTX_free(ctx);
    
    for (int i = 0; i < 16; i++) {
        sprintf(&output_hex[i * 2], "%02x", md5_result[i]);
    }
    output_hex[32] = '\0';
}

char* compute_http_digest_response(
    const char *username,
    const char *realm,
    const char *password,
    const char *method,
    const char *uri,
    const char *nonce,
    const char *nc,
    const char *cnonce,
    const char *qop
) {
    static char response[33];
    char ha1[33], ha2[33];
    char input[512];
    
    // HA1 = MD5(username:realm:password)
    snprintf(input, sizeof(input), "%s:%s:%s", username, realm, password);
    md5_hex(input, ha1);
    
    // HA2 = MD5(method:uri)
    snprintf(input, sizeof(input), "%s:%s", method, uri);
    md5_hex(input, ha2);
    
    // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    snprintf(input, sizeof(input), "%s:%s:%s:%s:%s:%s",
             ha1, nonce, nc, cnonce, qop, ha2);
    md5_hex(input, response);
    
    return response;
}

int main() {
    char *response = compute_http_digest_response(
        "admin",           // username
        "ONVIF_Device",    // realm
        "pass",            // password
        "POST",            // method
        "/onvif/device",   // uri
        "abc123",          // nonce
        "00000001",        // nc
        "xyz789",          // cnonce
        "auth"             // qop
    );
    
    printf("Digest Response: %s\n", response);
    return 0;
}
```

### Example 2: WS-UsernameToken Verification

```c
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

int base64_decode(const char *in, int in_len, unsigned char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(in, in_len);
    bio = BIO_push(b64, bio);
    int out_len = BIO_read(bio, out, in_len);
    BIO_free_all(bio);
    return out_len;
}

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

bool verify_ws_usernametoken(
    const char *received_digest_b64,
    const char *nonce_b64,
    const char *created,
    const char *stored_password
) {
    // Decode nonce from Base64
    unsigned char nonce_raw[128];
    int nonce_len = base64_decode(nonce_b64, strlen(nonce_b64), nonce_raw);
    
    // Compute SHA-1(nonce + created + password)
    unsigned char sha1_result[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, nonce_raw, nonce_len);
    EVP_DigestUpdate(ctx, created, strlen(created));
    EVP_DigestUpdate(ctx, stored_password, strlen(stored_password));
    
    unsigned int len;
    EVP_DigestFinal_ex(ctx, sha1_result, &len);
    EVP_MD_CTX_free(ctx);
    
    // Base64 encode the result
    char computed_digest[128];
    base64_encode(sha1_result, 20, computed_digest);
    
    // Compare
    printf("Received: %s\n", received_digest_b64);
    printf("Computed: %s\n", computed_digest);
    
    return (strcmp(computed_digest, received_digest_b64) == 0);
}

int main() {
    // Test values
    const char *nonce_b64 = "YWJjZGVmZ2hpamtsbW5vcA==";
    const char *created = "2024-01-15T10:30:45Z";
    const char *password = "pass";
    
    // First, compute what the digest should be
    unsigned char nonce_raw[128];
    int nonce_len = base64_decode(nonce_b64, strlen(nonce_b64), nonce_raw);
    
    unsigned char sha1_result[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, nonce_raw, nonce_len);
    EVP_DigestUpdate(ctx, created, strlen(created));
    EVP_DigestUpdate(ctx, password, strlen(password));
    unsigned int len;
    EVP_DigestFinal_ex(ctx, sha1_result, &len);
    EVP_MD_CTX_free(ctx);
    
    char expected_digest[128];
    base64_encode(sha1_result, 20, expected_digest);
    
    // Now verify
    bool result = verify_ws_usernametoken(
        expected_digest,
        nonce_b64,
        created,
        password
    );
    
    printf("Verification: %s\n", result ? "PASSED" : "FAILED");
    return 0;
}
```

---

## Best Practices

### 1. Always Use EVP API

```c
// ❌ Deprecated
MD5((unsigned char*)data, len, hash);

// ✅ Recommended
EVP_Digest(data, len, hash, &hash_len, EVP_md5(), NULL);
```

### 2. Check Return Values

```c
// ❌ Ignoring errors
EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

// ✅ Checking errors
if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
    // Handle error
}
```

### 3. Free Resources

```c
// ❌ Memory leak
void bad_function() {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    // ... use ctx ...
    // Missing: EVP_MD_CTX_free(ctx);
}

// ✅ Proper cleanup
void good_function() {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    // ... use ctx ...
    EVP_MD_CTX_free(ctx);
}
```

### 4. Use Appropriate Buffer Sizes

```c
// ❌ Too small
unsigned char hash[16];  // Only works for MD5!

// ✅ Safe for any algorithm
unsigned char hash[EVP_MAX_MD_SIZE];  // 64 bytes
```

---

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `undefined reference to EVP_*` | Not linked with crypto | Add `-lcrypto` |
| `undefined reference to BIO_*` | Not linked with ssl | Add `-lssl -lcrypto` |
| Segmentation fault | NULL context | Check `EVP_MD_CTX_new()` return |
| Wrong hash output | Wrong algorithm | Verify `EVP_md5()` vs `EVP_sha1()` |
| Base64 has newlines | Default behavior | Use `BIO_FLAGS_BASE64_NO_NL` |

### Debug Tips

```c
// Print hash as hex
void print_hash(unsigned char *hash, int len) {
    printf("Hash: ");
    for (int i = 0; i < len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Check OpenSSL errors
#include <openssl/err.h>
void print_openssl_error() {
    ERR_print_errors_fp(stderr);
}
```

---

*Continue to [05-XML-SOAP-Formats.md](./05-XML-SOAP-Formats.md) →*
