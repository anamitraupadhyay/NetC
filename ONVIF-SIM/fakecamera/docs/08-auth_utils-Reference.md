# auth_utils.h - Code Reference

> Complete reference documentation for the `authhandler/auth_utils.h` header file

## Table of Contents

1. [File Overview](#file-overview)
2. [Dependencies](#dependencies)
3. [Helper Functions](#helper-functions)
4. [Base64 Functions](#base64-functions)
5. [Credential Management](#credential-management)
6. [Extraction Functions](#extraction-functions)
7. [Verification Functions](#verification-functions)
8. [Utility Functions](#utility-functions)
9. [Usage Examples](#usage-examples)

---

## File Overview

The `authhandler/auth_utils.h` file provides the core authentication functionality for the ONVIF server. It implements both HTTP Digest and WS-UsernameToken verification.

### Location

```
ONVIF-SIM/fakecamera/
├── authhandler/
│   ├── auth_utils.h     <- This file
│   └── digest_auth.h    <- Nonce generation
├── auth_server.h        <- Uses auth_utils.h
└── main.c
```

### Include Guard

```c
#ifndef AUTH_UTILS_H
#define AUTH_UTILS_H
// ... content ...
#endif /* AUTH_UTILS_H */
```

---

## Dependencies

```c
#include <stdio.h>      // printf, FILE, fopen, fgets, fclose
#include <stdlib.h>     // atoi, malloc
#include <string.h>     // strlen, strstr, strchr, strcmp, memcpy, strncpy
#include <time.h>       // (not directly used but available)
#include <stdbool.h>    // bool, true, false
#include <unistd.h>     // (POSIX standard)
#include <fcntl.h>      // (file control)
#include <ctype.h>      // isspace

// OpenSSL
#include <openssl/evp.h>     // EVP_* functions for hashing
#include <openssl/bio.h>     // BIO_* for Base64
#include <openssl/buffer.h>  // BUF_MEM

// Project headers
#include "../tcp_config.h"   // BUFFER_SIZE, templates
```

### Compilation

```bash
gcc -o program program.c -lssl -lcrypto
```

---

## Helper Functions

### `trim_whitespace()`

Removes leading and trailing whitespace from a string in-place.

```c
void trim_whitespace(char *str);
```

**Parameters:**
- `str` - String to trim (modified in-place)

**Returns:** Nothing (void)

**Implementation:**
```c
void trim_whitespace(char *str) {
    if (!str) return;
    
    // Trim trailing
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
    
    // Trim leading (by moving memory)
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != str) {
        memmove(str, start, len - (start - str) + 1);
    }
}
```

**Example:**
```c
char text[] = "  hello world  ";
trim_whitespace(text);
// text is now "hello world"
```

---

## Base64 Functions

### `base64_decode()`

Decodes a Base64-encoded string to binary data.

```c
int base64_decode(char *in, int in_len, unsigned char *out);
```

**Parameters:**
- `in` - Base64 encoded input string
- `in_len` - Length of input string
- `out` - Output buffer for decoded binary data

**Returns:** Number of bytes written to `out`

**Implementation:**
```c
int base64_decode(char *in, int in_len, unsigned char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(in, in_len);
    bio = BIO_push(b64, bio);
    int out_len = BIO_read(bio, out, in_len);
    BIO_free_all(bio);
    return out_len;
}
```

**Example:**
```c
char encoded[] = "SGVsbG8gV29ybGQ=";
unsigned char decoded[100];
int len = base64_decode(encoded, strlen(encoded), decoded);
decoded[len] = '\0';
// decoded contains "Hello World"
```

---

### `base64_encode()`

Encodes binary data to Base64 string.

```c
void base64_encode(const unsigned char *in, int in_len, char *out);
```

**Parameters:**
- `in` - Binary input data
- `in_len` - Length of input data
- `out` - Output buffer for Base64 string (must be large enough)

**Returns:** Nothing (void)

**Implementation:**
```c
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
```

**Example:**
```c
unsigned char data[] = "Hello World";
char encoded[100];
base64_encode(data, 11, encoded);
// encoded contains "SGVsbG8gV29ybGQ="
```

---

## Credential Management

### `get_password_from_csv()`

Looks up a user's password from the credentials database.

```c
bool get_password_from_csv(const char *username, char *password_out, size_t size);
```

**Parameters:**
- `username` - Username to look up
- `password_out` - Buffer to store the password
- `size` - Size of password_out buffer

**Returns:** `true` if user found, `false` otherwise

**File Format (Credentials.csv):**
```csv
username,password
admin,pass
```

**Implementation:**
```c
bool get_password_from_csv(const char *username, char *password_out, size_t size) {
    FILE *fp = fopen("Credentials.csv", "r");
    if (!fp) {
        printf("[Auth] Error: Credentials.csv not found\n");
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // 1. Find the first comma to split User from Password
        char *first_comma = strchr(line, ',');
        if (!first_comma) continue; 
        
        // Terminate username string here
        *first_comma = '\0'; 
        
        if (strcmp(line, username) == 0) {
            // 2. Password starts after the first comma
            char *pass_start = first_comma + 1;
            
            // 3. Find end of password: next comma OR newline OR return char
            size_t pass_len = strcspn(pass_start, ",\r\n");
            pass_start[pass_len] = '\0';

            strncpy(password_out, pass_start, size - 1);
            password_out[size - 1] = '\0';
            
            // 4. Clean up any accidental spaces
            trim_whitespace(password_out);
            
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}
```

**Example:**
```c
char password[64];
if (get_password_from_csv("admin", password, sizeof(password))) {
    printf("Password for admin: %s\n", password);
} else {
    printf("User not found\n");
}
```

---

## Extraction Functions

### `extract_method()`

Extracts the HTTP method from the request line.

```c
void extract_method(const char *msg, char *out, size_t out_size);
```

**Parameters:**
- `msg` - HTTP request string
- `out` - Output buffer for method
- `out_size` - Size of output buffer

**Example:**
```c
char method[16];
extract_method("POST /onvif/device HTTP/1.1\r\n...", method, sizeof(method));
// method is "POST"
```

---

### `extract_tag_value()`

Extracts the value from an XML tag.

```c
void extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size);
```

**Parameters:**
- `msg` - XML message string
- `tag` - Tag name to find (without angle brackets)
- `out` - Output buffer for value
- `out_size` - Size of output buffer

**Note:** Works with both `<tag>` and `<ns:tag>` formats.

**Implementation:**
```c
void extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size) {
    out[0] = '\0';
    const char *start = strstr(msg, tag);
    if (!start) return;
    
    start = strchr(start, '>');
    if (!start) return;
    start++; 
    
    const char *end = strstr(start, "</");
    if (!end) return;
    
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    trim_whitespace(out);
}
```

**Example:**
```c
char username[64];
extract_tag_value("<wsse:Username>admin</wsse:Username>", "Username", username, sizeof(username));
// username is "admin"
```

---

### `extract_header_val()`

Extracts a value from the HTTP Digest Authorization header.

```c
void extract_header_val(const char *msg, const char *key, char *out, size_t out_size);
```

**Parameters:**
- `msg` - HTTP request with Authorization header
- `key` - Key to extract (e.g., "username", "realm", "nonce")
- `out` - Output buffer
- `out_size` - Size of output buffer

**Handles:**
- Quoted values: `username="admin"`
- Unquoted values: `nc=00000001`
- Various separators (comma, space)

**Example:**
```c
const char *request = 
    "POST /onvif HTTP/1.1\r\n"
    "Authorization: Digest username=\"admin\", realm=\"ONVIF\", nonce=\"abc123\"\r\n";

char username[64], realm[64], nonce[128];
extract_header_val(request, "username", username, sizeof(username));  // "admin"
extract_header_val(request, "realm", realm, sizeof(realm));            // "ONVIF"
extract_header_val(request, "nonce", nonce, sizeof(nonce));            // "abc123"
```

---

## Verification Functions

### `verify_ws_security()`

Verifies WS-UsernameToken authentication from SOAP header.

```c
bool verify_ws_security(const char *request);
```

**Parameters:**
- `request` - Complete HTTP request with SOAP body

**Returns:** `true` if authentication valid, `false` otherwise

**Algorithm:**
1. Extract Username, Password (digest), Nonce, Created from XML
2. Look up stored password for username
3. Decode Base64 nonce to raw bytes
4. Compute: `SHA1(nonce_raw + created + stored_password)`
5. Base64 encode result
6. Compare with received digest

**Implementation:**
```c
bool verify_ws_security(const char *request) {
    char user[64]={0}, pass_digest[128]={0}, nonce_b64[128]={0};
    char created[64]={0}, stored_pass[64]={0};
    
    extract_tag_value(request, "Username", user, sizeof(user));
    extract_tag_value(request, "Password", pass_digest, sizeof(pass_digest));
    extract_tag_value(request, "Nonce", nonce_b64, sizeof(nonce_b64));
    extract_tag_value(request, "Created", created, sizeof(created));

    if (!user[0]) return false;
    if (!get_password_from_csv(user, stored_pass, sizeof(stored_pass))) return false;

    unsigned char nonce_raw[128];
    int nonce_len = base64_decode(nonce_b64, strlen(nonce_b64), nonce_raw);
    
    unsigned char sha1_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, nonce_raw, nonce_len);
    EVP_DigestUpdate(ctx, created, strlen(created));
    EVP_DigestUpdate(ctx, stored_pass, strlen(stored_pass));
    unsigned int len;
    EVP_DigestFinal_ex(ctx, sha1_buf, &len);
    EVP_MD_CTX_free(ctx);

    char computed_digest[128];
    base64_encode(sha1_buf, 20, computed_digest);

    return (strcmp(computed_digest, pass_digest) == 0);
}
```

---

### `verify_http_digest()`

Verifies HTTP Digest Authentication from Authorization header.

```c
bool verify_http_digest(const char *request, const char *forced_method);
```

**Parameters:**
- `request` - Complete HTTP request
- `forced_method` - HTTP method to use if not extractable from request (e.g., "POST")

**Returns:** `true` if authentication valid, `false` otherwise

**Algorithm:**
1. Extract all digest parameters from Authorization header
2. Look up stored password for username
3. Calculate `HA1 = MD5(username:realm:password)`
4. For MD5-sess: `HA1 = MD5(HA1:nonce:cnonce)`
5. Calculate `HA2 = MD5(method:uri)`
6. Calculate response:
   - With qop: `MD5(HA1:nonce:nc:cnonce:qop:HA2)`
   - Without qop: `MD5(HA1:nonce:HA2)`
7. Compare with received response

**Key Code Sections:**

```c
bool verify_http_digest(const char *request, const char *forced_method) {
    // Extract all header values
    char user[64]={0}, realm[64]={0}, nonce[128]={0}, uri[128]={0};
    char response[64]={0}, stored_pass[64]={0};
    char qop[16]={0}, nc[16]={0}, cnonce[64]={0}, algo[16]={0}, method[16]={0};

    extract_header_val(request, "username", user, sizeof(user));
    extract_header_val(request, "realm", realm, sizeof(realm));
    extract_header_val(request, "nonce", nonce, sizeof(nonce));
    extract_header_val(request, "uri", uri, sizeof(uri));
    extract_header_val(request, "response", response, sizeof(response));
    // ... more extractions ...

    if (!user[0] || !response[0]) return false;
    if (!get_password_from_csv(user, stored_pass, sizeof(stored_pass))) return false;

    // Calculate HA1
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    char ha1_hex[33], ha2_hex[33], resp_hex[33];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, user, strlen(user));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, realm, strlen(realm));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, stored_pass, strlen(stored_pass));
    EVP_DigestFinal_ex(ctx, md_buf, &len);
    EVP_MD_CTX_reset(ctx);

    // Convert to hex
    for(int i=0;i<16;i++) sprintf(&ha1_hex[i*2], "%02x", md_buf[i]);

    // ... HA2 calculation ...
    // ... Final response calculation ...

    return (strcmp(resp_hex, response) == 0);
}
```

**Debug Output (on failure):**
```c
printf("[Auth] Digest Mismatch!\n");
printf("  User: '%s', Pass: '%s', Realm: '%s'\n", user, stored_pass, realm);
printf("  Method: '%s', URI: '%s'\n", final_method, uri);
printf("  Nonce: '%s'\n", nonce);
printf("  NC: '%s'\n", nc);
printf("  CNonce: '%s'\n", cnonce);
printf("  QoP: '%s'\n", qop);
printf("  HA1: %s\n", ha1_hex);
printf("  HA2: %s\n", ha2_hex);
printf("  Computed: %s\n", resp_hex);
printf("  Received: %s\n", response);
```

---

## Utility Functions

### `is_get_device_information()`

Checks if request is a GetDeviceInformation operation.

```c
static inline bool is_get_device_information(const char *msg);
```

**Parameters:**
- `msg` - SOAP request message

**Returns:** `true` if GetDeviceInformation request, `false` otherwise

**Implementation:**
```c
static inline bool is_get_device_information(const char *msg) {
    return (strstr(msg, "GetDeviceInformation") != NULL);
}
```

---

### `getmessageid1()`

Extracts the WS-Addressing MessageID from request.

```c
void getmessageid1(const char *msg, char *out, size_t out_size);
```

**Parameters:**
- `msg` - SOAP request message
- `out` - Output buffer for MessageID
- `out_size` - Size of output buffer

**Implementation:**
```c
void getmessageid1(const char *msg, char *out, size_t out_size) {
    extract_tag_value(msg, "MessageID", out, out_size);
}
```

**Example:**
```c
char msg_id[256];
getmessageid1(request, msg_id, sizeof(msg_id));
// msg_id might be "urn:uuid:12345678-1234-1234-1234-123456789abc"
```

---

## Usage Examples

### Complete Authentication Check

```c
#include "authhandler/auth_utils.h"

void handle_request(int client_socket, const char *request) {
    // Check if protected operation
    if (strstr(request, "GetDeviceInformation")) {
        
        // Try WS-Security first
        if (strstr(request, "wsse:Security")) {
            if (verify_ws_security(request)) {
                printf("[Auth] WS-Security OK\n");
                send_device_info_response(client_socket, request);
                return;
            }
            printf("[Auth] WS-Security FAILED\n");
        }
        
        // Try HTTP Digest
        if (strstr(request, "Authorization: Digest")) {
            if (verify_http_digest(request, "POST")) {
                printf("[Auth] HTTP Digest OK\n");
                send_device_info_response(client_socket, request);
                return;
            }
            printf("[Auth] HTTP Digest FAILED\n");
        }
        
        // No valid auth - send challenge
        send_401_unauthorized(client_socket);
    }
}
```

### Using in auth_server.h

```c
int has_any_authentication(const char *request) {
    // WS-UsernameToken check
    if (strstr(request, "wsse:Security") || strstr(request, "<Security")) {
        if (verify_ws_security(request)) {
            return 1;
        }
    }

    // HTTP Digest check
    if (strstr(request, "Authorization: Digest")) {
        if (verify_http_digest(request, "POST")) {
            return 1;
        }
    }
    
    return 0;
}
```

---

## Function Summary Table

| Function | Purpose | Returns |
|----------|---------|---------|
| `trim_whitespace()` | Remove leading/trailing whitespace | void |
| `base64_decode()` | Decode Base64 to binary | int (length) |
| `base64_encode()` | Encode binary to Base64 | void |
| `get_password_from_csv()` | Lookup user password | bool |
| `extract_method()` | Get HTTP method | void |
| `extract_tag_value()` | Get XML tag value | void |
| `extract_header_val()` | Get HTTP Digest header value | void |
| `verify_ws_security()` | Verify WS-UsernameToken | bool |
| `verify_http_digest()` | Verify HTTP Digest auth | bool |
| `is_get_device_information()` | Check if GetDeviceInfo | bool |
| `getmessageid1()` | Extract MessageID | void |

---

## See Also

- [02-HTTP-Digest-Authentication.md](./02-HTTP-Digest-Authentication.md) - HTTP Digest details
- [03-WS-UsernameToken-Authentication.md](./03-WS-UsernameToken-Authentication.md) - WS-Security details
- [04-OpenSSL-Guide.md](./04-OpenSSL-Guide.md) - OpenSSL functions used
- [07-Integration-Guide.md](./07-Integration-Guide.md) - How to use these functions

---

*← Back to [README.md](./README.md)*
