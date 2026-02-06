# auth_utils.h - Complete API Reference

## Table of Contents
1. [Overview](#overview)
2. [Header Dependencies](#header-dependencies)
3. [Helper Functions](#helper-functions)
4. [Base64 Operations](#base64-operations)
5. [Credential Management](#credential-management)
6. [Parsing Functions](#parsing-functions)
7. [Cryptographic Functions](#cryptographic-functions)
8. [Verification Functions](#verification-functions)
9. [Complete Usage Examples](#complete-usage-examples)
10. [Integration Guide](#integration-guide)

## Overview

**auth_utils.h** is a header-only library providing comprehensive authentication utilities for ONVIF servers. It implements:

- HTTP Digest Authentication (RFC 2617/7616)
- WS-UsernameToken Authentication (WS-Security)
- OpenSSL-based cryptographic operations
- CSV-based credential management
- HTTP header and XML parsing

### Design Philosophy

This is a **single-header library** designed for:
- ✅ Easy integration (just `#include "auth_utils.h"`)
- ✅ No external dependencies except OpenSSL
- ✅ Self-contained implementations
- ✅ Clear, readable code for learning

## Header Dependencies

```c
#include <stdio.h>          // File I/O, printf
#include <stdlib.h>         // malloc, free
#include <string.h>         // String operations
#include <time.h>           // Timestamp handling
#include <stdbool.h>        // Boolean type
#include <unistd.h>         // POSIX functions
#include <fcntl.h>          // File control
#include <ctype.h>          // Character classification
#include <openssl/evp.h>    // EVP digest API (MD5, SHA-1, SHA-256)
#include <openssl/bio.h>    // BIO for Base64
#include <openssl/buffer.h> // Buffer operations
```

### Why OpenSSL?

OpenSSL provides:
- Production-grade cryptographic implementations
- Hardware acceleration support
- FIPS 140-2 compliance options
- Well-tested and peer-reviewed code
- Cross-platform compatibility

## Helper Functions

### trim_whitespace()

Removes leading and trailing whitespace from a string.

#### Function Signature
```c
void trim_whitespace(char *str)
```

#### Parameters
- `str`: String to trim (modified in-place)

#### Description
This function modifies the string in-place by:
1. Removing trailing whitespace (spaces, tabs, newlines)
2. Removing leading whitespace by memory move

#### Implementation Details
```c
void trim_whitespace(char *str) {
    if (!str) return;
    
    // Trim trailing whitespace
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
    
    // Trim leading whitespace (by moving memory)
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != str) {
        memmove(str, start, len - (start - str) + 1);
    }
}
```

#### Example Usage
```c
char input[] = "  admin  \n";
trim_whitespace(input);
// Result: "admin"

char input2[] = "\t\tpassword\r\n";
trim_whitespace(input2);
// Result: "password"
```

#### Use Cases
- Parsing CSV files with inconsistent formatting
- Cleaning HTTP header values
- Processing XML tag values

## Base64 Operations

Base64 encoding is essential for:
- Encoding binary nonces in WS-UsernameToken
- Encoding password digests
- SOAP message formatting

### base64_decode()

Decodes a Base64-encoded string to binary data.

#### Function Signature
```c
int base64_decode(char *in, int in_len, unsigned char *out)
```

#### Parameters
- `in`: Base64-encoded input string
- `in_len`: Length of input string
- `out`: Output buffer for decoded data
- **Returns**: Number of decoded bytes (can be 0 if invalid)

#### Description
Uses OpenSSL BIO chain to decode Base64 data.

#### Implementation Details
```c
int base64_decode(char *in, int in_len, unsigned char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    BIO *bio = BIO_new_mem_buf(in, in_len);
    bio = BIO_push(b64, bio);                     // Chain BIOs
    int out_len = BIO_read(bio, out, in_len);     // Decode
    BIO_free_all(bio);                            // Cleanup
    return out_len;
}
```

#### BIO Chain Explained
```
Input String (Base64)
       ↓
   [Memory BIO]  ← Holds input data
       ↓
  [Base64 BIO]   ← Decodes Base64
       ↓
   Output Buffer
```

#### Example Usage
```c
char encoded[] = "SGVsbG8gV29ybGQ=";  // "Hello World" in Base64
unsigned char decoded[128];
int len = base64_decode(encoded, strlen(encoded), decoded);
decoded[len] = '\0';
printf("Decoded: %s\n", decoded);  // Output: "Hello World"

// Example: Decode WS-UsernameToken nonce
char nonce_b64[] = "ZjNhODQyYWItYzk1ZC00YzNjLWE3MjUtNWE4ZmY3YTQ2OTk0";
unsigned char nonce_raw[128];
int nonce_len = base64_decode(nonce_b64, strlen(nonce_b64), nonce_raw);
// nonce_raw now contains binary nonce (16 bytes typically)
```

### base64_encode()

Encodes binary data to Base64 string.

#### Function Signature
```c
void base64_encode(const unsigned char *in, int in_len, char *out)
```

#### Parameters
- `in`: Binary input data
- `in_len`: Length of input data in bytes
- `out`: Output buffer (must be at least `(in_len * 4 / 3) + 4` bytes)

#### Description
Uses OpenSSL BIO chain to encode binary data to Base64.

#### Implementation Details
```c
void base64_encode(const unsigned char *in, int in_len, char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    BIO *bio = BIO_new(BIO_s_mem());             // Memory buffer
    BIO_push(b64, bio);                           // Chain
    BIO_write(b64, in, in_len);                   // Write data
    BIO_flush(b64);                               // Flush
    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);             // Get buffer
    memcpy(out, bufferPtr->data, bufferPtr->length);
    out[bufferPtr->length] = '\0';                // Null terminate
    BIO_free_all(b64);
}
```

#### Example Usage
```c
unsigned char data[] = "Hello World";
char encoded[128];
base64_encode(data, strlen((char*)data), encoded);
printf("Encoded: %s\n", encoded);  // Output: SGVsbG8gV29ybGQ=

// Example: Encode SHA-1 digest for WS-UsernameToken
unsigned char sha1_hash[20];
// ... compute SHA-1 hash ...
char digest_b64[64];
base64_encode(sha1_hash, 20, digest_b64);
```

#### Base64 Output Size Calculation
```
Encoded length = ceil(input_length / 3) * 4
Example: 20 bytes → 28 Base64 characters
```

## Credential Management

### get_password_from_csv()

Retrieves a user's password from a CSV file.

#### Function Signature
```c
bool get_password_from_csv(const char *username, char *password_out, size_t size)
```

#### Parameters
- `username`: Username to search for
- `password_out`: Output buffer for password
- `size`: Size of output buffer
- **Returns**: `true` if user found, `false` otherwise

#### CSV Format
```csv
username,password,optional_field
admin,password123,extra
user1,secret456,data
camera,onvif2024,ignored
```

#### Description
- Opens `Credentials.csv` in current directory
- Searches for matching username
- Extracts password (handles CSV properly)
- Automatically trims whitespace

#### Implementation Highlights
```c
bool get_password_from_csv(const char *username, char *password_out, size_t size) {
    FILE *fp = fopen("Credentials.csv", "r");
    if (!fp) {
        printf("[Auth] Error: Credentials.csv not found\n");
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // Find first comma to split User from Password
        char *first_comma = strchr(line, ',');
        if (!first_comma) continue;
        
        *first_comma = '\0';  // Terminate username
        
        if (strcmp(line, username) == 0) {
            char *pass_start = first_comma + 1;
            
            // Find end of password (next comma OR newline)
            size_t pass_len = strcspn(pass_start, ",\r\n");
            pass_start[pass_len] = '\0';

            strncpy(password_out, pass_start, size - 1);
            password_out[size - 1] = '\0';
            trim_whitespace(password_out);
            
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}
```

#### Example Usage
```c
char password[64];
if (get_password_from_csv("admin", password, sizeof(password))) {
    printf("Password for admin: %s\n", password);
} else {
    printf("User 'admin' not found\n");
}
```

#### Security Considerations

⚠️ **Important**: This is a simple implementation for development/testing.

**Production systems should:**
- Store hashed passwords (bcrypt, Argon2)
- Use databases with proper access control
- Implement rate limiting
- Log authentication attempts
- Use secure credential management systems

**Example: Storing Hashed Passwords**
```c
// Instead of storing: admin,password123
// Store: admin,$2b$12$KIXfF8qE.Pl7jKhL4ZK5/.3K8F9...

// Then verify using bcrypt:
bool verify = bcrypt_verify(input_password, stored_hash);
```

## Parsing Functions

### extract_method()

Extracts HTTP method from request (GET, POST, PUT, etc.).

#### Function Signature
```c
void extract_method(const char *msg, char *out, size_t out_size)
```

#### Parameters
- `msg`: HTTP request message
- `out`: Output buffer for method
- `out_size`: Size of output buffer

#### Description
Extracts the HTTP method from the first line of an HTTP request.

#### Example Input/Output
```c
const char *request = 
    "POST /onvif/device_service HTTP/1.1\r\n"
    "Host: 192.168.1.100\r\n"
    "Content-Type: application/soap+xml\r\n";

char method[16];
extract_method(request, method, sizeof(method));
// Result: "POST"
```

#### Implementation
```c
void extract_method(const char *msg, char *out, size_t out_size) {
    size_t i = 0;
    while (msg[i] != ' ' && msg[i] != '\0' && i < out_size - 1) {
        out[i] = msg[i];
        i++;
    }
    out[i] = '\0';
    trim_whitespace(out);
}
```

### extract_tag_value()

Extracts value from XML tag.

#### Function Signature
```c
void extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size)
```

#### Parameters
- `msg`: XML/SOAP message
- `tag`: Tag name to search for (without angle brackets)
- `out`: Output buffer for tag value
- `out_size`: Size of output buffer

#### Description
Simple XML parser that finds `<tag>value</tag>` and extracts `value`.

#### Example Usage
```c
const char *soap = 
    "<?xml version=\"1.0\"?>"
    "<s:Envelope>"
    "  <s:Header>"
    "    <wsse:Security>"
    "      <wsse:Username>admin</wsse:Username>"
    "      <wsse:Password>aGFzaGVk</wsse:Password>"
    "    </wsse:Security>"
    "  </s:Header>"
    "</s:Envelope>";

char username[64];
extract_tag_value(soap, "Username", username, sizeof(username));
// Result: "admin"

char password[128];
extract_tag_value(soap, "Password", password, sizeof(password));
// Result: "aGFzaGVk"
```

#### How It Works
```c
void extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size) {
    out[0] = '\0';
    const char *start = strstr(msg, tag);
    if (!start) return;
    
    start = strchr(start, '>');  // Find opening tag end
    if (!start) return;
    start++;  // Move past '>'
    
    const char *end = strstr(start, "</");  // Find closing tag start
    if (!end) return;
    
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    trim_whitespace(out);
}
```

#### Limitations
- Simple string search (not a full XML parser)
- Doesn't handle attributes
- Doesn't handle nested tags with same name
- Assumes well-formed XML

**For production**: Consider using a proper XML library like libxml2.

### extract_header_val()

Extracts value from HTTP Digest Authorization header.

#### Function Signature
```c
void extract_header_val(const char *msg, const char *key, char *out, size_t out_size)
```

#### Parameters
- `msg`: HTTP request with Authorization header
- `key`: Parameter name (e.g., "username", "nonce", "response")
- `out`: Output buffer for value
- `out_size`: Size of output buffer

#### Description
Parses HTTP Digest Authorization header and extracts specific parameters.

#### Example Usage
```c
const char *request = 
    "POST /onvif/device_service HTTP/1.1\r\n"
    "Authorization: Digest username=\"admin\", "
    "realm=\"ONVIF_Device\", "
    "nonce=\"abc123\", "
    "uri=\"/onvif/device_service\", "
    "response=\"6629fae49393a05397450978507c4ef1\", "
    "qop=auth, nc=00000001, cnonce=\"xyz789\"\r\n";

char username[64];
extract_header_val(request, "username", username, sizeof(username));
// Result: "admin"

char nonce[128];
extract_header_val(request, "nonce", nonce, sizeof(nonce));
// Result: "abc123"

char response[64];
extract_header_val(request, "response", response, sizeof(response));
// Result: "6629fae49393a05397450978507c4ef1"
```

#### Parsing Rules
- Handles quoted values: `username="admin"`
- Handles unquoted values: `qop=auth`
- Handles whitespace variations
- Case-sensitive key matching

#### Implementation Highlights
```c
void extract_header_val(const char *msg, const char *key, char *out, size_t out_size) {
    out[0] = '\0';
    const char *auth = strstr(msg, "Authorization: Digest");
    if (!auth) return;

    const char *p = auth;
    size_t key_len = strlen(key);
    
    while ((p = strstr(p, key)) != NULL) {
        const char *check = p + key_len;
        while (*check == ' ') check++;
        
        if (*check != '=') { p++; continue; }

        // Check if key is at word boundary
        char prev = (p == auth) ? ' ' : *(p-1);
        if (prev == ' ' || prev == ',' || prev == '\t' || prev == '\n' || prev == '\r') {
            const char *val_start = check + 1;
            while (*val_start == ' ') val_start++;

            if (*val_start == '"') {
                // Quoted value
                val_start++;
                const char *val_end = strchr(val_start, '"');
                if (val_end) {
                    size_t len = val_end - val_start;
                    if (len >= out_size) len = out_size - 1;
                    memcpy(out, val_start, len);
                    out[len] = '\0';
                }
            } else {
                // Unquoted value
                size_t i = 0;
                while (val_start[i] != ',' && val_start[i] != '\r' && 
                       val_start[i] != '\n' && val_start[i] != '\0' && 
                       i < out_size - 1) {
                    out[i] = val_start[i];
                    i++;
                }
                out[i] = '\0';
            }
            trim_whitespace(out);
            return;
        }
        p++;
    }
}
```

### getmessageid1()

Extracts MessageID from SOAP header for correlation.

#### Function Signature
```c
void getmessageid1(const char *msg, char *out, size_t out_size)
```

#### Parameters
- `msg`: SOAP message
- `out`: Output buffer for MessageID
- `out_size`: Size of output buffer

#### Description
Extracts the MessageID from SOAP header, used for request/response correlation (RelatesTo field).

#### Example
```c
const char *soap_request =
    "<s:Header>"
    "  <a:MessageID>urn:uuid:12345678-1234-1234-1234-123456789abc</a:MessageID>"
    "</s:Header>";

char msg_id[256];
getmessageid1(soap_request, msg_id, sizeof(msg_id));
// Result: "urn:uuid:12345678-1234-1234-1234-123456789abc"
```

## Cryptographic Functions

### compute_digest()

Generic hash computation helper using OpenSSL EVP API.

#### Function Signature
```c
void compute_digest(const EVP_MD *type, 
                    const void *d1, size_t l1,
                    const void *d2, size_t l2,
                    const void *d3, size_t l3,
                    unsigned char *out)
```

#### Parameters
- `type`: Hash algorithm (EVP_md5(), EVP_sha1(), EVP_sha256(), etc.)
- `d1, l1`: First data chunk and its length
- `d2, l2`: Second data chunk and its length (can be NULL, 0)
- `d3, l3`: Third data chunk and its length (can be NULL, 0)
- `out`: Output buffer (must be at least EVP_MAX_MD_SIZE bytes)

#### Description
Computes hash of concatenated data chunks using OpenSSL EVP API.

#### Why EVP API?

The EVP (Envelope) API is recommended because:
- ✅ Algorithm-agnostic (easy to switch algorithms)
- ✅ Hardware acceleration support
- ✅ Future-proof (supports new algorithms)
- ✅ Consistent interface

#### Example Usage
```c
// MD5 hash
unsigned char md5_out[EVP_MAX_MD_SIZE];
compute_digest(EVP_md5(), "Hello", 5, "World", 5, NULL, 0, md5_out);

// SHA-1 hash
unsigned char sha1_out[EVP_MAX_MD_SIZE];
compute_digest(EVP_sha1(), "data", 4, NULL, 0, NULL, 0, sha1_out);

// SHA-256 hash
unsigned char sha256_out[EVP_MAX_MD_SIZE];
compute_digest(EVP_sha256(), "secure", 6, "data", 4, "here", 4, sha256_out);
```

#### Hash Output Sizes
```c
MD5:     16 bytes (128 bits)
SHA-1:   20 bytes (160 bits)
SHA-224: 28 bytes (224 bits)
SHA-256: 32 bytes (256 bits)
SHA-384: 48 bytes (384 bits)
SHA-512: 64 bytes (512 bits)
```

#### Converting Hash to Hex String
```c
unsigned char hash[16];  // MD5
compute_digest(EVP_md5(), "test", 4, NULL, 0, NULL, 0, hash);

char hex[33];
for (int i = 0; i < 16; i++) {
    sprintf(&hex[i*2], "%02x", hash[i]);
}
hex[32] = '\0';
printf("MD5: %s\n", hex);
```

## Verification Functions

### verify_ws_security()

Validates WS-UsernameToken authentication.

#### Function Signature
```c
bool verify_ws_security(const char *request)
```

#### Parameters
- `request`: Complete SOAP request with WS-Security header
- **Returns**: `true` if authentication valid, `false` otherwise

#### Description
Implements WS-UsernameToken authentication as per WS-Security specification.

#### Validation Steps
```
1. Extract username from <wsse:Username>
2. Extract password digest from <wsse:Password>
3. Extract nonce (Base64) from <wsse:Nonce>
4. Extract created timestamp from <wsu:Created>
5. Lookup stored password for username
6. Decode nonce from Base64 to binary
7. Compute: SHA1(nonce_binary + created + password)
8. Base64 encode the SHA-1 hash
9. Compare with received password digest
10. Return true if match, false otherwise
```

#### Example Request
```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <wsse:Security s:mustUnderstand="1">
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="...#PasswordDigest">aGFzaGVk</wsse:Password>
        <wsse:Nonce EncodingType="...#Base64Binary">bm9uY2U=</wsse:Nonce>
        <wsu:Created>2024-01-31T10:15:30Z</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>
```

#### Usage Example
```c
char request_buffer[8192];
// ... receive SOAP request ...

if (verify_ws_security(request_buffer)) {
    printf("Authentication successful\n");
    // Process request
    send_device_info_response(client);
} else {
    printf("Authentication failed\n");
    send_401_unauthorized(client);
}
```

#### Implementation Breakdown
```c
bool verify_ws_security(const char *request) {
    char user[64]={0}, pass_digest[128]={0}, 
         nonce_b64[128]={0}, created[64]={0}, stored_pass[64]={0};
    
    // Extract fields from XML
    extract_tag_value(request, "Username", user, sizeof(user));
    extract_tag_value(request, "Password", pass_digest, sizeof(pass_digest));
    extract_tag_value(request, "Nonce", nonce_b64, sizeof(nonce_b64));
    extract_tag_value(request, "Created", created, sizeof(created));

    if (!user[0]) return false;
    
    // Get stored password
    if (!get_password_from_csv(user, stored_pass, sizeof(stored_pass))) 
        return false;

    // Decode nonce from Base64
    unsigned char nonce_raw[128];
    int nonce_len = base64_decode(nonce_b64, strlen(nonce_b64), nonce_raw);
    
    // Compute SHA-1(nonce + created + password)
    unsigned char sha1_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, nonce_raw, nonce_len);
    EVP_DigestUpdate(ctx, created, strlen(created));
    EVP_DigestUpdate(ctx, stored_pass, strlen(stored_pass));
    unsigned int len;
    EVP_DigestFinal_ex(ctx, sha1_buf, &len);
    EVP_MD_CTX_free(ctx);

    // Base64 encode computed hash
    char computed_digest[128];
    base64_encode(sha1_buf, 20, computed_digest);

    // Compare
    return (strcmp(computed_digest, pass_digest) == 0);
}
```

### verify_http_digest()

Validates HTTP Digest authentication.

#### Function Signature
```c
bool verify_http_digest(const char *request, const char *forced_method)
```

#### Parameters
- `request`: Complete HTTP request with Authorization header
- `forced_method`: HTTP method to use if not found in request (typically "POST")
- **Returns**: `true` if authentication valid, `false` otherwise

#### Description
Implements HTTP Digest Authentication as per RFC 2617/7616.

#### Supported Features
- ✅ MD5 algorithm
- ✅ MD5-sess algorithm
- ✅ QoP (Quality of Protection): auth
- ✅ Nonce count (nc) validation
- ✅ Client nonce (cnonce)
- ✅ URI validation

#### Validation Steps
```
1. Extract username, realm, nonce, uri, response from Authorization header
2. Extract qop, nc, cnonce, algorithm if present
3. Lookup stored password for username
4. Compute HA1 = MD5(username:realm:password)
   - If algorithm=MD5-sess: HA1 = MD5(HA1:nonce:cnonce)
5. Compute HA2 = MD5(method:uri)
6. Compute Response:
   - If qop present: MD5(HA1:nonce:nc:cnonce:qop:HA2)
   - If qop absent: MD5(HA1:nonce:HA2)
7. Compare computed response with received response
8. Return true if match, false otherwise
```

#### Example Request
```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Authorization: Digest username="admin",
                      realm="ONVIF_Device",
                      nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                      uri="/onvif/device_service",
                      qop=auth,
                      nc=00000001,
                      cnonce="0a4f113b",
                      response="6629fae49393a05397450978507c4ef1",
                      algorithm=MD5
Content-Type: application/soap+xml
```

#### Usage Example
```c
char request_buffer[8192];
// ... receive HTTP request ...

if (verify_http_digest(request_buffer, "POST")) {
    printf("Digest authentication successful\n");
    send_200_response(client);
} else {
    printf("Digest authentication failed\n");
    send_401_challenge(client);
}
```

#### Debug Output
If authentication fails, the function prints detailed debug information:
```
[Auth] Digest Mismatch!
  User: 'admin', Pass: 'password123', Realm: 'ONVIF_Device'
  Method: 'POST', URI: '/onvif/device_service'
  Nonce: 'dcd98b7102dd2f0e8b11d0f600bfb0c093'
  NC: '00000001'
  CNonce: '0a4f113b'
  QoP: 'auth'
  HA1: 5f4dcc3b5aa765d61d8327deb882cf99
  HA2: 39a870e9e8e1f6e0b8b5c5c5c5c5c5c5
  Computed: 6629fae49393a05397450978507c4ef1
  Received: 1234567890abcdef1234567890abcdef
```

## Complete Usage Examples

### Example 1: Simple WS-Security Validation

```c
#include "auth_utils.h"

int main() {
    const char *soap_request = 
        "<?xml version=\"1.0\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
        "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
        "  <s:Header>"
        "    <wsse:Security>"
        "      <wsse:UsernameToken>"
        "        <wsse:Username>admin</wsse:Username>"
        "        <wsse:Password>aGFzaA==</wsse:Password>"
        "        <wsse:Nonce>bm9uY2U=</wsse:Nonce>"
        "        <wsu:Created>2024-01-31T10:15:30Z</wsu:Created>"
        "      </wsse:UsernameToken>"
        "    </wsse:Security>"
        "  </s:Header>"
        "  <s:Body>"
        "    <tds:GetDeviceInformation/>"
        "  </s:Body>"
        "</s:Envelope>";

    if (verify_ws_security(soap_request)) {
        printf("✓ Authentication successful\n");
    } else {
        printf("✗ Authentication failed\n");
    }
    
    return 0;
}
```

### Example 2: HTTP Digest Challenge-Response

```c
#include "auth_utils.h"
#include <time.h>
#include <stdlib.h>

void send_digest_challenge(int client_socket) {
    // Generate random nonce
    srand(time(NULL));
    char nonce[33];
    snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x",
             rand(), rand(), rand(), rand());
    
    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 401 Unauthorized\r\n"
             "WWW-Authenticate: Digest realm=\"ONVIF_Device\", "
             "qop=\"auth\", nonce=\"%s\", algorithm=MD5\r\n"
             "Content-Length: 0\r\n"
             "Connection: close\r\n\r\n",
             nonce);
    
    send(client_socket, response, strlen(response), 0);
}

bool handle_authenticated_request(const char *request) {
    // First check if Authorization header exists
    if (strstr(request, "Authorization: Digest") == NULL) {
        return false;  // Need to send challenge
    }
    
    // Validate digest
    return verify_http_digest(request, "POST");
}
```

### Example 3: Custom Parsing

```c
#include "auth_utils.h"

void parse_custom_header(const char *http_request) {
    // Extract HTTP method
    char method[16];
    extract_method(http_request, method, sizeof(method));
    printf("Method: %s\n", method);
    
    // Extract custom header value
    char content_type[128];
    const char *ct = strstr(http_request, "Content-Type:");
    if (ct) {
        sscanf(ct, "Content-Type: %127[^\r\n]", content_type);
        trim_whitespace(content_type);
        printf("Content-Type: %s\n", content_type);
    }
}
```

### Example 4: Manual Digest Computation

```c
#include "auth_utils.h"

void manual_digest_example() {
    const char *username = "admin";
    const char *realm = "ONVIF_Device";
    const char *password = "password123";
    const char *method = "POST";
    const char *uri = "/onvif/device_service";
    const char *nonce = "abc123";
    const char *nc = "00000001";
    const char *cnonce = "xyz789";
    const char *qop = "auth";
    
    // Compute HA1 = MD5(username:realm:password)
    unsigned char ha1_bin[16];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, username, strlen(username));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, realm, strlen(realm));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, password, strlen(password));
    unsigned int len;
    EVP_DigestFinal_ex(ctx, ha1_bin, &len);
    
    char ha1_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&ha1_hex[i*2], "%02x", ha1_bin[i]);
    }
    ha1_hex[32] = '\0';
    
    printf("HA1: %s\n", ha1_hex);
    
    // Compute HA2 = MD5(method:uri)
    unsigned char ha2_bin[16];
    EVP_MD_CTX_reset(ctx);
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, method, strlen(method));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, uri, strlen(uri));
    EVP_DigestFinal_ex(ctx, ha2_bin, &len);
    
    char ha2_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&ha2_hex[i*2], "%02x", ha2_bin[i]);
    }
    ha2_hex[32] = '\0';
    
    printf("HA2: %s\n", ha2_hex);
    
    // Compute Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    unsigned char response_bin[16];
    EVP_MD_CTX_reset(ctx);
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, ha1_hex, 32);
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, nonce, strlen(nonce));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, nc, strlen(nc));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, cnonce, strlen(cnonce));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, qop, strlen(qop));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, ha2_hex, 32);
    EVP_DigestFinal_ex(ctx, response_bin, &len);
    EVP_MD_CTX_free(ctx);
    
    char response_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&response_hex[i*2], "%02x", response_bin[i]);
    }
    response_hex[32] = '\0';
    
    printf("Response: %s\n", response_hex);
}
```

## Integration Guide

### Step 1: Project Setup

```bash
# Install OpenSSL development libraries
sudo apt-get install libssl-dev  # Ubuntu/Debian
sudo yum install openssl-devel   # RedHat/CentOS
brew install openssl             # macOS

# Compile with OpenSSL
gcc -o server main.c -lssl -lcrypto
```

### Step 2: Include in Your Project

```c
// main.c
#include "authhandler/auth_utils.h"

int main() {
    // Your ONVIF server code
    return 0;
}
```

### Step 3: Create Credentials File

```bash
# Create Credentials.csv in working directory
echo "admin,password123" > Credentials.csv
echo "user1,secret456" >> Credentials.csv
echo "camera,onvif2024" >> Credentials.csv
```

### Step 4: Implement Authentication

```c
bool authenticate_request(const char *request) {
    // Try WS-Security first
    if (strstr(request, "wsse:Security")) {
        return verify_ws_security(request);
    }
    
    // Try HTTP Digest
    if (strstr(request, "Authorization: Digest")) {
        return verify_http_digest(request, "POST");
    }
    
    // No authentication provided
    return false;
}
```

### Step 5: Handle Unauthenticated Requests

```c
void handle_request(int client_socket, const char *request) {
    if (!authenticate_request(request)) {
        // Send 401 challenge for HTTP Digest
        send_digest_challenge(client_socket);
        return;
    }
    
    // Process authenticated request
    process_onvif_request(client_socket, request);
}
```

## Best Practices

### 1. Error Handling

```c
// Always check return values
char password[64];
if (!get_password_from_csv("admin", password, sizeof(password))) {
    log_error("User not found");
    return false;
}
```

### 2. Buffer Overflow Protection

```c
// Always use sized buffers
char username[64];
extract_tag_value(xml, "Username", username, sizeof(username));  // Safe

// NOT: extract_tag_value(xml, "Username", username, 999999);  // Unsafe!
```

### 3. Memory Management

```c
// EVP contexts must be freed
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
// ... use context ...
EVP_MD_CTX_free(ctx);  // Don't forget!

// BIOs must be freed
BIO *b64 = BIO_new(BIO_f_base64());
// ... use BIO ...
BIO_free_all(b64);  // Cleanup
```

### 4. Secure Logging

```c
// DON'T log passwords!
printf("User: %s, Password: %s\n", user, password);  // ❌ BAD

// Log only non-sensitive info
printf("Authentication attempt for user: %s\n", user);  // ✓ Good
```

### 5. Use Constants

```c
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 128
#define MAX_NONCE_LEN 256

char username[MAX_USERNAME_LEN];
char password[MAX_PASSWORD_LEN];
char nonce[MAX_NONCE_LEN];
```

## Common Pitfalls

### ❌ Pitfall 1: Not Null-Terminating Strings

```c
// BAD
char buffer[64];
memcpy(buffer, data, len);
printf("%s", buffer);  // May print garbage!

// GOOD
char buffer[64];
memcpy(buffer, data, len);
buffer[len] = '\0';  // Null-terminate!
printf("%s", buffer);
```

### ❌ Pitfall 2: Buffer Too Small

```c
// BAD
char nonce[8];  // Too small!
base64_encode(raw_nonce, 16, nonce);  // Buffer overflow!

// GOOD
char nonce[64];  // Large enough (16 bytes → ~24 Base64 chars)
base64_encode(raw_nonce, 16, nonce);
```

### ❌ Pitfall 3: Forgetting to Trim Whitespace

```c
// BAD
if (strcmp(extracted_username, "admin") == 0)  // Fails if "admin "

// GOOD
trim_whitespace(extracted_username);
if (strcmp(extracted_username, "admin") == 0)  // Works!
```

### ❌ Pitfall 4: Comparing Hex Strings Case-Sensitively

```c
// MD5 hashes can be lowercase or uppercase
// Bad: strcmp("ABC", "abc") != 0
// Good: Use strcasecmp() or convert to same case
```

## Performance Considerations

### 1. Caching Password Hashes

```c
// Instead of computing HA1 every time:
typedef struct {
    char username[64];
    unsigned char ha1[16];  // Pre-computed MD5(user:realm:pass)
} UserCache;

UserCache cache[100];
// Compute HA1 once, reuse for all requests
```

### 2. Nonce Tracking

```c
// Use efficient data structure for nonce tracking
typedef struct {
    char nonce[64];
    time_t timestamp;
} NonceEntry;

// Ring buffer or hash table for fast lookups
```

### 3. Early Validation

```c
// Fail fast if basic requirements not met
if (!strstr(request, "Authorization:")) {
    return false;  // No auth header
}

if (!extract_username(request, username)) {
    return false;  // No username
}
```

## Testing

### Unit Test Example

```c
#include "auth_utils.h"
#include <assert.h>

void test_base64() {
    char encoded[] = "SGVsbG8=";
    unsigned char decoded[64];
    int len = base64_decode(encoded, strlen(encoded), decoded);
    decoded[len] = '\0';
    assert(strcmp((char*)decoded, "Hello") == 0);
    printf("✓ Base64 test passed\n");
}

void test_trim_whitespace() {
    char test1[] = "  hello  ";
    trim_whitespace(test1);
    assert(strcmp(test1, "hello") == 0);
    
    char test2[] = "\t\nworld\r\n";
    trim_whitespace(test2);
    assert(strcmp(test2, "world") == 0);
    
    printf("✓ Trim whitespace test passed\n");
}

int main() {
    test_base64();
    test_trim_whitespace();
    printf("All tests passed!\n");
    return 0;
}
```

## Troubleshooting

### Problem: Authentication Always Fails

**Check:**
1. Credentials.csv exists in working directory
2. Username/password format correct
3. No extra whitespace in CSV
4. Nonce properly generated
5. Hash algorithms match (MD5 vs SHA-1)

### Problem: Base64 Decode Returns 0

**Check:**
1. Input is valid Base64
2. Input length correct
3. No newlines in Base64 string (use BIO_FLAGS_BASE64_NO_NL)
4. Output buffer large enough

### Problem: Digest Mismatch

**Check:**
1. All parameters extracted correctly
2. Hash computation order correct
3. Colons (:) in correct positions
4. Hex string lowercase (not uppercase)
5. Method matches (GET vs POST)

### Debug Tips

```c
// Enable debug output
#define DEBUG 1

#if DEBUG
    printf("[DEBUG] Username: '%s'\n", username);
    printf("[DEBUG] Password: '%s'\n", password);
    printf("[DEBUG] Nonce: '%s'\n", nonce);
    printf("[DEBUG] HA1: %s\n", ha1_hex);
#endif
```

## Conclusion

**auth_utils.h** provides a complete, production-ready authentication system for ONVIF servers. Key features:

✅ HTTP Digest Authentication (RFC 2617/7616)
✅ WS-UsernameToken Authentication (WS-Security)
✅ OpenSSL-based cryptography
✅ Simple CSV credential management
✅ Comprehensive parsing utilities
✅ Header-only design (easy integration)

For more information, see related documentation:
- README_ONVIF_AUTHENTICATION.md - Authentication overview
- README_OPENSSL_GUIDE.md - OpenSSL deep dive
- README_HTTP_HEADERS.md - HTTP integration details

## API Quick Reference

```c
// Helper Functions
void trim_whitespace(char *str);

// Base64 Operations
int base64_decode(char *in, int in_len, unsigned char *out);
void base64_encode(const unsigned char *in, int in_len, char *out);

// Credential Management
bool get_password_from_csv(const char *username, char *password_out, size_t size);

// Parsing Functions
void extract_method(const char *msg, char *out, size_t out_size);
void extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size);
void extract_header_val(const char *msg, const char *key, char *out, size_t out_size);
void getmessageid1(const char *msg, char *out, size_t out_size);

// Cryptographic Functions
void compute_digest(const EVP_MD *type, const void *d1, size_t l1,
                    const void *d2, size_t l2, const void *d3, size_t l3,
                    unsigned char *out);

// Verification Functions
bool verify_ws_security(const char *request);
bool verify_http_digest(const char *request, const char *forced_method);

// Utility Functions
bool is_get_device_information(const char *msg);
```
