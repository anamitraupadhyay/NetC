# WS-UsernameToken Authentication - Complete Guide

> Understanding WS-Security UsernameToken authentication for ONVIF SOAP services

## Table of Contents

1. [What is WS-UsernameToken?](#what-is-ws-usernametoken)
2. [How It Works](#how-it-works)
3. [SOAP Message Structure](#soap-message-structure)
4. [Password Digest Calculation](#password-digest-calculation)
5. [Implementation Walkthrough](#implementation-walkthrough)
6. [Comparison with HTTP Digest](#comparison-with-http-digest)
7. [Security Considerations](#security-considerations)

---

## What is WS-UsernameToken?

WS-UsernameToken is part of the **WS-Security (Web Services Security)** specification defined by OASIS. It provides a way to authenticate SOAP messages by including username credentials in the SOAP envelope header.

### Why ONVIF Uses WS-UsernameToken

- **SOAP-native** - Authentication is part of the message itself
- **Transport independent** - Works over any protocol (HTTP, HTTPS, etc.)
- **Standardized** - Well-defined by OASIS standards
- **Client-side nonce** - No challenge-response round trip needed

### Key Standards

| Standard | Description |
|----------|-------------|
| WS-Security 1.1 | Web Services Security framework |
| OASIS WSS UsernameToken Profile 1.1 | Username/password authentication |
| XML Signature | Digital signatures (optional) |
| XML Encryption | Message encryption (optional) |

---

## How It Works

### Basic Concept

The client generates authentication credentials and includes them in the SOAP header. Unlike HTTP Digest, there's no server challenge - the client includes everything needed for verification in a single request.

### Visual Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                    WS-UsernameToken Authentication                      │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Client Side                                                           │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │ 1. Generate random Nonce (16+ bytes)                          │    │
│   │ 2. Get current timestamp (Created)                            │    │
│   │ 3. Calculate: PasswordDigest = Base64(SHA1(Nonce + Created +  │    │
│   │                                           Password))          │    │
│   │ 4. Base64 encode the Nonce                                    │    │
│   │ 5. Build SOAP header with UsernameToken                       │    │
│   └───────────────────────────────────────────────────────────────┘    │
│                                                                         │
│   Server Side                                                           │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │ 1. Extract Username, PasswordDigest, Nonce, Created           │    │
│   │ 2. Lookup password for Username                               │    │
│   │ 3. Base64 decode the Nonce                                    │    │
│   │ 4. Calculate: ExpectedDigest = Base64(SHA1(Nonce + Created +  │    │
│   │                                             Password))        │    │
│   │ 5. Compare ExpectedDigest with PasswordDigest                 │    │
│   └───────────────────────────────────────────────────────────────┘    │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

### Request Flow

```
Client                                    Server
   │                                         │
   │  SOAP Request with UsernameToken        │
   │  ┌────────────────────────────────┐    │
   │  │ <Security>                     │    │
   │  │   <UsernameToken>              │    │
   │  │     <Username>admin</Username> │    │
   │  │     <Password>digest</Password>│    │
   │  │     <Nonce>b64nonce</Nonce>    │    │
   │  │     <Created>timestamp</Created│    │
   │  │   </UsernameToken>             │    │
   │  │ </Security>                    │    │
   │  └────────────────────────────────┘    │
   │────────────────────────────────────────>│
   │                                         │
   │                                   Verify│
   │                                         │
   │  200 OK + Response                      │
   │<────────────────────────────────────────│
   │                                         │
```

---

## SOAP Message Structure

### Complete Request Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    
    <s:Header>
        <!-- WS-Security Header -->
        <wsse:Security s:mustUnderstand="1">
            <wsse:UsernameToken wsu:Id="UsernameToken-1">
                <wsse:Username>admin</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
                    qN3x8T5gK2mF1pL7vW4zR9yJ6nM=
                </wsse:Password>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
                    YWJjZGVmZ2hpamtsbW5vcA==
                </wsse:Nonce>
                <wsu:Created>2024-01-15T10:30:45Z</wsu:Created>
            </wsse:UsernameToken>
        </wsse:Security>
        
        <!-- Other SOAP headers -->
        <wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">
            http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation
        </wsa:Action>
    </s:Header>
    
    <s:Body>
        <tds:GetDeviceInformation/>
    </s:Body>
</s:Envelope>
```

### Key Elements Breakdown

#### 1. Security Header

```xml
<wsse:Security s:mustUnderstand="1">
```

- **wsse** - WS-Security Extension namespace
- **mustUnderstand="1"** - Server MUST process this or reject the message

#### 2. UsernameToken Container

```xml
<wsse:UsernameToken wsu:Id="UsernameToken-1">
```

- Contains all authentication credentials
- **wsu:Id** - Unique identifier (optional but useful for signing)

#### 3. Username

```xml
<wsse:Username>admin</wsse:Username>
```

- Plain text username
- Must match an entry in the credential database

#### 4. Password (Digest)

```xml
<wsse:Password Type="...#PasswordDigest">qN3x8T5gK2mF1pL7vW4zR9yJ6nM=</wsse:Password>
```

The **Type** attribute specifies the password format:

| Type URI | Description |
|----------|-------------|
| `...#PasswordDigest` | SHA-1 digest (recommended) |
| `...#PasswordText` | Plain text (avoid if possible) |

#### 5. Nonce

```xml
<wsse:Nonce EncodingType="...#Base64Binary">YWJjZGVmZ2hpamtsbW5vcA==</wsse:Nonce>
```

- Client-generated random value
- Base64 encoded
- Prevents replay attacks

#### 6. Created Timestamp

```xml
<wsu:Created>2024-01-15T10:30:45Z</wsu:Created>
```

- ISO 8601 format in UTC
- Used in digest calculation
- Server can reject old timestamps

---

## Password Digest Calculation

### The Formula

```
PasswordDigest = Base64( SHA1( Nonce + Created + Password ) )
```

**Important:** The components are concatenated as **raw bytes**, not as strings!

### Step-by-Step Calculation

#### Given Values:
- Password: `pass`
- Nonce (raw bytes): `[0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, ...]` (16 bytes)
- Created: `2024-01-15T10:30:45Z`

#### Step 1: Concatenate Raw Bytes

```
Input = Nonce_bytes + Created_bytes + Password_bytes
      = [nonce 16 bytes] + "2024-01-15T10:30:45Z" + "pass"
```

#### Step 2: Apply SHA-1

```
SHA1_result = SHA1(Input)
            = [20 bytes hash]
```

#### Step 3: Base64 Encode

```
PasswordDigest = Base64(SHA1_result)
               = "qN3x8T5gK2mF1pL7vW4zR9yJ6nM="
```

### Code Implementation (OpenSSL)

```c
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

bool verify_ws_security(const char *request) {
    char user[64]={0}, pass_digest[128]={0}, nonce_b64[128]={0};
    char created[64]={0}, stored_pass[64]={0};
    
    // Extract values from XML
    extract_tag_value(request, "Username", user, sizeof(user));
    extract_tag_value(request, "Password", pass_digest, sizeof(pass_digest));
    extract_tag_value(request, "Nonce", nonce_b64, sizeof(nonce_b64));
    extract_tag_value(request, "Created", created, sizeof(created));

    if (!user[0]) return false;
    
    // Lookup password from database
    if (!get_password_from_csv(user, stored_pass, sizeof(stored_pass))) 
        return false;

    // Decode Base64 nonce to raw bytes
    unsigned char nonce_raw[128];
    int nonce_len = base64_decode(nonce_b64, strlen(nonce_b64), nonce_raw);
    
    // Calculate SHA-1(nonce + created + password)
    unsigned char sha1_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, nonce_raw, nonce_len);      // Nonce (raw bytes)
    EVP_DigestUpdate(ctx, created, strlen(created));  // Created (string)
    EVP_DigestUpdate(ctx, stored_pass, strlen(stored_pass)); // Password (string)
    
    unsigned int len;
    EVP_DigestFinal_ex(ctx, sha1_buf, &len);
    EVP_MD_CTX_free(ctx);

    // Base64 encode the SHA-1 result
    char computed_digest[128];
    base64_encode(sha1_buf, 20, computed_digest);  // SHA-1 is always 20 bytes

    // Compare with client-provided digest
    return (strcmp(computed_digest, pass_digest) == 0);
}
```

---

## Implementation Walkthrough

### 1. Extracting XML Tag Values

```c
void extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size) {
    out[0] = '\0';
    
    // Find the tag in the message
    const char *start = strstr(msg, tag);
    if (!start) return;
    
    // Find the closing '>'
    start = strchr(start, '>');
    if (!start) return;
    start++;  // Skip '>'
    
    // Find closing tag '</...'
    const char *end = strstr(start, "</");
    if (!end) return;
    
    // Copy value
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    
    // Clean up whitespace
    trim_whitespace(out);
}
```

### 2. Base64 Decode (Using OpenSSL BIO)

```c
int base64_decode(char *in, int in_len, unsigned char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    
    BIO *bio = BIO_new_mem_buf(in, in_len);
    bio = BIO_push(b64, bio);
    
    int out_len = BIO_read(bio, out, in_len);
    BIO_free_all(bio);
    
    return out_len;
}
```

### 3. Base64 Encode (Using OpenSSL BIO)

```c
void base64_encode(const unsigned char *in, int in_len, char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    
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

### 4. Password Lookup

```c
bool get_password_from_csv(const char *username, char *password_out, size_t size) {
    FILE *fp = fopen("Credentials.csv", "r");
    if (!fp) {
        printf("[Auth] Error: Credentials.csv not found\n");
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // Find comma separator
        char *first_comma = strchr(line, ',');
        if (!first_comma) continue;
        
        // Terminate username at comma
        *first_comma = '\0';
        
        if (strcmp(line, username) == 0) {
            // Password starts after comma
            char *pass_start = first_comma + 1;
            
            // Find end of password
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

---

## Comparison with HTTP Digest

| Aspect | WS-UsernameToken | HTTP Digest |
|--------|------------------|-------------|
| **Location** | SOAP Header (XML) | HTTP Header |
| **Hash Algorithm** | SHA-1 | MD5 |
| **Nonce Source** | Client-generated | Server-provided |
| **Round Trips** | 1 (no challenge) | 2 (challenge-response) |
| **Timestamp** | Required | Optional |
| **URI Protection** | No | Yes (in HA2) |
| **Method Protection** | No | Yes (in HA2) |
| **Replay Protection** | Timestamp + Nonce | Server nonce |

### When to Use Which?

| Scenario | Recommended Method |
|----------|-------------------|
| SOAP services | WS-UsernameToken |
| REST APIs | HTTP Digest |
| Single request needed | WS-UsernameToken |
| Server tracks sessions | HTTP Digest |
| Need to protect method/URI | HTTP Digest |

---

## Security Considerations

### Strengths of WS-UsernameToken

1. **Single request** - No round-trip overhead
2. **Timestamp-based replay protection** - Server can reject old requests
3. **Standard format** - Widely supported by tools

### Potential Weaknesses

| Weakness | Mitigation |
|----------|------------|
| SHA-1 deprecated | Consider SHA-256 extension |
| Timestamp manipulation | Validate timestamp freshness (±5 minutes) |
| Nonce reuse | Track seen nonces (optional) |
| No encryption | Use HTTPS |

### Best Practices

1. **Validate timestamp** - Reject requests older than 5 minutes
2. **Use UTC** - Avoid timezone confusion
3. **Generate strong nonces** - Use cryptographic random
4. **Trim whitespace** - XML can have unexpected whitespace
5. **Support both types** - Some clients use PasswordText

### Handling PasswordText Type

```c
// The Type attribute indicates password format
// Type="...#PasswordDigest" -> Digest (recommended)
// Type="...#PasswordText"   -> Plain text (legacy)

// Check the Type attribute and handle accordingly
if (strstr(request, "#PasswordText")) {
    // Plain text comparison
    return (strcmp(received_pass, stored_pass) == 0);
} else {
    // Digest verification
    return verify_digest(...);
}
```

---

## XML Namespaces Reference

| Prefix | Namespace URI | Purpose |
|--------|---------------|---------|
| `wsse` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd` | Security extension |
| `wsu` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd` | Security utility |
| `s` | `http://www.w3.org/2003/05/soap-envelope` | SOAP 1.2 envelope |
| `wsa` | `http://schemas.xmlsoap.org/ws/2004/08/addressing` | WS-Addressing |

---

## Debugging Tips

### Common Issues

1. **Base64 encoding differences**
   - Some encoders add newlines
   - Use `BIO_FLAGS_BASE64_NO_NL`

2. **Timestamp format**
   - Must be ISO 8601 UTC
   - Example: `2024-01-15T10:30:45Z`

3. **Whitespace in XML**
   - Always trim extracted values
   - Watch for newlines in multi-line tags

4. **Nonce encoding**
   - Raw bytes must be decoded from Base64
   - Don't use the Base64 string directly

### Debug Logging

```c
printf("[WS-Auth] Debug Info:\n");
printf("  Username: '%s'\n", user);
printf("  Nonce (b64): '%s'\n", nonce_b64);
printf("  Nonce length: %d bytes\n", nonce_len);
printf("  Created: '%s'\n", created);
printf("  Stored Password: '%s'\n", stored_pass);
printf("  Received Digest: '%s'\n", pass_digest);
printf("  Computed Digest: '%s'\n", computed_digest);
```

---

*Continue to [04-OpenSSL-Guide.md](./04-OpenSSL-Guide.md) →*
