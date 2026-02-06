# ONVIF Authentication - Complete Guide

## Table of Contents
1. [Introduction to ONVIF](#introduction-to-onvif)
2. [Authentication Methods in ONVIF](#authentication-methods-in-onvif)
3. [HTTP Digest Authentication](#http-digest-authentication)
4. [WS-UsernameToken Authentication](#ws-usernametoken-authentication)
5. [Security Considerations](#security-considerations)
6. [Implementation in This Project](#implementation-in-this-project)
7. [Related Documentation](#related-documentation)

## Introduction to ONVIF

**ONVIF** (Open Network Video Interface Forum) is an open industry forum that provides and promotes standardized interfaces for effective interoperability of IP-based physical security products.

### What is ONVIF Used For?
- **IP Camera Management**: Control and configure IP cameras from different manufacturers
- **Video Streaming**: Standardized protocols for video stream access
- **Device Discovery**: Find cameras on the network automatically
- **PTZ Control**: Pan, Tilt, Zoom camera control
- **Event Management**: Receive notifications from cameras

### ONVIF Protocol Stack
```
┌─────────────────────────────┐
│    ONVIF Services           │  ← Application Layer
│  (Device, Media, PTZ, etc.) │
├─────────────────────────────┤
│    SOAP/XML Messages        │  ← Message Format
├─────────────────────────────┤
│  HTTP/HTTPS Transport       │  ← Transport Layer
├─────────────────────────────┤
│      TCP/IP Network         │  ← Network Layer
└─────────────────────────────┘
```

## Authentication Methods in ONVIF

ONVIF supports two primary authentication methods:

### 1. HTTP Digest Authentication
- **Transport-level** authentication
- Works at the **HTTP header** level
- Standardized by RFC 2617
- Used for REST-like operations

### 2. WS-UsernameToken Authentication
- **Message-level** authentication
- Embedded in **SOAP body** (XML)
- Part of WS-Security standard
- Used for SOAP operations

### Comparison Table

| Feature | HTTP Digest | WS-UsernameToken |
|---------|-------------|------------------|
| **Location** | HTTP Headers | SOAP XML Body |
| **Challenge-Response** | Yes (401 challenge) | No |
| **Standards** | RFC 2617, RFC 7616 | WS-Security |
| **Typical Use** | HTTP/REST operations | SOAP operations |
| **Replay Protection** | Nonce + NC counter | Nonce + Timestamp |
| **Password Storage** | Hashed (MD5/SHA) | Hashed (SHA-1) |
| **Implementation Complexity** | Medium | High |

## HTTP Digest Authentication

### How It Works

HTTP Digest authentication is a **challenge-response** mechanism:

```
┌──────────┐                                      ┌──────────┐
│  Client  │                                      │  Server  │
└────┬─────┘                                      └────┬─────┘
     │                                                 │
     │  1. Request without Authentication              │
     │ ──────────────────────────────────────────────> │
     │                                                 │
     │  2. 401 + WWW-Authenticate Challenge            │
     │ <────────────────────────────────────────────── │
     │    (Contains: realm, nonce, qop, algorithm)     │
     │                                                 │
     │  3. Request with Authorization: Digest          │
     │ ──────────────────────────────────────────────> │
     │    (Contains: response, username, nonce, etc.)  │
     │                                                 │
     │  4. 200 OK with Response Data                   │
     │ <────────────────────────────────────────────── │
     │                                                 │
```

### Step-by-Step Process

#### Step 1: Initial Request (No Auth)
```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: application/soap+xml

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

#### Step 2: Server Challenge (401)
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="ONVIF_Device", 
                         qop="auth", 
                         nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                         algorithm=MD5
Content-Length: 0
Connection: close
```

**Challenge Parameters:**
- `realm`: Security realm (usually "ONVIF_Device")
- `nonce`: Server-generated random string (prevents replay attacks)
- `qop`: Quality of protection ("auth" or "auth-int")
- `algorithm`: Hash algorithm (MD5 or SHA-256)

#### Step 3: Client Response with Authorization
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

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

**Authorization Parameters:**
- `username`: User identifier
- `realm`: Copied from challenge
- `nonce`: Copied from challenge
- `uri`: Request URI
- `qop`: Quality of protection
- `nc`: Nonce count (increments with each request)
- `cnonce`: Client nonce
- `response`: Computed digest (the actual password proof)
- `algorithm`: Hash algorithm

### Computing the Response Hash

The `response` field is computed through a series of hash operations:

```
1. HA1 = MD5(username:realm:password)
   Example: MD5("admin:ONVIF_Device:password123")

2. HA2 = MD5(method:digestURI)
   Example: MD5("POST:/onvif/device_service")

3. Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
   Example: MD5("HA1:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:HA2")
```

#### MD5-sess Algorithm Variant
```
For algorithm=MD5-sess:
1. HA1_initial = MD5(username:realm:password)
2. HA1_final = MD5(HA1_initial:nonce:cnonce)
3. HA2 = MD5(method:digestURI)
4. Response = MD5(HA1_final:nonce:nc:cnonce:qop:HA2)
```

#### Step 4: Server Validates and Responds
```http
HTTP/1.1 200 OK
Content-Type: application/soap+xml
Content-Length: 450

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>Videonetics</tds:Manufacturer>
      <tds:Model>Emulator_Cam</tds:Model>
      <tds:FirmwareVersion>1.0</tds:FirmwareVersion>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>
```

### Security Features

1. **No Plaintext Passwords**: Password never sent over the network
2. **Nonce**: Server-generated random value prevents replay attacks
3. **NC Counter**: Client nonce count prevents replay attacks
4. **CNonce**: Client-generated nonce adds randomness
5. **Realm Isolation**: Different realms can have different credentials

## WS-UsernameToken Authentication

### How It Works

WS-UsernameToken embeds authentication credentials directly in the SOAP message:

```
┌──────────┐                                      ┌──────────┐
│  Client  │                                      │  Server  │
└────┬─────┘                                      └────┬─────┘
     │                                                 │
     │  1. SOAP Request with WS-Security Header        │
     │ ──────────────────────────────────────────────> │
     │    (Contains: Username, PasswordDigest,         │
     │     Nonce, Created timestamp)                   │
     │                                                 │
     │  2. Validates timestamp, nonce, and digest      │
     │                                                 │
     │  3. 200 OK with Response Data                   │
     │ <────────────────────────────────────────────── │
     │                                                 │
```

### SOAP Message Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  
  <!-- WS-Security Header -->
  <s:Header>
    <wsse:Security s:mustUnderstand="1">
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
          aG9kMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM=
        </wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
          ZjNhODQyYWItYzk1ZC00YzNjLWE3MjUtNWE4ZmY3YTQ2OTk0
        </wsse:Nonce>
        <wsu:Created>2024-01-31T10:15:30Z</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  
  <!-- SOAP Body -->
  <s:Body>
    <tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

### Components Explained

#### 1. Username
```xml
<wsse:Username>admin</wsse:Username>
```
- Plain text username
- Identifies the user

#### 2. Password Digest
```xml
<wsse:Password Type="...#PasswordDigest">
  aG9kMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM=
</wsse:Password>
```
- **NOT** the actual password!
- Base64-encoded SHA-1 hash
- Computed as: `Base64(SHA1(Nonce + Created + Password))`

#### 3. Nonce
```xml
<wsse:Nonce EncodingType="...#Base64Binary">
  ZjNhODQyYWItYzk1ZC00YzNjLWE3MjUtNWE4ZmY3YTQ2OTk0
</wsse:Nonce>
```
- Random value (typically 16+ bytes)
- Base64 encoded
- Prevents replay attacks
- Should be unique for each request

#### 4. Created Timestamp
```xml
<wsu:Created>2024-01-31T10:15:30Z</wsu:Created>
```
- ISO 8601 timestamp (UTC)
- Format: `YYYY-MM-DDTHH:MM:SSZ`
- Server validates timestamp freshness (typically ±5 minutes)

### Computing Password Digest

```
Step 1: Generate or decode the nonce (binary)
  nonce_binary = decode_base64("ZjNhODQyYWItYzk1ZC00YzNjLWE3MjUtNWE4ZmY3YTQ2OTk0")

Step 2: Get the created timestamp string
  created = "2024-01-31T10:15:30Z"

Step 3: Get the plaintext password
  password = "password123"

Step 4: Concatenate and hash
  digest_input = nonce_binary + created + password
  sha1_hash = SHA1(digest_input)

Step 5: Base64 encode the result
  password_digest = Base64(sha1_hash)
```

### Example Calculation (Python-like pseudocode)

```python
import hashlib
import base64
from datetime import datetime

# Inputs
nonce_b64 = "ZjNhODQyYWItYzk1ZC00YzNjLWE3MjUtNWE4ZmY3YTQ2OTk0"
created = "2024-01-31T10:15:30Z"
password = "password123"

# Decode nonce
nonce_raw = base64.b64decode(nonce_b64)

# Compute digest
digest_input = nonce_raw + created.encode('utf-8') + password.encode('utf-8')
sha1_hash = hashlib.sha1(digest_input).digest()
password_digest = base64.b64encode(sha1_hash).decode('utf-8')

print("Password Digest:", password_digest)
```

### Security Features

1. **No Plaintext Passwords**: Password hashed with nonce and timestamp
2. **Replay Protection**: Nonce and timestamp prevent replay attacks
3. **Timestamp Validation**: Server rejects old messages (±5 min tolerance)
4. **Integrity**: Entire message can be signed (advanced WS-Security)
5. **End-to-End Security**: Authentication survives proxies/intermediaries

## HTTP Digest vs WS-UsernameToken

### When to Use HTTP Digest

✅ **Use HTTP Digest when:**
- You're using HTTP/REST APIs
- You want standard HTTP authentication
- Client doesn't support WS-Security
- You need simpler implementation
- Working with non-SOAP protocols

### When to Use WS-UsernameToken

✅ **Use WS-UsernameToken when:**
- Using SOAP/XML Web Services
- Need end-to-end security through intermediaries
- ONVIF specification requires it
- Implementing full ONVIF profile
- Need message-level security

### Key Differences in Implementation

| Aspect | HTTP Digest | WS-UsernameToken |
|--------|-------------|------------------|
| **Location** | HTTP Authorization header | SOAP s:Header section |
| **Challenge** | Requires initial 401 | No challenge needed |
| **Round Trips** | 2 (challenge + response) | 1 (direct auth) |
| **Hash Algorithm** | MD5 or SHA-256 | SHA-1 |
| **Digest Computation** | HA1:nonce:nc:cnonce:qop:HA2 | SHA1(nonce+created+password) |
| **Timestamp** | No (uses nonce only) | Yes (Created field) |
| **Nonce Count** | Yes (nc parameter) | No |
| **Client Nonce** | Yes (cnonce) | No (only server nonce) |

### Security Comparison

| Security Feature | HTTP Digest | WS-UsernameToken |
|------------------|-------------|------------------|
| **Replay Protection** | Nonce + NC counter | Nonce + Timestamp |
| **Password Protection** | Hashed (MD5/SHA-256) | Hashed (SHA-1) |
| **Man-in-Middle** | No (use HTTPS) | No (use TLS/HTTPS) |
| **Intermediary Safe** | No | Yes (message-level) |
| **Brute Force** | Resistant | Resistant |
| **Hash Strength** | MD5 (weak), SHA-256 (strong) | SHA-1 (medium) |

### Protocol Flow Comparison

#### HTTP Digest Flow
```
Client                          Server
  │                               │
  ├─── Request ──────────────────>│  No Auth
  │<───────────────── 401 ────────┤  Challenge
  ├─── Request + Auth ───────────>│  With Digest
  │<───────────────── 200 ────────┤  Success
  │                               │
```

#### WS-UsernameToken Flow
```
Client                          Server
  │                               │
  ├─── Request + Auth ───────────>│  With Token
  │<───────────────── 200 ────────┤  Success
  │                               │
```

## Security Considerations

### 1. Always Use HTTPS/TLS

⚠️ **Critical**: Both authentication methods are vulnerable to man-in-the-middle attacks over plain HTTP.

```
✗ Bad:  http://192.168.1.100:8080/onvif/device_service
✓ Good: https://192.168.1.100:443/onvif/device_service
```

### 2. Strong Passwords

```c
// Bad passwords
❌ "admin"
❌ "password"
❌ "12345"

// Good passwords
✓ "Ax7#mK2!pL9@wQ"
✓ "MyCamera!2024#Secure"
✓ Use password managers
```

### 3. Nonce Management

**For HTTP Digest:**
- Generate cryptographically random nonces
- Track used nonces (prevent replay)
- Implement nonce expiration

**For WS-UsernameToken:**
- Generate unique nonces per request
- Validate nonce hasn't been used recently
- Check timestamp freshness (±5 minutes typical)

### 4. Credential Storage

```c
// Server-side password storage

// ❌ NEVER store plaintext passwords
char password[] = "password123";  // WRONG!

// ✓ Store hashed passwords
// For HTTP Digest: Store MD5(username:realm:password)
// For WS-UsernameToken: Store hashed password

// Example: Use a secure database
// users.db:
//   username | realm | ha1_hash
//   admin    | ONVIF | 5f4dcc3b5aa765d61d8327deb882cf99
```

### 5. Implement Rate Limiting

```c
// Prevent brute-force attacks
int failed_attempts = 0;
const int MAX_ATTEMPTS = 5;
const int LOCKOUT_SECONDS = 300;

if (failed_attempts >= MAX_ATTEMPTS) {
    // Lock account or add delay
    sleep(LOCKOUT_SECONDS);
}
```

### 6. Validate Input

```c
// Always validate and sanitize inputs
void validate_username(const char *username) {
    if (strlen(username) > MAX_USERNAME_LEN) {
        return false;  // Too long
    }
    // Check for SQL injection, XSS, etc.
    // Only allow alphanumeric + specific chars
}
```

### 7. Timestamp Validation (WS-UsernameToken)

```c
// Validate Created timestamp
time_t now = time(NULL);
time_t created = parse_iso8601(created_str);

// Allow ±5 minutes tolerance
const int TOLERANCE = 300;  // seconds

if (abs(difftime(now, created)) > TOLERANCE) {
    return false;  // Timestamp too old/future
}
```

### 8. HTTPS Certificate Validation

```c
// Client-side: Always validate server certificates
// Don't ignore certificate errors!

// ❌ Bad: Skip certificate validation
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

// ✓ Good: Validate certificates
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
```

## Implementation in This Project

### File Structure

```
ONVIF-SIM/
└── fakecamera/
    ├── authhandler/
    │   ├── auth_utils.h          ← Core authentication utilities
    │   └── digest_auth.h         ← Digest-specific helpers
    ├── auth_server.h             ← Server implementation
    ├── tcp_config.h              ← SOAP templates
    ├── Credentials.csv           ← User database
    └── main.c                    ← Entry point
```

### Key Components

1. **auth_utils.h**: Core authentication logic
   - Base64 encoding/decoding
   - Digest computation (HTTP & WS)
   - Credential validation
   - Header/XML parsing

2. **auth_server.h**: Server implementation
   - TCP socket handling
   - Request routing
   - Challenge generation
   - Response formatting

3. **Credentials.csv**: User database
   ```csv
   admin,password123
   user1,secret456
   camera,onvif2024
   ```

### Authentication Flow

```
1. Client connects to TCP port 8080
2. Server receives HTTP POST with SOAP body
3. Server checks for authentication:
   a. Check for "wsse:Security" → WS-UsernameToken
   b. Check for "Authorization: Digest" → HTTP Digest
4. If no auth and protected resource → Send 401 challenge
5. If valid auth → Process request and send 200 response
6. If invalid auth → Send 401 Unauthorized
```

### Example Usage

See detailed examples in:
- `README_AUTH_UTILS.md` - auth_utils.h reference
- `README_HTTP_HEADERS.md` - HTTP integration
- `README_XML_ONVIF.md` - XML structure guide

## Related Documentation

This guide is part of a comprehensive documentation set:

1. **README_ONVIF_AUTHENTICATION.md** (This file)
   - Overview of ONVIF authentication
   - HTTP Digest vs WS-UsernameToken comparison

2. **README_AUTH_UTILS.md**
   - Detailed auth_utils.h API reference
   - Function-by-function breakdown
   - Usage examples

3. **README_OPENSSL_GUIDE.md**
   - Complete OpenSSL library guide
   - Hash functions (MD5, SHA-1, SHA-256)
   - BIO operations for Base64
   - EVP digest API

4. **README_HTTP_HEADERS.md**
   - HTTP header structure
   - Authorization header parsing
   - WWW-Authenticate challenges
   - ONVIF-specific HTTP usage

5. **README_XML_ONVIF.md**
   - SOAP/XML message structure
   - WS-Security namespaces
   - ONVIF service templates
   - XML parsing techniques

6. **README_MODULAR_DESIGN.md**
   - Architecture overview
   - Modular design patterns
   - Integration guidelines

7. **README_PACKET_ANALYSIS.md**
   - Network packet analysis
   - Wireshark guide for ONVIF
   - Debugging authentication

## Quick Reference

### HTTP Digest Authentication

```c
// Server generates challenge
char nonce[33];
snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x", 
         rand(), rand(), rand(), rand());
         
send_challenge(client, "ONVIF_Device", nonce);

// Server validates response
bool valid = verify_http_digest(request, "POST");
```

### WS-UsernameToken Authentication

```c
// Server validates WS-Security
bool valid = verify_ws_security(request);

// Extract credentials
char username[64];
extract_tag_value(request, "Username", username, sizeof(username));
```

### Common Pitfalls

1. ❌ Not implementing nonce tracking → Replay attacks
2. ❌ Using MD5 without MD5-sess → Weak security
3. ❌ Not validating timestamps → Replay attacks
4. ❌ Storing plaintext passwords → Security breach
5. ❌ Not using HTTPS → Man-in-the-middle attacks
6. ❌ Ignoring certificate validation → Fake servers
7. ❌ Not rate-limiting auth attempts → Brute force

## Conclusion

ONVIF authentication provides flexible security options for IP camera systems. Understanding both HTTP Digest and WS-UsernameToken authentication is essential for implementing secure ONVIF services.

**Key Takeaways:**
- Always use HTTPS/TLS for production
- Implement proper nonce and timestamp validation
- Use strong passwords and secure storage
- Understand the differences between HTTP Digest and WS-UsernameToken
- Follow ONVIF specifications for compatibility

For implementation details, see the related documentation files.

## Further Reading

- [ONVIF Core Specification](https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf)
- [RFC 2617 - HTTP Digest Authentication](https://tools.ietf.org/html/rfc2617)
- [RFC 7616 - HTTP Digest Authentication (Updated)](https://tools.ietf.org/html/rfc7616)
- [WS-Security Specification](http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
