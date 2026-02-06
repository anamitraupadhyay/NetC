# HTTP Digest Authentication - Complete Guide

> A deep dive into HTTP Digest Authentication as implemented in ONVIF camera servers

## Table of Contents

1. [What is HTTP Digest Authentication?](#what-is-http-digest-authentication)
2. [How It Works](#how-it-works)
3. [The Challenge-Response Flow](#the-challenge-response-flow)
4. [Understanding the Components](#understanding-the-components)
5. [Hash Calculations](#hash-calculations)
6. [Implementation Walkthrough](#implementation-walkthrough)
7. [Security Considerations](#security-considerations)
8. [Common Issues and Debugging](#common-issues-and-debugging)

---

## What is HTTP Digest Authentication?

HTTP Digest Authentication is defined in **RFC 2617** (later updated by RFC 7616). Unlike Basic Authentication, it never sends the password over the network - instead, it sends a cryptographic digest (hash) that proves the client knows the password.

### Key Advantages

| Feature | Benefit |
|---------|---------|
| Password never transmitted | Even if intercepted, password is safe |
| Replay protection | Nonce prevents reuse of captured requests |
| Integrity verification | Digest proves message wasn't tampered |
| Mutual authentication | Server can also prove identity (with qop=auth-int) |

### Why ONVIF Uses HTTP Digest

ONVIF devices (cameras) operate in potentially insecure networks. HTTP Digest provides:

1. **No plaintext passwords** - Important since HTTPS isn't always available
2. **Stateless** - Each request contains all auth info
3. **Wide compatibility** - Supported by all HTTP clients/libraries
4. **Lightweight** - No key exchange protocols needed

---

## How It Works

### The Basic Idea

Instead of sending `password`, the client sends:
```
MD5(username + realm + password + nonce + method + uri + ...)
```

The server knows all these values (including the password from its database), so it can compute the same hash and compare.

### Visual Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                    HTTP Digest Authentication                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   Client                                    Server                    │
│     │                                         │                       │
│     │   1. GET /resource (no auth)            │                       │
│     │────────────────────────────────────────>│                       │
│     │                                         │                       │
│     │   2. 401 Unauthorized                   │                       │
│     │      WWW-Authenticate: Digest           │                       │
│     │        realm="ONVIF_Device"             │                       │
│     │        nonce="server_random_123"        │                       │
│     │        qop="auth"                       │                       │
│     │<────────────────────────────────────────│                       │
│     │                                         │                       │
│     │   3. Client computes:                   │                       │
│     │      HA1 = MD5(user:realm:password)     │                       │
│     │      HA2 = MD5(method:uri)              │                       │
│     │      response = MD5(HA1:nonce:nc:       │                       │
│     │                     cnonce:qop:HA2)     │                       │
│     │                                         │                       │
│     │   4. GET /resource                      │                       │
│     │      Authorization: Digest              │                       │
│     │        username="admin"                 │                       │
│     │        realm="ONVIF_Device"             │                       │
│     │        nonce="server_random_123"        │                       │
│     │        uri="/resource"                  │                       │
│     │        response="computed_hash"         │                       │
│     │        nc=00000001                      │                       │
│     │        cnonce="client_random_456"       │                       │
│     │        qop="auth"                       │                       │
│     │────────────────────────────────────────>│                       │
│     │                                         │                       │
│     │   5. Server verifies:                   │                       │
│     │      - Looks up password for "admin"    │                       │
│     │      - Computes same hash               │                       │
│     │      - Compares with client's response  │                       │
│     │                                         │                       │
│     │   6. 200 OK (or 401 if mismatch)        │                       │
│     │<────────────────────────────────────────│                       │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## The Challenge-Response Flow

### Step 1: Initial Request (No Authentication)

```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:7000
Content-Type: application/soap+xml

<soap:Envelope>
  <soap:Body>
    <GetDeviceInformation/>
  </soap:Body>
</soap:Envelope>
```

### Step 2: Server Challenge (401 Response)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="ONVIF_Device", qop="auth", nonce="abc123def456", algorithm=MD5
Content-Length: 0
Connection: close
```

#### Challenge Parameters Explained

| Parameter | Description | Example |
|-----------|-------------|---------|
| `realm` | Protection space identifier | "ONVIF_Device" |
| `nonce` | Server-generated unique value | Random hex string |
| `qop` | Quality of Protection | "auth" or "auth-int" |
| `algorithm` | Hash algorithm | MD5, MD5-sess, SHA-256 |
| `opaque` | Optional value to return unchanged | (not always used) |

### Step 3: Client Response (Authenticated Request)

```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:7000
Content-Type: application/soap+xml
Authorization: Digest username="admin", realm="ONVIF_Device", nonce="abc123def456", uri="/onvif/device_service", response="8ca523f5e9506fed4657c9700eebdbec", qop=auth, nc=00000001, cnonce="xyz789client"

<soap:Envelope>
  <soap:Body>
    <GetDeviceInformation/>
  </soap:Body>
</soap:Envelope>
```

---

## Understanding the Components

### Server-Provided Values (from WWW-Authenticate)

| Component | Purpose | Who Creates |
|-----------|---------|-------------|
| `realm` | Identifies protected area | Server |
| `nonce` | One-time value for this session | Server |
| `qop` | Determines what's protected | Server |
| `opaque` | Opaque data to return | Server |

### Client-Provided Values (in Authorization)

| Component | Purpose | Who Creates |
|-----------|---------|-------------|
| `username` | Account identifier | Client |
| `response` | Computed hash | Client |
| `cnonce` | Client's random value | Client |
| `nc` | Nonce count (request number) | Client |
| `uri` | Request URI | Client |

### The Response Hash

This is the critical piece - it proves the client knows the password:

```
response = MD5(HA1 : nonce : nc : cnonce : qop : HA2)
```

Where:
- `HA1` = MD5(username : realm : password)
- `HA2` = MD5(method : uri)

---

## Hash Calculations

### Standard MD5 Algorithm

```
HA1 = MD5(username:realm:password)
HA2 = MD5(method:uri)
response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
```

### Example Calculation

Given:
- username: `admin`
- password: `pass`
- realm: `ONVIF_Device`
- method: `POST`
- uri: `/onvif/device_service`
- nonce: `abc123`
- cnonce: `xyz789`
- nc: `00000001`
- qop: `auth`

**Step 1: Calculate HA1**
```
HA1 = MD5("admin:ONVIF_Device:pass")
    = "6f7c8e4e9e7e8e7e8e7e8e7e8e7e8e7e"  (example)
```

**Step 2: Calculate HA2**
```
HA2 = MD5("POST:/onvif/device_service")
    = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"  (example)
```

**Step 3: Calculate Response**
```
response = MD5("6f7c8e4e9e7e8e7e8e7e8e7e8e7e8e7e:abc123:00000001:xyz789:auth:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d")
         = "8ca523f5e9506fed4657c9700eebdbec"  (example)
```

### MD5-sess Variant

For `algorithm=MD5-sess`, HA1 is calculated differently:

```
HA1 = MD5(MD5(username:realm:password):nonce:cnonce)
```

This allows session-based authentication where the base HA1 can be pre-computed.

---

## Implementation Walkthrough

### Server-Side: Sending the Challenge

From `auth_server.h`:

```c
// SUB-CASE 2B: NO AUTH -> CHALLENGE (Send 401 + WWW-Authenticate)
printf("[TCP] Req: GetDeviceInformation (No Auth) -> CHALLENGE\n");

// Random nonce generation
char nonce[33];
snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x", 
        rand(), rand(), rand(), rand());

char response[1024];
snprintf(response, sizeof(response),
         "HTTP/1.1 401 Unauthorized\r\n"
         "WWW-Authenticate: Digest realm=\"ONVIF_Device\", "
         "qop=\"auth\", nonce=\"%s\", algorithm=MD5\r\n"
         "Content-Type: application/soap+xml; charset=utf-8\r\n"
         "Content-Length: 0\r\n"
         "Connection: close\r\n\r\n",
         nonce);

send(cs, response, strlen(response), 0);
```

### Server-Side: Verifying the Response

From `authhandler/auth_utils.h`:

```c
bool verify_http_digest(const char *request, const char *forced_method) {
    char user[64]={0}, realm[64]={0}, nonce[128]={0}, uri[128]={0};
    char response[64]={0}, stored_pass[64]={0};
    char qop[16]={0}, nc[16]={0}, cnonce[64]={0}, algo[16]={0}, method[16]={0};

    // Extract all values from Authorization header
    extract_header_val(request, "username", user, sizeof(user));
    extract_header_val(request, "realm", realm, sizeof(realm));
    extract_header_val(request, "nonce", nonce, sizeof(nonce));
    extract_header_val(request, "uri", uri, sizeof(uri));
    extract_header_val(request, "response", response, sizeof(response));
    extract_header_val(request, "qop", qop, sizeof(qop));
    extract_header_val(request, "cnonce", cnonce, sizeof(cnonce));
    extract_header_val(request, "algorithm", algo, sizeof(algo));
    extract_header_val(request, "nc", nc, sizeof(nc));
    
    // Get HTTP method from request line
    extract_method(request, method, sizeof(method));

    // Lookup password from database
    if (!get_password_from_csv(user, stored_pass, sizeof(stored_pass))) 
        return false;

    // Calculate HA1 = MD5(username:realm:password)
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

    // Handle MD5-sess algorithm variant
    if (strcasecmp(algo, "MD5-sess") == 0) {
        EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
        EVP_DigestUpdate(ctx, md_buf, 16);
        EVP_DigestUpdate(ctx, ":", 1);
        EVP_DigestUpdate(ctx, nonce, strlen(nonce));
        EVP_DigestUpdate(ctx, ":", 1);
        EVP_DigestUpdate(ctx, cnonce, strlen(cnonce));
        EVP_DigestFinal_ex(ctx, md_buf, &len);
        EVP_MD_CTX_reset(ctx);
    }
    
    // Convert to hex string
    for(int i=0;i<16;i++) sprintf(&ha1_hex[i*2], "%02x", md_buf[i]);

    // Calculate HA2 = MD5(method:uri)
    const char *final_method = (method[0]) ? method : forced_method;
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, final_method, strlen(final_method));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, uri, strlen(uri));
    EVP_DigestFinal_ex(ctx, md_buf, &len);
    EVP_MD_CTX_reset(ctx);
    
    for(int i=0;i<16;i++) sprintf(&ha2_hex[i*2], "%02x", md_buf[i]);

    // Calculate final response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, ha1_hex, 32);
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, nonce, strlen(nonce));
    EVP_DigestUpdate(ctx, ":", 1);
    
    if (qop[0]) {
        EVP_DigestUpdate(ctx, nc, strlen(nc));
        EVP_DigestUpdate(ctx, ":", 1);
        EVP_DigestUpdate(ctx, cnonce, strlen(cnonce));
        EVP_DigestUpdate(ctx, ":", 1);
        EVP_DigestUpdate(ctx, qop, strlen(qop));
        EVP_DigestUpdate(ctx, ":", 1);
    }
    
    EVP_DigestUpdate(ctx, ha2_hex, 32);
    EVP_DigestFinal_ex(ctx, md_buf, &len);
    EVP_MD_CTX_free(ctx);

    for(int i=0;i<16;i++) sprintf(&resp_hex[i*2], "%02x", md_buf[i]);

    // Compare computed response with client's response
    return (strcmp(resp_hex, response) == 0);
}
```

### Extracting Header Values

The `extract_header_val` function parses the Authorization header:

```c
void extract_header_val(const char *msg, const char *key, char *out, size_t out_size) {
    out[0] = '\0';
    
    // Find Authorization: Digest header
    const char *auth = strstr(msg, "Authorization: Digest");
    if (!auth) return;

    const char *p = auth;
    size_t key_len = strlen(key);
    
    while ((p = strstr(p, key)) != NULL) {
        // Check this is a key=value pair
        const char *check = p + key_len;
        while (*check == ' ') check++;
        
        if (*check != '=') { p++; continue; }

        // Verify it's a proper key boundary
        char prev = (p == auth) ? ' ' : *(p-1);
        if (prev == ' ' || prev == ',' || prev == '\t') {
            const char *val_start = check + 1;
            while (*val_start == ' ') val_start++;

            // Handle quoted values
            if (*val_start == '"') {
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

---

## Security Considerations

### Strengths

1. **No password exposure** - Password never sent over network
2. **Nonce prevents replay** - Each request needs fresh calculation
3. **Integrity with qop=auth-int** - Can protect message body

### Weaknesses and Mitigations

| Weakness | Mitigation |
|----------|------------|
| MD5 vulnerabilities | Use SHA-256 if possible |
| Nonce reuse | Generate cryptographically random nonces |
| No encryption | Use HTTPS when possible |
| Man-in-the-middle | Consider mutual authentication |

### Best Practices

1. **Use strong random nonces** - Avoid predictable values
2. **Track nonce count (nc)** - Detect replay attempts
3. **Set nonce expiration** - Force re-authentication periodically
4. **Log failed attempts** - Monitor for brute-force attacks

---

## Common Issues and Debugging

### Issue 1: Response Mismatch

**Symptoms:** Server always returns 401 despite correct credentials

**Debug logging in code:**
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

**Common causes:**
- URI mismatch (client vs server)
- Whitespace in credentials
- Case sensitivity issues
- Method mismatch (GET vs POST)

### Issue 2: Missing nc or cnonce

**Symptoms:** Hash calculation fails

**Solution:** Check if qop is being used:
```c
if (qop[0]) {
    // With qop, nc and cnonce are required
    EVP_DigestUpdate(ctx, nc, strlen(nc));
    // ...
}
```

### Issue 3: MD5-sess Algorithm

**Symptoms:** Works with standard clients, fails with some

**Solution:** Implement MD5-sess variant:
```c
if (strcasecmp(algo, "MD5-sess") == 0) {
    // Use session-based HA1 calculation
}
```

---

## Quick Reference

### Challenge Header Format
```
WWW-Authenticate: Digest realm="<realm>", qop="<qop>", nonce="<nonce>", algorithm=<algo>
```

### Authorization Header Format
```
Authorization: Digest username="<user>", realm="<realm>", nonce="<nonce>", uri="<uri>", response="<hash>", qop=<qop>, nc=<count>, cnonce="<client_nonce>"
```

### Hash Formulas
```
HA1 = MD5(username:realm:password)
HA2 = MD5(method:uri)
response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
```

---

*Continue to [03-WS-UsernameToken-Authentication.md](./03-WS-UsernameToken-Authentication.md) →*
