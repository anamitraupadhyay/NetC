# HTTP Protocol Guide for ONVIF

> Understanding HTTP headers, packet transfers, and request/response handling for ONVIF services

## Table of Contents

1. [HTTP Basics for ONVIF](#http-basics-for-onvif)
2. [Request Structure](#request-structure)
3. [Response Structure](#response-structure)
4. [Important HTTP Headers](#important-http-headers)
5. [Authentication Headers](#authentication-headers)
6. [Packet Transfer Flow](#packet-transfer-flow)
7. [TCP Socket Implementation](#tcp-socket-implementation)
8. [Debugging HTTP Traffic](#debugging-http-traffic)

---

## HTTP Basics for ONVIF

### Why HTTP?

ONVIF uses HTTP as the transport layer for SOAP messages because:

- **Widely supported** - Works through firewalls
- **Well-understood** - Standard protocol
- **Extensible** - Headers for authentication, content negotiation
- **Request/Response** - Natural fit for service calls

### ONVIF HTTP Characteristics

| Feature | Value |
|---------|-------|
| Protocol | HTTP/1.1 |
| Method | POST (for SOAP) |
| Content-Type | `application/soap+xml; charset=utf-8` |
| Port | Typically 80 or 8080 (configurable) |

### HTTP Message Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     HTTP Request/Response Cycle                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Client (VMS/Browser)                    Server (Camera)                │
│         │                                       │                        │
│         │   HTTP POST Request                   │                        │
│         │  ┌─────────────────────┐             │                        │
│         │  │ Request Line        │             │                        │
│         │  │ Headers             │             │                        │
│         │  │ (blank line)        │             │                        │
│         │  │ SOAP Body           │             │                        │
│         │  └─────────────────────┘             │                        │
│         │─────────────────────────────────────>│                        │
│         │                                       │                        │
│         │                                       │ Parse request          │
│         │                                       │ Check auth             │
│         │                                       │ Process                │
│         │                                       │                        │
│         │   HTTP Response                       │                        │
│         │  ┌─────────────────────┐             │                        │
│         │  │ Status Line         │             │                        │
│         │  │ Headers             │             │                        │
│         │  │ (blank line)        │             │                        │
│         │  │ SOAP Response       │             │                        │
│         │  └─────────────────────┘             │                        │
│         │<─────────────────────────────────────│                        │
│         │                                       │                        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Request Structure

### HTTP Request Format

```
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:7000
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 524
Connection: keep-alive

<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope>
  ... SOAP content ...
</s:Envelope>
```

### Request Line

```
METHOD URI HTTP/VERSION
```

| Component | ONVIF Value | Description |
|-----------|-------------|-------------|
| METHOD | POST | Always POST for SOAP |
| URI | `/onvif/device_service` | Service endpoint |
| VERSION | HTTP/1.1 | Protocol version |

### Common ONVIF URIs

| URI | Service |
|-----|---------|
| `/onvif/device_service` | Device Management |
| `/onvif/media_service` | Media Configuration |
| `/onvif/ptz_service` | PTZ Control |
| `/onvif/events_service` | Event Handling |

---

## Response Structure

### HTTP Response Format

```
HTTP/1.1 200 OK
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 1234
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope>
  ... SOAP response ...
</s:Envelope>
```

### Status Line

```
HTTP/VERSION STATUS_CODE REASON_PHRASE
```

### Common Status Codes in ONVIF

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful request |
| 400 | Bad Request | Malformed SOAP |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Invalid URI |
| 500 | Internal Server Error | Server error |

### 401 Response with Challenge

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="ONVIF_Device", qop="auth", nonce="abc123def456", algorithm=MD5
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 0
Connection: close

```

---

## Important HTTP Headers

### Request Headers

| Header | Purpose | Example |
|--------|---------|---------|
| `Host` | Target server | `192.168.1.100:7000` |
| `Content-Type` | Body format | `application/soap+xml; charset=utf-8` |
| `Content-Length` | Body size | `524` |
| `Connection` | Connection handling | `keep-alive` or `close` |
| `User-Agent` | Client identifier | `ONVIF-Client/1.0` |
| `Authorization` | Credentials | `Digest username="admin"...` |

### Response Headers

| Header | Purpose | Example |
|--------|---------|---------|
| `Content-Type` | Response format | `application/soap+xml; charset=utf-8` |
| `Content-Length` | Response size | `1234` |
| `Connection` | Connection handling | `close` |
| `WWW-Authenticate` | Auth challenge | `Digest realm="..."` |
| `Date` | Response timestamp | `Mon, 15 Jan 2024 10:30:45 GMT` |

### Header Parsing

```c
// Extract HTTP method from request
void extract_method(const char *msg, char *out, size_t out_size) {
    size_t i = 0;
    while (msg[i] != ' ' && msg[i] != '\0' && i < out_size - 1) {
        out[i] = msg[i];
        i++;
    }
    out[i] = '\0';
}

// Extract Content-Length
int get_content_length(const char *request) {
    const char *cl = strstr(request, "Content-Length:");
    if (!cl) return -1;
    return atoi(cl + 15);  // Skip "Content-Length:"
}

// Find body start (after \r\n\r\n)
const char* find_body(const char *request) {
    const char *body = strstr(request, "\r\n\r\n");
    return body ? body + 4 : NULL;
}
```

---

## Authentication Headers

### WWW-Authenticate (Server → Client)

Sent by server to request authentication:

```http
WWW-Authenticate: Digest realm="ONVIF_Device", qop="auth", nonce="abc123", algorithm=MD5
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `realm` | Protection space name |
| `qop` | Quality of protection |
| `nonce` | Server-generated unique value |
| `algorithm` | Hash algorithm (MD5, SHA-256) |
| `opaque` | Optional value to return unchanged |

### Authorization (Client → Server)

Sent by client with credentials:

```http
Authorization: Digest username="admin", realm="ONVIF_Device", nonce="abc123", uri="/onvif/device_service", response="8ca523f5e9506fed4657c9700eebdbec", qop=auth, nc=00000001, cnonce="xyz789"
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `username` | User account name |
| `realm` | Must match server's realm |
| `nonce` | Server-provided nonce |
| `uri` | Request URI |
| `response` | Calculated digest |
| `qop` | Quality of protection |
| `nc` | Nonce count (hex, 8 digits) |
| `cnonce` | Client-generated nonce |

### Implementation: Generating Challenge

```c
void send_401_challenge(int client_socket) {
    // Generate random nonce
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
             "Connection: close\r\n"
             "\r\n",
             nonce);
    
    send(client_socket, response, strlen(response), 0);
}
```

### Implementation: Parsing Authorization Header

```c
void extract_header_val(const char *msg, const char *key, char *out, size_t out_size) {
    out[0] = '\0';
    
    // Find Authorization: Digest
    const char *auth = strstr(msg, "Authorization: Digest");
    if (!auth) return;

    const char *p = auth;
    size_t key_len = strlen(key);
    
    while ((p = strstr(p, key)) != NULL) {
        const char *check = p + key_len;
        while (*check == ' ') check++;
        
        if (*check != '=') { p++; continue; }

        // Check boundary (space, comma, or start)
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
            return;
        }
        p++;
    }
}
```

---

## Packet Transfer Flow

### Complete Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    HTTP Digest Authentication Flow                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   1. Client sends request without auth                                   │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │ POST /onvif/device_service HTTP/1.1                            │    │
│   │ Host: 192.168.1.100:7000                                       │    │
│   │ Content-Type: application/soap+xml; charset=utf-8              │    │
│   │ Content-Length: 200                                            │    │
│   │                                                                 │    │
│   │ <s:Envelope>...<GetDeviceInformation/>...</s:Envelope>         │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   2. Server sends 401 with challenge                                     │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │ HTTP/1.1 401 Unauthorized                                      │    │
│   │ WWW-Authenticate: Digest realm="ONVIF_Device",                 │    │
│   │                   qop="auth",                                  │    │
│   │                   nonce="abc123def456789012345678901234567",   │    │
│   │                   algorithm=MD5                                │    │
│   │ Content-Length: 0                                              │    │
│   │ Connection: close                                              │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   3. Client calculates response and retries                              │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │ POST /onvif/device_service HTTP/1.1                            │    │
│   │ Host: 192.168.1.100:7000                                       │    │
│   │ Content-Type: application/soap+xml; charset=utf-8              │    │
│   │ Authorization: Digest username="admin",                        │    │
│   │                realm="ONVIF_Device",                           │    │
│   │                nonce="abc123def456789012345678901234567",      │    │
│   │                uri="/onvif/device_service",                    │    │
│   │                response="8ca523f5e9506fed4657c9700eebdbec",   │    │
│   │                qop=auth,                                       │    │
│   │                nc=00000001,                                    │    │
│   │                cnonce="xyz789client"                           │    │
│   │ Content-Length: 200                                            │    │
│   │                                                                 │    │
│   │ <s:Envelope>...<GetDeviceInformation/>...</s:Envelope>         │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   4. Server validates and responds                                       │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │ HTTP/1.1 200 OK                                                │    │
│   │ Content-Type: application/soap+xml; charset=utf-8              │    │
│   │ Content-Length: 850                                            │    │
│   │ Connection: close                                              │    │
│   │                                                                 │    │
│   │ <s:Envelope>...<GetDeviceInformationResponse>...</s:Envelope>  │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### WS-UsernameToken Flow (Single Request)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WS-UsernameToken Authentication Flow                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   1. Client sends request with WS-Security header                        │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │ POST /onvif/device_service HTTP/1.1                            │    │
│   │ Host: 192.168.1.100:7000                                       │    │
│   │ Content-Type: application/soap+xml; charset=utf-8              │    │
│   │ Content-Length: 800                                            │    │
│   │                                                                 │    │
│   │ <s:Envelope>                                                   │    │
│   │   <s:Header>                                                   │    │
│   │     <wsse:Security>                                            │    │
│   │       <wsse:UsernameToken>                                     │    │
│   │         <wsse:Username>admin</wsse:Username>                   │    │
│   │         <wsse:Password Type="#PasswordDigest">...</wsse:Password>│   │
│   │         <wsse:Nonce>...</wsse:Nonce>                           │    │
│   │         <wsu:Created>2024-01-15T10:30:45Z</wsu:Created>        │    │
│   │       </wsse:UsernameToken>                                    │    │
│   │     </wsse:Security>                                           │    │
│   │   </s:Header>                                                  │    │
│   │   <s:Body><GetDeviceInformation/></s:Body>                     │    │
│   │ </s:Envelope>                                                  │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   2. Server validates WS-Security and responds directly                  │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │ HTTP/1.1 200 OK                                                │    │
│   │ Content-Type: application/soap+xml; charset=utf-8              │    │
│   │ Content-Length: 850                                            │    │
│   │                                                                 │    │
│   │ <s:Envelope>...<GetDeviceInformationResponse>...</s:Envelope>  │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## TCP Socket Implementation

### Server Setup

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int create_server(int port) {
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    // Enable address reuse
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind to address
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    
    // Listen for connections
    listen(sock, 5);
    
    return sock;
}
```

### Main Server Loop

```c
void server_loop(int server_sock) {
    char buffer[65536];
    
    while (1) {
        // Accept connection
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, 
                                 (struct sockaddr *)&client_addr, 
                                 &client_len);
        if (client_sock < 0) continue;
        
        // Receive request
        memset(buffer, 0, sizeof(buffer));
        ssize_t n = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) {
            close(client_sock);
            continue;
        }
        buffer[n] = '\0';
        
        // Process request
        process_request(client_sock, buffer);
        
        // Close connection
        close(client_sock);
    }
}
```

### Processing Requests

```c
void process_request(int client_sock, const char *request) {
    // Check operation type
    if (strstr(request, "GetSystemDateAndTime")) {
        // Public operation - no auth needed
        handle_get_datetime(client_sock, request);
    }
    else if (strstr(request, "GetDeviceInformation")) {
        // Protected operation
        if (has_any_authentication(request)) {
            handle_get_device_info(client_sock, request);
        } else {
            send_401_challenge(client_sock);
        }
    }
    else {
        send_400_bad_request(client_sock);
    }
}
```

### Building HTTP Response

```c
void send_soap_response(int sock, const char *soap_body) {
    char response[65536];
    
    snprintf(response, sizeof(response),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             strlen(soap_body),
             soap_body);
    
    send(sock, response, strlen(response), 0);
}
```

---

## Debugging HTTP Traffic

### Wireshark Filters

```
# Capture ONVIF traffic
tcp port 7000

# HTTP POST requests
http.request.method == "POST"

# Specific host
ip.addr == 192.168.1.100

# Contains specific text
http contains "GetDeviceInformation"
```

### curl Testing

```bash
# Test GetSystemDateAndTime (no auth)
curl -X POST http://192.168.1.100:7000/onvif/device_service \
  -H "Content-Type: application/soap+xml; charset=utf-8" \
  -d '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'

# Test with Digest auth
curl -X POST http://192.168.1.100:7000/onvif/device_service \
  --digest -u admin:pass \
  -H "Content-Type: application/soap+xml; charset=utf-8" \
  -d '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'

# Verbose output
curl -v -X POST ...
```

### Server-Side Logging

```c
void log_request(const char *request, ssize_t len) {
    printf("\n[TCP] Received Request (%zd bytes)\n", len);
    printf("----------------------------------------\n");
    
    // Print first few lines (headers)
    const char *body = strstr(request, "\r\n\r\n");
    if (body) {
        int header_len = body - request;
        printf("Headers:\n%.*s\n", header_len, request);
        printf("Body starts at offset %d\n", header_len + 4);
    }
    printf("----------------------------------------\n");
}
```

### Common Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| Missing Content-Length | Client hangs | Always include header |
| Wrong Content-Type | Client error | Use `application/soap+xml` |
| Connection not closed | Resources leak | Add `Connection: close` or close socket |
| Buffer too small | Truncated messages | Use 65536+ byte buffer |
| Missing `\r\n\r\n` | Parse fails | Ensure header/body separator |

---

## Quick Reference

### Minimal Valid Request

```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:7000
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 200

<SOAP Body>
```

### Minimal Valid Response

```http
HTTP/1.1 200 OK
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 800
Connection: close

<SOAP Body>
```

### Status Code Quick Reference

| Code | Send When |
|------|-----------|
| 200 | Success |
| 400 | Bad SOAP/XML |
| 401 | Auth needed/failed |
| 500 | Server error |

---

*Continue to [07-Integration-Guide.md](./07-Integration-Guide.md) →*
