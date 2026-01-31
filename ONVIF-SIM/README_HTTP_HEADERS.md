# HTTP Headers and ONVIF Integration Guide

## Table of Contents
1. [HTTP Protocol Basics](#http-protocol-basics)
2. [HTTP Request Structure](#http-request-structure)
3. [HTTP Response Structure](#http-response-structure)
4. [Authentication Headers](#authentication-headers)
5. [HTTP Digest Challenge-Response](#http-digest-challenge-response)
6. [SOAP over HTTP](#soap-over-http)
7. [ONVIF-Specific HTTP Usage](#onvif-specific-http-usage)
8. [Parsing HTTP Headers](#parsing-http-headers)
9. [Building HTTP Messages](#building-http-messages)
10. [Common Issues and Solutions](#common-issues-and-solutions)

## HTTP Protocol Basics

### What is HTTP?

**HTTP** (HyperText Transfer Protocol) is an application-layer protocol for distributed, collaborative, hypermedia information systems.

```
┌────────────────────────────────────────────┐
│         Application Layer                  │
│  ┌──────────┐         ┌──────────┐        │
│  │  Client  │ ◄─────► │  Server  │        │
│  └──────────┘         └──────────┘        │
├────────────────────────────────────────────┤
│    HTTP (Request/Response Protocol)        │
├────────────────────────────────────────────┤
│    TCP (Reliable Transport)                │
├────────────────────────────────────────────┤
│    IP (Network Layer)                      │
└────────────────────────────────────────────┘
```

### HTTP Versions

| Version | Year | Features |
|---------|------|----------|
| HTTP/0.9 | 1991 | Simple GET only |
| HTTP/1.0 | 1996 | Headers, methods, status codes |
| **HTTP/1.1** | 1997 | **Persistent connections, chunked encoding** |
| HTTP/2 | 2015 | Binary protocol, multiplexing |
| HTTP/3 | 2022 | QUIC transport |

**ONVIF uses HTTP/1.1** primarily.

### Request-Response Model

```
Client                          Server
  │                               │
  ├─── HTTP Request ─────────────>│
  │                               │
  │<────── HTTP Response ─────────┤
  │                               │
```

## HTTP Request Structure

### Complete Anatomy

```http
POST /onvif/device_service HTTP/1.1              ← Request Line
Host: 192.168.1.100:8080                         ← Headers
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 450
Authorization: Digest username="admin", ...
Connection: keep-alive
                                                 ← Blank Line
<?xml version="1.0"?>                            ← Body (Optional)
<s:Envelope>
  ...
</s:Envelope>
```

### 1. Request Line

```
METHOD PATH HTTP-VERSION
```

**Format:**
- **METHOD**: HTTP verb (GET, POST, PUT, DELETE, etc.)
- **PATH**: Resource identifier (URI)
- **HTTP-VERSION**: Protocol version (HTTP/1.1)

**Examples:**
```http
GET /onvif/device_service HTTP/1.1
POST /onvif/device_service HTTP/1.1
PUT /config/settings HTTP/1.1
DELETE /camera/profile/1 HTTP/1.1
```

### 2. HTTP Methods

| Method | Purpose | Has Body | Idempotent | Safe |
|--------|---------|----------|------------|------|
| **GET** | Retrieve resource | No | Yes | Yes |
| **POST** | Create/Submit data | Yes | No | No |
| **PUT** | Update resource | Yes | Yes | No |
| **DELETE** | Delete resource | No | Yes | No |
| **HEAD** | Get headers only | No | Yes | Yes |
| **OPTIONS** | Query capabilities | No | Yes | Yes |

**ONVIF uses POST** for most operations (SOAP requests).

### 3. Request Headers

Headers provide metadata about the request:

```http
Host: 192.168.1.100:8080
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 450
User-Agent: ONVIF-Client/1.0
Accept: application/soap+xml
Connection: keep-alive
Authorization: Digest username="admin", ...
```

#### Common Request Headers

| Header | Purpose | Example |
|--------|---------|---------|
| **Host** | Target server | `Host: 192.168.1.100:8080` |
| **Content-Type** | Body format | `Content-Type: application/soap+xml` |
| **Content-Length** | Body size (bytes) | `Content-Length: 450` |
| **Authorization** | Credentials | `Authorization: Digest ...` |
| **User-Agent** | Client info | `User-Agent: ONVIF-Client/1.0` |
| **Accept** | Accepted formats | `Accept: application/soap+xml` |
| **Connection** | Connection control | `Connection: keep-alive` |

### 4. Request Body

Optional data sent with request (POST, PUT):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformation 
         xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

### Complete Example

```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 235
Connection: close

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetSystemDateAndTime xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

## HTTP Response Structure

### Complete Anatomy

```http
HTTP/1.1 200 OK                                  ← Status Line
Content-Type: application/soap+xml; charset=utf-8  ← Headers
Content-Length: 520
Connection: close
Date: Wed, 31 Jan 2024 10:15:30 GMT
Server: ONVIF-Server/1.0
                                                 ← Blank Line
<?xml version="1.0"?>                            ← Body
<s:Envelope>
  ...
</s:Envelope>
```

### 1. Status Line

```
HTTP-VERSION STATUS-CODE REASON-PHRASE
```

**Examples:**
```http
HTTP/1.1 200 OK
HTTP/1.1 401 Unauthorized
HTTP/1.1 404 Not Found
HTTP/1.1 500 Internal Server Error
```

### 2. HTTP Status Codes

| Code | Category | Meaning |
|------|----------|---------|
| **1xx** | Informational | Request received, continuing |
| **2xx** | Success | Request successful |
| **3xx** | Redirection | Further action needed |
| **4xx** | Client Error | Bad request |
| **5xx** | Server Error | Server failed |

#### Common Status Codes in ONVIF

| Code | Status | Use Case |
|------|--------|----------|
| **200** | OK | Successful operation |
| **400** | Bad Request | Malformed SOAP |
| **401** | Unauthorized | Authentication required |
| **403** | Forbidden | Access denied |
| **404** | Not Found | Unknown service |
| **500** | Internal Server Error | Server error |

### 3. Response Headers

```http
HTTP/1.1 200 OK
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 520
Connection: close
Date: Wed, 31 Jan 2024 10:15:30 GMT
Server: ONVIF-Server/1.0
```

#### Common Response Headers

| Header | Purpose | Example |
|--------|---------|---------|
| **Content-Type** | Body format | `Content-Type: application/soap+xml` |
| **Content-Length** | Body size | `Content-Length: 520` |
| **Connection** | Connection control | `Connection: close` |
| **Date** | Response timestamp | `Date: Wed, 31 Jan 2024 10:15:30 GMT` |
| **Server** | Server info | `Server: ONVIF-Server/1.0` |
| **WWW-Authenticate** | Auth challenge | `WWW-Authenticate: Digest realm=...` |

### 4. Response Body

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>Videonetics</tds:Manufacturer>
      <tds:Model>Camera_Emulator</tds:Model>
      <tds:FirmwareVersion>1.0</tds:FirmwareVersion>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>
```

## Authentication Headers

### Authorization Header

Used by **client** to send credentials:

```http
Authorization: <auth-scheme> <credentials>
```

**Schemes:**
- `Basic`: Base64-encoded username:password
- `Digest`: Challenge-response authentication
- `Bearer`: Token-based authentication

### WWW-Authenticate Header

Used by **server** to request authentication:

```http
WWW-Authenticate: <auth-scheme> <parameters>
```

**Example:**
```http
WWW-Authenticate: Digest realm="ONVIF_Device", qop="auth", nonce="abc123"
```

## HTTP Digest Challenge-Response

### Step 1: Client Request (No Auth)

```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: application/soap+xml
Content-Length: 235

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

### Step 2: Server Challenge (401)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="ONVIF_Device", 
                         qop="auth", 
                         nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                         algorithm=MD5
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 0
Connection: close
```

#### WWW-Authenticate Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| **realm** | Protection space | `"ONVIF_Device"` |
| **qop** | Quality of protection | `"auth"` or `"auth-int"` |
| **nonce** | Server challenge | `"abc123..."` |
| **algorithm** | Hash algorithm | `MD5` or `MD5-sess` |
| **opaque** | Server data (optional) | `"xyz..."` |

### Step 3: Client Response (With Auth)

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
Content-Length: 235

<?xml version="1.0"?>
<s:Envelope>...</s:Envelope>
```

#### Authorization Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| **username** | User identifier | Yes | `"admin"` |
| **realm** | From challenge | Yes | `"ONVIF_Device"` |
| **nonce** | From challenge | Yes | `"abc123..."` |
| **uri** | Request URI | Yes | `"/onvif/device_service"` |
| **response** | Computed digest | Yes | `"6629fae..."` |
| **qop** | Quality of protection | If in challenge | `auth` |
| **nc** | Nonce count | If qop present | `00000001` |
| **cnonce** | Client nonce | If qop present | `"0a4f113b"` |
| **algorithm** | Hash algorithm | Optional | `MD5` |
| **opaque** | From challenge | If present | `"xyz..."` |

### Step 4: Server Success (200)

```http
HTTP/1.1 200 OK
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 450
Connection: close

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>Videonetics</tds:Manufacturer>
      <tds:Model>Camera_Emulator</tds:Model>
      <tds:FirmwareVersion>1.0</tds:FirmwareVersion>
      <tds:SerialNumber>VN001</tds:SerialNumber>
      <tds:HardwareId>1.0</tds:HardwareId>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>
```

## SOAP over HTTP

### What is SOAP?

**SOAP** (Simple Object Access Protocol) is an XML-based messaging protocol.

**Why SOAP over HTTP?**
- ✅ Standardized protocol
- ✅ Works through firewalls (port 80/443)
- ✅ Platform independent
- ✅ Supports complex operations

### SOAP Message Structure

```http
POST /onvif/device_service HTTP/1.1
Host: camera.local:8080
Content-Type: application/soap+xml; charset=utf-8    ← Important!
Content-Length: <length>
SOAPAction: "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"

<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Header>
    <!-- Optional headers (WS-Security, etc.) -->
  </s:Header>
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>
```

### SOAP Content-Type

ONVIF uses:
```http
Content-Type: application/soap+xml; charset=utf-8
```

**Alternatives:**
- `application/soap+xml` (SOAP 1.2)
- `text/xml` (SOAP 1.1, legacy)

### SOAPAction Header (Optional)

```http
SOAPAction: "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
```

- Indicates the intent of the SOAP request
- Can be empty string: `SOAPAction: ""`
- ONVIF specification recommends including it

## ONVIF-Specific HTTP Usage

### Common ONVIF HTTP Patterns

#### 1. GetSystemDateAndTime (Unauthenticated)

```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 245

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetSystemDateAndTime xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 520

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetSystemDateAndTimeResponse>
      <tds:SystemDateAndTime>
        <tt:UTCDateTime>
          <tt:Time><tt:Hour>10</tt:Hour>...</tt:Time>
          <tt:Date><tt:Year>2024</tt:Year>...</tt:Date>
        </tt:UTCDateTime>
      </tds:SystemDateAndTime>
    </tds:GetSystemDateAndTimeResponse>
  </s:Body>
</s:Envelope>
```

#### 2. GetDeviceInformation (Authenticated - HTTP Digest)

**Initial Request (No Auth):**
```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: application/soap+xml
Content-Length: 250

<s:Envelope>
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>
```

**Server Challenge:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="ONVIF_Device", qop="auth", nonce="abc123", algorithm=MD5
Content-Length: 0
```

**Retry with Auth:**
```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Authorization: Digest username="admin", realm="ONVIF_Device", nonce="abc123", ...
Content-Type: application/soap+xml
Content-Length: 250

<s:Envelope>...</s:Envelope>
```

**Success:**
```http
HTTP/1.1 200 OK
Content-Type: application/soap+xml
Content-Length: 450

<s:Envelope>
  <s:Body>
    <tds:GetDeviceInformationResponse>
      ...
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>
```

#### 3. GetDeviceInformation (Authenticated - WS-Security)

**Single Request with Auth:**
```http
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: application/soap+xml
Content-Length: 650

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <wsse:Security s:mustUnderstand="1">
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="...#PasswordDigest">aGFzaA==</wsse:Password>
        <wsse:Nonce>bm9uY2U=</wsse:Nonce>
        <wsu:Created>2024-01-31T10:15:30Z</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>
```

### ONVIF Service Endpoints

Common ONVIF services and their typical paths:

| Service | Path | Purpose |
|---------|------|---------|
| Device Management | `/onvif/device_service` | Device info, configuration |
| Media | `/onvif/media_service` | Video profiles, streams |
| PTZ | `/onvif/ptz_service` | Pan, tilt, zoom control |
| Events | `/onvif/events_service` | Event subscription |
| Imaging | `/onvif/imaging_service` | Image settings |
| Analytics | `/onvif/analytics_service` | Video analytics |

## Parsing HTTP Headers

### Manual Parsing (C)

```c
#include <string.h>
#include <stdio.h>

void extract_header_value(const char *http_msg, const char *header_name, 
                          char *value, size_t value_size) {
    value[0] = '\0';
    
    // Find header name
    const char *header_start = strstr(http_msg, header_name);
    if (!header_start) return;
    
    // Skip to value (after ": ")
    const char *value_start = strstr(header_start, ": ");
    if (!value_start) return;
    value_start += 2;  // Skip ": "
    
    // Find end of line
    const char *value_end = strstr(value_start, "\r\n");
    if (!value_end) value_end = strstr(value_start, "\n");
    if (!value_end) return;
    
    // Copy value
    size_t len = value_end - value_start;
    if (len >= value_size) len = value_size - 1;
    memcpy(value, value_start, len);
    value[len] = '\0';
}

// Usage
char http_request[] = 
    "POST /path HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Content-Type: application/soap+xml\r\n"
    "\r\n";

char content_type[128];
extract_header_value(http_request, "Content-Type", content_type, sizeof(content_type));
printf("Content-Type: %s\n", content_type);
// Output: application/soap+xml
```

### Parsing Authorization Header

From `auth_utils.h`:

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

## Building HTTP Messages

### Building HTTP Request

```c
#include <stdio.h>
#include <string.h>

void build_http_request(const char *method, const char *path, 
                       const char *host, const char *body,
                       char *request, size_t request_size) {
    size_t body_len = body ? strlen(body) : 0;
    
    snprintf(request, request_size,
             "%s %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             method, path, host, body_len, body ? body : "");
}

// Usage
char request[4096];
const char *soap_body = 
    "<?xml version=\"1.0\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
    "  <s:Body>"
    "    <tds:GetSystemDateAndTime xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>"
    "  </s:Body>"
    "</s:Envelope>";

build_http_request("POST", "/onvif/device_service", "192.168.1.100:8080",
                   soap_body, request, sizeof(request));
```

### Building HTTP Response

```c
void build_http_response(int status_code, const char *status_text,
                        const char *body, char *response, size_t response_size) {
    size_t body_len = body ? strlen(body) : 0;
    
    snprintf(response, response_size,
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             status_code, status_text, body_len, body ? body : "");
}

// Usage
char response[4096];
build_http_response(200, "OK", soap_response_body, response, sizeof(response));
```

### Building 401 Challenge

```c
void build_401_challenge(const char *nonce, char *response, size_t response_size) {
    snprintf(response, response_size,
             "HTTP/1.1 401 Unauthorized\r\n"
             "WWW-Authenticate: Digest realm=\"ONVIF_Device\", "
             "qop=\"auth\", nonce=\"%s\", algorithm=MD5\r\n"
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "Content-Length: 0\r\n"
             "Connection: close\r\n"
             "\r\n",
             nonce);
}

// Usage
char nonce[33];
generate_nonce(nonce, sizeof(nonce));
char challenge[1024];
build_401_challenge(nonce, challenge, sizeof(challenge));
send(client_socket, challenge, strlen(challenge), 0);
```

## Common Issues and Solutions

### Issue 1: Missing Content-Length

❌ **Problem:**
```http
POST /path HTTP/1.1
Host: example.com
Content-Type: application/soap+xml

<s:Envelope>...</s:Envelope>
```

Server doesn't know where body ends!

✓ **Solution:**
```http
POST /path HTTP/1.1
Host: example.com
Content-Type: application/soap+xml
Content-Length: 235

<s:Envelope>...</s:Envelope>
```

### Issue 2: Missing Blank Line

❌ **Problem:**
```http
POST /path HTTP/1.1
Host: example.com
Content-Length: 10
Hello Body
```

No separation between headers and body!

✓ **Solution:**
```http
POST /path HTTP/1.1
Host: example.com
Content-Length: 10

Hello Body
```

### Issue 3: Wrong Line Endings

❌ **Problem:**
```c
char request[] = "POST /path HTTP/1.1\n"  // Wrong: \n
                 "Host: example.com\n";
```

HTTP requires `\r\n` (CRLF), not just `\n` (LF)!

✓ **Solution:**
```c
char request[] = "POST /path HTTP/1.1\r\n"  // Correct: \r\n
                 "Host: example.com\r\n"
                 "\r\n";
```

### Issue 4: Case Sensitivity

HTTP header **names** are case-insensitive:
```http
Content-Type: ...    ← OK
content-type: ...    ← OK
CONTENT-TYPE: ...    ← OK
```

But header **values** may be case-sensitive:
```http
Authorization: Digest username="Admin"   ← Different from "admin"
```

### Issue 5: Chunked Transfer Encoding

Some clients/servers use chunked encoding:

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked

1A
This is chunk 1 of data
0

```

**Solution:** Check for `Transfer-Encoding: chunked` and parse accordingly.

### Issue 6: Keep-Alive Connections

```http
Connection: keep-alive
```

Server must keep socket open for subsequent requests!

```http
Connection: close
```

Server should close socket after response.

### Issue 7: Character Encoding

Always specify charset:
```http
Content-Type: application/soap+xml; charset=utf-8
```

Not:
```http
Content-Type: application/soap+xml
```

## Quick Reference

### Request Template

```http
POST <path> HTTP/1.1
Host: <host>:<port>
Content-Type: application/soap+xml; charset=utf-8
Content-Length: <length>
[Authorization: Digest ...]

<SOAP body>
```

### Response Template

```http
HTTP/1.1 <code> <status>
Content-Type: application/soap+xml; charset=utf-8
Content-Length: <length>
Connection: close

<SOAP body>
```

### 401 Challenge Template

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="<realm>", qop="<qop>", nonce="<nonce>", algorithm=<algo>
Content-Length: 0
Connection: close

```

## Testing with cURL

### Simple SOAP Request

```bash
curl -X POST http://192.168.1.100:8080/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  -d '<?xml version="1.0"?>
      <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
        <s:Body>
          <tds:GetSystemDateAndTime xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
        </s:Body>
      </s:Envelope>'
```

### With HTTP Digest Auth

```bash
curl -X POST http://192.168.1.100:8080/onvif/device_service \
  --digest \
  --user admin:password123 \
  -H "Content-Type: application/soap+xml" \
  -d '<s:Envelope>...</s:Envelope>'
```

### Show Headers

```bash
curl -v http://192.168.1.100:8080/onvif/device_service
```

## Conclusion

Understanding HTTP headers is crucial for ONVIF integration:

✅ **Request/Response structure**
✅ **Authentication headers** (Authorization, WWW-Authenticate)
✅ **SOAP over HTTP** (Content-Type, Content-Length)
✅ **Header parsing and building**
✅ **Common issues and solutions**

**Key Takeaways:**
1. Always include `Content-Length` and `Content-Type`
2. Use `\r\n` (CRLF) for line endings
3. Include blank line between headers and body
4. Handle 401 challenges correctly
5. Specify charset in Content-Type

For more information, see:
- README_ONVIF_AUTHENTICATION.md
- README_AUTH_UTILS.md
- README_XML_ONVIF.md

## Further Reading

- [RFC 2616 - HTTP/1.1](https://tools.ietf.org/html/rfc2616)
- [RFC 7230-7237 - HTTP/1.1 (Updated)](https://tools.ietf.org/html/rfc7230)
- [RFC 2617 - HTTP Digest Authentication](https://tools.ietf.org/html/rfc2617)
- [ONVIF Core Specification](https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf)
