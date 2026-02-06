# ONVIF Project - Modular Design & Architecture Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Project Structure Overview](#project-structure-overview)
3. [Architectural Principles](#architectural-principles)
4. [Core Modules](#core-modules)
5. [Module Interactions](#module-interactions)
6. [Configuration System](#configuration-system)
7. [Threading Model](#threading-model)
8. [Adding New Authentication Methods](#adding-new-authentication-methods)
9. [Adding New ONVIF Services](#adding-new-onvif-services)
10. [Best Practices](#best-practices)
11. [Design Patterns Used](#design-patterns-used)
12. [Related Documentation](#related-documentation)

---

## Introduction

This ONVIF Camera Simulator is designed with **modularity** and **separation of concerns** as core principles. Each component has a single, well-defined responsibility and interacts with others through clear interfaces.

### Why Modular Design?

| Benefit | Description |
|---------|-------------|
| **Maintainability** | Changes to one module don't break others |
| **Testability** | Each module can be tested independently |
| **Scalability** | Easy to add new features without refactoring |
| **Readability** | Clear structure makes code easier to understand |
| **Reusability** | Modules can be reused in other projects |

---

## Project Structure Overview

```
ONVIF-SIM/
├── fakecamera/                    # Main camera simulator
│   ├── main.c                     # Entry point, thread orchestration
│   ├── config.h                   # Configuration constants and structures
│   ├── config.xml                 # Device configuration file
│   ├── Credentials.csv            # User credentials database
│   ├── Attempts.csv               # Authentication attempt logs
│   │
│   ├── discovery_server.h         # WS-Discovery module
│   ├── dis_utils.h                # Discovery utilities
│   │
│   ├── auth_server.h              # Main TCP/HTTP ONVIF server
│   ├── tcp_config.h               # SOAP response templates
│   │
│   ├── authhandler/               # Authentication module
│   │   ├── auth_utils.h           # Core auth utilities
│   │   ├── digest_auth.h          # HTTP Digest implementation
│   │   └── README_AUTH_UTILS.md   # Auth module documentation
│   │
│   ├── simpleparser.h             # XML parsing utilities
│   └── *.xml                      # Various XML templates/logs
│
└── CamDiscoverer/                 # Discovery client
    └── camdis.c                   # WS-Discovery client implementation
```

### File Categorization

| Category | Files | Purpose |
|----------|-------|---------|
| **Entry Point** | `main.c` | Thread creation, orchestration |
| **Configuration** | `config.h`, `config.xml` | System-wide settings |
| **Discovery** | `discovery_server.h`, `dis_utils.h` | WS-Discovery (UDP multicast) |
| **ONVIF Services** | `auth_server.h`, `tcp_config.h` | HTTP/SOAP server |
| **Authentication** | `authhandler/auth_utils.h`, `digest_auth.h` | Auth verification |
| **Utilities** | `simpleparser.h` | XML parsing helpers |
| **Data** | `Credentials.csv`, `Attempts.csv` | User database, logs |

---

## Architectural Principles

### 1. Separation of Concerns

Each module handles **one responsibility**:

```
┌─────────────────┐
│   main.c        │  ← Orchestration only
└────────┬────────┘
         │
    ┌────┴────┬──────────────┐
    │         │              │
    v         v              v
┌──────┐  ┌──────┐      ┌──────┐
│Discov│  │Auth  │      │ONVIF │
│ery   │  │Handler│     │Server│
└──────┘  └──────┘      └──────┘
```

### 2. Header-Only Modules

Most modules are **header-only** (`*.h` files):
- No separate `.c` compilation needed
- Easy to include where needed
- Inline functions for small utilities

### 3. Configuration-Driven

All behavior controlled by:
- `config.h` - Compile-time constants
- `config.xml` - Runtime device settings
- `Credentials.csv` - User data

### 4. Thread-Based Architecture

Two independent servers in separate threads:
```
Main Thread
├── Thread 1: Discovery Server (UDP multicast)
└── Thread 2: ONVIF Server (TCP HTTP/SOAP)
```

---

## Core Modules

### Module 1: Entry Point (`main.c`)

**Responsibility**: Start all services

```c
int main(void) {
    pthread_t t_disc, tcpserv;
    
    // Start WS-Discovery server (UDP)
    pthread_create(&t_disc, NULL, discovery, NULL);
    
    // Start ONVIF HTTP server (TCP)
    pthread_create(&tcpserv, NULL, tcpserver, NULL);
    
    pthread_join(t_disc, NULL);
    pthread_join(tcpserv, NULL);
    return 0;
}
```

**Key Points**:
- Minimal logic - just thread management
- No business logic
- Clean shutdown handling

---

### Module 2: Configuration (`config.h`)

**Responsibility**: System-wide constants and data structures

```c
#define DISCOVERY_PORT      3702
#define MULTICAST_ADDR      "239.255.255.250"
#define CAMERA_NAME         "Videonetics_Camera_Emulator"
#define CAMERA_HTTP_PORT    8080
#define BUFFER_SIZE         65536

typedef struct datafromxml {
    uint16_t server_port;
    char manufacturer[64];
    char model[64];
    float firmware_version;
    char serial_number[32];
    float hardware_id;
    char type[64];
    char profile[64];
    char hardware[64];
    char location[64];
} config;
```

**Contains**:
- Network settings (ports, addresses)
- Buffer sizes
- Device information structure
- SOAP templates (e.g., `PROBE_MATCH_TEMPLATE`)

---

### Module 3: Discovery Server (`discovery_server.h`)

**Responsibility**: Implement WS-Discovery protocol (ONVIF device announcement)

#### Key Functions

```c
void *discovery(void *arg) {
    // 1. Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    // 2. Bind to multicast port 3702
    bind(sock, ...);
    
    // 3. Join multicast group 239.255.255.250
    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, ...);
    
    // 4. Listen for Probe requests
    while (1) {
        recvfrom(sock, buffer, ...);
        
        // 5. Parse and respond with ProbeMatch
        if (is_probe_request(buffer)) {
            send_probe_match(sock, ...);
        }
    }
}
```

#### Dependencies
- `config.h` - For DISCOVERY_PORT, MULTICAST_ADDR, PROBE_MATCH_TEMPLATE
- `dis_utils.h` - For helper functions:
  - `getlocalip()` - Get device IP
  - `initdevice_uuid()` - Generate device UUID
  - `getmessageid()` - Extract MessageID from XML

#### Isolation
- **No** auth logic
- **No** SOAP processing (only WS-Discovery XML)
- Independent of ONVIF service handlers

---

### Module 4: ONVIF Server (`auth_server.h`)

**Responsibility**: Handle ONVIF HTTP/SOAP requests

#### Architecture
```
TCP Server (port 8080)
    │
    ├─► Parse HTTP request
    │
    ├─► Extract SOAP body
    │
    ├─► Route based on Action:
    │   ├─► GetSystemDateAndTime → No auth required
    │   ├─► GetDeviceInformation → Check auth
    │   └─► GetServices → Check auth
    │
    └─► Send HTTP response with SOAP body
```

#### Key Functions

```c
void *tcpserver(void *arg) {
    // 1. Load configuration
    config cfg;
    load_config("config.xml", &cfg);
    
    // 2. Create TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    bind(sock, ...);
    listen(sock, 5);
    
    while (1) {
        // 3. Accept client connection
        int client = accept(sock, ...);
        
        // 4. Receive HTTP request
        recv(client, buffer, ...);
        
        // 5. Route based on request content
        if (strstr(buffer, "GetSystemDateAndTime")) {
            handle_get_datetime(client, buffer);
        }
        else if (strstr(buffer, "GetDeviceInformation")) {
            if (has_any_authentication(buffer)) {
                handle_get_device_info(client, buffer, &cfg);
            } else {
                send_auth_required(client);
            }
        }
        
        close(client);
    }
}
```

#### Request Routing

```c
int has_any_authentication(const char *request) {
    // 1. Check WS-UsernameToken (in SOAP body)
    if (strstr(request, "wsse:Security")) {
        return verify_ws_security(request);
    }
    
    // 2. Check HTTP Digest (in HTTP headers)
    if (strstr(request, "Authorization: Digest")) {
        return verify_http_digest(request, "POST");
    }
    
    return 0;  // No auth found
}
```

#### Dependencies
- `tcp_config.h` - SOAP response templates
- `authhandler/auth_utils.h` - Authentication verification
- `simpleparser.h` - XML parsing
- `config.h` - Server configuration

---

### Module 5: SOAP Templates (`tcp_config.h`)

**Responsibility**: Store reusable SOAP response templates

```c
const char *GET_DATE_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope ...>"
    "..."
    "</s:Envelope>";

const char *GET_DEVICE_INFO_TEMPLATE = "...";
const char *GET_SERVICES_TEMPLATE = "...";
```

**Why Separate?**
- Keeps XML out of logic code
- Easy to modify responses
- Reusable across multiple handlers

---

### Module 6: Authentication Handler (`authhandler/`)

**Responsibility**: All authentication logic

#### Submodules

| File | Purpose |
|------|---------|
| `auth_utils.h` | Core auth functions (WS-Security, credential lookup) |
| `digest_auth.h` | HTTP Digest authentication |
| `README_AUTH_UTILS.md` | Documentation |

#### Key Functions

**WS-Security Verification** (`auth_utils.h`):
```c
bool verify_ws_security(const char *request) {
    // 1. Extract username, nonce, created, password digest
    char username[64], nonce[128], created[32], digest[128];
    extract_username(request, username, sizeof(username));
    extract_nonce(request, nonce, sizeof(nonce));
    extract_created(request, created, sizeof(created));
    extract_passwd(request, digest, sizeof(digest));
    
    // 2. Look up user's real password from CSV
    char real_password[64];
    if (!get_password_from_csv(username, real_password, sizeof(real_password))) {
        return false;  // User not found
    }
    
    // 3. Compute expected digest: Base64(SHA1(Nonce + Created + Password))
    unsigned char expected_digest[20];
    compute_password_digest(nonce, created, real_password, expected_digest);
    
    // 4. Compare
    return (strcmp(digest, expected_digest) == 0);
}
```

**HTTP Digest Verification** (`digest_auth.h`):
```c
bool verify_http_digest(const char *request, const char *method) {
    // Parse Authorization header
    char username[64], realm[64], nonce[128], uri[256], response[64];
    parse_digest_header(request, username, realm, nonce, uri, response);
    
    // Look up password
    char password[64];
    get_password_from_csv(username, password, sizeof(password));
    
    // Compute HA1 = MD5(username:realm:password)
    // Compute HA2 = MD5(method:uri)
    // Compute response = MD5(HA1:nonce:HA2)
    char expected_response[64];
    compute_digest_response(username, realm, password, nonce, method, uri, expected_response);
    
    return (strcmp(response, expected_response) == 0);
}
```

#### Credential Storage (`Credentials.csv`)
```csv
admin,admin123,active
user1,pass456,active
testuser,testpass,disabled
```

**Access via**:
```c
bool get_password_from_csv(const char *username, char *password_out, size_t size) {
    FILE *fp = fopen("Credentials.csv", "r");
    // ... parse CSV, match username, return password
}
```

---

### Module 7: XML Parser (`simpleparser.h`)

**Responsibility**: Extract XML tag values

```c
uint8_t get_the_tag(const char *line, const char *tag, 
                    char *out, size_t out_size) {
    // Find <tag>content</tag> and extract "content"
}

int load_config(const char *filename, config *cfg) {
    // Parse config.xml into config struct
}
```

**Used By**:
- `auth_server.h` - Extract MessageID, Action
- `authhandler/auth_utils.h` - Extract username, password, nonce
- `discovery_server.h` - Extract discovery request fields

---

### Module 8: Discovery Utilities (`dis_utils.h`)

**Responsibility**: Helper functions for WS-Discovery

```c
void getlocalip(char *ip_buf, size_t size);
void initdevice_uuid(void);
void getmessageid(const char *xml, char *out, size_t size);
int is_probe_request(const char *xml);
void send_probe_match(int sock, struct sockaddr_in *dest, 
                      const char *request_msg_id);
```

---

## Module Interactions

### Discovery Flow

```
┌─────────────┐
│   Client    │
│ (Discovery) │
└──────┬──────┘
       │ UDP Multicast
       │ Probe Request
       v
┌──────────────────────────────────────┐
│    discovery_server.h                │
│  ┌────────────────────────────────┐  │
│  │ 1. Receive Probe               │  │
│  └─────────┬──────────────────────┘  │
│            v                          │
│  ┌────────────────────────────────┐  │
│  │ 2. Parse with dis_utils.h      │  │
│  └─────────┬──────────────────────┘  │
│            v                          │
│  ┌────────────────────────────────┐  │
│  │ 3. Fill PROBE_MATCH_TEMPLATE   │  │
│  │    (from config.h)             │  │
│  └─────────┬──────────────────────┘  │
│            v                          │
│  ┌────────────────────────────────┐  │
│  │ 4. Send ProbeMatch response    │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
       │
       v
┌─────────────┐
│   Client    │
│ (Receives)  │
└─────────────┘
```

---

### ONVIF Request Flow (Authenticated)

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTP POST
       │ GetDeviceInformation
       │ + WS-Security header
       v
┌────────────────────────────────────────────────┐
│              auth_server.h                     │
│  ┌──────────────────────────────────────────┐  │
│  │ 1. Receive HTTP request                  │  │
│  └──────────┬───────────────────────────────┘  │
│             v                                   │
│  ┌──────────────────────────────────────────┐  │
│  │ 2. has_any_authentication()?             │  │
│  │    ├─► Check for wsse:Security           │  │
│  │    └─► Check for Authorization: Digest   │  │
│  └──────────┬───────────────────────────────┘  │
│             v                                   │
│  ┌──────────────────────────────────────────┐  │
│  │ 3. Call authhandler/auth_utils.h         │  │
│  │    verify_ws_security()                  │  │
│  └──────────┬───────────────────────────────┘  │
└─────────────┼───────────────────────────────────┘
              v
┌─────────────────────────────────────────────────┐
│         authhandler/auth_utils.h                │
│  ┌────────────────────────────────────────────┐ │
│  │ 1. Extract username/password/nonce        │ │
│  │    (using simpleparser.h::get_the_tag)    │ │
│  └──────────┬─────────────────────────────────┘ │
│             v                                    │
│  ┌────────────────────────────────────────────┐ │
│  │ 2. get_password_from_csv(username)        │ │
│  │    → Read Credentials.csv                 │ │
│  └──────────┬─────────────────────────────────┘ │
│             v                                    │
│  ┌────────────────────────────────────────────┐ │
│  │ 3. Compute password digest                │ │
│  │    SHA1(Nonce + Created + Password)       │ │
│  │    (using OpenSSL)                        │ │
│  └──────────┬─────────────────────────────────┘ │
│             v                                    │
│  ┌────────────────────────────────────────────┐ │
│  │ 4. Compare digests → Return true/false    │ │
│  └────────────────────────────────────────────┘ │
└─────────────┬───────────────────────────────────┘
              v
┌─────────────────────────────────────────────────┐
│              auth_server.h                      │
│  ┌────────────────────────────────────────────┐ │
│  │ If verified:                               │ │
│  │   - Load config (simpleparser.h)           │ │
│  │   - Fill GET_DEVICE_INFO_TEMPLATE          │ │
│  │   - Send HTTP 200 + SOAP response          │ │
│  │                                            │ │
│  │ If NOT verified:                           │ │
│  │   - Send HTTP 401 Unauthorized             │ │
│  └────────────────────────────────────────────┘ │
└─────────────┬───────────────────────────────────┘
              v
       ┌─────────────┐
       │   Client    │
       └─────────────┘
```

---

## Configuration System

### Two-Tier Configuration

| Type | File | Purpose | When Loaded |
|------|------|---------|-------------|
| **Compile-time** | `config.h` | Constants, macros, templates | During compilation |
| **Runtime** | `config.xml` | Device metadata (manufacturer, model, etc.) | At server startup |

### Example: config.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <server_port>8080</server_port>
    <manufacturer>Videonetics</manufacturer>
    <model>Videonetics_Camera_Emulator</model>
    <firmware_version>10.0</firmware_version>
    <serial_number>12345</serial_number>
    <hardware>ARM_v8</hardware>
    <hardware_id>1</hardware_id>
    <location>Building_A</location>
    <profile>S</profile>
    <type>Network_Video_Transmitter</type>
</config>
```

### Loading Configuration

```c
config cfg = {0};
load_config("config.xml", &cfg);

printf("Manufacturer: %s\n", cfg.manufacturer);
printf("Model: %s\n", cfg.model);
printf("Port: %d\n", cfg.server_port);
```

**Advantage**: Change device details without recompilation

---

## Threading Model

### Thread Architecture

```
┌──────────────────────────────────────────────┐
│             Main Thread (main.c)             │
│  ┌────────────────────────────────────────┐  │
│  │ pthread_create(&t_disc, ...)           │  │
│  │ pthread_create(&tcpserv, ...)          │  │
│  │ pthread_join(...)                      │  │
│  └────────────────────────────────────────┘  │
└──────────────┬───────────────┬───────────────┘
               │               │
      ┌────────┘               └────────┐
      v                                 v
┌─────────────────┐           ┌─────────────────┐
│  Thread 1:      │           │  Thread 2:      │
│  discovery()    │           │  tcpserver()    │
│                 │           │                 │
│  - UDP Socket   │           │  - TCP Socket   │
│  - Port 3702    │           │  - Port 8080    │
│  - Multicast    │           │  - HTTP/SOAP    │
└─────────────────┘           └─────────────────┘
```

### Why Two Threads?

| Reason | Benefit |
|--------|---------|
| **Independent protocols** | UDP (discovery) and TCP (ONVIF) don't interfere |
| **Blocking I/O** | Each thread can block on its own socket |
| **Concurrency** | Handle discovery and ONVIF requests simultaneously |
| **Clean separation** | Discovery logic isolated from ONVIF service logic |

### Thread Safety

**No shared state between threads**:
- Each thread has its own socket
- Each thread has its own buffers
- Configuration is read-only after load

**No mutexes needed** (currently):
- Threads don't write to shared memory
- `Credentials.csv` is read-only
- Each request is handled independently

**Future consideration**: If adding logging or statistics, use mutexes:
```c
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_request(const char *msg) {
    pthread_mutex_lock(&log_mutex);
    fprintf(log_file, "%s\n", msg);
    pthread_mutex_unlock(&log_mutex);
}
```

---

## Adding New Authentication Methods

### Example: Adding OAuth 2.0

**Step 1: Create new auth module**

Create `authhandler/oauth_auth.h`:
```c
#ifndef OAUTH_AUTH_H
#define OAUTH_AUTH_H

#include <stdbool.h>
#include <string.h>

// Extract Bearer token from HTTP header
bool extract_bearer_token(const char *request, char *token, size_t size) {
    const char *auth_header = strstr(request, "Authorization: Bearer ");
    if (!auth_header) return false;
    
    auth_header += strlen("Authorization: Bearer ");
    sscanf(auth_header, "%s", token);
    return true;
}

// Verify token (e.g., check against database or validate JWT)
bool verify_oauth_token(const char *token) {
    // Implementation: Check token validity
    // For now, simple comparison
    return (strcmp(token, "valid_token_12345") == 0);
}

#endif
```

**Step 2: Update `auth_server.h`**

```c
#include "authhandler/oauth_auth.h"

int has_any_authentication(const char *request) {
    // Existing checks...
    
    // 3. OAuth Bearer Token
    if (strstr(request, "Authorization: Bearer")) {
        printf("[Auth] Checking OAuth Bearer Token...\n");
        char token[256];
        if (extract_bearer_token(request, token, sizeof(token))) {
            if (verify_oauth_token(token)) {
                printf("[Auth] OAuth Token Verified!\n");
                return 1;
            }
        }
        printf("[Auth] OAuth Token Failed.\n");
    }
    
    return 0;
}
```

**Step 3: Test**

Send request with:
```
POST /onvif/device_service HTTP/1.1
Authorization: Bearer valid_token_12345
Content-Type: application/soap+xml
...
```

---

## Adding New ONVIF Services

### Example: Adding GetProfiles (Media Service)

**Step 1: Define SOAP template in `tcp_config.h`**

```c
const char *GET_PROFILES_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Header>"
        "<a:Action xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">"
            "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse"
        "</a:Action>"
        "<a:RelatesTo xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">%s</a:RelatesTo>"
    "</s:Header>"
    "<s:Body>"
        "<trt:GetProfilesResponse>"
            "<trt:Profiles token=\"Profile_1\">"
                "<tt:Name>MainStream</tt:Name>"
                "<tt:VideoSourceConfiguration>"
                    "<tt:SourceToken>VideoSource_1</tt:SourceToken>"
                    "<tt:Bounds height=\"1080\" width=\"1920\" x=\"0\" y=\"0\"/>"
                "</tt:VideoSourceConfiguration>"
                "<tt:VideoEncoderConfiguration>"
                    "<tt:Encoding>H264</tt:Encoding>"
                    "<tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>"
                    "<tt:Quality>5.0</tt:Quality>"
                    "<tt:RateControl>"
                        "<tt:FrameRateLimit>30</tt:FrameRateLimit>"
                        "<tt:BitrateLimit>4096</tt:BitrateLimit>"
                    "</tt:RateControl>"
                "</tt:VideoEncoderConfiguration>"
            "</trt:Profiles>"
        "</trt:GetProfilesResponse>"
    "</s:Body>"
    "</s:Envelope>";
```

**Step 2: Add handler in `auth_server.h`**

```c
void *tcpserver(void *arg) {
    // ... existing code ...
    
    while (1) {
        // ... accept, recv ...
        
        // NEW: Handle GetProfiles
        else if (strstr(buf, "GetProfiles")) {
            if (has_any_authentication(buf)) {
                printf("[TCP] Req: GetProfiles (Auth Present) -> ALLOWED\n");
                
                // Extract MessageID
                char request_msg_id[256];
                getmessageid1(buf, request_msg_id, sizeof(request_msg_id));
                
                // Fill template
                char soap_res[4096];
                snprintf(soap_res, sizeof(soap_res), GET_PROFILES_TEMPLATE, request_msg_id);
                
                // Send HTTP response
                char http_res[8192];
                snprintf(http_res, sizeof(http_res),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/soap+xml; charset=utf-8\r\n"
                         "Content-Length: %zu\r\n"
                         "Connection: close\r\n\r\n%s",
                         strlen(soap_res), soap_res);
                
                send(cs, http_res, strlen(http_res), 0);
            } else {
                send_401_unauthorized(cs);
            }
        }
        
        close(cs);
    }
}
```

**Step 3: Test**

```bash
# Using curl or ONVIF client
curl -X POST http://192.168.1.100:8080/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  --data '<s:Envelope>...<trt:GetProfiles/>...</s:Envelope>'
```

---

## Best Practices

### 1. Keep Modules Independent

**DO**:
```c
// discovery_server.h
void *discovery(void *arg) {
    // Only uses: config.h, dis_utils.h
    // No knowledge of auth or ONVIF services
}
```

**DON'T**:
```c
// discovery_server.h
void *discovery(void *arg) {
    // BAD: Discovery shouldn't know about auth
    if (has_any_authentication(...)) {
        ...
    }
}
```

---

### 2. Use Configuration Files, Not Hardcoding

**DO**:
```c
config cfg;
load_config("config.xml", &cfg);
snprintf(response, ..., cfg.manufacturer, cfg.model);
```

**DON'T**:
```c
snprintf(response, ..., "Videonetics", "Camera_Emulator");  // Hardcoded
```

---

### 3. One Function, One Responsibility

**DO**:
```c
// Separate concerns
bool verify_ws_security(const char *request);
bool verify_http_digest(const char *request, const char *method);

int has_any_authentication(const char *request) {
    if (strstr(request, "wsse:Security"))
        return verify_ws_security(request);
    if (strstr(request, "Authorization: Digest"))
        return verify_http_digest(request, "POST");
    return 0;
}
```

**DON'T**:
```c
// God function that does everything
int check_auth_and_parse_and_respond(const char *request, int socket) {
    // 500 lines of mixed auth/parsing/response logic
}
```

---

### 4. Document Module Interfaces

In each header file, add:
```c
/**
 * Module: WS-Security Authentication
 * 
 * Purpose: Verify ONVIF WS-UsernameToken credentials
 * 
 * Dependencies:
 *   - OpenSSL (for SHA1, Base64)
 *   - Credentials.csv (for user lookup)
 * 
 * Public Functions:
 *   - verify_ws_security(request) → bool
 *   - get_password_from_csv(username, password_out) → bool
 */
```

---

### 5. Use Standard Patterns

| Pattern | When to Use | Example |
|---------|-------------|---------|
| **Strategy** | Multiple auth methods | `has_any_authentication()` tries each strategy |
| **Template Method** | Common request structure | SOAP templates with `%s` placeholders |
| **Factory** | Creating different responses | Different templates for different requests |
| **Observer** | Logging requests | (Future: log all auth attempts) |

---

## Design Patterns Used

### Pattern 1: Template Method (SOAP Templates)

**Problem**: SOAP responses have common structure but different data

**Solution**: String templates with placeholders

```c
const char *template = "<Envelope>...%s...</Envelope>";
snprintf(output, size, template, dynamic_data);
```

---

### Pattern 2: Strategy Pattern (Authentication)

**Problem**: Multiple authentication methods need to be checked

**Solution**: Try each strategy in sequence

```c
int has_any_authentication(const char *request) {
    if (strategy_ws_security(request)) return 1;
    if (strategy_http_digest(request)) return 1;
    if (strategy_oauth(request)) return 1;  // Future
    return 0;
}
```

---

### Pattern 3: Facade Pattern (`has_any_authentication`)

**Problem**: Complex authentication subsystem

**Solution**: Simple facade interface

```c
// Complex subsystem
bool verify_ws_security(...);
bool verify_http_digest(...);

// Simple facade
int has_any_authentication(const char *request);  // Hides complexity
```

---

### Pattern 4: Singleton (Configuration)

**Problem**: Configuration should be loaded once and shared

**Solution**: Load config once in `tcpserver()`, pass to handlers

```c
config cfg;  // Loaded once
load_config("config.xml", &cfg);
// Pass &cfg to all handlers that need it
```

---

## Related Documentation

- **[README_XML_ONVIF.md](README_XML_ONVIF.md)**: SOAP/XML message structure
- **[README_ONVIF_AUTHENTICATION.md](README_ONVIF_AUTHENTICATION.md)**: Authentication methods
- **[README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md)**: Network debugging
- **[README_HTTP_HEADERS.md](README_HTTP_HEADERS.md)**: HTTP protocol details
- **[authhandler/README_AUTH_UTILS.md](fakecamera/authhandler/README_AUTH_UTILS.md)**: Auth module details

---

## Summary Checklist

When adding a new feature:

- [ ] Does it belong in a new module or existing one?
- [ ] Does it have a single, clear responsibility?
- [ ] Are dependencies minimal and documented?
- [ ] Can it be tested independently?
- [ ] Does it use configuration instead of hardcoded values?
- [ ] Is the interface simple and well-documented?
- [ ] Does it follow existing patterns?

**Remember**: Good modular design makes code that's easy to understand, modify, and extend!

---

**Last Updated**: 2024-01-15  
**Project**: ONVIF Camera Simulator (fakecamera)
