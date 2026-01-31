# Integration Guide - Adding Authentication to ONVIF Services

> A practical guide to integrating authentication into your ONVIF server implementation

## Table of Contents

1. [Overview](#overview)
2. [Authentication Architecture](#authentication-architecture)
3. [Adding Protected Services](#adding-protected-services)
4. [Credential Management](#credential-management)
5. [Error Handling](#error-handling)
6. [Security Best Practices](#security-best-practices)
7. [Testing Your Implementation](#testing-your-implementation)
8. [Complete Integration Example](#complete-integration-example)

---

## Overview

This guide shows you how to integrate the authentication components (`auth_utils.h`) with your ONVIF services. We'll cover the patterns used in this codebase and how to extend them.

### Components Involved

```
┌───────────────────────────────────────────────────────────────────────┐
│                    Authentication Integration                         │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   ┌─────────────────┐     ┌─────────────────┐     ┌───────────────┐  │
│   │   TCP Server    │────>│  Auth Handler   │────>│  ONVIF Service│  │
│   │ (auth_server.h) │     │ (auth_utils.h)  │     │   (handlers)  │  │
│   └─────────────────┘     └─────────────────┘     └───────────────┘  │
│           │                       │                       │          │
│           │                       │                       │          │
│           ▼                       ▼                       ▼          │
│   ┌─────────────────┐     ┌─────────────────┐     ┌───────────────┐  │
│   │  HTTP Parsing   │     │  Credentials    │     │ SOAP Response │  │
│   │                 │     │  (CSV file)     │     │  Templates    │  │
│   └─────────────────┘     └─────────────────┘     └───────────────┘  │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### File Dependencies

```c
// Main entry point
#include "auth_server.h"       // TCP server with auth checks
    ├── "authhandler/digest_auth.h"   // HTTP Digest utilities
    ├── "authhandler/auth_utils.h"    // WS-Security & helpers
    └── "dis_utils.h"                 // Discovery utilities
            └── "simpleparser.h"      // XML config parsing
                    └── "config.h"    // Constants & templates
```

---

## Authentication Architecture

### Decision Flow

```c
int has_any_authentication(const char *request) {
    
    // 1. Check for WS-UsernameToken (SOAP Header)
    if (strstr(request, "wsse:Security") || strstr(request, "<Security")) {
        printf("[Auth] Checking WS-UsernameToken...\n");
        if (verify_ws_security(request)) {
            printf("[Auth] WS-Security Verified!\n");
            return 1;
        }
        printf("[Auth] WS-Security Failed.\n");
    }

    // 2. Check for HTTP Digest (HTTP Header)
    if (strstr(request, "Authorization: Digest")) {
        printf("[Auth] Checking HTTP Digest...\n");
        if (verify_http_digest(request, "POST")) {
            printf("[Auth] HTTP Digest Verified!\n");
            return 1;
        }
        printf("[Auth] HTTP Digest Failed.\n");
    }
    
    return 0;  // No valid authentication found
}
```

### Service Protection Pattern

```c
// In your request handler
if (strstr(request, "SomeProtectedOperation")) {
    
    if (has_any_authentication(request)) {
        // Authentication passed - process request
        handle_protected_operation(client_socket, request);
    } else {
        // No authentication - send challenge
        send_401_challenge(client_socket);
    }
}
```

---

## Adding Protected Services

### Step 1: Define Service Operation Check

```c
// In auth_utils.h or your service handler
static inline bool is_get_profiles(const char *msg) {
    return (strstr(msg, "GetProfiles") != NULL &&
            strstr(msg, "http://www.onvif.org/ver10/media/wsdl") != NULL);
}
```

### Step 2: Add Response Template

```c
// In tcp_config.h or your templates file
const char *GET_PROFILES_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">"
    "<s:Header>"
        "<a:Action xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">"
            "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse"
        "</a:Action>"
        "<a:RelatesTo xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">%s</a:RelatesTo>"
    "</s:Header>"
    "<s:Body>"
        "<trt:GetProfilesResponse>"
            "<trt:Profiles token=\"profile1\">"
                "<tt:Name xmlns:tt=\"http://www.onvif.org/ver10/schema\">MainProfile</tt:Name>"
                // ... more profile data ...
            "</trt:Profiles>"
        "</trt:GetProfilesResponse>"
    "</s:Body>"
"</s:Envelope>";
```

### Step 3: Add Handler in Server Loop

```c
// In auth_server.h tcpserver() function
else if (is_get_profiles(buf)) {
    
    if (has_any_authentication(buf)) {
        printf("[TCP] Req: GetProfiles (Auth OK) -> ALLOWED\n");
        
        // Extract MessageID for RelatesTo
        char request_message_id[256] = {0};
        getmessageid1(buf, request_message_id, sizeof(request_message_id));
        
        // Build response
        char soap_response[BUFFER_SIZE];
        snprintf(soap_response, sizeof(soap_response),
                 GET_PROFILES_TEMPLATE,
                 request_message_id);
        
        // Send HTTP response
        char http_response[BUFFER_SIZE];
        snprintf(http_response, sizeof(http_response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n\r\n%s",
                 strlen(soap_response), soap_response);
        
        send(cs, http_response, strlen(http_response), 0);
    } else {
        printf("[TCP] Req: GetProfiles (No Auth) -> CHALLENGE\n");
        send_401_challenge(cs);
    }
}
```

### Step 4: Helper for 401 Challenge

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
             "Connection: close\r\n\r\n",
             nonce);
    
    send(client_socket, response, strlen(response), 0);
}
```

---

## Credential Management

### Credentials File Format

The `Credentials.csv` file stores username/password pairs:

```csv
username,password
admin,pass
operator,operator123
viewer,view456
```

### Adding Users

Simply add new lines to `Credentials.csv`:

```csv
username,password
admin,pass
newuser,newpassword
```

### Password Lookup Function

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
        
        // Null-terminate username
        *first_comma = '\0';
        
        if (strcmp(line, username) == 0) {
            // Get password
            char *pass_start = first_comma + 1;
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

### Security Levels (Optional Extension)

For more advanced implementations, you can add role-based access:

```csv
username,password,role
admin,admin123,administrator
operator,op456,operator
viewer,view789,user
```

And modify the lookup:

```c
typedef struct {
    char username[64];
    char password[64];
    int role;  // 0=user, 1=operator, 2=admin
} Credential;

bool get_credential(const char *username, Credential *cred) {
    FILE *fp = fopen("Credentials.csv", "r");
    // ... parsing logic ...
}

bool check_permission(int required_role, int user_role) {
    return user_role >= required_role;
}
```

---

## Error Handling

### SOAP Fault Response

For authentication failures, you can return a SOAP fault:

```c
const char *SOAP_FAULT_AUTH_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
    "<s:Body>"
        "<s:Fault>"
            "<s:Code>"
                "<s:Value>s:Sender</s:Value>"
                "<s:Subcode>"
                    "<s:Value>ter:NotAuthorized</s:Value>"
                "</s:Subcode>"
            "</s:Code>"
            "<s:Reason>"
                "<s:Text xml:lang=\"en\">%s</s:Text>"
            "</s:Reason>"
        "</s:Fault>"
    "</s:Body>"
"</s:Envelope>";
```

### HTTP Status Codes

| Scenario | HTTP Code | Response |
|----------|-----------|----------|
| No credentials | 401 | WWW-Authenticate header |
| Invalid credentials | 401 | SOAP Fault or empty |
| Insufficient permissions | 403 | SOAP Fault |
| Server error | 500 | SOAP Fault |

### Error Response Function

```c
void send_error_response(int socket, int http_code, const char *message) {
    char soap_fault[1024];
    snprintf(soap_fault, sizeof(soap_fault), SOAP_FAULT_AUTH_TEMPLATE, message);
    
    const char *status_text;
    switch (http_code) {
        case 400: status_text = "Bad Request"; break;
        case 401: status_text = "Unauthorized"; break;
        case 403: status_text = "Forbidden"; break;
        case 500: status_text = "Internal Server Error"; break;
        default: status_text = "Error"; break;
    }
    
    char http_response[2048];
    snprintf(http_response, sizeof(http_response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n%s",
             http_code, status_text,
             strlen(soap_fault), soap_fault);
    
    send(socket, http_response, strlen(http_response), 0);
}
```

---

## Security Best Practices

### 1. Secure Nonce Generation

Use `/dev/urandom` instead of `rand()`:

```c
void generate_secure_nonce(char *nonce, size_t size) {
    unsigned char bytes[16];
    int fd = open("/dev/urandom", O_RDONLY);
    
    if (fd >= 0) {
        ssize_t n = read(fd, bytes, sizeof(bytes));
        close(fd);
        
        if (n == sizeof(bytes)) {
            for (int i = 0; i < 16; i++) {
                sprintf(&nonce[i * 2], "%02x", bytes[i]);
            }
            nonce[32] = '\0';
            return;
        }
    }
    
    // Fallback (less secure)
    snprintf(nonce, size, "%08x%08x%08x%08x",
             rand(), rand(), rand(), rand());
}
```

### 2. Timestamp Validation (WS-Security)

Reject old requests to prevent replay attacks:

```c
#include <time.h>

bool is_timestamp_valid(const char *created_str, int max_age_seconds) {
    struct tm tm = {0};
    
    // Parse ISO 8601: "2024-01-15T10:30:45Z"
    if (sscanf(created_str, "%d-%d-%dT%d:%d:%dZ",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
        return false;
    }
    
    tm.tm_year -= 1900;  // Years since 1900
    tm.tm_mon -= 1;      // Months 0-11
    
    time_t request_time = timegm(&tm);  // Convert to UTC epoch
    time_t now = time(NULL);
    
    int age = (int)difftime(now, request_time);
    
    // Allow 5 minutes clock skew
    return (age >= -max_age_seconds && age <= max_age_seconds);
}

// Usage in verify_ws_security:
if (!is_timestamp_valid(created, 300)) {  // 5 minutes
    printf("[Auth] Timestamp too old or too new\n");
    return false;
}
```

### 3. Rate Limiting

Prevent brute-force attacks:

```c
#include <time.h>

typedef struct {
    char ip[64];
    int attempts;
    time_t last_attempt;
} RateLimitEntry;

#define MAX_ATTEMPTS 5
#define LOCKOUT_TIME 300  // 5 minutes

RateLimitEntry rate_limit_table[100];
int rate_limit_count = 0;

bool check_rate_limit(const char *client_ip) {
    time_t now = time(NULL);
    
    for (int i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limit_table[i].ip, client_ip) == 0) {
            // Check if lockout period passed
            if (difftime(now, rate_limit_table[i].last_attempt) > LOCKOUT_TIME) {
                rate_limit_table[i].attempts = 0;
            }
            
            if (rate_limit_table[i].attempts >= MAX_ATTEMPTS) {
                return false;  // Blocked
            }
            return true;  // Allowed
        }
    }
    return true;  // New IP, allowed
}

void record_failed_attempt(const char *client_ip) {
    time_t now = time(NULL);
    
    for (int i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limit_table[i].ip, client_ip) == 0) {
            rate_limit_table[i].attempts++;
            rate_limit_table[i].last_attempt = now;
            return;
        }
    }
    
    // New entry
    if (rate_limit_count < 100) {
        strncpy(rate_limit_table[rate_limit_count].ip, client_ip, 63);
        rate_limit_table[rate_limit_count].attempts = 1;
        rate_limit_table[rate_limit_count].last_attempt = now;
        rate_limit_count++;
    }
}
```

### 4. Secure Credential Storage

For production, consider:

- Storing password hashes instead of plain passwords
- Using a proper database
- Encrypting the credentials file

```c
// Store: username,hash(password)
// Verify: compare hash(input) with stored hash

#include <openssl/evp.h>

void hash_password(const char *password, char *hash_hex) {
    unsigned char hash[32];
    unsigned int len;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    
    for (int i = 0; i < 32; i++) {
        sprintf(&hash_hex[i * 2], "%02x", hash[i]);
    }
    hash_hex[64] = '\0';
}
```

---

## Testing Your Implementation

### Manual Testing with curl

```bash
# Test unauthenticated request
curl -v -X POST http://localhost:7000/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'

# Test with HTTP Digest
curl -v --digest -u admin:pass -X POST http://localhost:7000/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
```

### Test Cases

| Test | Expected Result |
|------|-----------------|
| No auth on protected endpoint | 401 with WWW-Authenticate |
| Valid HTTP Digest auth | 200 with response |
| Invalid password | 401 |
| Valid WS-UsernameToken | 200 with response |
| Expired timestamp | 401 |
| Wrong username | 401 |
| Public endpoint (GetSystemDateAndTime) | 200 without auth |

### Using ONVIF Device Manager

1. Download ONVIF Device Manager
2. Add your device manually (IP:Port)
3. Test discovery and authentication
4. Verify responses

---

## Complete Integration Example

### Full Server Loop with Multiple Services

```c
void *tcpserver(void *arg) {
    (void)arg;
    
    config cfg = {0};
    load_config("config.xml", &cfg);
    printf("ONVIF Server started on port %d\n", cfg.server_port);
    
    int sock = setup_server(cfg.server_port);
    if (sock < 0) return NULL;
    
    char buf[BUFFER_SIZE];
    
    while (1) {
        int client = accept_client(sock);
        if (client < 0) continue;
        
        memset(buf, 0, sizeof(buf));
        ssize_t n = recv(client, buf, sizeof(buf) - 1, 0);
        if (n <= 0) { close(client); continue; }
        buf[n] = '\0';
        
        printf("\n[TCP] Request (%zd bytes)\n", n);
        
        // Extract MessageID for all responses
        char msg_id[256] = {0};
        getmessageid1(buf, msg_id, sizeof(msg_id));
        
        // === PUBLIC OPERATIONS ===
        
        if (strstr(buf, "GetSystemDateAndTime")) {
            handle_get_datetime(client, msg_id);
        }
        
        // === PROTECTED OPERATIONS ===
        
        else if (strstr(buf, "GetDeviceInformation")) {
            if (has_any_authentication(buf)) {
                handle_get_device_info(client, msg_id, &cfg);
            } else {
                send_401_challenge(client);
            }
        }
        
        else if (strstr(buf, "GetProfiles")) {
            if (has_any_authentication(buf)) {
                handle_get_profiles(client, msg_id);
            } else {
                send_401_challenge(client);
            }
        }
        
        else if (strstr(buf, "GetStreamUri")) {
            if (has_any_authentication(buf)) {
                handle_get_stream_uri(client, msg_id);
            } else {
                send_401_challenge(client);
            }
        }
        
        // === UNKNOWN REQUEST ===
        
        else {
            printf("[TCP] Unknown request -> 400\n");
            send_400_bad_request(client);
        }
        
        close(client);
    }
    
    close(sock);
    return NULL;
}
```

---

## Summary

### Key Integration Steps

1. ✅ Include `authhandler/auth_utils.h` for verification functions
2. ✅ Use `has_any_authentication()` to check both auth methods
3. ✅ Send 401 with challenge for unauthenticated protected requests
4. ✅ Extract MessageID for RelatesTo in responses
5. ✅ Use SOAP templates for responses
6. ✅ Manage credentials in `Credentials.csv`

### Security Checklist

- [ ] Use secure random nonce generation
- [ ] Validate timestamps (WS-Security)
- [ ] Implement rate limiting
- [ ] Log authentication attempts
- [ ] Consider TLS for production

---

*Continue to [08-auth_utils-Reference.md](./08-auth_utils-Reference.md) →*
