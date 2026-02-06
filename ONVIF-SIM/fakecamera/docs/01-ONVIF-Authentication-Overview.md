# ONVIF Authentication Overview

> Understanding the fundamentals of authentication in ONVIF-compliant devices

## Table of Contents

1. [What is ONVIF?](#what-is-onvif)
2. [Why Authentication Matters](#why-authentication-matters)
3. [Authentication Methods in ONVIF](#authentication-methods-in-onvif)
4. [Public vs Protected Services](#public-vs-protected-services)
5. [Authentication Decision Flow](#authentication-decision-flow)

---

## What is ONVIF?

**ONVIF (Open Network Video Interface Forum)** is a global standard for network-based physical security products. It enables interoperability between IP cameras, video management systems (VMS), and other security devices from different manufacturers.

### Key ONVIF Concepts

| Concept | Description |
|---------|-------------|
| **Device Service** | Core service providing device information and configuration |
| **Media Service** | Streaming and media configuration |
| **PTZ Service** | Pan-Tilt-Zoom camera control |
| **Events Service** | Event notification and subscription |

### ONVIF Communication Model

```
┌──────────────────────────────────────────────────────────────────┐
│                        ONVIF Protocol Stack                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│   │   Device    │  │    Media    │  │     PTZ     │    ...       │
│   │   Service   │  │   Service   │  │   Service   │              │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│          │                │                │                      │
│   ┌──────┴────────────────┴────────────────┴──────────────────┐  │
│   │                       SOAP/XML                             │  │
│   └──────────────────────────┬─────────────────────────────────┘  │
│                              │                                    │
│   ┌──────────────────────────┴─────────────────────────────────┐  │
│   │                         HTTP                                │  │
│   └──────────────────────────┬─────────────────────────────────┘  │
│                              │                                    │
│   ┌──────────────────────────┴─────────────────────────────────┐  │
│   │                       TCP/IP                                │  │
│   └─────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Why Authentication Matters

### Security Concerns

IP cameras are critical security infrastructure. Without proper authentication:

1. **Unauthorized Access** - Anyone could view camera feeds
2. **Configuration Tampering** - Attackers could modify camera settings
3. **Denial of Service** - Attackers could disable cameras
4. **Network Penetration** - Cameras could be used as entry points

### ONVIF Security Levels

ONVIF defines security levels for different operations:

| Level | Description | Example Operations |
|-------|-------------|-------------------|
| **None** | No authentication required | GetSystemDateAndTime, Discovery |
| **Operator** | Basic authenticated access | GetDeviceInformation, GetProfiles |
| **Administrator** | Full control | SetUser, SetNetworkSettings |

---

## Authentication Methods in ONVIF

ONVIF supports two primary authentication mechanisms:

### 1. HTTP Digest Authentication

- **Where:** HTTP header level
- **Standard:** RFC 2617
- **Used For:** REST-like requests, some SOAP requests
- **Advantage:** No password sent in clear text

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="ONVIF_Device", 
                  qop="auth", 
                  nonce="abc123...",
                  algorithm=MD5

```

### 2. WS-UsernameToken Authentication

- **Where:** SOAP envelope body (XML)
- **Standard:** WS-Security (OASIS)
- **Used For:** SOAP/XML requests
- **Advantage:** Works with SOAP message security

```xml
<wsse:Security>
  <wsse:UsernameToken>
    <wsse:Username>admin</wsse:Username>
    <wsse:Password Type="...#PasswordDigest">...</wsse:Password>
    <wsse:Nonce>...</wsse:Nonce>
    <wsu:Created>...</wsu:Created>
  </wsse:UsernameToken>
</wsse:Security>
```

### Comparison

| Feature | HTTP Digest | WS-UsernameToken |
|---------|-------------|------------------|
| Transport | HTTP Header | SOAP Body |
| Nonce Source | Server-provided | Client-generated |
| Timestamp | Optional | Required |
| Hash Algorithm | MD5 | SHA-1 |
| Replay Protection | Server nonce | Client timestamp |

---

## Public vs Protected Services

### Public Services (No Authentication)

These operations can be accessed without credentials:

| Service | Operation | Purpose |
|---------|-----------|---------|
| Device | GetSystemDateAndTime | Time synchronization |
| Discovery | Probe/ProbeMatch | Device discovery |
| Device | GetWsdlUrl | WSDL location |

### Protected Services (Authentication Required)

These require valid credentials:

| Service | Operation | Security Level |
|---------|-----------|----------------|
| Device | GetDeviceInformation | Operator |
| Device | GetCapabilities | Operator |
| Media | GetProfiles | Operator |
| Media | GetStreamUri | Operator |
| PTZ | AbsoluteMove | Operator |
| Device | SetUser | Administrator |

---

## Authentication Decision Flow

The server follows this decision tree for incoming requests:

```
                    ┌─────────────────────┐
                    │  Incoming Request   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Is it a public      │
                    │ operation?          │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
         ┌────▼────┐                      ┌────▼────┐
         │   YES   │                      │   NO    │
         └────┬────┘                      └────┬────┘
              │                                 │
    ┌─────────▼─────────┐          ┌──────────▼──────────┐
    │ Process directly  │          │ Check for auth      │
    │ Return response   │          │ header/body         │
    └───────────────────┘          └──────────┬──────────┘
                                              │
                          ┌───────────────────┴───────────────────┐
                          │                                       │
                    ┌─────▼─────┐                           ┌─────▼─────┐
                    │ Has Auth  │                           │  No Auth  │
                    └─────┬─────┘                           └─────┬─────┘
                          │                                       │
               ┌──────────▼──────────┐              ┌────────────▼────────────┐
               │ Verify credentials  │              │ Return 401 Unauthorized │
               └──────────┬──────────┘              │ + Challenge header      │
                          │                         └─────────────────────────┘
            ┌─────────────┴─────────────┐
            │                           │
      ┌─────▼─────┐               ┌─────▼─────┐
      │  Valid    │               │ Invalid   │
      └─────┬─────┘               └─────┬─────┘
            │                           │
  ┌─────────▼─────────┐      ┌─────────▼─────────┐
  │ Process request   │      │ Return 401        │
  │ Return response   │      │ Unauthorized      │
  └───────────────────┘      └───────────────────┘
```

### Implementation in Code

```c
// From auth_server.h
int has_any_authentication(const char *request) {
    
    // 1. WS-UsernameToken (XML Body)
    if (strstr(request, "wsse:Security") || strstr(request, "<Security")) {
        printf("[Auth] Checking WS-UsernameToken...\n");
        if (verify_ws_security(request)) {
            printf("[Auth] WS-Security Verified!\n");
            return 1;
        }
        printf("[Auth] WS-Security Failed.\n");
    }

    // 2. HTTP Digest (Header)
    if (strstr(request, "Authorization: Digest")) {
        printf("[Auth] Checking HTTP Digest...\n");
        if (verify_http_digest(request, "POST")) {
            printf("[Auth] HTTP Digest Verified!\n");
            return 1;
        }
        printf("[Auth] HTTP Digest Failed.\n");
    }
    
    return 0;
}
```

---

## Key Takeaways

1. **ONVIF uses SOAP over HTTP** - Understanding both protocols is essential
2. **Two authentication methods** - HTTP Digest and WS-UsernameToken
3. **Security levels** - Different operations require different permissions
4. **Always verify** - Never trust client-provided data without verification

---

## Next Steps

- Learn about [HTTP Digest Authentication](./02-HTTP-Digest-Authentication.md) in detail
- Understand [WS-UsernameToken](./03-WS-UsernameToken-Authentication.md) authentication
- Review the [OpenSSL Guide](./04-OpenSSL-Guide.md) for cryptographic operations

---

*Continue to [02-HTTP-Digest-Authentication.md](./02-HTTP-Digest-Authentication.md) →*
