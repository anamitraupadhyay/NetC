# ONVIF Authentication Guide - Complete Documentation

> A comprehensive guide for beginners to understand ONVIF authentication, OpenSSL integration, HTTP Digest Authentication, and WS-UsernameToken authentication in a camera server implementation.

## 📚 Table of Contents

1. [Overview](#overview)
2. [Documentation Structure](#documentation-structure)
3. [Quick Start](#quick-start)
4. [Prerequisites](#prerequisites)
5. [Architecture Overview](#architecture-overview)

---

## Overview

This documentation provides an in-depth guide for implementing authentication in ONVIF-compliant IP camera servers. It covers:

- **HTTP Digest Authentication** - The standard HTTP authentication mechanism used for web service requests
- **WS-UsernameToken** - SOAP-based authentication using WS-Security headers
- **OpenSSL Library** - Cryptographic operations for hashing and encoding
- **XML/SOAP Message Formats** - Understanding ONVIF message structures
- **Network Packet Flow** - How authentication happens at the protocol level

---

## Documentation Structure

| Document | Description |
|----------|-------------|
| [01-ONVIF-Authentication-Overview.md](./01-ONVIF-Authentication-Overview.md) | Introduction to ONVIF authentication concepts |
| [02-HTTP-Digest-Authentication.md](./02-HTTP-Digest-Authentication.md) | Deep dive into HTTP Digest Auth mechanism |
| [03-WS-UsernameToken-Authentication.md](./03-WS-UsernameToken-Authentication.md) | WS-Security and SOAP header authentication |
| [04-OpenSSL-Guide.md](./04-OpenSSL-Guide.md) | Complete OpenSSL library usage in C |
| [05-XML-SOAP-Formats.md](./05-XML-SOAP-Formats.md) | ONVIF XML/SOAP message reference |
| [06-HTTP-Protocol-Guide.md](./06-HTTP-Protocol-Guide.md) | HTTP headers and packet transfers |
| [07-Integration-Guide.md](./07-Integration-Guide.md) | Integrating authentication with ONVIF services |
| [08-auth_utils-Reference.md](./08-auth_utils-Reference.md) | Code reference for auth_utils.h |

---

## Quick Start

### Building the Fake Camera Server

```bash
# Navigate to the fakecamera directory
cd ONVIF-SIM/fakecamera

# Compile with OpenSSL
gcc -o fakecamera main.c -lpthread -lssl -lcrypto

# Run the server
./fakecamera
```

### Testing Authentication

```bash
# Test WS-Discovery (no authentication required)
# Use any ONVIF discovery tool or:
curl -X POST http://localhost:7000/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  -d '<soap request for GetSystemDateAndTime>'

# Test authenticated request (requires credentials)
# GetDeviceInformation requires authentication
```

---

## Prerequisites

### Knowledge Requirements
- Basic understanding of C programming
- Familiarity with network sockets
- Basic understanding of HTTP protocol
- XML basics

### Software Requirements
- GCC compiler
- OpenSSL development libraries (`libssl-dev`)
- POSIX-compliant system (Linux/Unix)

### Installation (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install gcc libssl-dev
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    ONVIF Camera Server                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐        ┌─────────────────────────────┐    │
│  │  WS-Discovery   │        │      TCP Auth Server        │    │
│  │   (UDP 3702)    │        │       (HTTP Port)           │    │
│  │                 │        │                             │    │
│  │  - Probe/Match  │        │  ┌─────────────────────┐    │    │
│  │  - No Auth      │        │  │  Authentication     │    │    │
│  └─────────────────┘        │  │  Handler            │    │    │
│                             │  │                     │    │    │
│                             │  │  - HTTP Digest      │    │    │
│                             │  │  - WS-UsernameToken │    │    │
│                             │  └─────────────────────┘    │    │
│                             │                             │    │
│                             │  ┌─────────────────────┐    │    │
│                             │  │  ONVIF Services     │    │    │
│                             │  │                     │    │    │
│                             │  │  - GetDateTime (P)  │    │    │
│                             │  │  - GetDeviceInfo(A) │    │    │
│                             │  │  - GetServices (A)  │    │    │
│                             │  └─────────────────────┘    │    │
│                             └─────────────────────────────┘    │
│                                                                 │
│  Legend: (P) = Public/No Auth, (A) = Authenticated             │
└─────────────────────────────────────────────────────────────────┘
```

### Authentication Flow

```
Client                                    Server
   │                                         │
   │  1. Request (no auth)                   │
   │────────────────────────────────────────>│
   │                                         │
   │  2. 401 Unauthorized + Challenge        │
   │<────────────────────────────────────────│
   │     (WWW-Authenticate: Digest ...)      │
   │                                         │
   │  3. Request + Auth Header/Body          │
   │────────────────────────────────────────>│
   │     (Authorization: Digest ... OR       │
   │      wsse:Security header)              │
   │                                         │
   │  4. 200 OK + Response                   │
   │<────────────────────────────────────────│
   │                                         │
```

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `main.c` | Entry point, starts discovery and auth servers |
| `auth_server.h` | TCP server handling SOAP requests |
| `authhandler/auth_utils.h` | Core authentication logic |
| `authhandler/digest_auth.h` | HTTP Digest specific utilities |
| `config.h` | Configuration constants and SOAP templates |
| `tcp_config.h` | Additional SOAP response templates |
| `Credentials.csv` | User credentials database |

---

## Next Steps

1. Start with [01-ONVIF-Authentication-Overview.md](./01-ONVIF-Authentication-Overview.md) to understand the big picture
2. Dive into specific authentication methods as needed
3. Review the OpenSSL guide for cryptographic operations
4. Use the integration guide to add authentication to your services

---

## Contributing

Feel free to improve this documentation by:
- Adding more examples
- Clarifying explanations
- Adding diagrams
- Reporting issues

---

*Last Updated: 2024*
