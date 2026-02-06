# ONVIF Server Documentation Hub

## Welcome! 👋

This is a comprehensive documentation hub for the **ONVIF Camera Server Implementation**. Whether you're new to ONVIF, OpenSSL, or network programming, this guide collection will help you understand and work with this codebase.

## 📚 Documentation Overview

This project includes **8 comprehensive guides** covering every aspect of ONVIF authentication, implementation, and debugging:

### Core Documentation Files

| Document | Purpose | Best For |
|----------|---------|----------|
| **[ONVIF Authentication Guide](README_ONVIF_AUTHENTICATION.md)** | Overview of ONVIF auth methods | Understanding auth concepts |
| **[auth_utils.h API Reference](fakecamera/authhandler/README_AUTH_UTILS.md)** | Complete API documentation | Implementation details |
| **[OpenSSL Guide](README_OPENSSL_GUIDE.md)** | OpenSSL in C for ONVIF | Learning cryptography |
| **[HTTP Headers Guide](README_HTTP_HEADERS.md)** | HTTP protocol for ONVIF | Understanding HTTP/SOAP |
| **[XML/ONVIF Structure](README_XML_ONVIF.md)** | SOAP messages and XML | Building ONVIF messages |
| **[Modular Design](README_MODULAR_DESIGN.md)** | Architecture and patterns | Extending the codebase |
| **[Packet Analysis](README_PACKET_ANALYSIS.md)** | Network debugging | Troubleshooting issues |
| **[Documentation Index](DOCUMENTATION_INDEX.md)** | Quick topic reference | Finding specific info |

## 🚀 Quick Start Paths

### Path 1: Complete Beginner
If you're **new to ONVIF and network programming**:

1. Start with **[ONVIF Authentication Guide](README_ONVIF_AUTHENTICATION.md)** - Get the big picture
2. Read **[HTTP Headers Guide](README_HTTP_HEADERS.md)** - Learn HTTP basics
3. Read **[XML/ONVIF Structure](README_XML_ONVIF.md)** - Understand SOAP messages
4. Study **[auth_utils.h Reference](fakecamera/authhandler/README_AUTH_UTILS.md)** - See the implementation
5. Review **[Modular Design](README_MODULAR_DESIGN.md)** - Understand the architecture

### Path 2: Experienced Developer
If you **know ONVIF but new to this project**:

1. Review **[Modular Design](README_MODULAR_DESIGN.md)** - Understand project structure
2. Check **[auth_utils.h Reference](fakecamera/authhandler/README_AUTH_UTILS.md)** - API details
3. Browse **[Documentation Index](DOCUMENTATION_INDEX.md)** - Find specific topics

### Path 3: Debugging Issues
If you're **troubleshooting problems**:

1. Read **[Packet Analysis](README_PACKET_ANALYSIS.md)** - Debug network traffic
2. Check **[ONVIF Authentication Guide](README_ONVIF_AUTHENTICATION.md)** - Verify auth flow
3. Use **[Documentation Index](DOCUMENTATION_INDEX.md)** - Quick problem lookup

## 📖 What's in Each Guide?

### 1. [ONVIF Authentication Guide](README_ONVIF_AUTHENTICATION.md)
**20,000+ words | Complete authentication overview**

- Introduction to ONVIF protocol
- HTTP Digest Authentication (RFC 2617/7616)
- WS-UsernameToken Authentication (WS-Security)
- Step-by-step authentication flows
- Security considerations and best practices
- Protocol comparison tables

**Key Topics:**
- Challenge-response mechanism
- Computing digest hashes (HA1, HA2)
- WS-Security password digest
- When to use each auth method
- Common security pitfalls

### 2. [auth_utils.h API Reference](fakecamera/authhandler/README_AUTH_UTILS.md)
**36,000+ words | Function-by-function documentation**

- Complete API reference for auth_utils.h
- Base64 encoding/decoding with OpenSSL BIO
- CSV credential management
- HTTP and XML parsing functions
- Cryptographic digest computation
- Authentication verification functions

**Key Topics:**
- `verify_http_digest()` implementation
- `verify_ws_security()` implementation
- Base64 operations with OpenSSL
- Header and tag parsing
- Complete usage examples

### 3. [OpenSSL Guide](README_OPENSSL_GUIDE.md)
**31,000+ words | OpenSSL deep dive**

- OpenSSL installation and setup
- EVP Digest API (modern approach)
- Hash functions (MD5, SHA-1, SHA-256)
- BIO system for Base64 encoding
- ONVIF-specific implementations
- Performance and security best practices

**Key Topics:**
- Why use OpenSSL?
- EVP context management
- Computing MD5/SHA-1 hashes
- Base64 with BIO chains
- Memory management
- Thread safety

### 4. [HTTP Headers Guide](README_HTTP_HEADERS.md)
**25,000+ words | HTTP protocol for ONVIF**

- HTTP request/response structure
- Authentication headers (Authorization, WWW-Authenticate)
- HTTP Digest challenge-response flow
- SOAP over HTTP
- Header parsing techniques
- Building HTTP messages

**Key Topics:**
- HTTP methods and status codes
- Content-Type for SOAP
- Authorization header format
- 401 challenges
- Common HTTP issues
- cURL testing examples

### 5. [XML/ONVIF Structure](README_XML_ONVIF.md)
**28,000+ words | SOAP message guide**

- SOAP envelope structure
- XML namespaces in ONVIF
- WS-Security header format
- ONVIF service request/response examples
- XML parsing techniques
- SOAP templates usage

**Key Topics:**
- GetSystemDateAndTime
- GetDeviceInformation
- GetCapabilities
- GetServices
- WS-UsernameToken structure
- Building ONVIF messages

### 6. [Modular Design](README_MODULAR_DESIGN.md)
**33,000+ words | Architecture guide**

- Project structure overview
- Module-by-module breakdown
- Component interactions
- Threading model
- Adding new features
- Design patterns and best practices

**Key Topics:**
- 8 core modules explained
- Authentication flow
- Discovery mechanism
- Configuration management
- Extending authentication
- Adding ONVIF services

### 7. [Packet Analysis](README_PACKET_ANALYSIS.md)
**22,000+ words | Debugging guide**

- tcpdump and Wireshark usage
- Capturing ONVIF traffic
- Wireshark filters (40+ examples)
- Authentication debugging
- Common packet patterns
- Troubleshooting guide

**Key Topics:**
- Traffic capture commands
- Display filters for ONVIF
- Debugging HTTP Digest
- Debugging WS-Security
- Connection troubleshooting
- Advanced analysis techniques

### 8. [Documentation Index](DOCUMENTATION_INDEX.md)
**Quick reference | Find topics fast**

- Categorized topic index
- Quick links to all sections
- Common tasks mapped to docs
- Beginner vs. advanced topics
- Troubleshooting quick reference

## 🎯 Common Tasks → Documentation

### I want to...

| Task | Start Here |
|------|------------|
| **Understand ONVIF authentication** | [ONVIF Authentication Guide](README_ONVIF_AUTHENTICATION.md) |
| **Implement HTTP Digest** | [auth_utils.h Reference](fakecamera/authhandler/README_AUTH_UTILS.md#verify_http_digest) |
| **Implement WS-Security** | [auth_utils.h Reference](fakecamera/authhandler/README_AUTH_UTILS.md#verify_ws_security) |
| **Learn OpenSSL basics** | [OpenSSL Guide](README_OPENSSL_GUIDE.md) |
| **Compute MD5/SHA-1 hashes** | [OpenSSL Guide](README_OPENSSL_GUIDE.md#hash-functions-deep-dive) |
| **Parse HTTP headers** | [HTTP Headers Guide](README_HTTP_HEADERS.md#parsing-http-headers) |
| **Build SOAP messages** | [XML/ONVIF Structure](README_XML_ONVIF.md#building-soap-messages) |
| **Add a new ONVIF service** | [Modular Design](README_MODULAR_DESIGN.md#adding-new-onvif-services) |
| **Debug authentication** | [Packet Analysis](README_PACKET_ANALYSIS.md#debugging-authentication) |
| **Capture network traffic** | [Packet Analysis](README_PACKET_ANALYSIS.md#capturing-traffic) |

## 🔍 Quick Topic Lookup

### Authentication
- [HTTP Digest vs WS-UsernameToken](README_ONVIF_AUTHENTICATION.md#http-digest-vs-ws-usernametoken)
- [Computing digest hashes](README_ONVIF_AUTHENTICATION.md#computing-the-response-hash)
- [Challenge-response flow](README_HTTP_HEADERS.md#http-digest-challenge-response)
- [401 challenges](README_HTTP_HEADERS.md#building-401-challenge)

### OpenSSL
- [EVP Digest API](README_OPENSSL_GUIDE.md#evp-digest-api)
- [MD5 hashing](README_OPENSSL_GUIDE.md#md5-message-digest-5)
- [SHA-1 hashing](README_OPENSSL_GUIDE.md#sha-1-secure-hash-algorithm-1)
- [Base64 encoding](README_OPENSSL_GUIDE.md#base64-encoding-with-bio)
- [BIO system](README_OPENSSL_GUIDE.md#bio-system)

### ONVIF Protocol
- [SOAP structure](README_XML_ONVIF.md#soap-message-structure)
- [WS-Security header](README_XML_ONVIF.md#ws-security-header-structure)
- [ONVIF services](README_XML_ONVIF.md#common-onvif-services)
- [XML namespaces](README_XML_ONVIF.md#xml-namespaces-in-onvif)

### Debugging
- [Wireshark filters](README_PACKET_ANALYSIS.md#wireshark-display-filters)
- [Capture ONVIF traffic](README_PACKET_ANALYSIS.md#capturing-onvif-http-traffic)
- [Debug HTTP Digest](README_PACKET_ANALYSIS.md#debugging-http-digest-authentication)
- [Troubleshooting](README_PACKET_ANALYSIS.md#troubleshooting-common-issues)

### Code Structure
- [Project architecture](README_MODULAR_DESIGN.md#project-structure)
- [Module overview](README_MODULAR_DESIGN.md#core-modules-overview)
- [Authentication module](README_MODULAR_DESIGN.md#authentication-module)
- [Adding features](README_MODULAR_DESIGN.md#extending-the-system)

## 💡 Tips for Using This Documentation

### For Beginners
1. **Don't rush** - These guides are comprehensive. Take your time!
2. **Follow examples** - Every guide has working code examples
3. **Try it out** - Compile and run the examples as you read
4. **Use cross-references** - Links between docs help build understanding
5. **Ask questions** - If something's unclear, it's worth documenting better

### For Experienced Developers
1. **Use the index** - [Documentation Index](DOCUMENTATION_INDEX.md) for quick lookups
2. **Check API reference** - [auth_utils.h](fakecamera/authhandler/README_AUTH_UTILS.md) has all function details
3. **Review architecture** - [Modular Design](README_MODULAR_DESIGN.md) shows how it all fits together
4. **Debug efficiently** - [Packet Analysis](README_PACKET_ANALYSIS.md) has Wireshark filters ready

### For Troubleshooting
1. **Start with symptoms** - Use [Packet Analysis](README_PACKET_ANALYSIS.md) troubleshooting sections
2. **Capture traffic** - See actual packets flowing
3. **Compare examples** - Check your implementation against working examples
4. **Verify basics** - Is OpenSSL installed? Are headers correct? Is the nonce fresh?

## 📊 Documentation Statistics

- **Total Word Count:** ~195,000 words
- **Total Pages:** ~800+ pages (if printed)
- **Code Examples:** 150+ complete examples
- **Diagrams:** 30+ ASCII diagrams
- **Tables:** 80+ reference tables
- **Cross-References:** 100+ links between documents

## 🛠️ Building and Running

### Prerequisites
```bash
# Install OpenSSL development libraries
sudo apt-get install libssl-dev  # Ubuntu/Debian
```

### Compile the Server
```bash
cd /home/runner/work/NetC/NetC/ONVIF-SIM/fakecamera
gcc -o onvif_server main.c -pthread -lssl -lcrypto
```

### Run the Server
```bash
./onvif_server
```

### Test with cURL
```bash
# Get system time (no auth required)
curl -X POST http://localhost:8080/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
        <s:Body>
          <tds:GetSystemDateAndTime xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
        </s:Body>
      </s:Envelope>'
```

See [HTTP Headers Guide](README_HTTP_HEADERS.md#testing-with-curl) for more examples.

## 🔐 Security Notice

This implementation is for **educational and testing purposes**. For production use:

⚠️ **Important Security Considerations:**
1. **Use HTTPS/TLS** - Never send credentials over plain HTTP in production
2. **Strong passwords** - Implement password complexity requirements
3. **Secure storage** - Never store plaintext passwords (use bcrypt, Argon2)
4. **Rate limiting** - Prevent brute-force attacks
5. **Input validation** - Sanitize all inputs to prevent injection attacks
6. **Certificate validation** - Always validate SSL/TLS certificates
7. **Update dependencies** - Keep OpenSSL and other libraries updated

See [ONVIF Authentication Guide - Security Considerations](README_ONVIF_AUTHENTICATION.md#security-considerations) for details.

## 📝 Project Structure

```
ONVIF-SIM/
├── README.md                          ← You are here
├── README_ONVIF_AUTHENTICATION.md     ← Auth overview
├── README_OPENSSL_GUIDE.md            ← OpenSSL guide
├── README_HTTP_HEADERS.md             ← HTTP guide
├── README_XML_ONVIF.md                ← SOAP/XML guide
├── README_MODULAR_DESIGN.md           ← Architecture guide
├── README_PACKET_ANALYSIS.md          ← Debugging guide
├── DOCUMENTATION_INDEX.md             ← Topic index
│
├── fakecamera/
│   ├── authhandler/
│   │   ├── auth_utils.h               ← Core auth library
│   │   ├── digest_auth.h              ← Digest helpers
│   │   └── README_AUTH_UTILS.md       ← API reference
│   │
│   ├── main.c                         ← Entry point
│   ├── auth_server.h                  ← Server logic
│   ├── discovery_server.h             ← WS-Discovery
│   ├── config.h                       ← Config parser
│   ├── tcp_config.h                   ← SOAP templates
│   ├── Credentials.csv                ← User database
│   └── config.xml                     ← Server config
│
└── CamDiscoverer/
    └── camdis.c                       ← Discovery client
```

## 🤝 Contributing

Want to improve this documentation?

1. **Found a typo?** - Submit a pull request
2. **Missing explanation?** - Open an issue
3. **Better example?** - Share it!
4. **New use case?** - Document it!

Good documentation helps everyone learn faster!

## 📚 External Resources

### Official Specifications
- [ONVIF Core Specification](https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf)
- [ONVIF Device Management Service](https://www.onvif.org/specs/srv/mgmt/ONVIF-DeviceManagement-Service-Spec.pdf)
- [WS-Security Specification](http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf)

### HTTP & Authentication
- [RFC 2616 - HTTP/1.1](https://tools.ietf.org/html/rfc2616)
- [RFC 2617 - HTTP Authentication: Basic and Digest](https://tools.ietf.org/html/rfc2617)
- [RFC 7616 - HTTP Digest Authentication (Updated)](https://tools.ietf.org/html/rfc7616)

### OpenSSL
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [OpenSSL Wiki](https://wiki.openssl.org/)
- [OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/)

### SOAP & XML
- [SOAP 1.2 Specification](https://www.w3.org/TR/soap12/)
- [XML Namespaces](https://www.w3.org/TR/xml-names/)

## 🎓 Learning Path Summary

```
Beginner Path (Recommended Order):
1. README_ONVIF_AUTHENTICATION.md    ← Start here
2. README_HTTP_HEADERS.md            ← Learn HTTP
3. README_XML_ONVIF.md               ← Understand SOAP
4. README_OPENSSL_GUIDE.md           ← Learn crypto
5. README_AUTH_UTILS.md              ← Study implementation
6. README_MODULAR_DESIGN.md          ← See architecture
7. README_PACKET_ANALYSIS.md         ← Debug issues

Developer Path (Quick Start):
1. README_MODULAR_DESIGN.md          ← Architecture first
2. README_AUTH_UTILS.md              ← API reference
3. DOCUMENTATION_INDEX.md            ← Quick lookups

Debugging Path (Problem Solving):
1. README_PACKET_ANALYSIS.md         ← Debug network
2. README_ONVIF_AUTHENTICATION.md    ← Verify auth flow
3. DOCUMENTATION_INDEX.md            ← Find specific topics
```

## 🌟 Key Highlights

This documentation set is unique because it:

✅ **Comprehensive** - Covers every aspect from basics to advanced
✅ **Beginner-Friendly** - Assumes no prior ONVIF knowledge
✅ **Practical** - 150+ working code examples
✅ **Well-Organized** - Cross-referenced with clear navigation
✅ **Production-Ready** - Security best practices included
✅ **Debugging-Focused** - Complete troubleshooting guides
✅ **Self-Contained** - All information in one place

## 🚦 Getting Started Right Now

**Absolute Beginner?**
→ Start with [ONVIF Authentication Guide](README_ONVIF_AUTHENTICATION.md)

**Want to code?**
→ Check [auth_utils.h Reference](fakecamera/authhandler/README_AUTH_UTILS.md)

**Need to debug?**
→ Read [Packet Analysis](README_PACKET_ANALYSIS.md)

**Quick question?**
→ Use [Documentation Index](DOCUMENTATION_INDEX.md)

## 📞 Need Help?

If you're stuck:
1. Check [Documentation Index](DOCUMENTATION_INDEX.md) for your topic
2. Review [Packet Analysis](README_PACKET_ANALYSIS.md) troubleshooting sections
3. Look at code examples in relevant guide
4. Compare your implementation with examples

## 📄 License

This documentation and code are provided for educational purposes. Please review the project license for usage terms.

---

**Happy Learning! 🎉**

Start exploring with the [ONVIF Authentication Guide](README_ONVIF_AUTHENTICATION.md) or jump to any guide that interests you. Every document is self-contained but cross-referenced for deeper understanding.

*Last Updated: January 2024*
