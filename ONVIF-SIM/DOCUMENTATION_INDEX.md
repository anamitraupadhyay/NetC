# ONVIF Camera Simulator - Complete Documentation Index

This directory contains comprehensive documentation for the ONVIF Camera Simulator project. All guides are beginner-friendly with practical examples.

## 📚 Documentation Overview

### Core Guides

| Document | Description | Size |
|----------|-------------|------|
| **[README_ONVIF_AUTHENTICATION.md](README_ONVIF_AUTHENTICATION.md)** | Complete guide to ONVIF authentication methods (WS-Security, HTTP Digest) | 682 lines |
| **[README_XML_ONVIF.md](README_XML_ONVIF.md)** | SOAP/XML message structure, namespaces, and ONVIF service examples | 883 lines |
| **[README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md)** | Project architecture, design patterns, and module interactions | 1017 lines |
| **[README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md)** | Network debugging with tcpdump/Wireshark for ONVIF traffic | 930 lines |
| **[README_HTTP_HEADERS.md](README_HTTP_HEADERS.md)** | HTTP protocol details for ONVIF communication | 963 lines |
| **[README_OPENSSL_GUIDE.md](README_OPENSSL_GUIDE.md)** | Cryptographic functions used in ONVIF authentication | 1323 lines |

---

## 🗺️ Learning Path

### For Beginners

Start here to understand ONVIF fundamentals:

1. **[README_ONVIF_AUTHENTICATION.md](README_ONVIF_AUTHENTICATION.md)** - Understand what ONVIF is and how authentication works
2. **[README_XML_ONVIF.md](README_XML_ONVIF.md)** - Learn SOAP/XML message structure
3. **[README_HTTP_HEADERS.md](README_HTTP_HEADERS.md)** - Understand HTTP transport layer

### For Developers

Dive into implementation details:

1. **[README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md)** - Understand project architecture
2. **[README_OPENSSL_GUIDE.md](README_OPENSSL_GUIDE.md)** - Learn about cryptographic functions
3. **[fakecamera/authhandler/README_AUTH_UTILS.md](fakecamera/authhandler/README_AUTH_UTILS.md)** - Authentication module details

### For Debugging

Troubleshoot issues with network analysis:

1. **[README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md)** - Capture and analyze ONVIF traffic
2. **[README_HTTP_HEADERS.md](README_HTTP_HEADERS.md)** - Understand HTTP request/response headers

---

## 📖 Quick Topic Reference

### Authentication
- **WS-Security (UsernameToken)**: [README_ONVIF_AUTHENTICATION.md](README_ONVIF_AUTHENTICATION.md#ws-usernametoken-authentication)
- **HTTP Digest**: [README_ONVIF_AUTHENTICATION.md](README_ONVIF_AUTHENTICATION.md#http-digest-authentication)
- **Password Digest Calculation**: [README_XML_ONVIF.md](README_XML_ONVIF.md#ws-security-header-structure)
- **Cryptographic Functions**: [README_OPENSSL_GUIDE.md](README_OPENSSL_GUIDE.md)

### XML/SOAP
- **SOAP Message Structure**: [README_XML_ONVIF.md](README_XML_ONVIF.md#soap-message-structure)
- **XML Namespaces**: [README_XML_ONVIF.md](README_XML_ONVIF.md#xml-namespaces-in-onvif)
- **SOAP Templates**: [README_XML_ONVIF.md](README_XML_ONVIF.md#soap-templates-in-this-project)
- **XML Parsing**: [README_XML_ONVIF.md](README_XML_ONVIF.md#xml-parsing-techniques)

### ONVIF Services
- **GetSystemDateAndTime**: [README_XML_ONVIF.md](README_XML_ONVIF.md#1-getsystemdateandtime-unauthenticated)
- **GetDeviceInformation**: [README_XML_ONVIF.md](README_XML_ONVIF.md#2-getdeviceinformation-requires-authentication)
- **GetServices**: [README_XML_ONVIF.md](README_XML_ONVIF.md#3-getservices)
- **GetCapabilities**: [README_XML_ONVIF.md](README_XML_ONVIF.md#4-getcapabilities)

### Architecture
- **Project Structure**: [README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md#project-structure-overview)
- **Module Interactions**: [README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md#module-interactions)
- **Threading Model**: [README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md#threading-model)
- **Adding New Services**: [README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md#adding-new-onvif-services)

### Network Debugging
- **Capturing Traffic**: [README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md#capturing-onvif-traffic)
- **Wireshark Filters**: [README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md#wireshark-filters-for-onvif)
- **Debugging Auth Issues**: [README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md#debugging-authentication-issues)
- **Common Patterns**: [README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md#common-packet-patterns)

### HTTP Protocol
- **HTTP Headers**: [README_HTTP_HEADERS.md](README_HTTP_HEADERS.md)
- **Content Types**: [README_HTTP_HEADERS.md](README_HTTP_HEADERS.md#content-type-header)
- **Status Codes**: [README_HTTP_HEADERS.md](README_HTTP_HEADERS.md#http-status-codes)

---

## 🔧 Common Tasks

### "I want to add a new authentication method"
→ [README_MODULAR_DESIGN.md - Adding New Authentication Methods](README_MODULAR_DESIGN.md#adding-new-authentication-methods)

### "I want to add a new ONVIF service"
→ [README_MODULAR_DESIGN.md - Adding New ONVIF Services](README_MODULAR_DESIGN.md#adding-new-onvif-services)

### "Authentication is failing, how do I debug?"
→ [README_PACKET_ANALYSIS.md - Debugging Authentication Issues](README_PACKET_ANALYSIS.md#debugging-authentication-issues)

### "I need to understand how WS-Security works"
→ [README_ONVIF_AUTHENTICATION.md - WS-UsernameToken](README_ONVIF_AUTHENTICATION.md#ws-usernametoken-authentication)

### "How do I construct an ONVIF message?"
→ [README_XML_ONVIF.md - Constructing ONVIF Messages](README_XML_ONVIF.md#constructing-onvif-messages)

### "Camera not responding to discovery"
→ [README_PACKET_ANALYSIS.md - Troubleshooting Connection Issues](README_PACKET_ANALYSIS.md#troubleshooting-connection-issues)

---

## 📊 Documentation Coverage

| Topic | Primary Document | Supporting Documents |
|-------|------------------|---------------------|
| **Authentication** | README_ONVIF_AUTHENTICATION.md | README_OPENSSL_GUIDE.md, README_PACKET_ANALYSIS.md |
| **XML/SOAP** | README_XML_ONVIF.md | README_HTTP_HEADERS.md |
| **Architecture** | README_MODULAR_DESIGN.md | fakecamera/authhandler/README_AUTH_UTILS.md |
| **Debugging** | README_PACKET_ANALYSIS.md | README_HTTP_HEADERS.md |
| **Cryptography** | README_OPENSSL_GUIDE.md | README_ONVIF_AUTHENTICATION.md |
| **HTTP Protocol** | README_HTTP_HEADERS.md | README_PACKET_ANALYSIS.md |

---

## 🎯 Features Covered

✅ WS-Security (UsernameToken) authentication  
✅ HTTP Digest authentication  
✅ SOAP message structure and namespaces  
✅ ONVIF service request/response examples  
✅ XML parsing techniques  
✅ Project architecture and modular design  
✅ Module interactions and threading  
✅ Network packet capture (tcpdump/Wireshark)  
✅ Wireshark filters for ONVIF  
✅ Debugging authentication issues  
✅ Common packet patterns  
✅ Troubleshooting connection problems  
✅ HTTP headers and status codes  
✅ OpenSSL cryptographic functions  

---

## 🚀 Quick Start

### New to ONVIF?
Start with [README_ONVIF_AUTHENTICATION.md](README_ONVIF_AUTHENTICATION.md) to understand the basics.

### Want to Develop?
Read [README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md) to understand the project structure.

### Need to Debug?
Use [README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md) to capture and analyze network traffic.

### Looking for Examples?
Check [README_XML_ONVIF.md](README_XML_ONVIF.md) for complete SOAP message examples.

---

## 📝 Documentation Statistics

- **Total Lines**: 5,798 lines
- **Total Size**: ~165 KB
- **Number of Documents**: 6 main guides + 1 module-specific guide
- **Topics Covered**: 50+ distinct topics
- **Code Examples**: 100+ examples
- **Network Commands**: 30+ tcpdump/Wireshark commands

---

## 🤝 Contributing

When adding new features, please update the relevant documentation:
- New authentication method → Update README_ONVIF_AUTHENTICATION.md
- New ONVIF service → Update README_XML_ONVIF.md
- New module → Update README_MODULAR_DESIGN.md
- New debugging technique → Update README_PACKET_ANALYSIS.md

---

## 📞 Support

If you can't find what you're looking for:
1. Check the table of contents in each document
2. Use search (Ctrl+F) for specific terms
3. Review cross-references between documents
4. Check code comments in source files

---

**Last Updated**: 2024-01-15  
**Project**: ONVIF Camera Simulator (fakecamera)
**Maintained by**: ONVIF-SIM Development Team
