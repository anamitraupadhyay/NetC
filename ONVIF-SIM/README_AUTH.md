# ONVIF Authentication Implementation

This directory contains a minimal, readable, and versatile implementation of ONVIF authentication using WS-Security UsernameToken.

## Overview

ONVIF (Open Network Video Interface Forum) devices require authentication for most operations. This implementation provides a simple way to add authentication to ONVIF SOAP requests.

## Files

- **`auth.h`** - Header file with authentication function declarations
- **`auth.c`** - Implementation of authentication functions
- **`auth_example.c`** - Example program demonstrating usage
- **`auth_example.xml`** - XML example showing the authentication format
- **`Makefile`** - Build script for the example program

## Authentication Method

This implementation uses **WS-Security UsernameToken** with **Password Digest** authentication:

- ✅ **Secure**: Password is never sent in plain text
- ✅ **Standard**: Follows ONVIF/WS-Security specifications
- ✅ **Replay-protected**: Uses nonce and timestamp
- ✅ **Versatile**: Works with any ONVIF device

### Password Digest Formula

```
PasswordDigest = Base64( SHA1( Nonce + Created + Password ) )
```

Where:
- **Nonce**: Random 16-byte value (Base64 encoded)
- **Created**: UTC timestamp in ISO 8601 format
- **Password**: The actual password (not transmitted)

## Building

### Prerequisites

```bash
# Install OpenSSL development libraries
# Ubuntu/Debian:
sudo apt-get install libssl-dev

# Fedora/RHEL:
sudo dnf install openssl-devel

# macOS (with Homebrew):
brew install openssl
```

### Compile

```bash
cd ONVIF-SIM
make
```

### Run Example

```bash
make run
```

Or directly:

```bash
./auth_example
```

## Usage

### Quick Start

```c
#include "auth.h"

int main(void) {
    char request[4096];
    const char *body = "<tds:GetDeviceInformation "
                      "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>";
    
    if (build_authenticated_request("admin", "password", body, 
                                   request, sizeof(request)) == 0) {
        // Send 'request' via HTTP POST to device
        printf("Ready to send: %s\n", request);
    }
    
    return 0;
}
```

### API Functions

#### 1. Generate Authentication Header Only

```c
int generate_auth_header(const char *username, const char *password, 
                        char *buffer, size_t buffer_size);
```

**Use this when**: You need just the WS-Security header to insert into your own SOAP envelope.

**Example**:
```c
char auth_header[2048];
generate_auth_header("admin", "password", auth_header, sizeof(auth_header));
// auth_header now contains: <wsse:Security>...</wsse:Security>
```

#### 2. Build Complete Authenticated Request

```c
int build_authenticated_request(const char *username, const char *password,
                               const char *soap_body, char *buffer, 
                               size_t buffer_size);
```

**Use this when**: You want a complete SOAP envelope with authentication.

**Example**:
```c
char request[4096];
const char *body = "<tds:GetSystemDateAndTime "
                  "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>";
build_authenticated_request("admin", "password", body, request, sizeof(request));
// request now contains complete SOAP envelope with auth header
```

## Common ONVIF Requests

### 1. Get Device Information

```c
const char *body = 
    "<tds:GetDeviceInformation "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>";

build_authenticated_request("admin", "password", body, request, sizeof(request));
// POST to: http://<device-ip>/onvif/device_service
```

### 2. Get System Date and Time

```c
const char *body = 
    "<tds:GetSystemDateAndTime "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>";

build_authenticated_request("admin", "password", body, request, sizeof(request));
// POST to: http://<device-ip>/onvif/device_service
```

### 3. Get Media Profiles

```c
const char *body = 
    "<trt:GetProfiles "
    "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"/>";

build_authenticated_request("admin", "password", body, request, sizeof(request));
// POST to: http://<device-ip>/onvif/media_service
```

### 4. Get Stream URI

```c
const char *body = 
    "<trt:GetStreamUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">"
    "<trt:StreamSetup>"
    "<tt:Stream xmlns:tt=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</tt:Stream>"
    "<tt:Transport xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<tt:Protocol>RTSP</tt:Protocol>"
    "</tt:Transport>"
    "</trt:StreamSetup>"
    "<trt:ProfileToken>Profile_1</trt:ProfileToken>"
    "</trt:GetStreamUri>";

build_authenticated_request("admin", "password", body, request, sizeof(request));
// POST to: http://<device-ip>/onvif/media_service
```

## HTTP Request Format

When sending to an ONVIF device:

```
POST /onvif/device_service HTTP/1.1
Host: <device-ip>
Content-Type: application/soap+xml; charset=utf-8
Content-Length: <length>
Accept: application/soap+xml

<SOAP Request from build_authenticated_request()>
```

## ONVIF Service Endpoints

| Service | Typical Endpoint |
|---------|------------------|
| Device  | `/onvif/device_service` |
| Media   | `/onvif/media_service` |
| PTZ     | `/onvif/ptz_service` |
| Imaging | `/onvif/imaging_service` |
| Events  | `/onvif/events_service` |

## XML Format Reference

See `auth_example.xml` for a fully annotated example of the authentication format.

Key components:
```xml
<s:Envelope>
  <s:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="...#PasswordDigest">...</wsse:Password>
        <wsse:Nonce EncodingType="...#Base64Binary">...</wsse:Nonce>
        <wsu:Created>2026-01-20T04:00:00Z</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <!-- Your ONVIF request here -->
  </s:Body>
</s:Envelope>
```

## Security Notes

1. **Password Digest**: The password is never transmitted in plain text. Instead, a SHA-1 digest is sent.

2. **Nonce**: A random value that prevents replay attacks. Each request should have a unique nonce.

3. **Timestamp**: The `Created` timestamp prevents old requests from being reused.

4. **HTTPS**: For maximum security, use HTTPS when communicating with ONVIF devices in production.

## Integration with Existing Code

To add authentication to the existing discovery/camera code:

```c
// After discovering a camera with discovery_server.c or camdis.c:
#include "auth.h"

void query_camera_info(const char *device_ip, int port, 
                      const char *username, const char *password) {
    char request[4096];
    const char *body = "<tds:GetDeviceInformation "
                      "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>";
    
    build_authenticated_request(username, password, body, request, sizeof(request));
    
    // Send via HTTP POST to http://<device_ip>:<port>/onvif/device_service
    // (HTTP sending code not included - use libcurl or similar)
}
```

## Troubleshooting

### Build Errors

**Error**: `fatal error: openssl/sha.h: No such file or directory`
- **Solution**: Install OpenSSL development libraries (see Prerequisites)

**Error**: `undefined reference to 'SHA1'`
- **Solution**: Make sure to link with `-lssl -lcrypto`

### Authentication Failures

**Error**: Device returns 401 Unauthorized
- Check username and password are correct
- Ensure device supports WS-Security authentication
- Verify the device's time is synchronized (timestamp validation)

**Error**: Device returns 400 Bad Request
- Check XML format is valid
- Ensure namespace declarations are correct
- Verify the service endpoint URL is correct

## Standards and References

- **WS-Security**: OASIS Web Services Security
- **ONVIF Core Specification**: www.onvif.org
- **Username Token Profile**: OASIS WS-Security UsernameToken Profile 1.0

## License

This implementation is part of the NetC repository and follows the repository's license.

## Author

Part of the NetC networking library collection.
