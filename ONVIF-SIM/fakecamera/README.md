# ONVIF Fake Camera Emulator

A minimal ONVIF-compliant camera emulator that implements WS-Discovery and HTTP-based authentication services.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ONVIF Client                               │
│                    (e.g., ONVIF Device Manager)                     │
└─────────────────────────────────────────────────────────────────────┘
                │                                   │
                │ (1) WS-Discovery Probe            │ (3) HTTP SOAP Request
                │     UDP Multicast                 │     TCP Connection
                │     239.255.255.250:3702          │     <IP>:8080
                ▼                                   ▼
┌───────────────────────────┐      ┌────────────────────────────────────┐
│   Discovery Server        │      │    Auth/HTTP Server                │
│   (UDP - Port 3702)       │      │    (TCP - Port 8080)               │
│                           │      │                                    │
│   - Joins multicast group │      │   - Accepts TCP connections        │
│   - Listens for Probe     │      │   - Parses SOAP requests           │
│   - Responds with         │      │   - Validates credentials          │
│     ProbeMatch including  │      │   - Returns device info (200 OK)   │
│     XAddrs with HTTP port │      │   - Or 401 Unauthorized            │
└───────────────────────────┘      └────────────────────────────────────┘
                │                                   ▲
                │ (2) ProbeMatch Response           │
                │     Contains XAddrs:              │
                │     http://<IP>:8080/onvif/       │
                │            device_service         │
                └───────────────────────────────────┘
```

## Port Configuration

### Fixed Port (DISCOVERY_PORT = 3702)
- **Protocol**: UDP Multicast
- **Purpose**: WS-Discovery as per OASIS specification
- **Why Fixed**: ONVIF mandates WS-Discovery on this port; all ONVIF devices and clients must use it
- **Multicast Address**: 239.255.255.250

### Configurable HTTP Port (default: 8080)
- **Protocol**: TCP HTTP
- **Purpose**: ONVIF Device Services (GetDeviceInformation, etc.)
- **Configuration**: Set in `config.xml`:
  ```xml
  <config>
      <server_port>8080</server_port>
  </config>
  ```
- **Why Configurable**: Per ONVIF spec, the HTTP port is advertised in discovery `<XAddrs>`

## Configuration (config.xml)

The emulator reads configuration from `config.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<config>
    <!-- Network Configuration -->
    <server_port>8080</server_port>
    
    <!-- Device Information -->
    <device>
        <manufacturer>Videonetics</manufacturer>
        <model>Videonetics_Camera_Emulator</model>
        <firmware_version>10.0</firmware_version>
        <serial_number>VN001</serial_number>
        <hardware_id>1.0</hardware_id>
    </device>
    
    <!-- ONVIF Scopes -->
    <scopes>
        <scope>onvif://www.onvif.org/type/video_encoder</scope>
        <scope>onvif://www.onvif.org/Profile/Streaming</scope>
    </scopes>
</config>
```

## Files Overview

| File | Purpose |
|------|---------|
| `main.c` | Thread orchestration |
| `discovery_server.h` | UDP multicast WS-Discovery implementation |
| `auth_server.h` | TCP HTTP server for SOAP authentication |
| `config.h` | Configuration loading (XML parsing) |
| `config.xml` | Configuration file (port, device info) |
| `xml_parser.h` | libxml2-based XML parsing utilities |
| `auth.xml` | Device information template |
| `Credentials.csv` | Username/password pairs for authentication |
| `Attempts.csv` | Log of authentication attempts |
| `last_response.xml` | Debug file - last sent discovery response (auto-generated, gitignored) |

### Documentation

See `docs/` folder for detailed documentation:
- `docs/libxml2_transition.md` - Transition from simple XML parsing to libxml2, including Swift XMLParser interop

## XML Parsing

The emulator supports two XML parsing modes:

### Simple Parser (Default)
- No external dependencies
- Uses `strstr()` for basic XML parsing
- Sufficient for simple config files

### libxml2 Parser (Optional)
- Full XML 1.0 compliance
- XPath support
- Namespace-aware parsing
- Enable with `-DUSE_LIBXML2`

```bash
# Build with libxml2 support
gcc -DUSE_LIBXML2 -o fakecamera main.c -lpthread $(pkg-config --cflags --libs libxml-2.0)
```

## UUID Management

The discovery server uses two types of UUIDs:

### Device Endpoint UUID (Fixed)
- **Purpose**: Identifies the device uniquely across all discovery requests
- **Source**: Derived from `/etc/machine-id` for consistency across restarts
- **Location**: `<a:EndpointReference><a:Address>` element
- **Behavior**: Remains the same for all responses from this device

### Response MessageID (Dynamic)
- **Purpose**: Uniquely identifies each response message
- **Source**: Generated fresh for each probe response using `/dev/urandom`
- **Location**: `<a:MessageID>` element in the response header
- **Behavior**: Different for every response

### RelatesTo
- **Purpose**: Links response back to the original probe request
- **Source**: Extracted from the incoming probe's `<a:MessageID>`
- **Behavior**: Always matches the probe's MessageID

## Theory: UDP vs TCP for ONVIF

### WS-Discovery (UDP)
```
Client                          Camera
   │                               │
   │──── Probe (UDP multicast) ───►│
   │                               │
   │◄─── ProbeMatch (UDP unicast)──│
   │                               │
```

- **Why UDP**: Discovery uses multicast to find all devices on network simultaneously
- **Multicast**: Sent to 239.255.255.250:3702, all devices receive and respond
- **No Connection**: No handshake required; fire-and-forget with optional response

### ONVIF Services (TCP HTTP)
```
Client                          Camera
   │                               │
   │──── TCP SYN ─────────────────►│
   │◄─── TCP SYN-ACK ─────────────│
   │──── TCP ACK ─────────────────►│
   │                               │
   │──── HTTP POST (SOAP) ────────►│
   │◄─── HTTP 200 (SOAP Response)──│
   │                               │
```

- **Why TCP**: Reliable delivery for SOAP requests/responses
- **Why HTTP**: ONVIF services are SOAP-over-HTTP
- **Connection-Oriented**: Ensures request-response integrity

## Minimal HTTP Server Implementation

The `auth_server.h` implements a minimal HTTP server sufficient for ONVIF:

```c
// TCP socket creation and binding
int sock = socket(AF_INET, SOCK_STREAM, 0);  // TCP
addr.sin_port = htons(CAMERA_HTTP_PORT);
bind(sock, (struct sockaddr *)&addr, sizeof(addr));
listen(sock, 5);

// Accept loop
while (1) {
    int cs = accept(sock, ...);
    recv(cs, buf, ...);
    // Parse SOAP, validate credentials
    send(cs, response, ...);  // HTTP 200 or 401
    close(cs);
}
```

### Why This Is Sufficient
1. ONVIF uses HTTP/1.1 with single request-response per connection
2. No keep-alive or complex HTTP features needed
3. SOAP is self-contained in request/response body

## Flow Sequence

### 1. Discovery Flow
```
[ONVIF Client] ──UDP multicast──► [Discovery Server:3702]
                                        │
                                        │ Check: is this a Probe?
                                        │
                   ◄──UDP unicast────────┘
                   ProbeMatch with:
                   XAddrs="http://<IP>:8080/onvif/device_service"
```

### 2. Authentication Flow
```
[ONVIF Client] ──TCP connect──► [Auth Server:8080]
                │
                │──HTTP POST──►
                │   SOAP GetDeviceInformation
                │   + WS-Security (username/password)
                │
                │◄──HTTP 200───
                │   SOAP DeviceInformation
                │
                └──TCP close──►
```

## Building and Running

### Basic Build (no libxml2)
```bash
# Compile
gcc -o fakecamera main.c -lpthread

# Run
./fakecamera
```

### Build with libxml2 (recommended)
```bash
# Install libxml2 (Ubuntu/Debian)
sudo apt-get install libxml2-dev

# Compile with libxml2 support
gcc -DUSE_LIBXML2 -o fakecamera main.c -lpthread $(pkg-config --cflags --libs libxml-2.0)

# Run
./fakecamera
```

### Expected Output
```
Both servers running. Press Ctrl+C to stop.
=== WS-Discovery Server ===
[CONFIG] Loaded config using simple parser from config.xml
[CONFIG] server_port=8080, manufacturer=Videonetics, model=Videonetics_Camera_Emulator
Auth server started on port 8080
Local IP: x.x.x.x
...
```

## Changing the HTTP Port

Simply edit `config.xml`:
```xml
<config>
    <server_port>9000</server_port>
</config>
```

The discovery response will automatically advertise the new port in XAddrs.

## Credential Configuration

### Default Hardcoded
- Username: `admin`
- Password: `password`

### CSV-Based
Add entries to `Credentials.csv`:
```csv
admin,mypassword
operator,operatorpass
```

## Testing Discovery

Using ONVIF Device Manager:
1. Run `./fakecamera`
2. Open ONVIF Device Manager
3. Click "Discover"
4. Camera should appear with name "Videonetics_Camera_Emulator"

Using command-line:
```bash
# Send WS-Discovery probe (requires netcat/socat with multicast support)
echo '<Probe>...</Probe>' | socat - UDP-DATAGRAM:239.255.255.250:3702

# Test HTTP endpoint
curl -X POST http://localhost:8080/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  -d '<SOAP envelope>'
```

## Design Decisions

### Why Not Separate HTTP Server?
The existing `auth_server.h` already implements a TCP server that:
1. Accepts HTTP connections
2. Parses SOAP requests
3. Returns HTTP responses

Creating a separate HTTP server would be redundant. The minimal TCP implementation is sufficient for ONVIF's SOAP-over-HTTP.

### Why CAMERA_HTTP_PORT in Discovery?
- Discovery advertises the HTTP service URL in XAddrs
- Auth server must bind to the same port that discovery advertises
- Both headers define the same port value (8080 by default)
- To change the port, update both `discovery_server.h` and `auth_server.h`

### Why Not UDP for Auth?
- SOAP requires reliable delivery
- Request/response must be matched
- Credentials must not be lost
- HTTP semantics (status codes) are needed

## Alternatives Considered

| Approach | Pros | Cons |
|----------|------|------|
| **Current (TCP in auth_server)** | Minimal, sufficient for ONVIF | Basic HTTP parsing |
| Separate HTTP library (libmicrohttpd) | Full HTTP support | Additional dependency |
| UDP-based protocol | Simpler | Not ONVIF compliant |
| Embedded web server | Production-ready | Overkill for emulator |

## Security Notes

⚠️ **This is an emulator for testing purposes only**

- Credentials are stored in plain text
- No TLS/HTTPS support
- No rate limiting on authentication
- All attempts are logged to CSV

For production ONVIF cameras, implement:
- TLS for HTTP
- Secure credential storage
- Digest authentication (WS-UsernameToken)
- Rate limiting
