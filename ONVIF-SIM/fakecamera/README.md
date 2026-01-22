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

### Flexible Port (CAMERA_HTTP_PORT = 8080)
- **Protocol**: TCP HTTP
- **Purpose**: ONVIF Device Services (GetDeviceInformation, etc.)
- **Why Flexible**: 
  - Per ONVIF spec, the HTTP port is advertised in discovery `<XAddrs>`
  - Clients read this from discovery response and connect accordingly
  - Can be changed in `discovery_server.h` and `auth_server.h` to use a different port

## Files Overview

| File | Purpose |
|------|---------|
| `discovery_server.h` | UDP multicast WS-Discovery implementation (defines CAMERA_HTTP_PORT, DISCOVERY_PORT) |
| `auth_server.h` | TCP HTTP server for SOAP authentication (defines AUTH_PORT = CAMERA_HTTP_PORT) |
| `main.c` | Thread orchestration |
| `dis.xml` | Cached discovery response (auto-generated) |
| `auth.xml` | Device information template |
| `Credentials.csv` | Username/password pairs for authentication |
| `Attempts.csv` | Log of authentication attempts |

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

```bash
# Compile
gcc -o fakecamera main.c -lpthread

# Run
./fakecamera

# Output:
# Both servers running. Press Ctrl+C to stop.
# === WS-Discovery Server ===
# Auth server started on port 8080
# Local IP: x.x.x.x
# ...
```

## Changing the HTTP Port

Edit both `discovery_server.h` and `auth_server.h`:
```c
#define CAMERA_HTTP_PORT 8081  // Changed from 8080
```
In `auth_server.h`, also change:
```c
#define AUTH_PORT 8081  // Changed from 8080
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
