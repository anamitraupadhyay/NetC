# ONVIF Packet Analysis & Network Debugging Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Tools Overview](#tools-overview)
3. [Capturing ONVIF Traffic](#capturing-onvif-traffic)
4. [Analyzing HTTP/SOAP Traffic](#analyzing-httpsoap-traffic)
5. [Wireshark Filters for ONVIF](#wireshark-filters-for-onvif)
6. [Debugging Authentication Issues](#debugging-authentication-issues)
7. [Common Packet Patterns](#common-packet-patterns)
8. [Troubleshooting Connection Issues](#troubleshooting-connection-issues)
9. [Reading Wireshark Output](#reading-wireshark-output)
10. [Advanced Debugging Techniques](#advanced-debugging-techniques)
11. [Related Documentation](#related-documentation)

---

## Introduction

Network packet analysis is **essential** for debugging ONVIF implementations. Since ONVIF uses HTTP/SOAP over TCP, all communication can be captured and analyzed.

### Why Packet Analysis?

| Scenario | How Packet Analysis Helps |
|----------|---------------------------|
| **Client not discovering camera** | See if WS-Discovery packets are being sent/received |
| **Authentication failing** | Inspect WS-Security headers for format errors |
| **No response from server** | Check if request reaches server, validate response format |
| **SOAP errors** | Read exact error messages in response body |
| **Performance issues** | Measure request/response times, identify bottlenecks |

---

## Tools Overview

### 1. tcpdump (Command-Line)

**Pros**:
- Lightweight, available on all Linux systems
- Perfect for server-side captures
- Can save to file for later analysis

**Cons**:
- Less user-friendly
- Harder to read complex protocols

**Use when**: Capturing on headless servers, automation

---

### 2. Wireshark (GUI)

**Pros**:
- Visual interface
- Protocol dissectors (automatic parsing)
- Powerful filtering
- Follow TCP stream feature

**Cons**:
- Requires GUI
- Heavier than tcpdump

**Use when**: Detailed analysis, learning protocol behavior

---

### 3. tshark (Command-Line Wireshark)

**Pros**:
- Wireshark's power in CLI
- Protocol dissection like Wireshark
- Can display specific fields

**Cons**:
- More complex syntax

**Use when**: Automated analysis, scripting

---

## Capturing ONVIF Traffic

### Basic Capture Setup

```bash
# Capture on specific port (ONVIF default: 8080)
sudo tcpdump -i any port 8080 -w onvif_capture.pcap

# Capture both discovery (3702) and ONVIF (8080)
sudo tcpdump -i any 'port 3702 or port 8080' -w onvif_full.pcap

# Capture with timestamp
sudo tcpdump -i any port 8080 -tttt -w onvif_$(date +%Y%m%d_%H%M%S).pcap
```

### Capturing WS-Discovery (UDP Multicast)

```bash
# Capture UDP port 3702 (WS-Discovery)
sudo tcpdump -i any udp port 3702 -w discovery.pcap

# Capture with hex + ASCII dump
sudo tcpdump -i any udp port 3702 -X

# Capture to stdout for immediate viewing
sudo tcpdump -i any udp port 3702 -A
```

**Example Output**:
```
14:30:45.123456 IP 192.168.1.50.54321 > 239.255.255.250.3702: UDP, length 512
E..!.@.@...2...........`.......
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
...
</s:Envelope>
```

---

### Capturing on Specific Interface

```bash
# List available interfaces
ip link show

# Capture on eth0
sudo tcpdump -i eth0 port 8080 -w onvif.pcap

# Capture on all interfaces (Linux)
sudo tcpdump -i any port 8080 -w onvif.pcap
```

---

### Limiting Capture Size

```bash
# Capture first 100 packets
sudo tcpdump -i any port 8080 -c 100 -w onvif.pcap

# Rotate files every 10MB
sudo tcpdump -i any port 8080 -W 5 -C 10 -w onvif

# Result: onvif0, onvif1, onvif2, onvif3, onvif4 (5 files, max 10MB each)
```

---

## Analyzing HTTP/SOAP Traffic

### Opening Capture in Wireshark

```bash
wireshark onvif_capture.pcap
```

Or drag-and-drop the `.pcap` file into Wireshark.

---

### Following TCP Stream

**Method 1: Right-click packet**
1. In Wireshark, find any HTTP packet
2. Right-click → "Follow" → "TCP Stream"
3. See complete conversation (request + response)

**Method 2: Filter by stream**
```
tcp.stream eq 0
```

**Example TCP Stream Output**:
```
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 487

<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetSystemDateAndTime/>
  </s:Body>
</s:Envelope>

HTTP/1.1 200 OK
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 534
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetSystemDateAndTimeResponse>
      <tds:SystemDateAndTime>
        <tt:UTCDateTime>
          <tt:Time><tt:Hour>14</tt:Hour>...
        </tt:UTCDateTime>
      </tds:SystemDateAndTime>
    </tds:GetSystemDateAndTimeResponse>
  </s:Body>
</s:Envelope>
```

---

### Using tshark for Quick Analysis

```bash
# Display HTTP requests
tshark -r onvif_capture.pcap -Y "http.request" -T fields -e http.request.method -e http.request.uri

# Display HTTP responses
tshark -r onvif_capture.pcap -Y "http.response" -T fields -e http.response.code -e http.response.phrase

# Show SOAP Actions
tshark -r onvif_capture.pcap -Y "xml" -T fields -e xml.tag.name
```

**Example Output**:
```
POST    /onvif/device_service
POST    /onvif/device_service
POST    /onvif/device_service

200     OK
401     Unauthorized
200     OK
```

---

## Wireshark Filters for ONVIF

### Basic Filters

| Filter | Description |
|--------|-------------|
| `tcp.port == 8080` | All ONVIF traffic (default port) |
| `udp.port == 3702` | All WS-Discovery traffic |
| `http` | All HTTP packets |
| `http.request` | HTTP requests only |
| `http.response` | HTTP responses only |
| `http.response.code == 401` | Unauthorized responses |
| `http.response.code == 200` | Successful responses |

---

### Advanced Filters

#### Filter by IP Address
```
ip.addr == 192.168.1.100        # Any traffic to/from this IP
ip.src == 192.168.1.50          # Traffic from this IP
ip.dst == 192.168.1.100         # Traffic to this IP
```

#### Filter by HTTP Method
```
http.request.method == "POST"   # All POST requests
http.request.method == "GET"    # All GET requests
```

#### Filter by Content-Type
```
http.content_type contains "soap+xml"
```

#### Filter by URL Path
```
http.request.uri contains "/onvif/device_service"
http.request.uri contains "/onvif/media_service"
```

#### Combining Filters (AND, OR)
```
# HTTP POST requests to port 8080
http.request.method == "POST" and tcp.port == 8080

# Responses that are either 200 or 401
http.response.code == 200 or http.response.code == 401

# ONVIF traffic (TCP or UDP)
tcp.port == 8080 or udp.port == 3702
```

---

### SOAP-Specific Filters

```
# Packets containing "GetSystemDateAndTime"
frame contains "GetSystemDateAndTime"

# Packets containing WS-Security
frame contains "wsse:Security"

# Packets containing authentication
frame contains "Authorization"

# Specific ONVIF actions
frame contains "GetDeviceInformation"
frame contains "GetCapabilities"
frame contains "GetProfiles"
```

---

### Time-Based Filters

```
# Packets after specific time
frame.time >= "2024-01-15 14:30:00"

# Packets in time range
frame.time >= "2024-01-15 14:30:00" and frame.time <= "2024-01-15 14:35:00"

# Time between packets > 1 second
frame.time_delta > 1
```

---

## Debugging Authentication Issues

### Scenario 1: WS-Security Authentication Failure

**Symptoms**:
- Client sends request with `<wsse:Security>` header
- Server responds with HTTP 401 or SOAP fault

**Analysis Steps**:

**Step 1: Capture traffic**
```bash
sudo tcpdump -i any port 8080 -w auth_debug.pcap
```

**Step 2: Open in Wireshark and filter**
```
http.request and frame contains "wsse:Security"
```

**Step 3: Follow TCP stream, check request**

Look for:
```xml
<wsse:Security>
    <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="...#PasswordDigest">
            fG3zNjQxYzE2ZjA5MzQ3ZTk4ZjEzNzI4ZDM5MTdiY2Q=
        </wsse:Password>
        <wsse:Nonce EncodingType="...#Base64Binary">
            MTY1NzU0MzIxMDEyMzQ1Njc4OQ==
        </wsse:Nonce>
        <wsu:Created>2024-01-15T14:30:45Z</wsu:Created>
    </wsse:UsernameToken>
</wsse:Security>
```

**Common Issues**:

| Issue | How to Identify | Fix |
|-------|----------------|-----|
| **Missing `wsu:Created`** | No `<wsu:Created>` tag | Add timestamp |
| **Invalid timestamp format** | Not ISO 8601 (`2024-01-15T14:30:45Z`) | Fix format |
| **Wrong password digest** | Digest doesn't match expected | Verify: Base64(SHA1(Nonce + Created + Password)) |
| **Nonce not Base64 encoded** | Nonce contains non-Base64 chars | Encode nonce |
| **Incorrect namespace** | Uses wrong `xmlns:wsse` URL | Use standard OASIS namespace |

---

### Scenario 2: HTTP Digest Authentication Failure

**Symptoms**:
- Server sends `401` with `WWW-Authenticate: Digest`
- Client retries with `Authorization: Digest` but still fails

**Analysis Steps**:

**Step 1: Capture 401 response**

Filter: `http.response.code == 401`

Check `WWW-Authenticate` header:
```
WWW-Authenticate: Digest realm="ONVIF", nonce="1234567890abcdef", qop="auth"
```

**Step 2: Capture client retry**

Filter: `http.request and frame contains "Authorization: Digest"`

Check `Authorization` header:
```
Authorization: Digest username="admin", realm="ONVIF", nonce="1234567890abcdef", 
uri="/onvif/device_service", response="5e8d1f3c2b4a6e9d...", qop=auth, nc=00000001, cnonce="xyz123"
```

**Step 3: Verify response calculation**

The `response` field should be:
```
MD5(MD5(username:realm:password):nonce:nc:cnonce:qop:MD5(method:uri))
```

**Common Issues**:

| Issue | How to Identify | Fix |
|-------|----------------|-----|
| **Mismatched realm** | Client uses different realm than server provided | Use exact realm from 401 response |
| **Incorrect nonce** | Client uses old/wrong nonce | Use nonce from most recent 401 |
| **Wrong URI** | `uri` in Authorization doesn't match request URI | Use exact request URI |
| **Algorithm mismatch** | Server expects MD5, client uses SHA-256 | Use MD5 for standard HTTP Digest |

---

### Scenario 3: No Authentication Sent

**Symptoms**:
- Server responds with `401 Unauthorized`
- Client doesn't include auth headers

**Analysis**:

Filter: `http.request`

Check if request has:
- `Authorization:` header (for HTTP Digest/Basic)
- `<wsse:Security>` in SOAP body (for WS-Security)

**If neither exists**: Client is not sending credentials.

**Solution**: Configure client to send authentication.

---

## Common Packet Patterns

### Pattern 1: Successful Discovery Flow

```
Client (192.168.1.50) → Multicast (239.255.255.250:3702)
    UDP Probe Request
    <?xml version="1.0"?>
    <s:Envelope>
      <s:Body>
        <d:Probe>
          <d:Types>dn:NetworkVideoTransmitter</d:Types>
        </d:Probe>
      </s:Body>
    </s:Envelope>

Camera (192.168.1.100) → Client (192.168.1.50)
    UDP ProbeMatch Response
    <?xml version="1.0"?>
    <s:Envelope>
      <s:Body>
        <d:ProbeMatches>
          <d:ProbeMatch>
            <a:EndpointReference>
              <a:Address>urn:uuid:12345678-1234-1234-1234-123456789012</a:Address>
            </a:EndpointReference>
            <d:XAddrs>http://192.168.1.100:8080/onvif/device_service</d:XAddrs>
          </d:ProbeMatch>
        </d:ProbeMatches>
      </s:Body>
    </s:Envelope>
```

**Wireshark Filter**: `udp.port == 3702`

---

### Pattern 2: Unauthenticated Request (GetSystemDateAndTime)

```
Client → Camera (TCP 3-way handshake)
    SYN
    SYN-ACK
    ACK

Client → Camera
    POST /onvif/device_service HTTP/1.1
    Content-Type: application/soap+xml
    
    <s:Envelope>
      <s:Body>
        <tds:GetSystemDateAndTime/>
      </s:Body>
    </s:Envelope>

Camera → Client
    HTTP/1.1 200 OK
    Content-Type: application/soap+xml
    
    <s:Envelope>
      <s:Body>
        <tds:GetSystemDateAndTimeResponse>
          <tds:SystemDateAndTime>...</tds:SystemDateAndTime>
        </tds:GetSystemDateAndTimeResponse>
      </s:Body>
    </s:Envelope>

Client → Camera (Connection close)
    FIN-ACK
    ACK
    FIN-ACK
    ACK
```

**Wireshark Filter**: `tcp.stream eq 0`

---

### Pattern 3: Authenticated Request (with WS-Security)

```
Client → Camera
    POST /onvif/device_service HTTP/1.1
    
    <s:Envelope>
      <s:Header>
        <wsse:Security>
          <wsse:UsernameToken>
            <wsse:Username>admin</wsse:Username>
            <wsse:Password>...</wsse:Password>
            <wsse:Nonce>...</wsse:Nonce>
            <wsu:Created>2024-01-15T14:30:45Z</wsu:Created>
          </wsse:UsernameToken>
        </wsse:Security>
      </s:Header>
      <s:Body>
        <tds:GetDeviceInformation/>
      </s:Body>
    </s:Envelope>

Camera → Client
    HTTP/1.1 200 OK
    
    <s:Envelope>
      <s:Body>
        <tds:GetDeviceInformationResponse>
          <tds:Manufacturer>Videonetics</tds:Manufacturer>
          <tds:Model>Camera_Emulator</tds:Model>
          ...
        </tds:GetDeviceInformationResponse>
      </s:Body>
    </s:Envelope>
```

**Wireshark Filter**: `frame contains "wsse:Security"`

---

### Pattern 4: HTTP Digest Challenge-Response

```
Client → Camera (Request without auth)
    POST /onvif/device_service HTTP/1.1
    
    <tds:GetDeviceInformation/>

Camera → Client (Challenge)
    HTTP/1.1 401 Unauthorized
    WWW-Authenticate: Digest realm="ONVIF", nonce="abc123", qop="auth"

Client → Camera (Retry with auth)
    POST /onvif/device_service HTTP/1.1
    Authorization: Digest username="admin", realm="ONVIF", nonce="abc123", 
                   uri="/onvif/device_service", response="5e8d1f3c..."
    
    <tds:GetDeviceInformation/>

Camera → Client (Success)
    HTTP/1.1 200 OK
    
    <tds:GetDeviceInformationResponse>...</tds:GetDeviceInformationResponse>
```

**Wireshark Filter**: `http.response.code == 401 or (http.request and frame contains "Authorization: Digest")`

---

## Troubleshooting Connection Issues

### Issue 1: Camera Not Responding to Discovery

**Symptoms**:
- Client sends Probe, no ProbeMatch received

**Debug Steps**:

**1. Check if Probe reaches camera**
```bash
# On camera/server
sudo tcpdump -i any udp port 3702 -A
```

If you see Probe requests → Server is receiving but not responding.

If you **don't** see Probe requests:
- Check firewall rules
- Verify client is on same network
- Check multicast routing

**2. Verify multicast membership**
```bash
# Check if joined multicast group
netstat -g | grep 239.255.255.250
```

Should show:
```
eth0  239.255.255.250
```

**3. Test with manual probe**
```bash
# Send manual Probe
echo '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>urn:uuid:test-123</a:MessageID></s:Header><s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></s:Body></s:Envelope>' | \
nc -u 239.255.255.250 3702
```

---

### Issue 2: Connection Timeout to ONVIF Port

**Symptoms**:
- Client can't connect to `http://192.168.1.100:8080`

**Debug Steps**:

**1. Check if server is listening**
```bash
# On server
netstat -tuln | grep 8080
```

Expected:
```
tcp  0  0  0.0.0.0:8080  0.0.0.0:*  LISTEN
```

**2. Test connectivity**
```bash
# From client
telnet 192.168.1.100 8080
```

If connection refused → Server not running or firewall blocking.

**3. Check firewall**
```bash
# On server (iptables)
sudo iptables -L -n | grep 8080

# Allow traffic
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

**4. Capture connection attempt**
```bash
# On server
sudo tcpdump -i any port 8080 -n
```

If you see SYN but no SYN-ACK → Server not responding.

---

### Issue 3: Partial HTTP Requests/Responses

**Symptoms**:
- Request/response seems truncated in Wireshark

**Causes**:
- TCP segmentation (large packets split across multiple segments)

**Solution in Wireshark**:

1. Enable "Reassemble TCP streams"
   - Edit → Preferences → Protocols → TCP
   - Check "Allow subdissector to reassemble TCP streams"

2. Follow TCP stream to see complete message

---

### Issue 4: Delayed Responses

**Symptoms**:
- Long time between request and response

**Analysis**:

**1. Check timing in Wireshark**

Add column: "Time (since previous frame)"
- Right-click column header → Column Preferences
- Add: `frame.time_delta_displayed`

**2. Identify slow operations**

Filter: `frame.time_delta > 1`  (Shows packets with >1 second gap)

**3. Profile server-side processing**

Add logging in `auth_server.h`:
```c
time_t start = time(NULL);
// ... process request ...
time_t end = time(NULL);
printf("[DEBUG] Request took %ld seconds\n", end - start);
```

---

## Reading Wireshark Output

### Understanding Packet List Columns

| Column | Meaning | Example |
|--------|---------|---------|
| **No.** | Packet number | 42 |
| **Time** | Timestamp | 14:30:45.123456 |
| **Source** | Source IP | 192.168.1.50 |
| **Destination** | Destination IP | 192.168.1.100 |
| **Protocol** | Protocol | HTTP, TCP, UDP |
| **Length** | Packet length (bytes) | 1514 |
| **Info** | Protocol info | GET /onvif/device_service |

---

### TCP Flags

| Flag | Meaning |
|------|---------|
| **SYN** | Synchronize (start connection) |
| **ACK** | Acknowledgment |
| **FIN** | Finish (close connection) |
| **RST** | Reset (abort connection) |
| **PSH** | Push (send data immediately) |

**Example 3-way handshake**:
```
1. Client → Server: [SYN]
2. Server → Client: [SYN, ACK]
3. Client → Server: [ACK]
```

---

### HTTP Status Codes in ONVIF

| Code | Meaning | Common Cause |
|------|---------|--------------|
| **200 OK** | Success | Valid request |
| **400 Bad Request** | Malformed request | Invalid XML/SOAP |
| **401 Unauthorized** | Auth required or failed | Missing/wrong credentials |
| **404 Not Found** | Wrong URL | Incorrect service path |
| **500 Internal Server Error** | Server error | Bug in server code |

---

## Advanced Debugging Techniques

### Technique 1: Compare Working vs. Failing Requests

**Scenario**: Client A works, Client B doesn't

**Steps**:

1. Capture both:
```bash
sudo tcpdump -i any port 8080 -w clientA.pcap  # While A connects
sudo tcpdump -i any port 8080 -w clientB.pcap  # While B connects
```

2. Open both in Wireshark

3. Follow TCP stream for each, save to text:
   - Follow TCP Stream → "Save as" → clientA.txt, clientB.txt

4. Compare with `diff`:
```bash
diff clientA.txt clientB.txt
```

5. Look for differences in:
   - HTTP headers (Content-Type, Content-Length)
   - SOAP namespaces
   - Auth headers/tokens
   - MessageID format

---

### Technique 2: Replay Modified Requests

**Use Case**: Test if changing a header fixes the issue

**Tools**: `curl`, `python requests`

**Example**: Replay captured request with modified auth

```bash
# Save request body from Wireshark to request.xml

# Replay with curl
curl -X POST http://192.168.1.100:8080/onvif/device_service \
  -H "Content-Type: application/soap+xml; charset=utf-8" \
  -d @request.xml \
  -v  # Verbose output
```

---

### Technique 3: Log Server-Side with Packet Timestamps

**Goal**: Correlate server logs with packets

**In server code**:
```c
#include <sys/time.h>

void log_with_timestamp(const char *msg) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("[%ld.%06ld] %s\n", tv.tv_sec, tv.tv_usec, msg);
}

// Usage
log_with_timestamp("Request received");
// ... process ...
log_with_timestamp("Response sent");
```

**Match with Wireshark**: Compare timestamps to identify delays.

---

### Technique 4: Export HTTP Objects

**Goal**: Save all SOAP requests/responses to files

**In Wireshark**:
1. File → Export Objects → HTTP
2. Select packets, click "Save All"
3. Inspect XML files with text editor or XML validator

---

### Technique 5: Statistics

**In Wireshark**:

**1. Conversations (find chattiest endpoints)**
- Statistics → Conversations → TCP tab
- Sort by "Bytes" to see highest traffic

**2. HTTP Statistics**
- Statistics → HTTP → Packet Counter
- See distribution of request methods and response codes

**3. I/O Graph (visualize traffic over time)**
- Statistics → I/O Graph
- Add filter: `http.request` (requests over time)
- Add filter: `http.response` (responses over time)

---

## Related Documentation

- **[README_XML_ONVIF.md](README_XML_ONVIF.md)**: SOAP/XML message structure
- **[README_ONVIF_AUTHENTICATION.md](README_ONVIF_AUTHENTICATION.md)**: Authentication methods
- **[README_HTTP_HEADERS.md](README_HTTP_HEADERS.md)**: HTTP protocol details
- **[README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md)**: Project architecture
- **[README_OPENSSL_GUIDE.md](README_OPENSSL_GUIDE.md)**: Cryptographic functions

---

## Quick Reference: Essential Commands

```bash
# Capture ONVIF traffic
sudo tcpdump -i any port 8080 -w onvif.pcap

# Capture WS-Discovery
sudo tcpdump -i any udp port 3702 -w discovery.pcap

# View capture live
sudo tcpdump -i any port 8080 -A

# Open in Wireshark
wireshark onvif.pcap

# Extract HTTP content
tshark -r onvif.pcap -Y "http" -T fields -e http.request.uri -e http.response.code

# Follow specific TCP stream
tshark -r onvif.pcap -z follow,tcp,ascii,0
```

---

## Troubleshooting Checklist

When debugging ONVIF issues:

- [ ] Capture traffic on both client and server
- [ ] Verify packets reach the destination (check with tcpdump)
- [ ] Check HTTP status codes (200 = success, 401 = auth issue)
- [ ] Validate SOAP XML structure (use XML validator)
- [ ] Inspect authentication headers (WS-Security or HTTP Digest)
- [ ] Compare with working reference implementation
- [ ] Check server logs for errors
- [ ] Measure request/response times
- [ ] Review firewall rules
- [ ] Test with minimal example (e.g., GetSystemDateAndTime)

**Remember**: Network captures never lie. If something's wrong, the packets will show it!

---

**Last Updated**: 2024-01-15  
**Project**: ONVIF Camera Simulator (fakecamera)
