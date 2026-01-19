# ONVIF Camera Implementation - Modular Learning Roadmap

## Overview

This guide outlines the **step-by-step progression** from a basic WS-Discovery server to a full ONVIF-compliant IP camera implementation. Each module builds on the previous one, maintaining educational clarity while adding functionality.

**Current Status**: ✅ Module 1 (WS-Discovery) is complete

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    ONVIF IP Camera                          │
├─────────────────────────────────────────────────────────────┤
│  Module 5: Media Streaming (RTSP/RTP)                      │
│  Module 4: PTZ Control (Pan/Tilt/Zoom)                     │
│  Module 3: Device Management (SOAP/HTTP)                   │
│  Module 2: Authentication (WS-UsernameToken/Digest)        │
│  Module 1: Discovery (WS-Discovery/UDP) ✅ COMPLETE        │
├─────────────────────────────────────────────────────────────┤
│         Networking Stack (UDP, TCP, Multicast)              │
└─────────────────────────────────────────────────────────────┘
```

---

## Module 1: WS-Discovery (✅ Complete)

**Location**: `fakecamera/discovery_server.c`, `onvif_discoverer.c`

**What it does:**
- Listens on UDP multicast (239.255.255.250:3702)
- Responds to ONVIF Probe messages with ProbeMatch
- Advertises camera presence on network

**Protocol**: WS-Discovery over UDP multicast

**Skills learned:**
- UDP socket programming
- Multicast group membership (IP_ADD_MEMBERSHIP)
- SOAP XML message parsing
- Non-blocking I/O patterns

**Code complexity**: ~250 lines (server), ~800 lines (client with docs)

**What's missing for full ONVIF camera:**
- Device services endpoint (HTTP server)
- Authentication mechanism
- Device information queries
- Media profiles and streaming

---

## Module 2: Authentication & Security

**Status**: 🔲 Not Implemented

### What to Add

#### 2.1: WS-UsernameToken (Basic Authentication)

**Location**: `fakecamera/auth_basic.c` (new file)

**Purpose**: Implement HTTP Basic Auth and WS-Security UsernameToken

**Components:**
```c
// Headers to add
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <time.h>

// Structures
typedef struct {
    char username[64];
    char password_hash[SHA256_DIGEST_LENGTH * 2 + 1];  // SHA-256 hex
    time_t created_at;
} user_credentials_t;

// Functions to implement
int base64_encode(const unsigned char *input, int length, char *output);
int base64_decode(const char *input, unsigned char *output);
int sha256_hash(const char *password, char *output);
int verify_credentials(const char *username, const char *password);
```

**SOAP Header for authentication:**
```xml
<s:Header>
  <Security xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <UsernameToken>
      <Username>admin</Username>
      <Password Type="...#PasswordDigest">...</Password>
      <Nonce>...</Nonce>
      <Created>...</Created>
    </UsernameToken>
  </Security>
</s:Header>
```

**Skills to learn:**
- HTTP Basic Authentication header parsing
- WS-Security UsernameToken specification
- SHA-256 hashing and Base64 encoding
- Nonce generation and replay attack prevention
- Time synchronization (Created timestamp validation)

**Dependencies:**
```bash
# Install OpenSSL development headers
sudo apt-get install libssl-dev
```

**References:**
- WS-Security UsernameToken Profile 1.1
- RFC 7617 (HTTP Basic Authentication)
- ONVIF Core Specification Section 5.12

---

#### 2.2: Digest Authentication (Enhanced Security)

**Location**: `fakecamera/auth_digest.c` (new file)

**Purpose**: HTTP Digest Auth for replay attack prevention

**Components:**
```c
typedef struct {
    char realm[128];
    char nonce[64];
    char opaque[64];
    char qop[32];  // "auth" or "auth-int"
    int nonce_count;
} digest_challenge_t;

// Functions
char* generate_nonce(void);
int verify_digest_response(const char *username, const char *uri, 
                          const char *response, const digest_challenge_t *challenge);
```

**Skills to learn:**
- MD5 hashing for digest computation
- Challenge-response authentication
- Nonce management and expiration
- Replay attack mitigation

**References:**
- RFC 7616 (HTTP Digest Access Authentication)

---

## Module 3: Device Management (HTTP/SOAP)

**Status**: 🔲 Not Implemented

### What to Add

#### 3.1: HTTP Server Foundation

**Location**: `fakecamera/http_server.c` (new file)

**Purpose**: Handle SOAP requests over HTTP

**Components:**
```c
#include <sys/epoll.h>
#include <pthread.h>

typedef struct {
    int client_fd;
    char method[16];      // GET, POST
    char uri[256];        // /onvif/device_service
    char soap_action[256];
    size_t content_length;
    char *body;
} http_request_t;

typedef struct {
    int status_code;      // 200, 401, 500
    char content_type[64];
    char *body;
    size_t body_length;
} http_response_t;

// Functions to implement
int http_server_init(int port);
int http_parse_request(int fd, http_request_t *req);
int http_send_response(int fd, http_response_t *resp);
void* http_worker_thread(void *arg);
```

**Skills to learn:**
- TCP server socket programming (accept, listen)
- HTTP/1.1 protocol parsing (headers, chunked encoding)
- Multi-threaded server design (thread pool pattern)
- epoll for I/O multiplexing
- Keep-alive connection management

**Server architecture:**
```
┌─────────────┐
│ Main Thread │ (accept connections)
└──────┬──────┘
       │
       ├──> Worker Thread 1 (handle request)
       ├──> Worker Thread 2
       └──> Worker Thread N
```

**References:**
- RFC 7230 (HTTP/1.1 Message Syntax)
- ONVIF Core Specification Section 5.1

---

#### 3.2: SOAP Message Processing

**Location**: `fakecamera/soap_processor.c` (new file)

**Purpose**: Parse SOAP envelopes and dispatch to handlers

**Components:**
```c
#include <libxml/parser.h>
#include <libxml/xpath.h>

typedef enum {
    SOAP_ACTION_GET_DEVICE_INFORMATION,
    SOAP_ACTION_GET_CAPABILITIES,
    SOAP_ACTION_GET_SERVICES,
    SOAP_ACTION_GET_SCOPES,
    SOAP_ACTION_SET_SCOPES,
    SOAP_ACTION_SYSTEM_REBOOT,
    // ... more actions
} soap_action_t;

typedef struct {
    soap_action_t action;
    xmlDocPtr doc;
    xmlXPathContextPtr xpath_ctx;
    void *user_data;
} soap_request_t;

typedef struct {
    char *xml_response;
    size_t length;
    int fault_code;  // 0 = success, others = SOAP fault
} soap_response_t;

// Functions
soap_action_t soap_parse_action(const char *soap_action_header);
int soap_parse_envelope(const char *xml, soap_request_t *req);
void soap_dispatch_handler(soap_request_t *req, soap_response_t *resp);
char* soap_build_fault(const char *fault_code, const char *fault_string);
```

**SOAP handlers to implement:**

1. **GetDeviceInformation**
   ```c
   void handle_get_device_information(soap_request_t *req, soap_response_t *resp);
   // Returns: Manufacturer, Model, FirmwareVersion, SerialNumber, HardwareId
   ```

2. **GetCapabilities**
   ```c
   void handle_get_capabilities(soap_request_t *req, soap_response_t *resp);
   // Returns: Supported ONVIF services (Device, Media, PTZ, Imaging, Analytics)
   ```

3. **GetServices**
   ```c
   void handle_get_services(soap_request_t *req, soap_response_t *resp);
   // Returns: List of service endpoints with versions
   ```

**Skills to learn:**
- XML parsing with libxml2
- XPath for element extraction
- SOAP envelope structure
- SOAP fault handling
- Namespace management in XML

**Dependencies:**
```bash
sudo apt-get install libxml2-dev
```

**Example SOAP request:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>
```

**Example SOAP response:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>FakeCam Inc.</tds:Manufacturer>
      <tds:Model>FC-1000</tds:Model>
      <tds:FirmwareVersion>1.0.0</tds:FirmwareVersion>
      <tds:SerialNumber>123456789</tds:SerialNumber>
      <tds:HardwareId>FC-HW-01</tds:HardwareId>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>
```

**References:**
- SOAP Version 1.2 Specification
- ONVIF Device Management Service Specification

---

#### 3.3: Device Configuration Management

**Location**: `fakecamera/device_config.c` (new file)

**Purpose**: Store and retrieve device settings

**Components:**
```c
typedef struct {
    char name[64];
    char location[128];
    char manufacturer[64];
    char model[64];
    char firmware_version[32];
    char serial_number[64];
    char hardware_id[64];
    
    // Network settings
    char hostname[64];
    bool dhcp_enabled;
    char ip_address[16];
    char netmask[16];
    char gateway[16];
    char dns_servers[2][16];
    
    // Scopes (for WS-Discovery)
    char scopes[10][256];
    int scope_count;
    
    // Date/Time
    bool ntp_enabled;
    char ntp_server[64];
    char timezone[64];
} device_config_t;

// Functions
int config_load(device_config_t *config);
int config_save(const device_config_t *config);
int config_set_network(device_config_t *config, const char *ip, const char *netmask);
int config_add_scope(device_config_t *config, const char *scope);
```

**Skills to learn:**
- Configuration file parsing (JSON, XML, or custom format)
- Atomic file updates (write to temp, rename)
- Configuration validation
- Default value management

**Example config file** (`device_config.json`):
```json
{
  "device": {
    "name": "MyFakeCamera",
    "manufacturer": "FakeCam Inc.",
    "model": "FC-1000",
    "firmware_version": "1.0.0",
    "serial_number": "123456789"
  },
  "network": {
    "dhcp": true,
    "ip": "192.168.1.100",
    "netmask": "255.255.255.0",
    "gateway": "192.168.1.1"
  },
  "scopes": [
    "onvif://www.onvif.org/name/MyFakeCamera",
    "onvif://www.onvif.org/location/Office",
    "onvif://www.onvif.org/hardware/FakeCam"
  ]
}
```

**References:**
- ONVIF Core Specification Section 5.2

---

## Module 4: Media Profiles & Streaming Configuration

**Status**: 🔲 Not Implemented

### What to Add

#### 4.1: Media Service

**Location**: `fakecamera/media_service.c` (new file)

**Purpose**: Manage video/audio profiles and stream URIs

**Components:**
```c
typedef struct {
    char token[64];
    char name[128];
    
    // Video encoder configuration
    struct {
        char encoding[32];     // H.264, H.265, JPEG
        int width;
        int height;
        int framerate;
        int bitrate;
        char profile[32];      // Baseline, Main, High
    } video;
    
    // Audio encoder configuration (optional)
    struct {
        char encoding[32];     // AAC, G.711
        int bitrate;
        int sample_rate;
    } audio;
} media_profile_t;

// Functions to implement
int media_get_profiles(media_profile_t *profiles, int *count);
int media_get_stream_uri(const char *profile_token, char *uri, size_t uri_size);
int media_get_snapshot_uri(const char *profile_token, char *uri, size_t uri_size);
int media_create_profile(media_profile_t *profile);
int media_delete_profile(const char *profile_token);
```

**SOAP handlers:**

1. **GetProfiles**
   ```c
   void handle_get_profiles(soap_request_t *req, soap_response_t *resp);
   // Returns list of all media profiles
   ```

2. **GetStreamUri**
   ```c
   void handle_get_stream_uri(soap_request_t *req, soap_response_t *resp);
   // Returns: rtsp://192.168.1.100:554/stream1
   ```

3. **GetSnapshotUri**
   ```c
   void handle_get_snapshot_uri(soap_request_t *req, soap_response_t *resp);
   // Returns: http://192.168.1.100:8080/snapshot.jpg
   ```

**Skills to learn:**
- Video/audio codec parameters
- Media profile management
- URI generation and validation
- Resource constraints handling

**Example response:**
```xml
<trt:GetProfilesResponse>
  <trt:Profiles token="profile_1">
    <tt:Name>High Quality</tt:Name>
    <tt:VideoEncoderConfiguration>
      <tt:Encoding>H264</tt:Encoding>
      <tt:Resolution>
        <tt:Width>1920</tt:Width>
        <tt:Height>1080</tt:Height>
      </tt:Resolution>
      <tt:Quality>5</tt:Quality>
      <tt:RateControl>
        <tt:FrameRateLimit>30</tt:FrameRateLimit>
        <tt:BitrateLimit>4096</tt:BitrateLimit>
      </tt:RateControl>
    </tt:VideoEncoderConfiguration>
  </trt:Profiles>
</trt:GetProfilesResponse>
```

**References:**
- ONVIF Media Service Specification

---

## Module 5: RTSP Streaming (Advanced)

**Status**: 🔲 Not Implemented

### What to Add

#### 5.1: RTSP Server

**Location**: `fakecamera/rtsp_server.c` (new file)

**Purpose**: Serve video streams via RTSP protocol

**Components:**
```c
typedef enum {
    RTSP_OPTIONS,
    RTSP_DESCRIBE,
    RTSP_SETUP,
    RTSP_PLAY,
    RTSP_PAUSE,
    RTSP_TEARDOWN
} rtsp_method_t;

typedef struct {
    int client_fd;
    rtsp_method_t method;
    char uri[256];
    int cseq;
    char session_id[64];
    int client_port[2];  // RTP, RTCP
} rtsp_request_t;

typedef struct {
    int status_code;
    int cseq;
    char session_id[64];
    int server_port[2];  // RTP, RTCP
    char sdp[4096];      // Session Description Protocol
} rtsp_response_t;

// Functions
int rtsp_server_init(int port);  // Default: 554
int rtsp_parse_request(int fd, rtsp_request_t *req);
int rtsp_send_response(int fd, rtsp_response_t *resp);
char* rtsp_generate_sdp(const media_profile_t *profile);
```

**RTSP protocol flow:**
```
Client                          Server
  |                               |
  |---------- OPTIONS ----------->|  (What methods supported?)
  |<-------- 200 OK --------------|
  |                               |
  |---------- DESCRIBE ---------->|  (Get SDP for stream)
  |<-- 200 OK + SDP --------------|
  |                               |
  |---------- SETUP ------------->|  (Establish session, ports)
  |<-- 200 OK + Session ID -------|
  |                               |
  |---------- PLAY -------------->|  (Start streaming)
  |<-------- 200 OK --------------|
  |                               |
  |<======= RTP Packets ==========|  (Video/audio data)
  |                               |
  |---------- TEARDOWN ---------->|  (Stop stream)
  |<-------- 200 OK --------------|
```

**Skills to learn:**
- RTSP protocol (RFC 2326 / RFC 7826)
- Session Description Protocol (SDP)
- Transport negotiation (UDP vs TCP)
- Session management

**Example SDP:**
```
v=0
o=- 1234567890 1234567890 IN IP4 192.168.1.100
s=FakeCam Stream
c=IN IP4 192.168.1.100
t=0 0
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
a=fmtp:96 packetization-mode=1;profile-level-id=42001f
a=control:track1
```

**References:**
- RFC 7826 (RTSP 2.0)
- RFC 4566 (SDP)

---

#### 5.2: RTP/RTCP Streaming

**Location**: `fakecamera/rtp_streaming.c` (new file)

**Purpose**: Send video/audio packets using RTP

**Components:**
```c
typedef struct {
    uint8_t version:2;
    uint8_t padding:1;
    uint8_t extension:1;
    uint8_t csrc_count:4;
    uint8_t marker:1;
    uint8_t payload_type:7;
    uint16_t sequence_number;
    uint32_t timestamp;
    uint32_t ssrc;
} rtp_header_t;

typedef struct {
    int socket_fd;
    struct sockaddr_in dest_addr;
    uint16_t sequence_number;
    uint32_t timestamp;
    uint32_t ssrc;
    media_profile_t *profile;
} rtp_session_t;

// Functions
int rtp_session_init(rtp_session_t *session, const char *dest_ip, int dest_port);
int rtp_send_h264_frame(rtp_session_t *session, const uint8_t *frame, size_t size);
int rtp_send_jpeg_frame(rtp_session_t *session, const uint8_t *jpeg, size_t size);
int rtcp_send_sender_report(rtp_session_t *session);
```

**Skills to learn:**
- RTP protocol (RFC 3550)
- H.264 NAL unit packetization (RFC 6184)
- JPEG over RTP (RFC 2435)
- RTCP sender/receiver reports
- Jitter buffer management

**H.264 packetization:**
```c
// For frames > MTU (~1400 bytes), use FU-A fragmentation
// FU-A Header:
// +---------------+
// |0|1|2|3|4|5|6|7|
// +-+-+-+-+-+-+-+-+
// |S|E|R|  Type   |
// +---------------+
```

**References:**
- RFC 3550 (RTP)
- RFC 6184 (H.264 Payload Format)
- RFC 4585 (RTCP Extensions)

---

#### 5.3: Video Source (Test Pattern Generator)

**Location**: `fakecamera/video_source.c` (new file)

**Purpose**: Generate test video frames (since we don't have real camera)

**Components:**
```c
typedef struct {
    int width;
    int height;
    int framerate;
    uint8_t *yuv_buffer;  // YUV420 format
    int frame_counter;
} video_source_t;

// Functions
int video_source_init(video_source_t *src, int width, int height, int fps);
int video_source_generate_frame(video_source_t *src);  // Creates test pattern
int video_source_encode_h264(video_source_t *src, uint8_t *out, size_t *out_size);
void video_source_destroy(video_source_t *src);
```

**Test patterns to generate:**
1. Color bars (SMPTE standard)
2. Moving gradient
3. Timestamp overlay
4. Checkerboard pattern

**Skills to learn:**
- YUV color space (YUV420, YUV422)
- H.264 encoding with libx264 or OpenH264
- Frame timing and pacing
- Memory management for video buffers

**Dependencies:**
```bash
sudo apt-get install libx264-dev  # or libopenh264-dev
```

**Example encoding:**
```c
#include <x264.h>

x264_param_t param;
x264_param_default_preset(&param, "ultrafast", "zerolatency");
param.i_width = 1920;
param.i_height = 1080;
param.i_fps_num = 30;
param.i_fps_den = 1;

x264_t *encoder = x264_encoder_open(&param);
```

**References:**
- libx264 documentation
- YUV format specifications

---

## Module 6: PTZ Control (Optional)

**Status**: 🔲 Not Implemented

### What to Add

**Location**: `fakecamera/ptz_service.c` (new file)

**Purpose**: Pan/Tilt/Zoom control interface

**Components:**
```c
typedef struct {
    float pan;    // -1.0 to 1.0 (left to right)
    float tilt;   // -1.0 to 1.0 (down to up)
    float zoom;   // 0.0 to 1.0
} ptz_position_t;

typedef struct {
    float pan_speed;
    float tilt_speed;
    float zoom_speed;
} ptz_velocity_t;

// Functions
int ptz_absolute_move(const char *profile_token, ptz_position_t *pos);
int ptz_relative_move(const char *profile_token, ptz_position_t *offset);
int ptz_continuous_move(const char *profile_token, ptz_velocity_t *vel);
int ptz_stop(const char *profile_token);
int ptz_get_status(const char *profile_token, ptz_position_t *pos);
```

**Skills to learn:**
- PTZ coordinate systems
- Velocity control algorithms
- Position feedback simulation

**References:**
- ONVIF PTZ Service Specification

---

## Module 7: Events & Analytics (Optional)

**Status**: 🔲 Not Implemented

### What to Add

**Location**: `fakecamera/event_service.c` (new file)

**Purpose**: Publish events (motion detection, tampering, etc.)

**Components:**
- Event subscription management (SOAP)
- Event notification (HTTP POST)
- Motion detection simulation
- Real-time event topics

**Skills to learn:**
- WS-BaseNotification
- WS-Topics
- Event filtering
- Subscription renewal

**References:**
- ONVIF Event Service Specification

---

## Learning Path & Dependencies

### Recommended Implementation Order

```
Module 1: WS-Discovery ✅ COMPLETE
   ↓
Module 2: Authentication (start with Basic, add Digest later)
   ↓
Module 3.1: HTTP Server
   ↓
Module 3.2: SOAP Processing + Device Management
   ↓
Module 3.3: Device Configuration
   ↓
Module 4: Media Profiles (without actual streaming yet)
   ↓
Module 5.3: Video Source (test pattern generator)
   ↓
Module 5.1: RTSP Server
   ↓
Module 5.2: RTP Streaming
   ↓
Module 6: PTZ (optional)
   ↓
Module 7: Events (optional)
```

### Dependency Graph

```
┌─────────────────┐
│  WS-Discovery   │ ✅ COMPLETE
└────────┬────────┘
         │
         ↓
┌─────────────────┐     ┌─────────────────┐
│ Authentication  │────>│  HTTP Server    │
└─────────────────┘     └────────┬────────┘
                                 │
                                 ↓
                        ┌─────────────────┐
                        │ SOAP Processor  │
                        └────────┬────────┘
                                 │
                    ┌────────────┼────────────┐
                    ↓            ↓            ↓
           ┌────────────┐ ┌──────────┐ ┌──────────┐
           │   Device   │ │  Media   │ │   PTZ    │
           │ Management │ │ Service  │ │ Service  │
           └────────────┘ └─────┬────┘ └──────────┘
                                │
                    ┌───────────┼───────────┐
                    ↓           ↓           ↓
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │   RTSP   │ │   RTP    │ │  Video   │
              │  Server  │ │ Streaming│ │  Source  │
              └──────────┘ └──────────┘ └──────────┘
```

---

## Testing Each Module

### Module 2: Authentication
```bash
# Test with curl
curl -u admin:password http://localhost:8080/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  -d @test_request.xml
```

### Module 3: Device Management
```bash
# Test GetDeviceInformation
curl -X POST http://localhost:8080/onvif/device_service \
  -H "Content-Type: application/soap+xml" \
  -d '<?xml version="1.0"?>...'
```

### Module 4: Media Profiles
```bash
# Use ONVIF Device Manager or custom client
./test_media_client
```

### Module 5: RTSP Streaming
```bash
# Test with VLC
vlc rtsp://admin:password@192.168.1.100:554/stream1

# Test with ffplay
ffplay -rtsp_transport tcp rtsp://localhost:554/stream1
```

---

## Code Size Estimates

| Module | Approx. Lines | Files |
|--------|--------------|-------|
| Module 1 (WS-Discovery) | 800 | 2 ✅ |
| Module 2 (Auth) | 500 | 2 |
| Module 3.1 (HTTP Server) | 800 | 1 |
| Module 3.2 (SOAP) | 1000 | 1 |
| Module 3.3 (Config) | 300 | 1 |
| Module 4 (Media) | 600 | 1 |
| Module 5.1 (RTSP) | 1200 | 1 |
| Module 5.2 (RTP) | 800 | 1 |
| Module 5.3 (Video) | 600 | 1 |
| Module 6 (PTZ) | 400 | 1 |
| Module 7 (Events) | 500 | 1 |
| **Total** | **~7,500** | **13** |

---

## External Dependencies Summary

```bash
# Core dependencies (needed early)
sudo apt-get install libssl-dev      # Module 2: Auth
sudo apt-get install libxml2-dev     # Module 3: SOAP

# Media dependencies (needed later)
sudo apt-get install libx264-dev     # Module 5: H.264 encoding
# or
sudo apt-get install libopenh264-dev # Alternative H.264 encoder

# Optional dependencies
sudo apt-get install libjpeg-dev     # JPEG snapshot support
```

---

## Educational Value of Each Module

### Module 1 (✅ Complete): **Foundation**
- UDP sockets, multicast
- Non-blocking I/O
- SOAP/XML basics

### Module 2: **Security**
- Cryptographic hashing
- Authentication protocols
- Replay attack prevention

### Module 3: **Application Protocol**
- HTTP parsing and generation
- Multi-threaded server design
- SOAP message handling
- epoll for scalability

### Module 4: **Multimedia Concepts**
- Video codecs and parameters
- Media profile management
- URI handling

### Module 5: **Real-time Streaming**
- RTSP protocol state machine
- RTP packetization
- Network timing and jitter
- Video encoding pipeline

### Module 6: **Control Systems**
- Coordinate systems
- Velocity control
- Position feedback

### Module 7: **Event-driven Architecture**
- Publish-subscribe pattern
- Event filtering
- Long-lived HTTP connections

---

## Complexity vs. Educational Value

```
High │                    ┌────────┐
     │                    │Module 5│ RTP/RTSP
     │         ┌────────┐ │(Hard)  │
E    │         │Module 3│ └────────┘
d    │         │ SOAP   │
u    │         └────────┘
c    │  ┌────────┐            ┌────────┐
a    │  │Module 2│            │Module 6│ PTZ
t    │  │  Auth  │            └────────┘
i    │  └────────┘     ┌────────┐
o  ✅│ Module 1         │Module 4│
n    │ Discovery        │ Media  │
a    │ (Complete)       └────────┘
l    │                  ┌────────┐
     │                  │Module 7│ Events
Low  │                  └────────┘
     └────────────────────────────────────
           Low        Medium        High
                 Complexity
```

**Recommendation**: Implement modules 2-4 next for maximum educational value with manageable complexity.

---

## Next Steps

1. **Start with Module 2.1** (Basic Authentication)
   - Implement WS-UsernameToken
   - Test with simple HTTP requests
   - ~2-3 days of work

2. **Then Module 3.1** (HTTP Server)
   - Basic TCP server
   - HTTP request parsing
   - Multi-threaded design
   - ~3-5 days of work

3. **Follow with Module 3.2** (SOAP Processing)
   - GetDeviceInformation handler
   - GetCapabilities handler
   - XML response building
   - ~4-6 days of work

**Estimated total time to full ONVIF camera**: 4-6 weeks of focused development

---

## Additional Resources

### Books
- **ONVIF Application Programmer's Guide**
- **Video Demystified** by Keith Jack (for video fundamentals)
- **RTP: Audio and Video for the Internet** by Colin Perkins

### Online
- ONVIF Specifications: [onvif.org/profiles](https://www.onvif.org/profiles/)
- RTSP RFC 7826: [tools.ietf.org/html/rfc7826](https://tools.ietf.org/html/rfc7826)
- RTP RFC 3550: [tools.ietf.org/html/rfc3550](https://tools.ietf.org/html/rfc3550)

### Tools for Testing
- **ONVIF Device Manager** (Windows)
- **ONVIF Device Test Tool** (Official conformance testing)
- **VLC Media Player** (for RTSP streams)
- **Wireshark** (protocol analysis)
- **curl** (HTTP/SOAP testing)

---

## Summary

This roadmap provides a **clear progression** from the completed WS-Discovery module to a full ONVIF camera implementation. Each module:

- ✅ Builds on previous modules
- ✅ Has clear learning objectives
- ✅ Includes code structure templates
- ✅ References relevant specifications
- ✅ Provides testing methods

**Start with Module 2 to add authentication, then gradually build up to streaming capabilities.**

The modular approach ensures you can stop at any point and still have a functional (albeit limited) ONVIF device, while maintaining the educational clarity that makes this project valuable for learning.
