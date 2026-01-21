# NetC - Networking Library for Video Management Systems

A comprehensive C networking library implementing ONVIF camera simulation, WS-Discovery, RTSP streaming, and the foundational components for building a Video Management System (VMS).

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Components](#components)
  - [ONVIF Camera Simulator](#onvif-camera-simulator)
  - [Camera Discovery Tool](#camera-discovery-tool)
  - [Streaming Server](#streaming-server)
  - [Image Transfer Protocol](#image-transfer-protocol)
- [Building a VMS System](#building-a-vms-system)
- [ONVIF Test Tool Integration](#onvif-test-tool-integration)
- [API Reference](#api-reference)
- [Code Examples](#code-examples)
- [Troubleshooting](#troubleshooting)

---

## Overview

NetC provides the building blocks for a complete Video Management System using standard networking protocols. The library implements:

- **WS-Discovery** (Port 3702, Multicast 239.255.255.250) - Device discovery
- **ONVIF Device Service** (Port 8080) - Camera configuration and control
- **RTSP Streaming** (Port 554) - Real-time video streaming
- **TCP/UDP Socket Communication** - Low-level data transfer

### Directory Structure

```
NetC/
├── ONVIF-SIM/
│   ├── fakecamera/          # ONVIF camera emulator
│   │   ├── auth_server.h    # ONVIF device/media service
│   │   ├── discovery_server.h # WS-Discovery server
│   │   └── main.c           # Entry point
│   └── CamDiscoverer/       # Camera discovery client
├── onviflibrary/
│   └── layer1/              # Low-level UDP multicast
├── dynaimgtcp/              # TCP image transfer
├── imgsharewithparitycheck/ # Reliable image transfer
├── kernelimplementationfromscratch/ # Socket implementation study
└── simplemsg/               # Basic messaging
```

---

## Architecture

### VMS System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     VIDEO MANAGEMENT SYSTEM                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Discovery  │    │    Device    │    │   Streaming  │          │
│  │    Layer     │    │   Control    │    │    Layer     │          │
│  │              │    │    Layer     │    │              │          │
│  │ WS-Discovery │    │    ONVIF     │    │    RTSP      │          │
│  │  UDP:3702    │    │  HTTP:8080   │    │   TCP:554    │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│         │                   │                   │                   │
│         └───────────────────┼───────────────────┘                   │
│                             │                                       │
│                    ┌────────▼────────┐                              │
│                    │  Camera Device  │                              │
│                    │    Emulator     │                              │
│                    └─────────────────┘                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Protocol Stack

```
┌─────────────────────────────────────────┐
│          APPLICATION LAYER              │
│  ONVIF SOAP Messages / RTSP / RTP       │
├─────────────────────────────────────────┤
│          TRANSPORT LAYER                │
│        TCP (ONVIF/RTSP) / UDP (WS-D)    │
├─────────────────────────────────────────┤
│          NETWORK LAYER                  │
│    IPv4 / Multicast (239.255.255.250)   │
├─────────────────────────────────────────┤
│          DATA LINK LAYER                │
│              Ethernet                   │
└─────────────────────────────────────────┘
```

---

## Components

### ONVIF Camera Simulator

The fake camera (`ONVIF-SIM/fakecamera/`) emulates a complete ONVIF-compliant IP camera.

#### Features

- **WS-Discovery Response**: Responds to probe requests on multicast group
- **Device Service**: GetCapabilities, GetDeviceInformation
- **Media Service**: GetProfiles, GetStreamUri
- **Authentication**: WS-UsernameToken (user: `admin`, pass: `password`)

#### Building

```bash
cd ONVIF-SIM/fakecamera
gcc main.c -o fakecamera -lpthread
./fakecamera
```

#### ONVIF Templates

The simulator provides properly formatted SOAP/XML responses:

**GetCapabilitiesResponse** (auth_template):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <tds:GetCapabilitiesResponse>
      <tds:Capabilities>
        <tt:Device>
          <tt:XAddr>http://192.168.1.100:8080/onvif/device_service</tt:XAddr>
          <tt:System>
            <tt:DiscoveryResolve>true</tt:DiscoveryResolve>
            <tt:DiscoveryBye>true</tt:DiscoveryBye>
          </tt:System>
        </tt:Device>
        <tt:Media>
          <tt:XAddr>http://192.168.1.100:8080/onvif/media_service</tt:XAddr>
          <tt:StreamingCapabilities>
            <tt:RTP_TCP>true</tt:RTP_TCP>
            <tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
          </tt:StreamingCapabilities>
        </tt:Media>
      </tds:Capabilities>
    </tds:GetCapabilitiesResponse>
  </s:Body>
</s:Envelope>
```

**GetDeviceInformationResponse** (device_info_template):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>Videonetics</tds:Manufacturer>
      <tds:Model>Camera Emulator</tds:Model>
      <tds:FirmwareVersion>10.0</tds:FirmwareVersion>
      <tds:SerialNumber>VN-SIM-001</tds:SerialNumber>
      <tds:HardwareId>VN-HW-001</tds:HardwareId>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>
```

**GetStreamUriResponse** (stream_uri_template):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <trt:GetStreamUriResponse>
      <trt:MediaUri>
        <tt:Uri>rtsp://192.168.1.100:554/stream1</tt:Uri>
        <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
        <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
        <tt:Timeout>PT0S</tt:Timeout>
      </trt:MediaUri>
    </trt:GetStreamUriResponse>
  </s:Body>
</s:Envelope>
```

---

### Camera Discovery Tool

The discovery client (`ONVIF-SIM/CamDiscoverer/`) finds ONVIF cameras on the network.

#### How It Works

1. Creates UDP socket and joins multicast group 239.255.255.250
2. Sends WS-Discovery Probe message
3. Receives ProbeMatch responses
4. Extracts device information (XAddrs, device name)

#### Building & Running

```bash
cd ONVIF-SIM/CamDiscoverer
gcc camdis.c -o camdis
./camdis
```

#### Probe Message Format

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <s:Header>
    <a:Action s:mustUnderstand="1">
      http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe
    </a:Action>
    <a:MessageID>uuid:12345678-1234-1234-1234-123456789012</a:MessageID>
  </s:Header>
  <s:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </s:Body>
</s:Envelope>
```

---

### Streaming Server

#### RTSP Implementation Guide

For a complete VMS, you need an RTSP server to stream video. Here's the implementation approach:

```c
/* RTSP Server Implementation Skeleton */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RTSP_PORT 554
#define BUFFER_SIZE 4096

/* RTSP Methods */
typedef enum {
    RTSP_OPTIONS,
    RTSP_DESCRIBE,
    RTSP_SETUP,
    RTSP_PLAY,
    RTSP_PAUSE,
    RTSP_TEARDOWN,
    RTSP_UNKNOWN
} rtsp_method_t;

/* RTSP Session State */
typedef struct {
    int client_fd;
    char session_id[64];
    int cseq;
    int rtp_port;
    int rtcp_port;
    int is_playing;
} rtsp_session_t;

/* Parse RTSP method from request */
rtsp_method_t parse_rtsp_method(const char *request) {
    if (strncmp(request, "OPTIONS", 7) == 0) return RTSP_OPTIONS;
    if (strncmp(request, "DESCRIBE", 8) == 0) return RTSP_DESCRIBE;
    if (strncmp(request, "SETUP", 5) == 0) return RTSP_SETUP;
    if (strncmp(request, "PLAY", 4) == 0) return RTSP_PLAY;
    if (strncmp(request, "PAUSE", 5) == 0) return RTSP_PAUSE;
    if (strncmp(request, "TEARDOWN", 8) == 0) return RTSP_TEARDOWN;
    return RTSP_UNKNOWN;
}

/* Generate OPTIONS response */
const char *options_response =
    "RTSP/1.0 200 OK\r\n"
    "CSeq: %d\r\n"
    "Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN\r\n\r\n";

/* Generate DESCRIBE response with SDP */
const char *describe_response =
    "RTSP/1.0 200 OK\r\n"
    "CSeq: %d\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: %zu\r\n\r\n"
    "%s";

const char *sdp_template =
    "v=0\r\n"
    "o=- 0 0 IN IP4 %s\r\n"
    "s=ONVIF Simulator Stream\r\n"
    "c=IN IP4 %s\r\n"
    "t=0 0\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=control:trackID=0\r\n";

/* Generate SETUP response */
const char *setup_response =
    "RTSP/1.0 200 OK\r\n"
    "CSeq: %d\r\n"
    "Transport: RTP/AVP;unicast;client_port=%d-%d;server_port=%d-%d\r\n"
    "Session: %s;timeout=60\r\n\r\n";

/* Generate PLAY response */
const char *play_response =
    "RTSP/1.0 200 OK\r\n"
    "CSeq: %d\r\n"
    "Session: %s\r\n"
    "Range: npt=0.000-\r\n"
    "RTP-Info: url=rtsp://%s:%d/stream1/trackID=0;seq=0;rtptime=0\r\n\r\n";

/* RTSP Server main loop */
void *rtsp_server(void *arg) {
    (void)arg;
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RTSP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);
    
    printf("RTSP Server started on port %d\n", RTSP_PORT);
    
    char buf[BUFFER_SIZE];
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        /* Handle RTSP session */
        rtsp_session_t session = {0};
        session.client_fd = client_fd;
        snprintf(session.session_id, sizeof(session.session_id), "%08X", rand());
        
        while (1) {
            ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = '\0';
            
            /* Parse and respond to RTSP method */
            rtsp_method_t method = parse_rtsp_method(buf);
            /* ... handle each method ... */
        }
        
        close(client_fd);
    }
    
    return NULL;
}
```

---

### Image Transfer Protocol

For transferring image frames over TCP:

```c
/* Server: Receive image frames */
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

int receive_frame(int sockfd, const char *output_path) {
    FILE *fp = fopen(output_path, "wb");
    if (!fp) return -1;
    
    char buf[4096];
    ssize_t n;
    
    while ((n = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
        fwrite(buf, 1, n, fp);
    }
    
    fclose(fp);
    return 0;
}

/* Client: Send image frames */
int send_frame(int sockfd, const char *image_path) {
    FILE *fp = fopen(image_path, "rb");
    if (!fp) return -1;
    
    char buf[4096];
    size_t n;
    
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        send(sockfd, buf, n, 0);
    }
    
    fclose(fp);
    return 0;
}
```

---

## Building a VMS System

### Step 1: Device Discovery

Use the discovery layer to find all ONVIF cameras:

```c
#include <stdio.h>

typedef struct {
    char ip_address[64];
    char device_name[256];
    char xaddrs[512];
    int port;
} camera_info_t;

#define MAX_CAMERAS 100
camera_info_t discovered_cameras[MAX_CAMERAS];
int camera_count = 0;

/* Discovery callback */
void on_camera_discovered(const char *ip, const char *name, const char *xaddrs) {
    if (camera_count < MAX_CAMERAS) {
        strncpy(discovered_cameras[camera_count].ip_address, ip, 63);
        strncpy(discovered_cameras[camera_count].device_name, name, 255);
        strncpy(discovered_cameras[camera_count].xaddrs, xaddrs, 511);
        camera_count++;
        printf("Discovered: %s at %s\n", name, ip);
    }
}
```

### Step 2: Connect to Cameras

After discovery, connect to each camera's ONVIF service:

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* SOAP request for GetDeviceInformation */
const char *get_device_info_request =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Header>"
    "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
    "<wsse:UsernameToken>"
    "<wsse:Username>admin</wsse:Username>"
    "<wsse:Password>password</wsse:Password>"
    "</wsse:UsernameToken>"
    "</wsse:Security>"
    "</s:Header>"
    "<s:Body>"
    "<tds:GetDeviceInformation/>"
    "</s:Body>"
    "</s:Envelope>";

int connect_to_camera(const char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return -1;
    }
    
    return sockfd;
}

int send_onvif_request(int sockfd, const char *soap_body, char *response, size_t resp_size) {
    char http_request[8192];
    
    snprintf(http_request, sizeof(http_request),
        "POST /onvif/device_service HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/soap+xml; charset=utf-8\r\n"
        "Content-Length: %zu\r\n\r\n%s",
        strlen(soap_body), soap_body);
    
    send(sockfd, http_request, strlen(http_request), 0);
    
    ssize_t n = recv(sockfd, response, resp_size - 1, 0);
    if (n > 0) response[n] = '\0';
    
    return n > 0 ? 0 : -1;
}
```

### Step 3: Get Stream URIs

Request the RTSP stream URI from each camera:

```c
const char *get_stream_uri_request =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Header>"
    "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
    "<wsse:UsernameToken>"
    "<wsse:Username>admin</wsse:Username>"
    "<wsse:Password>password</wsse:Password>"
    "</wsse:UsernameToken>"
    "</wsse:Security>"
    "</s:Header>"
    "<s:Body>"
    "<trt:GetStreamUri>"
    "<trt:StreamSetup>"
    "<tt:Stream>RTP-Unicast</tt:Stream>"
    "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
    "</trt:StreamSetup>"
    "<trt:ProfileToken>profile_1</trt:ProfileToken>"
    "</trt:GetStreamUri>"
    "</s:Body>"
    "</s:Envelope>";

/* Extract stream URI from response */
int extract_stream_uri(const char *response, char *uri, size_t uri_size) {
    const char *start = strstr(response, "<tt:Uri>");
    if (!start) return -1;
    start += 8;
    
    const char *end = strstr(start, "</tt:Uri>");
    if (!end) return -1;
    
    size_t len = end - start;
    if (len >= uri_size) len = uri_size - 1;
    
    memcpy(uri, start, len);
    uri[len] = '\0';
    return 0;
}
```

### Step 4: Connect to RTSP Streams

```c
/* RTSP client for connecting to camera streams */
typedef struct {
    int socket_fd;
    char session_id[64];
    int cseq;
    int rtp_socket;
    int rtcp_socket;
} rtsp_client_t;

int rtsp_connect(rtsp_client_t *client, const char *uri) {
    /* Parse URI: rtsp://ip:port/path */
    char ip[64];
    int port = 554;
    char path[256];
    
    sscanf(uri, "rtsp://%[^:/]:%d/%s", ip, &port, path);
    
    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (connect(client->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return -1;
    }
    
    client->cseq = 1;
    return 0;
}

int rtsp_options(rtsp_client_t *client, const char *uri) {
    char request[1024];
    snprintf(request, sizeof(request),
        "OPTIONS %s RTSP/1.0\r\n"
        "CSeq: %d\r\n\r\n",
        uri, client->cseq++);
    
    send(client->socket_fd, request, strlen(request), 0);
    
    char response[4096];
    recv(client->socket_fd, response, sizeof(response) - 1, 0);
    
    return strstr(response, "200 OK") ? 0 : -1;
}

int rtsp_describe(rtsp_client_t *client, const char *uri, char *sdp, size_t sdp_size) {
    char request[1024];
    snprintf(request, sizeof(request),
        "DESCRIBE %s RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Accept: application/sdp\r\n\r\n",
        uri, client->cseq++);
    
    send(client->socket_fd, request, strlen(request), 0);
    
    char response[8192];
    recv(client->socket_fd, response, sizeof(response) - 1, 0);
    
    /* Extract SDP from response body */
    const char *body = strstr(response, "\r\n\r\n");
    if (body) {
        body += 4;
        strncpy(sdp, body, sdp_size - 1);
    }
    
    return strstr(response, "200 OK") ? 0 : -1;
}

int rtsp_setup(rtsp_client_t *client, const char *uri, int rtp_port) {
    char request[1024];
    snprintf(request, sizeof(request),
        "SETUP %s/trackID=0 RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Transport: RTP/AVP;unicast;client_port=%d-%d\r\n\r\n",
        uri, client->cseq++, rtp_port, rtp_port + 1);
    
    send(client->socket_fd, request, strlen(request), 0);
    
    char response[4096];
    recv(client->socket_fd, response, sizeof(response) - 1, 0);
    
    /* Extract session ID */
    const char *session = strstr(response, "Session: ");
    if (session) {
        session += 9;
        int i = 0;
        while (session[i] && session[i] != ';' && session[i] != '\r' && i < 63) {
            client->session_id[i] = session[i];
            i++;
        }
        client->session_id[i] = '\0';
    }
    
    return strstr(response, "200 OK") ? 0 : -1;
}

int rtsp_play(rtsp_client_t *client, const char *uri) {
    char request[1024];
    snprintf(request, sizeof(request),
        "PLAY %s RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Session: %s\r\n"
        "Range: npt=0.000-\r\n\r\n",
        uri, client->cseq++, client->session_id);
    
    send(client->socket_fd, request, strlen(request), 0);
    
    char response[4096];
    recv(client->socket_fd, response, sizeof(response) - 1, 0);
    
    return strstr(response, "200 OK") ? 0 : -1;
}
```

### Step 5: VMS Main Application

```c
/* VMS Main Application Structure */
#include <pthread.h>

#define MAX_CAMERAS 64

typedef struct {
    camera_info_t info;
    rtsp_client_t rtsp;
    pthread_t stream_thread;
    int is_connected;
    int is_streaming;
} vms_camera_t;

typedef struct {
    vms_camera_t cameras[MAX_CAMERAS];
    int camera_count;
    pthread_mutex_t lock;
} vms_system_t;

/* Initialize VMS */
void vms_init(vms_system_t *vms) {
    memset(vms, 0, sizeof(*vms));
    pthread_mutex_init(&vms->lock, NULL);
}

/* Discover cameras */
int vms_discover(vms_system_t *vms) {
    /* Use discovery client code from CamDiscoverer */
    /* This will populate vms->cameras with discovered devices */
    return 0;
}

/* Connect to all discovered cameras */
int vms_connect_all(vms_system_t *vms) {
    pthread_mutex_lock(&vms->lock);
    
    for (int i = 0; i < vms->camera_count; i++) {
        vms_camera_t *cam = &vms->cameras[i];
        
        /* Connect to ONVIF service */
        int fd = connect_to_camera(cam->info.ip_address, cam->info.port);
        if (fd < 0) continue;
        
        /* Get stream URI */
        char response[8192];
        send_onvif_request(fd, get_stream_uri_request, response, sizeof(response));
        
        char stream_uri[512];
        if (extract_stream_uri(response, stream_uri, sizeof(stream_uri)) == 0) {
            /* Connect RTSP client */
            if (rtsp_connect(&cam->rtsp, stream_uri) == 0) {
                cam->is_connected = 1;
                printf("Connected to camera %d: %s\n", i, cam->info.device_name);
            }
        }
        
        close(fd);
    }
    
    pthread_mutex_unlock(&vms->lock);
    return 0;
}

/* Stream processing thread */
void *stream_processor(void *arg) {
    vms_camera_t *cam = (vms_camera_t *)arg;
    
    /* Receive RTP packets and decode */
    char rtp_buffer[65536];
    while (cam->is_streaming) {
        ssize_t n = recv(cam->rtsp.rtp_socket, rtp_buffer, sizeof(rtp_buffer), 0);
        if (n > 0) {
            /* Process RTP packet */
            /* Decode H.264 NAL units */
            /* Display or record frame */
        }
    }
    
    return NULL;
}

/* Start streaming from all cameras */
int vms_start_streaming(vms_system_t *vms) {
    pthread_mutex_lock(&vms->lock);
    
    for (int i = 0; i < vms->camera_count; i++) {
        vms_camera_t *cam = &vms->cameras[i];
        if (!cam->is_connected) continue;
        
        /* RTSP handshake */
        rtsp_options(&cam->rtsp, cam->info.xaddrs);
        rtsp_describe(&cam->rtsp, cam->info.xaddrs, NULL, 0);
        rtsp_setup(&cam->rtsp, cam->info.xaddrs, 5000 + i * 2);
        rtsp_play(&cam->rtsp, cam->info.xaddrs);
        
        cam->is_streaming = 1;
        pthread_create(&cam->stream_thread, NULL, stream_processor, cam);
    }
    
    pthread_mutex_unlock(&vms->lock);
    return 0;
}

/* Example main function */
int main(void) {
    vms_system_t vms;
    vms_init(&vms);
    
    printf("Starting VMS...\n");
    
    /* Step 1: Discover cameras */
    printf("Discovering cameras...\n");
    vms_discover(&vms);
    
    /* Step 2: Connect to cameras */
    printf("Connecting to cameras...\n");
    vms_connect_all(&vms);
    
    /* Step 3: Start streaming */
    printf("Starting streams...\n");
    vms_start_streaming(&vms);
    
    /* Keep running */
    printf("VMS running. Press Ctrl+C to stop.\n");
    while (1) {
        sleep(1);
    }
    
    return 0;
}
```

---

## ONVIF Test Tool Integration

### Testing with ONVIF Device Manager

1. **Start the fake camera:**
   ```bash
   cd ONVIF-SIM/fakecamera
   gcc main.c -o fakecamera -lpthread
   ./fakecamera
   ```

2. **Configure ONVIF Device Manager:**
   - Device address: `http://<your-ip>:8080/onvif/device_service`
   - Username: `admin`
   - Password: `password`

### Expected Test Results

| Test | Expected Response | Template Used |
|------|-------------------|---------------|
| Discovery | ProbeMatch with XAddrs | PROBE_MATCH_TEMPLATE |
| GetCapabilities | Device/Media capabilities | auth_template |
| GetDeviceInformation | Manufacturer, Model, etc. | device_info_template |
| GetProfiles | MainStream profile | profiles_template |
| GetStreamUri | RTSP URI | stream_uri_template |

### Authentication Flow

```
┌──────────────┐                    ┌──────────────┐
│  ONVIF Tool  │                    │ Fake Camera  │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       │  WS-Discovery Probe               │
       │──────────────────────────────────>│
       │                                   │
       │  ProbeMatch (XAddrs)              │
       │<──────────────────────────────────│
       │                                   │
       │  GetCapabilities (no auth)        │
       │──────────────────────────────────>│
       │                                   │
       │  Capabilities Response            │
       │<──────────────────────────────────│
       │                                   │
       │  GetDeviceInfo (with auth)        │
       │  WS-UsernameToken: admin/password │
       │──────────────────────────────────>│
       │                                   │
       │  Device Information               │
       │<──────────────────────────────────│
       │                                   │
       │  GetProfiles (with auth)          │
       │──────────────────────────────────>│
       │                                   │
       │  Media Profiles                   │
       │<──────────────────────────────────│
       │                                   │
       │  GetStreamUri (with auth)         │
       │──────────────────────────────────>│
       │                                   │
       │  RTSP URI                         │
       │<──────────────────────────────────│
       │                                   │
```

---

## API Reference

### Discovery Server API

| Function | Description |
|----------|-------------|
| `isprobe(const char *msg)` | Check if message is WS-Discovery probe |
| `getmessageid(const char *msg, char *out, size_t size)` | Extract MessageID from SOAP |
| `getlocalip(char *buf, size_t size)` | Get local IP address |
| `generate_uuid(char *buf, size_t size)` | Generate UUID for responses |
| `build_response(...)` | Build ProbeMatch response |
| `discovery(void *arg)` | Main discovery server thread |

### Authentication Server API

| Function | Description |
|----------|-------------|
| `extract_username(const char *msg, char *out, size_t size)` | Extract username from WS-Security |
| `extract_passwd(const char *msg, char *out, size_t size)` | Extract password from WS-Security |
| `detect_request_type(const char *buf)` | Detect ONVIF request type |
| `authentication(void *arg)` | Main ONVIF service thread |

### Request Types

```c
typedef enum {
  REQ_GET_CAPABILITIES,   /* GetCapabilities request */
  REQ_GET_DEVICE_INFO,    /* GetDeviceInformation request */
  REQ_GET_PROFILES,       /* GetProfiles request */
  REQ_GET_STREAM_URI,     /* GetStreamUri request */
  REQ_UNKNOWN             /* Unknown/unsupported request */
} onvif_request_type;
```

---

## Troubleshooting

### Discovery Not Working

1. **Check multicast group membership:**
   ```bash
   cat /proc/net/igmp | grep 239.255.255.250
   ```

2. **Check firewall rules:**
   ```bash
   sudo iptables -L -n | grep 3702
   sudo ufw allow 3702/udp
   ```

3. **Test with tcpdump:**
   ```bash
   sudo tcpdump -i any -n port 3702
   ```

### Authentication Failures

1. **Check credentials:**
   - Default: `admin` / `password`
   - Review `Attempts.csv` for logged attempts

2. **Verify SOAP format:**
   - Check for `wsse:UsernameToken` namespace
   - Ensure proper XML structure

### Stream Connection Issues

1. **Check RTSP port:**
   ```bash
   netstat -tuln | grep 554
   ```

2. **Test with VLC:**
   ```bash
   vlc rtsp://192.168.1.100:554/stream1
   ```

---

## License

This project is for educational purposes. See individual source files for licensing information.

## Contributing

Contributions are welcome! Please ensure your code follows the existing style and includes appropriate documentation.
