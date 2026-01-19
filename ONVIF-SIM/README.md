# ONVIF WS-Discovery: Low-Level Systems Programming Guide

## Overview

This directory contains educational implementations of ONVIF WS-Discovery protocol:

1. **fakecamera/discovery_server.c** - WS-Discovery responder (fake ONVIF camera)
2. **onvif_discoverer.c** - WS-Discovery client (camera discoverer)

These tools are designed for **systems programmers** who understand C, memory, and want to learn networking from the ground up—from application code through libc to kernel internals.

---

## Table of Contents

1. [What is ONVIF and WS-Discovery?](#what-is-onvif-and-ws-discovery)
2. [Building and Running](#building-and-running)
3. [Networking Fundamentals](#networking-fundamentals)
4. [UDP vs TCP: What You Own](#udp-vs-tcp-what-you-own)
5. [The Socket API Journey](#the-socket-api-journey)
6. [Multicast Semantics](#multicast-semantics)
7. [WS-Discovery Protocol Details](#ws-discovery-protocol-details)
8. [Troubleshooting](#troubleshooting)
9. [Extending This Code](#extending-this-code)

---

## What is ONVIF and WS-Discovery?

**ONVIF** (Open Network Video Interface Forum):
- Industry standard for IP-based physical security products
- Defines how to communicate with IP cameras, NVRs, access control devices
- Uses SOAP over HTTP for device control, RTSP for media streaming

**WS-Discovery** (Web Services Discovery):
- OASIS standard for discovering network services
- Multicast-based discovery (no configuration needed)
- Used by ONVIF, Windows WSD, printers, etc.

**Protocol Flow:**
```
┌─────────┐                                    ┌─────────┐
│ Client  │                                    │ Camera  │
└────┬────┘                                    └────┬────┘
     │                                              │
     │  Probe (multicast to 239.255.255.250:3702)  │
     ├─────────────────────────────────────────────>│
     │                                              │
     │           ProbeMatch (unicast)               │
     │<─────────────────────────────────────────────┤
     │                                              │
```

---

## Building and Running

### Prerequisites
```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# Red Hat/CentOS/Fedora
sudo yum install gcc make
```

### Build

```bash
cd ONVIF-SIM

# Build the fake camera server
gcc -o fakecamera/discovery_server fakecamera/discovery_server.c -Wall -Wextra

# Build the discovery client
gcc -o onvif_discoverer onvif_discoverer.c -Wall -Wextra
```

### Run

**Terminal 1: Start fake camera**
```bash
./fakecamera/discovery_server
```

**Terminal 2: Discover cameras**
```bash
./onvif_discoverer
```

You should see the fake camera discovered!

---

## Networking Fundamentals

### The Layer Model: Application → Hardware

```
┌────────────────────────────────────────────────────────┐
│ LAYER 1: APPLICATION CODE                              │
│   - Your C code: socket(), sendto(), recvfrom()        │
│   - Work with: file descriptors (int), buffers (char*) │
│   - Responsibility: protocol logic, message framing    │
└────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────┐
│ LAYER 2: LIBC (glibc, musl, BSD libc, Winsock)        │
│   - Thin wrapper around syscalls                       │
│   - Validates arguments, marshals data                 │
│   - Invokes syscall instruction                        │
│   - Location: sysdeps/unix/sysv/linux/socket.c (glibc) │
└────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────┐
│ LAYER 3: SYSCALL BOUNDARY                              │
│   - CPU privilege change: ring 3 → ring 0              │
│   - Syscall number determines handler                  │
│   - Userspace ←→ Kernel transition                     │
└────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────┐
│ LAYER 4: KERNEL NETWORKING STACK                       │
│   - sys_socket() → sock_create() → inet_create()       │
│   - struct sock: core socket object                    │
│   - Buffers, state machines, protocol ops              │
│   - Location: net/socket.c, net/ipv4/udp.c (Linux)     │
└────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────┐
│ LAYER 5: PROTOCOL IMPLEMENTATION                       │
│   - UDP: net/ipv4/udp.c (stateless, no retransmit)     │
│   - TCP: net/ipv4/tcp.c (state machine, reliable)      │
│   - IP: net/ipv4/ip_output.c (routing, fragmentation)  │
└────────────────────────────────────────────────────────┘
                           ↓
┌────────────────────────────────────────────────────────┐
│ LAYER 6: HARDWARE ABSTRACTION                          │
│   - NIC driver queues packets                          │
│   - DMA transfer to NIC                                │
│   - Packet transmitted on wire (Ethernet frame)        │
└────────────────────────────────────────────────────────┘
```

### Key Insights

1. **libc does NOT implement networking**
   - It's just syscall wrappers
   - Actual networking happens in kernel
   - This is why you read kernel source to understand networking!

2. **A socket is not a packet**
   - Socket is a kernel object (struct sock)
   - It has state: buffers, options, protocol control blocks
   - File descriptor is just an index into process fd table

3. **send() ≠ packet sent**
   - Application: "Here's data to send"
   - Kernel: "I'll send it when I think it's appropriate"
   - Actual transmission timing controlled by kernel

---

## UDP vs TCP: What You Own

### UDP (SOCK_DGRAM)

**You own:**
- ✅ Message boundaries (100 bytes sent = 100 bytes received, or nothing)
- ✅ Reliability (detect loss, retransmit yourself)
- ✅ Ordering (packets can arrive out of order)
- ✅ Congestion control (nothing stops you from flooding)

**Kernel provides:**
- ✅ Checksum (optional, can be disabled)
- ✅ Port multiplexing (routes packets to correct socket)
- ✅ Datagram buffering (limited by SO_RCVBUF)

**Key functions:**
```c
sendto(fd, buf, len, flags, dest_addr, addrlen);   // Send to specific address
recvfrom(fd, buf, len, flags, src_addr, addrlen);  // Receive from anyone
```

**Mental model:**
```
Each sendto() = one packet attempt
Each recvfrom() = one packet (or timeout)
No connection, no state
```

### TCP (SOCK_STREAM)

**You own:**
- ✅ When to send (but not when kernel transmits)
- ✅ Message framing (TCP is byte stream, no boundaries!)

**Kernel provides:**
- ✅ Reliable delivery (retransmission on loss)
- ✅ Ordering (kernel reorders packets)
- ✅ Flow control (sliding window prevents overwhelm)
- ✅ Congestion control (CUBIC, BBR, Reno, etc.)
- ✅ Connection state machine (handshake, teardown)

**Key functions:**
```c
listen(fd, backlog);            // Passive open (server)
accept(fd, addr, addrlen);      // Accept incoming connection
connect(fd, addr, addrlen);     // Active open (client)
send(fd, buf, len, flags);      // Add to send buffer
recv(fd, buf, len, flags);      // Read from receive buffer
```

**Mental model:**
```
Socket states: CLOSED → LISTEN → SYN_RCVD → ESTABLISHED → FIN_WAIT...
send() copies to kernel buffer (may block if buffer full)
recv() reads from kernel buffer (byte stream, not packets)
```

### Why WS-Discovery Uses UDP

1. **Discovery needs to reach unknown devices**
   - TCP requires knowing IP + port beforehand
   - UDP multicast reaches all devices on subnet

2. **Stateless, one-shot messages**
   - No need for connection overhead
   - Probe is small, response is small
   - Retransmission can be done at application level if needed

3. **Low overhead**
   - No handshake (3 packets saved)
   - No teardown (4 packets saved)
   - No state tracking in kernel

---

## The Socket API Journey

### socket() - Create Communication Endpoint

**Application code:**
```c
int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
```

**libc wrapper (glibc: sysdeps/unix/sysv/linux/socket.c):**
```c
int socket(int domain, int type, int protocol) {
    return INLINE_SYSCALL(socket, 3, domain, type, protocol);
}
```

**Syscall boundary:**
- Userspace → kernel mode (ring 3 → ring 0)
- SYS_socket (syscall number) invoked

**Kernel path (net/socket.c):**
```c
sys_socket() → sock_create() → __sock_create()
  → net_families[AF_INET]->create()  // inet_family_ops
    → inet_create() [net/ipv4/af_inet.c]
      - Allocate struct sock
      - Initialize protocol ops (udp_prot for UDP)
      - Return file descriptor
```

**Result:**
- File descriptor returned (small integer)
- Kernel maintains: struct socket + struct sock
- Process fd table entry points to kernel socket object

**POSIX compliance:**
- socket() is POSIX.1-2001 mandated
- Arguments and semantics standardized

---

### bind() - Associate Socket with Address

**Application code:**
```c
struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(3702),
    .sin_addr.s_addr = INADDR_ANY
};
bind(fd, (struct sockaddr*)&addr, sizeof(addr));
```

**Kernel path (net/ipv4/af_inet.c:inet_bind()):**
1. Validate address (not in use, not privileged if port < 1024)
2. Update `sock->sk_rcv_saddr`, `sock->sk_num`
3. Add socket to port hash table (for incoming packet lookup)

**Why bind() for multicast receiver?**
- Bind to `INADDR_ANY:3702` (not multicast address!)
- Multicast address is destination, not source
- Kernel needs to know which port to deliver incoming packets to

**Common mistake:**
```c
// WRONG: binding to multicast address
addr.sin_addr.s_addr = inet_addr("239.255.255.250");
bind(fd, ...);  // This fails or doesn't work as expected

// CORRECT: bind to INADDR_ANY
addr.sin_addr.s_addr = INADDR_ANY;
bind(fd, ...);
```

---

### setsockopt() - Configure Socket Behavior

**Socket-level options (SOL_SOCKET):**
```c
int opt = 1;
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
```
- Kernel: net/core/sock.c:sock_setsockopt()
- SO_REUSEADDR: Allow multiple sockets on same port
- SO_RCVBUF: Set receive buffer size
- SO_SNDBUF: Set send buffer size
- SO_RCVTIMEO: Set receive timeout

**IP-level options (IPPROTO_IP):**
```c
struct ip_mreq mreq = {
    .imr_multiaddr.s_addr = inet_addr("239.255.255.250"),
    .imr_interface.s_addr = INADDR_ANY
};
setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
```
- Kernel: net/ipv4/ip_sockglue.c:do_ip_setsockopt()
- IP_ADD_MEMBERSHIP: Join multicast group
- IP_MULTICAST_LOOP: Receive own multicast packets
- IP_MULTICAST_TTL: Set TTL for multicast packets

---

### sendto() - Send Datagram

**Application code:**
```c
sendto(fd, buffer, length, 0, (struct sockaddr*)&dest, sizeof(dest));
```

**Kernel path (net/ipv4/udp.c:udp_sendmsg()):**
1. Validate destination address
2. Route lookup (which interface to use?)
3. Allocate sk_buff (kernel packet buffer structure)
4. Copy user data to sk_buff
5. Build UDP header:
   - Source port (from bound port or ephemeral)
   - Destination port
   - Length
   - Checksum (optional for UDP)
6. Pass to IP layer: ip_send_skb()
7. IP layer builds IP header:
   - Source IP (from interface or routing)
   - Destination IP
   - TTL, protocol (17 for UDP), checksum
8. Pass to link layer
9. NIC driver queues packet, DMA to hardware

**Returns:**
- Number of bytes sent (usually == length)
- Does NOT mean packet reached destination!
- Just means kernel accepted it for transmission

**UDP vs TCP comparison:**
- UDP sendto(): typically immediate transmission
- TCP send(): copies to kernel buffer, may delay transmission
  - Nagle's algorithm batches small writes
  - Congestion control may block
  - send() returning ≠ packet sent ≠ data received!

---

### recvfrom() - Receive Datagram

**Application code:**
```c
struct sockaddr_in src;
socklen_t src_len = sizeof(src);
ssize_t n = recvfrom(fd, buffer, bufsize, 0, (struct sockaddr*)&src, &src_len);
```

**Kernel path (net/ipv4/udp.c:udp_recvmsg()):**
1. Check socket receive queue
2. If empty:
   - Block (sleep in wait queue) unless O_NONBLOCK
   - Wake on packet arrival or timeout (SO_RCVTIMEO)
3. Dequeue sk_buff from receive queue
4. Copy data to userspace buffer
5. Copy sender address (IP + port) to src
6. Free sk_buff
7. Return bytes received

**Blocking behavior:**
- Default: blocks until data arrives
- SO_RCVTIMEO: timeout with errno=EAGAIN/EWOULDBLOCK
- O_NONBLOCK: returns immediately if no data

**Message boundaries (UDP):**
```c
// Sender
sendto(fd, "hello", 5, ...);
sendto(fd, "world", 5, ...);

// Receiver
recvfrom(fd, buf, 100, ...);  // Returns 5, buf = "hello"
recvfrom(fd, buf, 100, ...);  // Returns 5, buf = "world"
```

**Message boundaries (TCP comparison):**
```c
// Sender
send(fd, "hello", 5, ...);
send(fd, "world", 5, ...);

// Receiver
recv(fd, buf, 100, ...);  // Might return 10, buf = "helloworld"
                          // Or 5, buf = "hello"
                          // Or 7, buf = "hellowo"
                          // TCP is a BYTE STREAM, no boundaries!
```

---

## Multicast Semantics

### What is Multicast?

**IP address ranges:**
- Class D: 224.0.0.0 - 239.255.255.255
- 224.0.0.0 - 224.0.0.255: Local subnet, not routed
- 239.0.0.0 - 239.255.255.255: Administratively scoped

**ONVIF uses:** 239.255.255.250 (administrative scope)

**Multicast → MAC mapping:**
- IP: 239.255.255.250
- MAC: 01:00:5e:7f:ff:fa
- Formula: Last 23 bits of IP → MAC
- NIC configured to accept packets to this MAC

### Joining a Multicast Group

**Application code:**
```c
struct ip_mreq mreq = {
    .imr_multiaddr.s_addr = inet_addr("239.255.255.250"),
    .imr_interface.s_addr = INADDR_ANY  // Let kernel choose interface
};
setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
```

**Kernel path (net/ipv4/ip_sockglue.c):**
1. `ip_mc_join_group()`
2. Add multicast group to socket's mc_list
3. Update NIC multicast filter:
   - `dev_mc_add()` tells NIC to accept packets to multicast MAC
4. Send IGMP Join message to router
   - Router learns: "This interface has interested receivers"

**IGMP (Internet Group Management Protocol):**
- Manages multicast group membership
- Join: "I want packets for this group"
- Leave: "I'm no longer interested"
- Query: Router asks "Who's still interested?"

### Interface Selection

**Why it matters:**
- Multiple interfaces: eth0 (192.168.1.10), wlan0 (10.0.0.5)
- Cameras on eth0 network
- If kernel picks wlan0 → no responses!

**Options:**
1. `INADDR_ANY`: Kernel chooses (usually default route interface)
2. Specific IP: Force interface
   ```c
   mreq.imr_interface.s_addr = inet_addr("192.168.1.10");  // eth0
   ```

**Check interface selection:**
```bash
# See multicast group memberships per interface
ip maddr show

# Check routing for multicast
ip route get 239.255.255.250
```

### Multicast Options

**IP_MULTICAST_LOOP:**
```c
int loop = 1;  // 1 = receive own packets, 0 = don't
setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
```
- Useful for testing (see your own probes)
- Usually disabled in production

**IP_MULTICAST_TTL:**
```c
int ttl = 1;  // 1 = subnet only, higher = cross routers
setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
```
- ONVIF standard: TTL=1 (local subnet only)
- Higher TTL requires multicast routing configuration

---

## WS-Discovery Protocol Details

### SOAP Envelope Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
  xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  
  <s:Header>
    <a:Action>...</a:Action>
    <a:MessageID>uuid:...</a:MessageID>
    <a:To>...</a:To>
  </s:Header>
  
  <s:Body>
    <d:Probe>...</d:Probe>
  </s:Body>
  
</s:Envelope>
```

**Namespaces:**
- `s:` - SOAP 1.2 envelope
- `a:` - WS-Addressing (message routing)
- `d:` - WS-Discovery (discovery semantics)
- `dn:` - ONVIF network device types

### Probe Message

```xml
<d:Probe>
  <d:Types>dn:NetworkVideoTransmitter</d:Types>
</d:Probe>
```

**Types filter:**
- `dn:NetworkVideoTransmitter` - ONVIF cameras
- Can be omitted to discover all devices
- Multiple types: space-separated

### ProbeMatch Response

```xml
<d:ProbeMatches>
  <d:ProbeMatch>
    <a:EndpointReference>
      <a:Address>urn:uuid:device-uuid</a:Address>
    </a:EndpointReference>
    <d:Types>dn:NetworkVideoTransmitter</d:Types>
    <d:Scopes>
      onvif://www.onvif.org/name/CameraName
      onvif://www.onvif.org/hardware/Model
      onvif://www.onvif.org/location/Office
    </d:Scopes>
    <d:XAddrs>http://192.168.1.100:8080/onvif/device_service</d:XAddrs>
    <d:MetadataVersion>1</d:MetadataVersion>
  </d:ProbeMatch>
</d:ProbeMatches>
```

**Key fields:**
- `EndpointReference/Address`: Unique device identifier
- `Types`: Device capabilities
- `Scopes`: Device metadata (name, location, etc.)
- `XAddrs`: HTTP endpoint for ONVIF services (THIS IS IMPORTANT!)
- `MetadataVersion`: Increments when device metadata changes

### Common XML Mistakes

❌ **Spaces in XML tags:**
```xml
<a: Action>...</a: Action>   <!-- WRONG -->
<a:Action>...</a:Action>      <!-- CORRECT -->
```

❌ **Spaces in URN:**
```xml
<a:Address>urn:uuid: device-id</a:Address>   <!-- WRONG -->
<a:Address>urn:uuid:device-id</a:Address>    <!-- CORRECT -->
```

These mistakes cause ONVIF test tools to reject the response!

---

## Troubleshooting

### No Devices Found

**1. Check network connectivity:**
```bash
# Are devices on same subnet?
ip addr show
ip route show

# Can you ping the device?
ping 192.168.1.100
```

**2. Check multicast routing:**
```bash
# Show multicast group memberships
ip maddr show

# Should see 239.255.255.250 on active interface
# Example output:
# 2: eth0
#    inet  239.255.255.250

# Check routing for multicast address
ip route get 239.255.255.250
```

**3. Check firewall:**
```bash
# iptables (Linux)
sudo iptables -L -n | grep 3702
sudo iptables -I INPUT -p udp --dport 3702 -j ACCEPT

# firewalld (Red Hat/CentOS)
sudo firewall-cmd --add-port=3702/udp --permanent
sudo firewall-cmd --reload

# ufw (Ubuntu)
sudo ufw allow 3702/udp
```

**4. Capture traffic:**
```bash
# Capture on all interfaces
sudo tcpdump -i any -n -X port 3702

# What to look for:
# - Outgoing Probe (src=your_ip, dst=239.255.255.250)
# - Incoming ProbeMatch (src=camera_ip, dst=your_ip)

# If you see Probe but no ProbeMatch:
# - Camera not running
# - Camera on different subnet
# - Camera firewall blocking
```

**5. Check interface selection:**
```bash
# This tool uses INADDR_ANY (kernel chooses interface)
# To see which interface kernel chose:
ss -u -a -n | grep 3702

# To force specific interface, modify code:
mreq.imr_interface.s_addr = inet_addr("192.168.1.10");  // Your eth0 IP
```

**6. Kernel debugging:**
```bash
# Check if multicast group joined
cat /proc/net/igmp | grep -A2 239.255.255.250

# Check socket state
ss -u -a -n | grep 3702

# Check UDP statistics
cat /proc/net/snmp | grep Udp

# Check multicast routing
ip mroute show
```

### Device Responds But Not Parsed

**XML parsing issues:**
- Use proper XML parser in production (libxml2, expat)
- This code uses string search (educational purposes only)
- Check for namespace variations (a: vs wsa:, d: vs ns1:)

**Debug output:**
```c
// Add to code to see raw XML
printf("Received:\n%s\n", recv_buf);
```

### Permission Denied

**Binding to privileged ports (<1024):**
```bash
# Run as root (not recommended)
sudo ./onvif_discoverer

# Or grant capability (Linux)
sudo setcap cap_net_bind_service=+ep ./onvif_discoverer
```

**Multicast on some systems:**
- Usually doesn't require root
- If denied, check selinux/apparmor policies

---

## Extending This Code

### 1. Add IPv6 Support

**IPv6 multicast:**
- Address: ff02::c (link-local scope)
- Protocol: MLDv2 (Multicast Listener Discovery) instead of IGMP

```c
// Create IPv6 socket
int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

// Join multicast group
struct ipv6_mreq mreq = {0};
inet_pton(AF_INET6, "ff02::c", &mreq.ipv6mr_multiaddr);
mreq.ipv6mr_interface = 0;  // Interface index, 0 = kernel chooses
setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
```

### 2. Parse XML Properly

**Use libxml2:**
```c
#include <libxml/parser.h>
#include <libxml/xpath.h>

xmlDocPtr doc = xmlReadMemory(recv_buf, received, NULL, NULL, 0);
xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
xmlXPathRegisterNs(ctx, BAD_CAST "d", 
                   BAD_CAST "http://schemas.xmlsoap.org/ws/2005/04/discovery");
xmlXPathObjectPtr result = xmlXPathEvalExpression(
    BAD_CAST "//d:XAddrs/text()", ctx);
```

### 3. Implement Retransmission

**Application-level reliability:**
```c
for (int retry = 0; retry < 3; retry++) {
    sendto(...);  // Send probe
    
    // Set shorter timeout per retry
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Collect responses
    while (recvfrom(...) > 0) {
        // Process...
    }
}
```

### 4. Query Device Details

**After discovery, use HTTP:**
```c
// XAddrs from ProbeMatch: http://192.168.1.100:8080/onvif/device_service

// Create TCP socket
int tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
connect(tcp_sock, ...);

// Send ONVIF GetDeviceInformation request (SOAP over HTTP)
const char *soap_request =
    "POST /onvif/device_service HTTP/1.1\r\n"
    "Host: 192.168.1.100:8080\r\n"
    "Content-Type: application/soap+xml\r\n"
    "Content-Length: ...\r\n"
    "\r\n"
    "<?xml version=\"1.0\"?>..."
    "<tds:GetDeviceInformation>...";

send(tcp_sock, soap_request, strlen(soap_request), 0);
```

### 5. Add epoll for Multiple Sockets

**For high-performance discovery client:**
```c
int epfd = epoll_create1(0);

struct epoll_event ev = {
    .events = EPOLLIN,
    .data.fd = sock
};
epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

struct epoll_event events[10];
int nfds = epoll_wait(epfd, events, 10, timeout_ms);
for (int i = 0; i < nfds; i++) {
    if (events[i].events & EPOLLIN) {
        recvfrom(events[i].data.fd, ...);
    }
}
```

### 6. Implement Directed Probe (Unicast)

**If you know device IP:**
```c
// Instead of multicast address
dest_addr.sin_addr.s_addr = inet_addr("192.168.1.100");  // Direct to device

// No need to join multicast group
// Faster, less network traffic
```

---

## Further Reading

### Linux Kernel Source
- **net/socket.c**: Syscall handlers (sys_socket, sys_bind, etc.)
- **net/ipv4/udp.c**: UDP protocol implementation
- **net/ipv4/tcp.c**: TCP protocol implementation (for comparison)
- **net/core/sock.c**: Core socket infrastructure
- **net/ipv4/ip_sockglue.c**: IP-level socket options
- **net/ipv4/igmp.c**: IGMP multicast protocol

### libc Source (glibc)
- **sysdeps/unix/sysv/linux/socket.c**: socket() wrapper
- **socket/sendto.c**: sendto() wrapper
- **socket/recvfrom.c**: recvfrom() wrapper

### Standards
- **POSIX.1-2001**: socket(), bind(), sendto(), recvfrom()
- **RFC 768**: UDP specification
- **RFC 793**: TCP specification
- **RFC 1112**: IGMP and IP multicast
- **RFC 3927**: Link-Local IPv4 addresses
- **OASIS WS-Discovery 1.1**: Discovery protocol
- **ONVIF Core Specification**: Camera device specification

### Tools
- **strace**: Trace syscalls
  ```bash
  strace -e socket,bind,sendto,recvfrom ./onvif_discoverer
  ```
- **tcpdump**: Capture packets
  ```bash
  sudo tcpdump -i eth0 -n -X port 3702
  ```
- **ss**: Socket statistics
  ```bash
  ss -u -a -n  # UDP sockets
  ss -t -a -n  # TCP sockets
  ```
- **ip**: Network configuration
  ```bash
  ip addr show       # Show interfaces and IPs
  ip route show      # Show routing table
  ip maddr show      # Show multicast groups
  ```

### Books
- **Unix Network Programming** by W. Richard Stevens
  - Vol 1: The Sockets Networking API
- **TCP/IP Illustrated** by W. Richard Stevens
  - Vol 1: The Protocols
  - Vol 2: The Implementation
- **Understanding Linux Network Internals** by Christian Benvenuti

---

## License

This code is for educational purposes. Use it to learn, modify, extend, break, and understand networking from the ground up.

The goal is **not** to provide production-ready ONVIF implementation, but to **teach how networking works** from application to kernel.

Read the code, read the kernel source, trace with strace, capture with tcpdump, and most importantly: **understand the execution path**.

---

## Questions to Explore

1. What happens if you send a UDP packet larger than MTU?
   - Hint: IP fragmentation, check with tcpdump

2. Where does TCP congestion control live?
   - Hint: net/ipv4/tcp_*.c (CUBIC, BBR, Reno)

3. How does the kernel know which socket to deliver incoming packets to?
   - Hint: Port hash tables, 4-tuple (src_ip, src_port, dst_ip, dst_port)

4. What's the difference between SO_REUSEADDR and SO_REUSEPORT?
   - Hint: One allows binding to same port, other enables load balancing

5. Why does TCP have listen() and accept(), but UDP doesn't?
   - Hint: Connection state machine vs stateless protocol

6. What happens during a TCP handshake at kernel level?
   - Hint: SYN queue, accept queue, syncookies

7. How does select/poll/epoll work in kernel?
   - Hint: Wait queues, file operations, event notification

Trace these in kernel source. No better way to learn!
