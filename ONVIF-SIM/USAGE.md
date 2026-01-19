# ONVIF WS-Discovery - Quick Start Guide

## For the Impatient

```bash
# Build everything
cd ONVIF-SIM
make

# Terminal 1: Start fake camera
make run-server

# Terminal 2: Discover cameras
make run-client
```

## What You'll Learn

This directory teaches **systems-level network programming** from first principles:

1. **How sockets work** - from application code to kernel internals
2. **UDP vs TCP** - what you own, what the kernel owns
3. **Multicast networking** - IGMP, interface selection, routing
4. **WS-Discovery protocol** - SOAP-based device discovery
5. **ONVIF** - IP camera standard

**Target audience:** C programmers who can read kernel source and want to understand networking execution paths.

---

## Files in This Directory

```
ONVIF-SIM/
├── README.md              ← Comprehensive networking guide (25KB)
├── USAGE.md               ← This file (quick start)
├── Makefile               ← Build system
├── onvif_discoverer.c     ← Discovery client (800+ lines, heavily documented)
└── fakecamera/
    ├── discovery_server.c ← Fake camera server (250 lines, production-like)
    └── mind_server.c      ← Minimal server (70 lines, for learning)
```

### Which Server to Use?

**discovery_server.c** (recommended):
- Proper ONVIF-compliant responses
- Dynamic local IP detection
- Proper message parsing
- Works with ONVIF test tools

**mind_server.c** (educational):
- Minimal implementation
- Hardcoded responses
- Good for understanding basics
- May not work with strict ONVIF clients

---

## Building

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# Red Hat/CentOS
sudo yum install gcc make

# Arch Linux
sudo pacman -S base-devel
```

### Build Commands

```bash
cd ONVIF-SIM

# Build all
make

# Build specific target
make build/onvif_discoverer
make build/discovery_server

# Debug build (with symbols, no optimization)
make debug

# Clean
make clean
```

---

## Running

### Method 1: Manual (Two Terminals)

**Terminal 1 - Start fake camera:**
```bash
cd ONVIF-SIM
./build/discovery_server

# You should see:
# === WS-Discovery Server ===
# Local IP: 192.168.1.10
# socket created
# Bound to port 3702
# Joined multicast 239.255.255.250
# Listening...
```

**Terminal 2 - Discover cameras:**
```bash
cd ONVIF-SIM
./build/onvif_discoverer

# You should see:
# ═══════════════════════════════════════════════
#   ONVIF WS-Discovery Client
# ═══════════════════════════════════════════════
# [LAYER 1: APPLICATION] Socket created, fd=3
# [LAYER 4: KERNEL] struct sock allocated, protocol=UDP
# ...
# Device #1:
#   Name:      MyFakeCamera
#   Address:   192.168.1.10
#   XAddrs:    http://192.168.1.10:8080/onvif/device_service
```

### Method 2: Makefile Targets

```bash
# Terminal 1
make run-server

# Terminal 2
make run-client
```

### Method 3: Automated Demo

```bash
make demo
# Starts server in background, runs client, cleans up
```

---

## Understanding the Output

### Discovery Client Output

The client outputs **educational annotations** at each layer:

```
[LAYER 1: APPLICATION] Socket created, fd=3
  ↳ Your C code: socket() returns file descriptor

[LAYER 2: LIBC] setsockopt() called → syscall invoked
  ↳ glibc wrapper marshals arguments, invokes syscall

[LAYER 4: KERNEL] struct sock allocated, protocol=UDP
  ↳ Kernel allocates socket object in net/socket.c

[LAYER 1: APPLICATION] Sending WS-Discovery Probe
  ↳ Back to your code: sendto()

[LAYER 4: KERNEL] Packet processing
  ↳ udp_sendmsg() builds UDP header, passes to IP layer
```

**This traces the execution path** from your code → libc → kernel → NIC.

### Server Output

```
[Probe #1] from 192.168.1.100
         Sent ProbeMatch (1033 bytes)
```

Simple, because the server is focused on protocol, not education.

---

## Troubleshooting

### No Devices Found

**1. Check if server is running:**
```bash
# In another terminal
ps aux | grep discovery_server

# Check if port 3702 is listening
ss -ulnp | grep 3702
# or
netstat -ulnp | grep 3702
```

**2. Check multicast group membership:**
```bash
ip maddr show
# Should see 239.255.255.250 on your active interface
```

**3. Check firewall:**
```bash
# iptables (most Linux)
sudo iptables -L INPUT -n | grep 3702
sudo iptables -I INPUT -p udp --dport 3702 -j ACCEPT

# firewalld (Red Hat/CentOS)
sudo firewall-cmd --add-port=3702/udp --permanent
sudo firewall-cmd --reload

# ufw (Ubuntu)
sudo ufw allow 3702/udp
```

**4. Capture traffic to verify:**
```bash
# Capture on all interfaces
sudo tcpdump -i any -n port 3702

# What to expect:
# - Outgoing packet to 239.255.255.250:3702 (Probe)
# - Incoming packet from server IP (ProbeMatch)
```

**5. Check routing:**
```bash
# See which interface would be used
ip route get 239.255.255.250

# Check if multicast routing is enabled
cat /proc/sys/net/ipv4/ip_forward
```

### "Operation not permitted" Error

**Cause:** Firewall, network restrictions, or namespace isolation.

**Fix:**
```bash
# Try running with sudo (not recommended for production)
sudo ./build/onvif_discoverer

# Or add capability (Linux only)
sudo setcap cap_net_raw,cap_net_bind_service=+ep ./build/onvif_discoverer
```

### Port Already in Use

```bash
# Find process using port 3702
sudo lsof -i :3702
# or
sudo ss -tulpn | grep 3702

# Kill the process
kill <PID>
```

### Server Starts But Client Finds Nothing

**Interface mismatch!**

The server and client must be on the same network interface.

```bash
# See all interfaces and IPs
ip addr show

# Server will print its detected IP:
# Local IP: 192.168.1.10

# If client is on different interface (e.g., wlan0 vs eth0):
# - Multicast won't work across interfaces
# - Need to force interface selection
```

**Fix:** Modify code to use specific interface:
```c
// In both server and client
mreq.imr_interface.s_addr = inet_addr("192.168.1.10");  // Your eth0 IP
```

---

## Testing with Real ONVIF Tools

### ONVIF Device Test Tool

Official test tool from ONVIF organization.

**Windows:**
1. Download from [onvif.org](https://www.onvif.org/conformance/tools/introduction/)
2. Install
3. Start your fake camera: `./build/discovery_server`
4. In test tool: Discovery → Start
5. Should find "MyFakeCamera"

**Note:** Full ONVIF compliance requires implementing device services (HTTP endpoints), not just discovery. This fake camera only implements discovery.

### ONVIF Device Manager (ODM)

Free Windows client for ONVIF cameras.

1. Download from [sourceforge](https://sourceforge.net/projects/onvifdm/)
2. Install
3. Start fake camera
4. In ODM: Devices → Add → Discovery
5. Should find camera

**Limitations:** ODM will try to query device info, which our fake camera doesn't implement.

### onvif-discovery (Python)

```bash
# Install
pip install onvif-discovery

# Run
onvif-discovery --timeout 5
```

Should find your fake camera!

### Custom Test Script

```bash
# Using netcat to send probe manually
echo '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
<a:MessageID>uuid:test-123</a:MessageID>
<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header>
<s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></s:Body>
</s:Envelope>' | nc -u 239.255.255.250 3702
```

---

## Next Steps

### 1. Read the Documentation

The code itself is the documentation!

- **onvif_discoverer.c** has 500+ lines of comments explaining every syscall
- **README.md** has detailed networking fundamentals

### 2. Trace with strace

See syscalls in action:

```bash
# Trace discovery client
strace -e socket,bind,setsockopt,sendto,recvfrom ./build/onvif_discoverer

# Sample output:
# socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) = 3
# setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
# bind(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
# setsockopt(3, IPPROTO_IP, IP_ADD_MEMBERSHIP, ..., 8) = 0
# sendto(3, "<?xml version=...", 624, 0, {sa_family=AF_INET, sin_port=htons(3702), sin_addr=inet_addr("239.255.255.250")}, 16) = 624
# recvfrom(3, ...)
```

This shows the execution path from your code to kernel!

### 3. Capture with tcpdump

See packets on wire:

```bash
# Capture WS-Discovery traffic
sudo tcpdump -i any -n -X port 3702

# Sample output:
# 10:30:45.123456 IP 192.168.1.100.54321 > 239.255.255.250.3702: UDP, length 624
# 0x0000:  4500 028c 1234 4000 4011 abcd c0a8 0164  E...4@.@......d
# 0x0010:  efff fffa d431 0e7e 0278 1234 3c3f 786d  .....1.~.x.4<?xm
# 0x0020:  6c20 7665 7273 696f 6e3d 2231 2e30 223f  l.version="1.0"?
```

This shows the actual bytes transmitted!

### 4. Read Kernel Source

Understand what happens after syscalls:

```bash
# Clone Linux kernel (optional, can browse online)
git clone https://github.com/torvalds/linux.git
cd linux

# Key files for networking:
# - net/socket.c          : sys_socket(), sys_bind(), sys_sendto()
# - net/ipv4/udp.c        : udp_sendmsg(), udp_recvmsg()
# - net/ipv4/ip_output.c  : IP layer, routing
# - net/core/sock.c       : Socket infrastructure
# - net/ipv4/igmp.c       : Multicast group management
```

### 5. Implement Full ONVIF Device

This fake camera only implements discovery. A real camera needs:

- HTTP server for device services
- GetDeviceInformation
- GetCapabilities
- GetProfiles
- GetStreamUri
- RTSP server for video streaming

This is beyond scope, but now you understand the networking!

### 6. Explore Other Protocols

Same patterns apply:

- **mDNS** (Multicast DNS): 224.0.0.251:5353
- **SSDP** (UPnP discovery): 239.255.255.250:1900
- **DHCP**: UDP broadcast
- **DNS**: Usually UDP, falls back to TCP for large responses
- **NTP**: UDP time sync

All use same socket APIs, just different protocols!

---

## Educational Philosophy

This code prioritizes **understanding** over **abstraction**.

### What this code teaches:

✅ Execution path: application → libc → syscall → kernel → hardware  
✅ Memory layout: where data lives at each layer  
✅ Responsibility: what you control vs what kernel controls  
✅ Failure modes: how to debug when things break  

### What this code doesn't do:

❌ Abstract away complexity  
❌ Use high-level libraries  
❌ Hide the kernel  
❌ Skip error handling "for brevity"  

**Goal:** Trace every function call from your code to the NIC.

---

## FAQ

**Q: Why is the code so verbose?**  
A: The code itself is the lesson. Every comment teaches a concept.

**Q: Why not use libonvif or similar?**  
A: Libraries abstract away what we're trying to learn. We're teaching networking, not ONVIF.

**Q: Will this work in production?**  
A: No. This is educational. Production needs proper XML parsing, error handling, authentication, etc.

**Q: Why UDP instead of TCP?**  
A: Discovery requires reaching unknown devices. Multicast only works with UDP. Later device queries use TCP (HTTP).

**Q: What about IPv6?**  
A: Exercise for the reader! See README for hints. (Multicast address: ff02::c, use MLDv2 instead of IGMP)

**Q: Can I use this to learn TCP?**  
A: Absolutely! The socket API is the same. Comments explain TCP differences. Try implementing a TCP echo server!

**Q: Why so many comments about kernel internals?**  
A: Networking IS kernel code. You can't understand networking without understanding the kernel.

---

## Resources

### Books
- **Unix Network Programming** by W. Richard Stevens (Vol 1)
- **TCP/IP Illustrated** by W. Richard Stevens (Vol 1 & 2)
- **Understanding Linux Network Internals** by Christian Benvenuti

### Online
- Linux kernel source: [kernel.org](https://kernel.org)
- glibc source: [gnu.org/software/libc](https://www.gnu.org/software/libc/)
- ONVIF specs: [onvif.org](https://www.onvif.org/specs/)
- WS-Discovery: [OASIS standard](http://docs.oasis-open.org/ws-dd/discovery/)

### Tools
- `strace`: Trace syscalls
- `tcpdump`: Capture packets
- `ss`/`netstat`: Socket statistics
- `ip`: Network configuration
- `wireshark`: GUI packet analyzer

---

## Contributing

This is educational code. If you find:

- Incorrect explanations → Open an issue
- Missing concepts → Suggest additions
- Typos → PRs welcome

**Keep the philosophy:** Trace execution, explain layers, teach networking from the ground up.

---

## License

Educational use. Learn, modify, extend, break, fix, understand.

The goal is not to provide production ONVIF implementation.  
The goal is to teach **how networking works** from application to kernel.

---

**Ready to learn?**

```bash
make
make run-server  # Terminal 1
make run-client  # Terminal 2
```

Then read the source code. Every line teaches something.
