# NetC - Low-Level C Networking Projects

Educational repository for learning C network programming from first principles.

## Projects

### 🎥 ONVIF-SIM - ONVIF Camera Discovery (★ Recommended)

**Educational ONVIF WS-Discovery implementation with 800+ lines of systems programming documentation.**

Learn networking from application code to kernel internals:
- Socket API: application → libc → syscall → kernel → hardware
- UDP vs TCP: what you own vs what the kernel owns
- Multicast semantics: IGMP, interface selection, routing
- WS-Discovery protocol for IP camera discovery

**Key Features:**
- Fake ONVIF camera server (responds to WS-Discovery probes)
- Discovery client with comprehensive inline documentation
- 25KB README explaining networking fundamentals
- Quick start guide with troubleshooting tips

**Target Audience:** C programmers who read kernel source and want to understand networking execution paths.

```bash
cd ONVIF-SIM
make
make run-server  # Terminal 1
make run-client  # Terminal 2
```

📖 [Full Documentation](ONVIF-SIM/README.md) | 🚀 [Quick Start](ONVIF-SIM/USAGE.md)

---

### 📡 onviflibrary - ONVIF Protocol Components

Low-level UDP multicast networking utilities.

- `layer1/` - Basic UDP client/server implementations
- `udpmulticastdiscovery.h` - Multicast discovery structures

---

### 🖼️ imgsharewithparitycheck - UDP Image Transfer

Custom protocol for reliable image transfer over UDP.

- Implements application-level reliability (parity checks)
- Demonstrates message framing over datagram protocol
- Client/server architecture

---

### 🔧 simplemsg - Basic TCP Client/Server

Simple TCP message passing demonstration.

---

### 🧱 kernelimplementationfromscratch - Kernel Concepts

Exploration of kernel-level structures and implementations.

---

## Philosophy

This repository prioritizes **understanding over abstraction**:

✅ Trace execution paths from application to hardware  
✅ Explain what happens at each layer  
✅ Reference kernel source code  
✅ No "magic" - everything is explained  

❌ No high-level abstractions hiding complexity  
❌ No "just use this library" shortcuts  
❌ No skipping error handling "for brevity"  

**Goal:** Teach networking as a traceable execution path, not an API cookbook.

## Educational Approach

These projects are designed for programmers who:

- Understand C, memory layout, pointers, structs
- Can read Linux kernel source
- Want to learn how networking actually works
- Don't want rote learning or black-box explanations

Each project includes:

1. **Working code** - Compiles, runs, does something useful
2. **Inline documentation** - Comments explain every important line
3. **Layer explanations** - What happens at each level (app, libc, kernel)
4. **Failure modes** - How to debug when things break

## Getting Started

**Recommended path:**

1. Start with **ONVIF-SIM** - Most comprehensive documentation
2. Learn socket basics: `socket()`, `bind()`, `sendto()`, `recvfrom()`
3. Understand UDP vs TCP tradeoffs
4. Explore other projects as needed

**Prerequisites:**

```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# Red Hat/CentOS
sudo yum install gcc make
```

## Tools for Learning

- **strace** - Trace syscalls: `strace -e socket,bind,sendto,recvfrom ./program`
- **tcpdump** - Capture packets: `sudo tcpdump -i eth0 -n port 3702`
- **ss** - Socket stats: `ss -u -a -n`
- **ip** - Network config: `ip addr show`, `ip maddr show`

## Resources

### Books
- **Unix Network Programming** by W. Richard Stevens
- **TCP/IP Illustrated** by W. Richard Stevens
- **Understanding Linux Network Internals** by Christian Benvenuti

### Online
- Linux kernel source: [kernel.org](https://kernel.org)
  - `net/socket.c` - Socket syscalls
  - `net/ipv4/udp.c` - UDP implementation
  - `net/ipv4/tcp.c` - TCP implementation
- glibc source: [gnu.org/software/libc](https://www.gnu.org/software/libc/)

## Contributing

Found an error? Have a question? Want to add explanations?

Open an issue or PR. Keep the philosophy: explain layers, trace execution, teach from first principles.

## License

Educational use. Learn, modify, extend, break, understand.

---

**"A socket is not a packet. A socket is a stateful kernel object. TCP hides packets. UDP exposes packets. libc does not implement networking — the kernel does."**

Start with [ONVIF-SIM](ONVIF-SIM/) to learn why. 🚀
