# Experimental: Low-Level Networking Without Abstractions

## Purpose

This directory contains **raw syscall-level implementations** that bypass libc abstractions to help you understand networking at the kernel boundary.

**Goal**: Make TCP/UDP behavior memorable by showing explicit kernel interactions.

---

## Why This Exists

When you call `socket()` or `send()`, you're using **libc wrappers** that hide what's really happening. This makes networking feel like "magic" and forces memorization instead of understanding.

**This directory shows you**:
- Direct syscall invocations using `syscall(2)`
- Kernel struct layout (`struct msghdr`, `struct mmsghdr`, `struct sockaddr_in`)
- Memory page alignment (4KB pages)
- Buffer management without malloc/free abstractions
- TCP state machine at syscall level
- UDP datagram boundaries explicitly visible

---

## Files

### 1. `raw_udp_syscall.c` - UDP Without libc
Shows UDP using raw syscalls (`SYS_socket`, `SYS_sendto`, `SYS_recvfrom`)

**Key concepts**:
- Direct syscall boundary crossing
- Explicit `struct sockaddr_in` layout
- No hidden buffering (see exactly what kernel does)
- Message boundary preservation

### 2. `raw_tcp_syscall.c` - TCP State Machine Exposed
Shows TCP connection lifecycle using raw syscalls

**Key concepts**:
- 3-way handshake visibility (SYN, SYN-ACK, ACK)
- Socket state transitions (CLOSED → LISTEN → ESTABLISHED)
- Stream vs datagram semantics
- Explicit accept queue management

### 3. `memory_explicit.c` - Page-Aligned Buffer Management
Shows memory management at 4KB page granularity

**Key concepts**:
- `mmap()` for page-aligned allocation
- `madvise()` for kernel hints
- `memfd_create()` for anonymous memory
- Cache-line alignment (64-byte boundaries)

### 4. `tcp_vs_udp_side_by_side.c` - Direct Comparison
Same echo server in both TCP and UDP using raw syscalls

**Key concepts**:
- Identical code structure, different semantics
- Message boundaries (UDP) vs byte stream (TCP)
- Connection state (TCP) vs stateless (UDP)

### 5. `mmsghdr_batch.c` - Batch Message I/O
Shows `sendmmsg()` / `recvmmsg()` for efficient multi-message I/O

**Key concepts**:
- Vectored I/O without system call overhead
- Kernel struct `mmsghdr` layout
- Zero-copy techniques

---

## Building

Each file is standalone and compiles directly:

```bash
cd experimental

# Build individual files
gcc -o raw_udp_syscall raw_udp_syscall.c -std=c11 -Wall

# Build all
make -f Makefile.experimental
```

---

## Learning Path

**Recommended order**:

1. `raw_udp_syscall.c` - Start here (simplest)
2. `memory_explicit.c` - Understand buffers
3. `raw_tcp_syscall.c` - TCP complexity
4. `tcp_vs_udp_side_by_side.c` - Compare
5. `mmsghdr_batch.c` - Advanced optimization

---

## Defeating Abstractions: What You'll Learn

### Abstraction 1: `socket()` is just a number

```c
// What you think:
int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

// What actually happens:
long sock = syscall(SYS_socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
// Returns: file descriptor (small integer, index into kernel fd table)
// Kernel creates: struct socket + struct sock in kernel memory
```

### Abstraction 2: `send()` doesn't send packets

```c
// TCP: send() copies to kernel buffer, returns immediately
// Kernel decides WHEN to transmit (Nagle's algorithm, congestion control)
send(sock, buf, len, 0);  // ≠ packet sent!

// UDP: sendto() typically results in immediate packet
// But still no guarantee (interface down, routing failure, etc.)
sendto(sock, buf, len, 0, &dest, sizeof(dest));
```

### Abstraction 3: Structs have explicit layout

```c
struct sockaddr_in {
    sa_family_t sin_family;   // 2 bytes: AF_INET
    in_port_t sin_port;        // 2 bytes: network byte order (big-endian)
    struct in_addr sin_addr;   // 4 bytes: IP address
    char sin_zero[8];          // 8 bytes: padding (MUST be zero)
};
// Total: 16 bytes, no hidden fields
```

### Abstraction 4: Memory pages are 4KB

```c
// malloc() hides page alignment, but kernel works in 4KB chunks
void *buf = mmap(NULL, 4096,  // 4KB = one page
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
// Returns: page-aligned address (divisible by 4096)
```

---

## Theory → Code Correlation

### TCP 3-Way Handshake (Memorable)

**Theory**: SYN → SYN-ACK → ACK

**Code**:
```c
// Server:
int lfd = syscall(SYS_socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
syscall(SYS_listen, lfd, 128);  // Kernel: move to LISTEN state

// Client sends SYN (connect())
// Kernel: creates entry in SYN queue

int cfd = syscall(SYS_accept4, lfd, NULL, NULL, 0);
// Kernel: 
//   - Receives SYN
//   - Sends SYN-ACK
//   - Waits for ACK
//   - Moves to accept queue
//   - Returns new socket in ESTABLISHED state
```

### UDP Datagram Boundaries (Memorable)

**Theory**: Each send() = one packet, each recv() = one packet

**Code**:
```c
// Send 10 bytes, then 20 bytes
syscall(SYS_sendto, sock, "0123456789", 10, 0, &dest, sizeof(dest));
syscall(SYS_sendto, sock, "ABCDEFGHIJKLMNOPQRST", 20, 0, &dest, sizeof(dest));

// Receive: ALWAYS gets complete datagrams
char buf[100];
ssize_t n1 = syscall(SYS_recvfrom, sock, buf, 100, 0, NULL, NULL);
// n1 = 10, buf = "0123456789"

ssize_t n2 = syscall(SYS_recvfrom, sock, buf, 100, 0, NULL, NULL);
// n2 = 20, buf = "ABCDEFGHIJKLMNOPQRST"
```

### TCP Byte Stream (Memorable)

**Theory**: No message boundaries, all data merged

**Code**:
```c
// Send 10 bytes, then 20 bytes
syscall(SYS_send, sock, "0123456789", 10, 0);
syscall(SYS_send, sock, "ABCDEFGHIJKLMNOPQRST", 20, 0);

// Receive: Could be ANY combination
char buf[100];
ssize_t n = syscall(SYS_recv, sock, buf, 100, 0);
// Possible values:
//   n = 30, buf = "0123456789ABCDEFGHIJKLMNOPQRST"
//   n = 5,  buf = "01234"
//   n = 15, buf = "0123456789ABCDE"
// You CANNOT predict! It's a stream!
```

---

## Mental Model: Syscall Boundary

```
┌─────────────────────────────────────────┐
│         YOUR C CODE                     │
│  (userspace, ring 3)                    │
├─────────────────────────────────────────┤
│  syscall(SYS_socket, ...)               │
│         ↓                                │
│  Assembly: syscall instruction          │
│         ↓                                │
│  CPU privilege change (ring 3 → ring 0) │
├─────────────────────────────────────────┤
│         KERNEL CODE                     │
│  (kernelspace, ring 0)                  │
│                                          │
│  sys_socket()                           │
│    ↓                                     │
│  sock_create()                          │
│    ↓                                     │
│  inet_create()                          │
│    ↓                                     │
│  Allocate struct sock                   │
│    ↓                                     │
│  Return fd to userspace                 │
└─────────────────────────────────────────┘
```

**Key insight**: Every networking operation crosses this boundary. Understanding this makes everything else obvious.

---

## Memory Page Mental Model

```
Virtual Address Space (your process):
┌──────────────────┬──────────────────┬──────────────────┐
│  Page 0 (4KB)    │  Page 1 (4KB)    │  Page 2 (4KB)    │
│  0x00000000      │  0x00001000      │  0x00002000      │
├──────────────────┼──────────────────┼──────────────────┤
│  Code (.text)    │  Data (.data)    │  Heap (mmap)     │
└──────────────────┴──────────────────┴──────────────────┘

Each page:
- 4096 bytes (4KB)
- Addressable by page number (addr / 4096)
- Aligned (addr % 4096 == 0)
- Mapped by kernel (virtual → physical)
```

**Why care?**
- Network buffers should be page-aligned for DMA (Direct Memory Access)
- Kernel can zero-copy page-aligned buffers (splice, sendfile)
- Cache misses happen at cache-line boundaries (64 bytes)

---

## No Memorization Needed

**Instead of memorizing**:
- "TCP is connection-oriented, UDP is connectionless"
- "TCP has flow control, UDP doesn't"
- "TCP is reliable, UDP isn't"

**Understand the code**:
```c
// TCP: Kernel maintains state
struct sock {
    int state;  // LISTEN, SYN_SENT, ESTABLISHED, FIN_WAIT1, ...
    struct sk_buff_head write_queue;  // Unsent data
    struct sk_buff_head receive_queue;  // Received data
    // ... retransmission timers, congestion window, etc.
};

// UDP: Kernel has almost no state
struct udp_sock {
    struct sk_buff_head receive_queue;  // Just received packets
    // That's it! No connection state!
};
```

**Result**: You don't memorize "TCP is stateful" - you SEE the state in the struct!

---

## Correlation Examples

### Example 1: Why TCP send() can "lose" data

**Code**:
```c
send(sock, buf, 1000000, 0);  // 1MB
// Returns: 32768 (only 32KB sent)
```

**Why?**
```c
// In kernel (simplified):
int tcp_sendmsg(...) {
    while (len > 0) {
        if (sk->sk_sndbuf - sk->sk_wmem_queued < len) {
            // Send buffer full! Block or return partial.
            return bytes_sent_so_far;
        }
        // Copy to send buffer...
    }
}
```

**Mental model**: send() fills kernel buffer. When buffer full, returns how much it accepted. Application must retry!

### Example 2: Why UDP doesn't need connect()

**Code**:
```c
// UDP: sendto() includes destination
sendto(sock, buf, len, 0, &dest, sizeof(dest));

// TCP: send() uses connected destination
connect(sock, &dest, sizeof(dest));
send(sock, buf, len, 0);
```

**Why?**
```c
// UDP: Kernel builds packet header on EVERY send
udp_sendmsg(...) {
    // Get destination from function argument
    struct sockaddr_in *addr = ...;
    // Build UDP header with dest IP/port
    // Send immediately
}

// TCP: Kernel already knows destination (from connect)
tcp_sendmsg(...) {
    // Use sock->sk_daddr (destination already stored)
    // Add to send queue (may not send immediately!)
}
```

---

## Using This Directory

1. **Read the theory** in this README
2. **Read the code** in order (raw_udp → memory → raw_tcp → comparison → batch)
3. **Run the programs** and observe behavior
4. **Modify the code** - break things, see what happens
5. **Trace with strace** - see syscalls in real-time

**Don't memorize. Understand the structs, see the syscalls, internalize the patterns.**

---

## Next Steps

After mastering this directory:

1. Go back to main ONVIF implementation - it will make sense now
2. Implement Module 2 (Authentication) from ROADMAP.md
3. Read Linux kernel source: `net/ipv4/tcp.c` and `net/ipv4/udp.c`
4. Experiment with advanced features (zero-copy, splice, io_uring)

---

## References

**Man pages**:
- `man 2 syscall` - Making raw syscalls
- `man 2 socket` - Socket creation
- `man 2 sendmmsg` - Batch message sending
- `man 2 mmap` - Memory mapping

**Kernel source** (linux/net/):
- `socket.c` - Socket syscall handlers
- `ipv4/tcp.c` - TCP implementation
- `ipv4/udp.c` - UDP implementation

**Books**:
- "The Linux Programming Interface" by Michael Kerrisk - Chapters 56-61
- "Understanding the Linux Kernel" - Chapter 18 (Memory Management)

---

**Goal**: No more "magic". Every line of code is traceable to kernel behavior. No memorization required.
