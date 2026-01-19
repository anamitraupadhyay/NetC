/* Enable BSD and POSIX extensions for ip_mreq */
#define _DEFAULT_SOURCE
#define _BSD_SOURCE

/*
 * ONVIF WS-Discovery Client - Educational Implementation
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * LOW-LEVEL NETWORKING PRIMER: FROM APPLICATION TO KERNEL
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * This tool discovers ONVIF cameras on the network using WS-Discovery protocol.
 * It demonstrates UDP multicast networking from a systems programming perspective.
 * 
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │ LAYER MODEL: APPLICATION → LIBC → SYSCALL → KERNEL → HARDWARE            │
 * └──────────────────────────────────────────────────────────────────────────┘
 * 
 * LAYER 1: APPLICATION CODE (this file)
 *   - Your C code that calls socket(), sendto(), recvfrom()
 *   - You work with file descriptors (int fd) and buffers (char *)
 *   - Responsibility: Message framing, protocol logic, application state
 * 
 * LAYER 2: LIBC WRAPPER (glibc, musl, BSD libc)
 *   - socket() in glibc is a thin wrapper around the socket syscall
 *   - Location in glibc source: sysdeps/unix/sysv/linux/socket.c
 *   - The wrapper:
 *       1. Validates arguments (in some implementations)
 *       2. Sets up syscall arguments per ABI (SYS_socket, domain, type, protocol)
 *       3. Invokes syscall instruction (int 0x80 on x86, syscall on x64)
 *       4. Returns result (fd or -1, sets errno on error)
 *   - THIS IS NOT WHERE NETWORKING HAPPENS - it's just marshalling!
 * 
 * LAYER 3: SYSCALL BOUNDARY
 *   - When you call socket(), execution transitions from userspace to kernel
 *   - CPU switches privilege level (ring 3 → ring 0 on x86/x64)
 *   - Syscall number determines which kernel function handles it
 *   - For socket(): sys_socket() in net/socket.c (Linux kernel)
 * 
 * LAYER 4: KERNEL NETWORKING STACK
 *   - Kernel code path for socket():
 *       net/socket.c:sys_socket()
 *         → sock_create()
 *           → __sock_create()
 *             → net_families[family]->create()  // AF_INET → inet_create()
 *               → inet_create() allocates struct sock, struct socket
 *   
 *   - struct sock: The core kernel socket object (net/sock.h)
 *       - Contains: protocol ops, buffers, state machine, etc.
 *   
 *   - For UDP (SOCK_DGRAM + IPPROTO_UDP):
 *       - Protocol ops point to UDP functions (net/ipv4/udp.c)
 *       - No connection state (unlike TCP)
 *       - No retransmission, ordering, flow control
 * 
 * LAYER 5: PROTOCOL IMPLEMENTATION
 *   - UDP (net/ipv4/udp.c):
 *       - sendto() → udp_sendmsg()
 *           - Builds UDP header (source port, dest port, length, checksum)
 *           - Passes to IP layer
 *       - recvfrom() → udp_recvmsg()
 *           - Reads from socket receive queue
 *           - Returns datagram with sender address
 * 
 *   - TCP (net/ipv4/tcp.c) - FOR COMPARISON:
 *       - socket() creates CLOSED state
 *       - connect() → SYN, SYN-ACK, ACK handshake → ESTABLISHED
 *       - send() → tcp_sendmsg() → may block on send buffer, congestion control
 *       - recv() → tcp_recvmsg() → returns byte stream, not packets
 *       - State machine: LISTEN, SYN_SENT, SYN_RCVD, ESTABLISHED, FIN_WAIT...
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * UDP VS TCP: WHAT YOU OWN
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * UDP RESPONSIBILITIES:
 *   Application owns:
 *     - Message boundaries (you send 100 bytes → receiver gets 100 bytes or nothing)
 *     - Reliability (detect loss, retransmit if needed)
 *     - Ordering (packets can arrive out of order)
 *     - Congestion control (nothing stops you from flooding the network)
 *   
 *   Kernel provides:
 *     - Checksum (optional, can be disabled)
 *     - Port multiplexing (OS routes packets to correct socket)
 *     - Datagram buffering (limited by SO_RCVBUF)
 * 
 * TCP RESPONSIBILITIES:
 *   Application owns:
 *     - When to send data (kernel decides when to transmit packets)
 *     - Message framing (TCP is a byte stream, no boundaries)
 *   
 *   Kernel provides:
 *     - Reliable delivery (retransmission on loss)
 *     - Ordering (reorders out-of-order packets)
 *     - Flow control (sliding window)
 *     - Congestion control (CUBIC, BBR, etc.)
 *     - Connection state machine
 * 
 * KEY INSIGHT: TCP send() ≠ packet transmission
 *   - send() copies data to kernel send buffer
 *   - Kernel decides when to transmit (Nagle's algorithm, congestion window)
 *   - send() returning doesn't mean data was received by peer!
 * 
 * KEY INSIGHT: UDP sendto() ≈ packet transmission
 *   - sendto() typically results in immediate packet transmission
 *   - But no guarantee it reached destination!
 *   - No ACK, no retransmission
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * MULTICAST SEMANTICS
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * WHAT IS MULTICAST?
 *   - Special IP addresses (224.0.0.0 - 239.255.255.255) for one-to-many
 *   - One sender, multiple receivers
 *   - Used in: ONVIF discovery, mDNS, SSDP, video streaming
 * 
 * WHY MULTICAST FOR ONVIF?
 *   - Client doesn't know camera IPs beforehand
 *   - Broadcasting "Who's an ONVIF camera?" to all devices
 *   - Cameras listening on multicast group respond with their details
 * 
 * MULTICAST GROUP JOIN: IP_ADD_MEMBERSHIP
 *   - Tells kernel: "I want to receive packets sent to this multicast address"
 *   - Kernel updates:
 *       1. Network interface card (NIC) to accept packets to this MAC address
 *          (Multicast IP → Multicast MAC mapping)
 *       2. IGMP (Internet Group Management Protocol) message sent to router
 *          (Router learns which interfaces have interested receivers)
 *   
 *   - struct ip_mreq { in_addr imr_multiaddr, imr_interface }
 *       - imr_multiaddr: Which multicast group to join (e.g., 239.255.255.250)
 *       - imr_interface: Which local interface to use (INADDR_ANY = kernel chooses)
 * 
 * INTERFACE SELECTION MATTERS!
 *   - If you have multiple network interfaces (eth0, wlan0, etc.)
 *   - INADDR_ANY: kernel picks one (usually default route interface)
 *   - Specific IP: use that interface
 *   - WRONG INTERFACE = NO PACKETS RECEIVED!
 *       - Example: cameras on eth0, but you join on wlan0 → silent failure
 * 
 * MULTICAST LOOPBACK: IP_MULTICAST_LOOP
 *   - Should sender receive its own multicast packets?
 *   - Default: yes (1)
 *   - For testing: useful to see your own probes
 *   - For production: usually disabled (0)
 * 
 * MULTICAST TTL: IP_MULTICAST_TTL
 *   - Time-to-live for multicast packets
 *   - 1 = subnet only (default for ONVIF)
 *   - Higher = can cross routers (if routers forward multicast)
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * SOCKET API DETAILS
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP):
 *   - AF_INET: IPv4 address family
 *   - SOCK_DGRAM: Datagram socket (UDP, SCTP_DGRAM, etc.)
 *   - IPPROTO_UDP: Explicitly request UDP (could use 0 for default)
 *   - Returns: file descriptor (small integer, index into process fd table)
 *   - Kernel allocates: struct socket + struct sock + protocol state
 *   - POSIX-mandated: yes (socket() is in POSIX.1-2001)
 * 
 * setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, ...):
 *   - Sets socket-level options
 *   - SO_REUSEADDR: Allow reusing local address immediately after close
 *       - Without it: TIME_WAIT state prevents immediate rebind
 *       - Kernel behavior: net/core/sock.c:sock_setsockopt()
 *   - ABI: option value passed as void*, length as socklen_t
 * 
 * setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, ...):
 *   - IP-level option (not socket-level)
 *   - Kernel path: net/ipv4/ip_sockglue.c:do_ip_setsockopt()
 *       - Adds multicast group to socket's mc_list
 *       - Updates NIC multicast filter
 *       - Sends IGMP Join message
 * 
 * bind(fd, addr, addrlen):
 *   - Associates socket with local address (IP + port)
 *   - For multicast receiver: bind to INADDR_ANY + port (not multicast address!)
 *   - Why not bind to multicast address?
 *       - Multicast address is destination, not source
 *       - bind() sets local address
 *   - Kernel: net/ipv4/af_inet.c:inet_bind()
 * 
 * sendto(fd, buf, len, flags, dest_addr, addrlen):
 *   - Send datagram to specific address
 *   - For multicast: dest_addr = multicast group address
 *   - Kernel path: net/ipv4/udp.c:udp_sendmsg()
 *       - Validates destination
 *       - Builds UDP + IP header
 *       - Queues to IP layer
 *       - Returns immediately (no ACK wait)
 * 
 * recvfrom(fd, buf, len, flags, src_addr, addrlen):
 *   - Receive datagram and sender address
 *   - Blocks until packet arrives (unless O_NONBLOCK set)
 *   - Kernel path: net/ipv4/udp.c:udp_recvmsg()
 *       - Dequeues from socket receive buffer
 *       - Copies sender address to src_addr
 *   - Returns: number of bytes received
 *   - If buffer too small: data truncated (UDP message boundaries!)
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * WS-DISCOVERY PROTOCOL
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * WHAT IS WS-DISCOVERY?
 *   - SOAP-based discovery protocol (OASIS standard)
 *   - Used by ONVIF (IP camera standard), Windows WSD, printers
 *   - Multicast address: 239.255.255.250
 *   - Port: 3702
 * 
 * PROTOCOL FLOW:
 *   1. Client sends Probe (multicast to 239.255.255.250:3702)
 *   2. Matching devices respond with ProbeMatch (unicast to client)
 *   3. Client can query device details
 * 
 * PROBE MESSAGE:
 *   - SOAP envelope with <d:Probe> in body
 *   - Includes MessageID (UUID) for matching responses
 *   - Can include filters (device types, scopes)
 * 
 * PROBEMATCH RESPONSE:
 *   - SOAP envelope with <d:ProbeMatches>
 *   - RelatesTo: echoes client's MessageID
 *   - XAddrs: HTTP endpoint for device services
 *   - Types: device capabilities (NetworkVideoTransmitter for cameras)
 * 
 * WHY UDP + MULTICAST?
 *   - Discovery needs to reach unknown devices
 *   - TCP requires knowing IP + port beforehand
 *   - Multicast allows "broadcast within subnet"
 *   - UDP is stateless, low overhead for one-shot messages
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * MENTAL MODELS
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * SOCKET IS NOT A PACKET:
 *   - A socket is a kernel object representing a communication endpoint
 *   - It has state (buffers, options, protocol control blocks)
 *   - You send/receive through it, but it's not the data itself
 * 
 * LIBC DOES NOT IMPLEMENT NETWORKING:
 *   - libc provides syscall wrappers
 *   - Actual networking (routing, buffering, retransmission) is in kernel
 *   - This is why reading kernel source (net/ipv4/) teaches you networking
 * 
 * UDP EXPOSES PACKETS, TCP HIDES PACKETS:
 *   - UDP: each sendto() is a packet, each recvfrom() is a packet
 *   - TCP: send() adds to stream, recv() reads from stream
 *   - TCP handles packetization invisibly (MSS, Nagle's algorithm)
 * 
 * FAILURE MODE: MULTICAST NOT RECEIVED:
 *   - Symptoms: probe sent, no responses, but devices exist
 *   - Debugging:
 *       1. tcpdump -i eth0 port 3702  (see if packets reach interface)
 *       2. Check interface selection (imr_interface in IP_ADD_MEMBERSHIP)
 *       3. Check firewall (iptables, ufw)
 *       4. Check multicast routing (ip maddr show)
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>

/*
 * ONVIF WS-Discovery constants
 */
#define DISCOVERY_PORT 3702
#define MULTICAST_ADDR "239.255.255.250"
#define BUFFER_SIZE 65536
#define DISCOVERY_TIMEOUT_SEC 5

/*
 * WS-Discovery Probe message template
 * 
 * PROTOCOL NOTES:
 *   - SOAP 1.2 envelope (xmlns:s)
 *   - WS-Addressing for message routing (xmlns:a)
 *   - WS-Discovery for probe semantics (xmlns:d)
 *   - MessageID: unique identifier for this probe (UUID)
 *   - Types filter: dn:NetworkVideoTransmitter (ONVIF cameras)
 */
const char *PROBE_MESSAGE =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope "
    "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "
    "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<s:Header>"
    "<a:Action s:mustUnderstand=\"1\">"
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
    "</a:Action>"
    "<a:MessageID>uuid:%s</a:MessageID>"
    "<a:To s:mustUnderstand=\"1\">"
    "urn:schemas-xmlsoap-org:ws:2005:04:discovery"
    "</a:To>"
    "</s:Header>"
    "<s:Body>"
    "<d:Probe>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "</d:Probe>"
    "</s:Body>"
    "</s:Envelope>";

/*
 * Generate a simple UUID (not cryptographically secure, but sufficient for discovery)
 * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 * 
 * NOTE: Uses rand() which is NOT cryptographically secure.
 * For production: use proper UUID library (libuuid) or read from /dev/urandom
 * For educational/testing purposes: rand() is sufficient
 */
void generate_uuid(char *uuid_buf, size_t size) {
    snprintf(uuid_buf, size,
             "%08x-%04x-4%03x-%04x-%012x",
             (unsigned)rand(), (unsigned)rand() & 0xFFFF,
             (unsigned)rand() & 0xFFF, (unsigned)rand() & 0xFFFF,
             (unsigned)rand());
}

/*
 * Extract XAddrs (device service URLs) from ProbeMatch response
 * This is where you'd connect to get device info, capabilities, etc.
 */
int extract_xaddrs(const char *xml, char *xaddrs, size_t size) {
    const char *start = strstr(xml, "<d:XAddrs>");
    if (!start) start = strstr(xml, "<XAddrs>");
    if (!start) return -1;
    
    start = strchr(start, '>');
    if (!start) return -1;
    start++;
    
    const char *end = strstr(start, "</");
    if (!end) return -1;
    
    /* Validate bounds to prevent integer overflow */
    if (end <= start) return -1;
    
    size_t len = (size_t)(end - start);
    if (len >= size) len = size - 1;
    
    memcpy(xaddrs, start, len);
    xaddrs[len] = '\0';
    
    return 0;
}

/*
 * Extract device name from Scopes
 */
int extract_device_name(const char *xml, char *name, size_t size) {
    const char *scopes = strstr(xml, "<d:Scopes>");
    if (!scopes) scopes = strstr(xml, "<Scopes>");
    if (!scopes) return -1;
    
    const char *name_marker = strstr(scopes, "onvif://www.onvif.org/name/");
    if (!name_marker) return -1;
    
    name_marker += strlen("onvif://www.onvif.org/name/");
    
    size_t i;
    /* Add null terminator check to prevent buffer overrun */
    for (i = 0; i < size - 1 && name_marker[i] != '\0' && 
         name_marker[i] != ' ' && name_marker[i] != '<'; i++) {
        name[i] = name_marker[i];
    }
    name[i] = '\0';
    
    return 0;
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("  ONVIF WS-Discovery Client - Educational Low-Level Implementation\n");
    printf("═══════════════════════════════════════════════════════════════════\n\n");
    
    srand((unsigned)time(NULL));
    
    /*
     * ┌────────────────────────────────────────────────────────────────────┐
     * │ STEP 1: CREATE UDP SOCKET                                          │
     * └────────────────────────────────────────────────────────────────────┘
     * 
     * APPLICATION CODE:
     *   socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
     * 
     * LIBC WRAPPER (glibc/musl):
     *   - Thin wrapper around sys_socket syscall
     *   - Sets up syscall number and arguments
     *   - Invokes syscall instruction
     * 
     * SYSCALL BOUNDARY:
     *   - Userspace → kernel mode transition
     *   - CPU privilege level change (ring 3 → ring 0)
     * 
     * KERNEL PATH:
     *   net/socket.c:sys_socket()
     *     → sock_create()
     *       → __sock_create()
     *         → pf->create() where pf = inet_family_ops
     *           → inet_create() [net/ipv4/af_inet.c]
     *             - Allocates struct sock
     *             - Initializes UDP protocol ops (udp_prot)
     *             - Returns file descriptor
     * 
     * RESULT:
     *   - File descriptor (integer index into process fd table)
     *   - Kernel maintains struct socket + struct sock
     *   - No connection, no buffers allocated yet (UDP is stateless)
     */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket() failed");
        printf("\nKERNEL ERROR: Could not create socket\n");
        printf("Possible causes:\n");
        printf("  - Process out of file descriptors (ulimit -n)\n");
        printf("  - System out of memory\n");
        printf("  - Kernel module not loaded (unlikely for UDP)\n");
        return 1;
    }
    
    printf("[LAYER 1: APPLICATION] Socket created, fd=%d\n", sock);
    printf("[LAYER 4: KERNEL] struct sock allocated, protocol=UDP\n\n");
    
    /*
     * ┌────────────────────────────────────────────────────────────────────┐
     * │ STEP 2: SET SOCKET OPTIONS                                         │
     * └────────────────────────────────────────────────────────────────────┘
     * 
     * SO_REUSEADDR:
     *   - Allows multiple sockets to bind to same port
     *   - Necessary for multiple discovery clients on same machine
     *   - Kernel: net/core/sock.c:sock_setsockopt()
     *       - Sets sk->sk_reuse = SK_CAN_REUSE
     * 
     * SO_RCVTIMEO:
     *   - Sets receive timeout (prevents infinite blocking)
     *   - Kernel: socket rcv_timeo field
     *   - recvfrom() returns -1 with errno=EAGAIN/EWOULDBLOCK on timeout
     */
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }
    
    struct timeval tv = { .tv_sec = DISCOVERY_TIMEOUT_SEC, .tv_usec = 0 };
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO) failed");
    }
    
    printf("[LAYER 2: LIBC] setsockopt() called → syscall invoked\n");
    printf("[LAYER 4: KERNEL] Socket options updated in struct sock\n");
    printf("  - SO_REUSEADDR: enabled (port sharing allowed)\n");
    printf("  - SO_RCVTIMEO: %d seconds\n\n", DISCOVERY_TIMEOUT_SEC);
    
    /*
     * ┌────────────────────────────────────────────────────────────────────┐
     * │ STEP 3: CONFIGURE MULTICAST                                        │
     * └────────────────────────────────────────────────────────────────────┘
     * 
     * IP_MULTICAST_LOOP:
     *   - Should we receive our own multicast packets?
     *   - 1 = yes (useful for testing)
     *   - 0 = no (typical production setting)
     *   - Kernel: net/ipv4/ip_sockglue.c
     * 
     * IP_MULTICAST_TTL:
     *   - Time-to-live for multicast packets
     *   - 1 = local subnet only (ONVIF standard)
     *   - Higher values allow routing across subnets (if routers configured)
     *   - Kernel: stored in socket's multicast TTL field
     */
    int loop = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        perror("setsockopt(IP_MULTICAST_LOOP) failed");
    }
    
    int ttl = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt(IP_MULTICAST_TTL) failed");
    }
    
    printf("[LAYER 4: KERNEL] Multicast options configured:\n");
    printf("  - IP_MULTICAST_LOOP: enabled (will receive own packets)\n");
    printf("  - IP_MULTICAST_TTL: %d (subnet only)\n\n", ttl);
    
    /*
     * ┌────────────────────────────────────────────────────────────────────┐
     * │ STEP 4: BIND TO PORT (OPTIONAL FOR CLIENT, BUT GOOD PRACTICE)     │
     * └────────────────────────────────────────────────────────────────────┘
     * 
     * WHY BIND AS CLIENT?
     *   - Ensures predictable source port for responses
     *   - Without bind(), kernel picks ephemeral port
     *   - With bind(INADDR_ANY:0), kernel still picks port but you control it
     * 
     * BIND SEMANTICS:
     *   - Associates socket with local address (IP + port)
     *   - For receiving multicast: bind to INADDR_ANY + port
     *   - Do NOT bind to multicast address (that's destination, not source!)
     * 
     * KERNEL PATH:
     *   net/ipv4/af_inet.c:inet_bind()
     *     - Validates address (not in use, not privileged if port < 1024)
     *     - Updates sock->sk_rcv_saddr, sock->sk_num
     *     - Adds socket to hash table for port lookup
     */
    struct sockaddr_in local_addr = {0};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0;  // Let kernel pick port
    
    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind() failed");
    }
    
    printf("[LAYER 2: LIBC] bind() called\n");
    printf("[LAYER 4: KERNEL] Socket bound to INADDR_ANY:ephemeral_port\n");
    printf("  - Kernel assigns ephemeral port from range (e.g., 32768-60999)\n");
    printf("  - Socket added to kernel's port hash table\n\n");
    
    /*
     * ┌────────────────────────────────────────────────────────────────────┐
     * │ STEP 5: JOIN MULTICAST GROUP (FOR RECEIVING RESPONSES)            │
     * └────────────────────────────────────────────────────────────────────┘
     * 
     * WHY JOIN AS CLIENT?
     *   - ProbeMatch responses are sent to multicast group (some devices do this)
     *   - Or they're sent unicast (most common)
     *   - Joining ensures we receive either way
     * 
     * struct ip_mreq:
     *   - imr_multiaddr: Multicast group IP (239.255.255.250)
     *   - imr_interface: Local interface to use (INADDR_ANY = kernel chooses)
     * 
     * KERNEL PATH:
     *   net/ipv4/ip_sockglue.c:do_ip_setsockopt()
     *     case IP_ADD_MEMBERSHIP:
     *       → ip_mc_join_group()
     *         - Adds group to socket's mc_list
     *         - Updates NIC multicast filter (via dev_mc_add())
     *         - Sends IGMP Join message (tells router we're interested)
     * 
     * WHAT HAPPENS AT NIC LEVEL?
     *   - Multicast IP 239.255.255.250 → Multicast MAC 01:00:5e:7f:ff:fa
     *   - NIC configured to accept packets to this MAC address
     *   - Without joining: NIC drops multicast packets (not in filter)
     * 
     * IGMP (Internet Group Management Protocol):
     *   - Protocol for multicast group management
     *   - Join: "I want to receive packets for this group"
     *   - Router learns which interfaces have interested receivers
     *   - Router forwards multicast traffic only to those interfaces
     */
    struct ip_mreq mreq = {0};
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt(IP_ADD_MEMBERSHIP) failed");
        printf("\nWARNING: Could not join multicast group\n");
        printf("Possible causes:\n");
        printf("  - No network interface available\n");
        printf("  - Multicast routing not enabled\n");
        printf("  - Permission denied (unlikely for non-admin)\n");
        printf("Continuing anyway (unicast responses may still work)...\n\n");
    } else {
        printf("[LAYER 2: LIBC] setsockopt(IP_ADD_MEMBERSHIP) called\n");
        printf("[LAYER 4: KERNEL] Multicast group joined:\n");
        printf("  - Group: %s\n", MULTICAST_ADDR);
        printf("  - Interface: INADDR_ANY (kernel selects default)\n");
        printf("  - NIC multicast filter updated\n");
        printf("  - IGMP Join message sent to router\n\n");
    }
    
    /*
     * ┌────────────────────────────────────────────────────────────────────┐
     * │ STEP 6: BUILD AND SEND PROBE MESSAGE                              │
     * └────────────────────────────────────────────────────────────────────┘
     * 
     * MESSAGE CONSTRUCTION:
     *   - Generate UUID for MessageID (track responses)
     *   - Fill SOAP envelope template
     * 
     * sendto() SEMANTICS:
     *   - Sends datagram to specified address
     *   - For multicast: destination = multicast group address
     *   - Returns immediately (no ACK wait, no connection)
     * 
     * KERNEL PATH:
     *   net/ipv4/udp.c:udp_sendmsg()
     *     1. Validate destination address
     *     2. Route lookup (find interface to send on)
     *     3. Allocate sk_buff (kernel's packet buffer structure)
     *     4. Copy user data to sk_buff
     *     5. Build UDP header (src port, dst port, length, checksum)
     *     6. Pass to IP layer: ip_send_skb()
     *        - Build IP header (src IP, dst IP, TTL, protocol=UDP)
     *        - Pass to link layer
     *     7. Link layer queues packet to NIC
     * 
     * HARDWARE:
     *   - NIC DMA reads packet from kernel memory
     *   - NIC transmits packet on wire (Ethernet frame)
     * 
     * UDP VS TCP COMPARISON:
     *   - UDP sendto(): typically results in immediate transmission
     *   - TCP send(): copies to kernel buffer, may not transmit immediately
     *       - Nagle's algorithm may delay transmission
     *       - Congestion control may block
     *       - send() returning ≠ packet sent ≠ data received by peer
     */
    char uuid[64];
    generate_uuid(uuid, sizeof(uuid));
    
    char probe_msg[4096];
    snprintf(probe_msg, sizeof(probe_msg), PROBE_MESSAGE, uuid);
    
    struct sockaddr_in multicast_addr = {0};
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_port = htons(DISCOVERY_PORT);
    multicast_addr.sin_addr.s_addr = inet_addr(MULTICAST_ADDR);
    
    printf("[LAYER 1: APPLICATION] Sending WS-Discovery Probe:\n");
    printf("  - MessageID: %s\n", uuid);
    printf("  - Destination: %s:%d (multicast)\n", MULTICAST_ADDR, DISCOVERY_PORT);
    printf("  - Message size: %zu bytes\n\n", strlen(probe_msg));
    
    ssize_t sent = sendto(sock, probe_msg, strlen(probe_msg), 0,
                          (struct sockaddr*)&multicast_addr,
                          sizeof(multicast_addr));
    
    if (sent < 0) {
        perror("sendto() failed");
        printf("\nAPPLICATION ERROR: Could not send probe\n");
        close(sock);
        return 1;
    }
    
    printf("[LAYER 2: LIBC] sendto() called → syscall invoked\n");
    printf("[LAYER 4: KERNEL] Packet processing:\n");
    printf("  - udp_sendmsg() in net/ipv4/udp.c\n");
    printf("  - UDP header built (src_port, dst_port=3702, checksum)\n");
    printf("  - IP header built (src_ip, dst_ip=239.255.255.250, ttl=%d)\n", ttl);
    printf("  - Packet queued to NIC\n");
    printf("[LAYER 5: HARDWARE] NIC transmits Ethernet frame\n\n");
    
    printf("Probe sent, waiting for responses (timeout: %d seconds)...\n\n", DISCOVERY_TIMEOUT_SEC);
    
    /*
     * ┌────────────────────────────────────────────────────────────────────┐
     * │ STEP 7: RECEIVE PROBEMATCH RESPONSES                              │
     * └────────────────────────────────────────────────────────────────────┘
     * 
     * recvfrom() SEMANTICS:
     *   - Blocks until packet arrives (or timeout via SO_RCVTIMEO)
     *   - Returns: datagram data + sender address
     *   - UDP maintains message boundaries (send 100 bytes → recv 100 bytes)
     * 
     * KERNEL PATH:
     *   net/ipv4/udp.c:udp_recvmsg()
     *     1. Wait on socket receive queue
     *        - Packets arrive via interrupt → kernel queues to socket
     *        - If queue empty: sleep (interruptible) or timeout
     *     2. Dequeue packet (sk_buff) from queue
     *     3. Copy data to userspace buffer
     *     4. Copy sender address to src_addr
     *     5. Free sk_buff
     *     6. Return bytes received
     * 
     * BLOCKING BEHAVIOR:
     *   - Default: recvfrom() blocks until data arrives
     *   - With SO_RCVTIMEO: returns after timeout with errno=EAGAIN
     *   - With O_NONBLOCK: returns immediately if no data
     * 
     * MESSAGE BOUNDARIES (UDP vs TCP):
     *   - UDP: each recvfrom() returns ONE datagram
     *       - send 10 bytes + send 20 bytes = recv 10 bytes, recv 20 bytes
     *   - TCP: recv() returns byte stream
     *       - send 10 bytes + send 20 bytes = recv 30 bytes (or any combination)
     *       - Application must frame messages (length prefix, delimiter, etc.)
     * 
     * WHY LOOP?
     *   - Multiple cameras may respond
     *   - Each response is a separate UDP datagram
     *   - Loop until timeout (no more responses)
     */
    char recv_buf[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t sender_len;
    int response_count = 0;
    
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("  Discovered ONVIF Devices:\n");
    printf("═══════════════════════════════════════════════════════════════════\n\n");
    
    while (1) {
        sender_len = sizeof(sender_addr);
        memset(recv_buf, 0, sizeof(recv_buf));
        
        printf("[LAYER 2: LIBC] recvfrom() called → blocking on socket\n");
        printf("[LAYER 4: KERNEL] Waiting on socket receive queue...\n");
        
        ssize_t received = recvfrom(sock, recv_buf, sizeof(recv_buf) - 1, 0,
                                    (struct sockaddr*)&sender_addr, &sender_len);
        
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("[LAYER 4: KERNEL] Receive timeout reached\n");
                printf("[LAYER 1: APPLICATION] No more responses\n\n");
                break;
            }
            perror("recvfrom() failed");
            break;
        }
        
        recv_buf[received] = '\0';
        
        printf("[LAYER 4: KERNEL] Packet received:\n");
        printf("  - Source: %s:%d\n", 
               inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port));
        printf("  - Size: %zd bytes\n", received);
        printf("[LAYER 2: LIBC] Data copied to userspace buffer\n");
        printf("[LAYER 1: APPLICATION] Processing response...\n\n");
        
        /*
         * VALIDATE RESPONSE:
         *   - Check if it's a ProbeMatch (not our own Probe echo)
         *   - ProbeMatch contains device information
         */
        if (!strstr(recv_buf, "ProbeMatch")) {
            printf("  → Not a ProbeMatch, ignoring\n\n");
            continue;
        }
        
        response_count++;
        
        /*
         * PARSE RESPONSE:
         *   - Extract XAddrs (device service URLs)
         *   - Extract device name from Scopes
         *   - In production: use proper XML parser (libxml2, expat)
         *   - Here: simple string search for educational purposes
         */
        char xaddrs[512] = {0};
        char device_name[256] = {0};
        
        extract_xaddrs(recv_buf, xaddrs, sizeof(xaddrs));
        extract_device_name(recv_buf, device_name, sizeof(device_name));
        
        printf("───────────────────────────────────────────────────────────────────\n");
        printf("  Device #%d:\n", response_count);
        printf("───────────────────────────────────────────────────────────────────\n");
        printf("  Name:      %s\n", device_name[0] ? device_name : "(unknown)");
        printf("  Address:   %s\n", inet_ntoa(sender_addr.sin_addr));
        printf("  XAddrs:    %s\n", xaddrs[0] ? xaddrs : "(not found)");
        printf("\n  NEXT STEPS:\n");
        printf("    1. HTTP GET to XAddrs URL for device capabilities\n");
        printf("    2. ONVIF GetDeviceInformation request\n");
        printf("    3. Query media profiles, stream URIs, etc.\n");
        printf("───────────────────────────────────────────────────────────────────\n\n");
    }
    
    /*
     * ┌────────────────────────────────────────────────────────────────────┐
     * │ STEP 8: CLEANUP                                                    │
     * └────────────────────────────────────────────────────────────────────┘
     * 
     * close() SEMANTICS:
     *   - Releases file descriptor
     *   - Kernel cleans up socket resources
     * 
     * KERNEL PATH:
     *   net/socket.c:sock_close()
     *     → sock_release()
     *       → proto->close() [udp_close() for UDP]
     *         - Leaves multicast groups (IGMP Leave message)
     *         - Flushes send/receive queues
     *         - Frees struct sock, struct socket
     *         - Removes from port hash table
     */
    close(sock);
    printf("[LAYER 2: LIBC] close() called\n");
    printf("[LAYER 4: KERNEL] Socket cleanup:\n");
    printf("  - IGMP Leave message sent\n");
    printf("  - Socket buffers freed\n");
    printf("  - File descriptor released\n\n");
    
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("  Discovery complete: %d device(s) found\n", response_count);
    printf("═══════════════════════════════════════════════════════════════════\n\n");
    
    if (response_count == 0) {
        printf("TROUBLESHOOTING: No devices found\n");
        printf("─────────────────────────────────────────────────────────────────\n");
        printf("1. Check if devices are on same subnet:\n");
        printf("   - Multicast TTL=1 limits to local subnet\n");
        printf("   - Run: ip route show\n");
        printf("\n");
        printf("2. Check multicast routing:\n");
        printf("   - Run: ip maddr show\n");
        printf("   - Should see 239.255.255.250 on active interface\n");
        printf("\n");
        printf("3. Check firewall:\n");
        printf("   - Run: sudo iptables -L -n | grep 3702\n");
        printf("   - Ensure UDP port 3702 is allowed\n");
        printf("\n");
        printf("4. Capture traffic to verify probe was sent:\n");
        printf("   - Run: sudo tcpdump -i any -n port 3702\n");
        printf("   - Should see outgoing Probe and incoming ProbeMatch\n");
        printf("\n");
        printf("5. Check interface selection:\n");
        printf("   - This tool uses INADDR_ANY (kernel chooses interface)\n");
        printf("   - If multiple interfaces, kernel picks one (usually default route)\n");
        printf("   - To force specific interface: bind to specific IP\n");
        printf("\n");
        printf("KERNEL DEBUGGING:\n");
        printf("  - Check if multicast group was joined: cat /proc/net/igmp\n");
        printf("  - Check socket state: ss -u -a | grep 3702\n");
        printf("  - Check routing: ip route get 239.255.255.250\n");
        printf("═══════════════════════════════════════════════════════════════════\n");
    }
    
    return 0;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * FURTHER READING
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * LINUX KERNEL SOURCE:
 *   - net/socket.c: syscall handlers (sys_socket, sys_bind, etc.)
 *   - net/ipv4/udp.c: UDP protocol implementation
 *   - net/ipv4/tcp.c: TCP protocol implementation (for comparison)
 *   - net/core/sock.c: Core socket infrastructure
 *   - net/ipv4/ip_sockglue.c: IP-level socket options
 *   - net/ipv4/igmp.c: IGMP multicast protocol
 * 
 * LIBC SOURCE (glibc):
 *   - sysdeps/unix/sysv/linux/socket.c: socket() wrapper
 *   - socket/sendto.c: sendto() wrapper
 *   - socket/recvfrom.c: recvfrom() wrapper
 * 
 * STANDARDS:
 *   - POSIX.1-2001: socket(), bind(), sendto(), recvfrom()
 *   - RFC 768: UDP specification
 *   - RFC 793: TCP specification
 *   - RFC 1112: IGMP and multicast
 *   - RFC 3927: Link-Local IPv4 addresses
 *   - OASIS WS-Discovery 1.1: Discovery protocol
 *   - ONVIF Core Specification: Camera device specification
 * 
 * TOOLS FOR LEARNING:
 *   - strace: trace syscalls (strace -e socket,bind,sendto,recvfrom ./program)
 *   - tcpdump: capture network packets (tcpdump -i eth0 -n -X port 3702)
 *   - ss: socket statistics (ss -u -a -n)
 *   - ip: network configuration (ip addr, ip route, ip maddr)
 *   - netstat: legacy socket statistics (netstat -g for multicast groups)
 * 
 * EXERCISES:
 *   1. Add support for receiving multicast on specific interface (not INADDR_ANY)
 *   2. Implement timeout handling per-device (detect slow responders)
 *   3. Parse XML properly using libxml2
 *   4. Implement follow-up ONVIF queries (GetDeviceInformation, GetCapabilities)
 *   5. Compare UDP vs TCP for ONVIF device services (HTTP)
 *   6. Implement unicast probe (direct device query if IP known)
 *   7. Add IPv6 support (IPv6 multicast: ff02::c, MLDv2 instead of IGMP)
 * 
 * DEBUGGING TECHNIQUES:
 *   1. Use strace to see syscalls and their arguments/return values
 *   2. Use tcpdump to verify packets on wire
 *   3. Compare kernel source with observed behavior
 *   4. Check /proc/net/ for kernel state (igmp, udp, raw)
 *   5. Use GDB to step through code and inspect structs
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */
