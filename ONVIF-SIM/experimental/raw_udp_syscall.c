/*
 * RAW UDP SYSCALL IMPLEMENTATION
 * 
 * This shows UDP networking using DIRECT SYSCALLS (no libc wrappers).
 * 
 * GOAL: Understand what socket(), sendto(), recvfrom() REALLY do.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * KEY INSIGHT: UDP Message Boundaries
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * UDP preserves message boundaries:
 *   - Each sendto() = one packet
 *   - Each recvfrom() = one complete packet
 *   - No partial reads (unlike TCP)
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

#define _GNU_SOURCE
#include <sys/syscall.h>      /* SYS_socket, SYS_sendto, etc. */
#include <unistd.h>           /* syscall() */
#include <sys/socket.h>       /* AF_INET, SOCK_DGRAM */
#include <netinet/in.h>       /* struct sockaddr_in, IPPROTO_UDP */
#include <arpa/inet.h>        /* inet_addr */
#include <string.h>           /* memset */
#include <stdio.h>            /* printf */
#include <errno.h>            /* errno */

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * THEORY → CODE: What is a socket?
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * A socket is NOT a packet. A socket is:
 *   1. A file descriptor (small integer)
 *   2. An index into your process's file descriptor table
 *   3. Points to kernel object: struct socket + struct sock
 * 
 * When you call socket():
 *   - Syscall crosses userspace → kernel boundary
 *   - Kernel allocates struct sock (net/sock.h)
 *   - Kernel allocates struct socket (linux/net.h)
 *   - Returns fd (index) to your process
 */

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  RAW UDP SYSCALL EXAMPLE\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 1: CREATE UDP SOCKET (direct syscall)                     │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * Normal code:
     *   int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     * 
     * Raw syscall:
     *   long sock = syscall(SYS_socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     * 
     * What happens:
     *   1. CPU executes syscall instruction
     *   2. Privilege escalation (ring 3 → ring 0)
     *   3. Kernel: sys_socket() → sock_create() → inet_create()
     *   4. Kernel allocates struct sock (UDP protocol ops)
     *   5. Returns fd number
     */
    
    long sock = syscall(SYS_socket, 
                        AF_INET,        /* IPv4 */
                        SOCK_DGRAM,     /* Datagram (UDP) */
                        IPPROTO_UDP);   /* UDP protocol */
    
    if (sock < 0) {
        perror("SYS_socket failed");
        return 1;
    }
    
    printf("[SYSCALL] SYS_socket returned fd=%ld\n", sock);
    printf("[KERNEL]  Allocated struct sock at kernel address (hidden from us)\n");
    printf("[KERNEL]  Socket state: UNBOUND (no local address yet)\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 2: PREPARE DESTINATION ADDRESS                            │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * struct sockaddr_in is EXACTLY 16 bytes:
     *   - sin_family: 2 bytes (AF_INET = 2)
     *   - sin_port:   2 bytes (network byte order, big-endian)
     *   - sin_addr:   4 bytes (IP address, 32-bit)
     *   - sin_zero:   8 bytes (padding, MUST be zero)
     * 
     * Memory layout (16 bytes total):
     *   [0x0002] [port] [ip] [00000000]
     */
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));  /* Zero all bytes (especially sin_zero!) */
    
    dest.sin_family = AF_INET;                    /* 2 bytes: 0x0002 */
    dest.sin_port = __builtin_bswap16(9999);     /* 2 bytes: htons(9999) */
    dest.sin_addr.s_addr = __builtin_bswap32(    /* 4 bytes: 127.0.0.1 */
        (127 << 24) | (0 << 16) | (0 << 8) | 1
    );
    /* sin_zero already zeroed by memset */
    
    printf("[MEMORY]  struct sockaddr_in at address %p\n", (void*)&dest);
    printf("[MEMORY]  Layout (16 bytes):\n");
    printf("          sin_family = 0x%04x (AF_INET)\n", dest.sin_family);
    printf("          sin_port   = 0x%04x (port %d in network order)\n", 
           dest.sin_port, __builtin_bswap16(dest.sin_port));
    printf("          sin_addr   = 0x%08x (127.0.0.1)\n", dest.sin_addr.s_addr);
    printf("          sin_zero   = [8 bytes of zeros]\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 3: SEND UDP DATAGRAM (direct syscall)                     │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * Normal code:
     *   sendto(sock, message, len, 0, (struct sockaddr*)&dest, sizeof(dest));
     * 
     * Raw syscall:
     *   syscall(SYS_sendto, sock, message, len, 0, &dest, sizeof(dest));
     * 
     * What happens in kernel (net/ipv4/udp.c:udp_sendmsg):
     *   1. Validate destination address
     *   2. Route lookup (which interface to use?)
     *   3. Allocate sk_buff (kernel packet buffer)
     *   4. Copy user data to sk_buff
     *   5. Build UDP header:
     *        - Source port (from socket or ephemeral)
     *        - Dest port (from sockaddr_in)
     *        - Length (data + 8-byte header)
     *        - Checksum (optional for UDP)
     *   6. Build IP header:
     *        - Source IP (from routing)
     *        - Dest IP (from sockaddr_in)
     *        - Protocol (17 = UDP)
     *        - TTL, flags, etc.
     *   7. Pass to link layer
     *   8. NIC queues packet for transmission
     *   9. Return bytes sent
     * 
     * KEY: This happens IMMEDIATELY for UDP (unlike TCP which buffers)
     */
    
    const char *message = "Hello from raw UDP syscall!";
    size_t msg_len = strlen(message);
    
    printf("[APPLICATION] Sending message: \"%s\" (%zu bytes)\n", message, msg_len);
    printf("[SYSCALL]     Invoking SYS_sendto...\n");
    
    long sent = syscall(SYS_sendto,
                        sock,                      /* socket fd */
                        message,                   /* buffer */
                        msg_len,                   /* length */
                        0,                         /* flags */
                        (struct sockaddr*)&dest,  /* destination */
                        sizeof(dest));             /* address length */
    
    if (sent < 0) {
        perror("SYS_sendto failed");
        syscall(SYS_close, sock);
        return 1;
    }
    
    printf("[KERNEL]      udp_sendmsg() executed:\n");
    printf("              - Built UDP header (src_port, dst_port=9999, len=%ld, checksum)\n", sent + 8);
    printf("              - Built IP header (src_ip, dst_ip=127.0.0.1, proto=17)\n");
    printf("              - Queued packet to loopback interface\n");
    printf("[SYSCALL]     SYS_sendto returned %ld (bytes sent)\n\n", sent);

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ THEORY: UDP vs TCP - Message Boundaries                        │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * UDP (SOCK_DGRAM):
     *   - Each sendto() = ONE complete packet
     *   - Each recvfrom() = ONE complete packet
     *   - If you send 10 bytes, receiver gets EXACTLY 10 bytes (or nothing)
     *   - Receiver cannot do partial read
     * 
     * TCP (SOCK_STREAM):
     *   - send() adds data to stream
     *   - recv() reads from stream
     *   - Send 10 bytes + send 20 bytes = recv might get 30, or 5, or 15...
     *   - NO message boundaries!
     * 
     * Example:
     *   UDP: sendto(10 bytes); sendto(20 bytes);
     *        → recvfrom() returns 10
     *        → recvfrom() returns 20
     * 
     *   TCP: send(10 bytes); send(20 bytes);
     *        → recv() might return 30 (merged)
     *        → or recv() might return 5 (partial)
     *        → you cannot predict!
     */
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  KEY INSIGHT: UDP Message Boundaries\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    printf("We sent %ld bytes in ONE sendto() call.\n", sent);
    printf("If there was a receiver, it would get EXACTLY %ld bytes in ONE recvfrom().\n", sent);
    printf("\nNo partial reads. No merged packets. Each sendto() = one packet.\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 4: CLEANUP (direct syscall)                               │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * Normal code:
     *   close(sock);
     * 
     * Raw syscall:
     *   syscall(SYS_close, sock);
     * 
     * What happens:
     *   - Kernel frees struct sock
     *   - Kernel frees struct socket
     *   - fd removed from process fd table
     */
    
    long close_ret = syscall(SYS_close, sock);
    if (close_ret < 0) {
        perror("SYS_close failed");
        return 1;
    }
    
    printf("[SYSCALL]     SYS_close(%ld) completed\n", sock);
    printf("[KERNEL]      struct sock freed\n");
    printf("[KERNEL]      fd=%ld removed from process fd table\n\n", sock);

    /*
     * ═══════════════════════════════════════════════════════════════════
     * MEMORY MODEL: What just happened?
     * ═══════════════════════════════════════════════════════════════════
     * 
     * 1. socket() syscall:
     *    - Userspace: int sock = ...
     *    - Kernelspace: struct sock *sk = kmalloc(...)
     *    - Returns: fd (index) mapping to sk
     * 
     * 2. sendto() syscall:
     *    - Userspace: sendto(sock, buf, len, ...)
     *    - Kernelspace: 
     *        - Look up struct sock *sk using fd
     *        - Allocate struct sk_buff (packet buffer)
     *        - Copy buf to sk_buff->data
     *        - Build headers (UDP + IP)
     *        - Queue to network interface
     * 
     * 3. close() syscall:
     *    - Userspace: close(sock)
     *    - Kernelspace:
     *        - Look up struct sock *sk using fd
     *        - kfree(sk)
     *        - Remove fd entry
     * 
     * KEY: File descriptor is just an INDEX. All state lives in kernel.
     */

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  COMPLETE\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    printf("You now understand:\n");
    printf("  ✓ socket() creates kernel struct sock\n");
    printf("  ✓ sendto() builds packet and transmits\n");
    printf("  ✓ UDP preserves message boundaries\n");
    printf("  ✓ File descriptors are just indices\n");
    printf("  ✓ All networking state lives in kernel\n\n");
    printf("No abstractions. No magic. Just syscalls and kernel structs.\n\n");

    return 0;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * COMPILE AND RUN
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Compile:
 *   gcc -o raw_udp_syscall raw_udp_syscall.c -std=c11 -Wall
 * 
 * Run:
 *   ./raw_udp_syscall
 * 
 * Trace syscalls:
 *   strace -e socket,sendto,close ./raw_udp_syscall
 * 
 * Expected strace output:
 *   socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) = 3
 *   sendto(3, "Hello from raw UDP syscall!", 28, 0, {sa_family=AF_INET, ...}, 16) = 28
 *   close(3) = 0
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * EXERCISES
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * 1. Add a receiver using SYS_bind and SYS_recvfrom
 * 2. Send multiple packets, observe message boundaries
 * 3. Compare with TCP (SOCK_STREAM) - see stream behavior
 * 4. Use SYS_sendmmsg to send multiple packets in one syscall
 * 5. Measure syscall overhead with getrusage()
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */
