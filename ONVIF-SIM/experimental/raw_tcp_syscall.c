/*
 * RAW TCP SYSCALL IMPLEMENTATION
 * 
 * This shows TCP's 3-way handshake and state machine using DIRECT SYSCALLS.
 * 
 * GOAL: Understand TCP connection lifecycle WITHOUT abstractions.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * KEY INSIGHT: TCP State Machine
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * TCP socket has STATE that changes over time:
 *   CLOSED → LISTEN → SYN_RCVD → ESTABLISHED → FIN_WAIT1 → ... → CLOSED
 * 
 * Each syscall (listen, accept, connect, send, close) transitions state.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/socket.h>       /* AF_INET, SOCK_STREAM */
#include <netinet/in.h>       /* struct sockaddr_in, IPPROTO_TCP */
#include <arpa/inet.h>        /* inet_addr */
#include <string.h>
#include <stdio.h>
#include <errno.h>

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * THEORY → CODE: TCP 3-Way Handshake
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Theory:
 *   Client                    Server
 *     |                         |
 *     |-------- SYN ----------->|  (SYN_SENT)
 *     |<------ SYN-ACK ---------|  (SYN_RCVD)
 *     |-------- ACK ----------->|  (ESTABLISHED)
 *     |                         |
 * 
 * Code (what actually happens):
 * 
 * Server side:
 *   1. socket(SOCK_STREAM)  → State: CLOSED
 *   2. bind()               → State: CLOSED (still!)
 *   3. listen()             → State: LISTEN
 *   4. accept()             → Waits for SYN
 *      - Receives SYN       → Creates entry in SYN queue
 *      - Sends SYN-ACK      → State: SYN_RCVD
 *      - Receives ACK       → Moves to accept queue
 *      - Returns new socket → State: ESTABLISHED
 * 
 * Client side:
 *   1. socket(SOCK_STREAM)  → State: CLOSED
 *   2. connect()            → Sends SYN, State: SYN_SENT
 *      - Receives SYN-ACK   → Sends ACK, State: ESTABLISHED
 * 
 * KEY: accept() returns a NEW socket. Original socket stays in LISTEN.
 */

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  RAW TCP SYSCALL EXAMPLE - Server Side\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 1: CREATE TCP SOCKET (listening socket)                   │
     * └────────────────────────────────────────────────────────────────┘
     */
    
    long listen_sock = syscall(SYS_socket, 
                               AF_INET, 
                               SOCK_STREAM,      /* Stream (TCP) */
                               IPPROTO_TCP);     /* TCP protocol */
    
    if (listen_sock < 0) {
        perror("SYS_socket failed");
        return 1;
    }
    
    printf("[SYSCALL] SYS_socket returned fd=%ld\n", listen_sock);
    printf("[KERNEL]  Allocated struct tcp_sock (extends struct sock)\n");
    printf("[STATE]   TCP state: CLOSED\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 2: BIND TO LOCAL ADDRESS                                  │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * bind() associates socket with local IP:port.
     * 
     * What happens in kernel (net/ipv4/af_inet.c:inet_bind):
     *   1. Validate port not in use
     *   2. If port < 1024, check CAP_NET_BIND_SERVICE capability
     *   3. Set sock->sk_rcv_saddr (local IP)
     *   4. Set sock->sk_num (local port)
     *   5. Add to hash table for incoming packet lookup
     *   6. State: still CLOSED (bind doesn't change state!)
     */
    
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = __builtin_bswap16(9999);  /* Port 9999 */
    local.sin_addr.s_addr = 0;  /* INADDR_ANY = 0.0.0.0 (all interfaces) */
    
    long bind_ret = syscall(SYS_bind,
                           listen_sock,
                           (struct sockaddr*)&local,
                           sizeof(local));
    
    if (bind_ret < 0) {
        perror("SYS_bind failed");
        syscall(SYS_close, listen_sock);
        return 1;
    }
    
    printf("[SYSCALL] SYS_bind completed\n");
    printf("[KERNEL]  sock->sk_rcv_saddr = 0.0.0.0 (INADDR_ANY)\n");
    printf("[KERNEL]  sock->sk_num = 9999\n");
    printf("[KERNEL]  Added to port hash table\n");
    printf("[STATE]   TCP state: CLOSED (bind doesn't change state!)\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 3: LISTEN FOR CONNECTIONS                                 │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * listen() transitions socket to LISTEN state.
     * 
     * What happens in kernel (net/ipv4/tcp.c:inet_listen):
     *   1. Allocate accept queue (for completed connections)
     *   2. Allocate SYN queue (for pending handshakes)
     *   3. Change state: CLOSED → LISTEN
     *   4. Enable SYN cookie protection (if configured)
     * 
     * Backlog parameter:
     *   - Limits accept queue size
     *   - Default: 128 (from /proc/sys/net/core/somaxconn)
     *   - If queue full, SYN packets dropped (or use SYN cookies)
     */
    
    int backlog = 128;  /* Accept queue size */
    
    long listen_ret = syscall(SYS_listen, listen_sock, backlog);
    
    if (listen_ret < 0) {
        perror("SYS_listen failed");
        syscall(SYS_close, listen_sock);
        return 1;
    }
    
    printf("[SYSCALL] SYS_listen completed (backlog=%d)\n", backlog);
    printf("[KERNEL]  Allocated accept queue (max %d connections)\n", backlog);
    printf("[KERNEL]  Allocated SYN queue (for partial handshakes)\n");
    printf("[STATE]   TCP state: CLOSED → LISTEN\n");
    printf("[READY]   Socket can now accept connections!\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ THEORY: What happens during accept()?                          │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * accept() is a BLOCKING call that waits for a client to connect.
     * 
     * Timeline:
     *   1. accept() called → kernel blocks (sleeps) waiting for connection
     *   2. Client sends SYN → Kernel wakes up
     *   3. Kernel sends SYN-ACK → Connection in SYN queue
     *   4. Client sends ACK → Connection complete, moved to accept queue
     *   5. accept() returns NEW socket → Original socket still in LISTEN
     * 
     * Important: accept() returns a NEW socket for the established connection.
     *            The listening socket (fd=listen_sock) stays in LISTEN state.
     * 
     * In kernel (net/ipv4/tcp_ipv4.c):
     *   - tcp_v4_do_rcv() handles incoming SYN
     *   - tcp_v4_conn_request() creates new struct sock for connection
     *   - tcp_v4_syn_recv_sock() completes handshake
     *   - inet_csk_accept() returns new socket to userspace
     */
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  WAITING FOR CONNECTION (this would block in real code)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    printf("In real implementation, accept() would:\n");
    printf("  1. Block until client connects\n");
    printf("  2. Receive SYN from client\n");
    printf("  3. Send SYN-ACK to client\n");
    printf("  4. Receive ACK from client (3-way handshake complete)\n");
    printf("  5. Return NEW socket in ESTABLISHED state\n\n");
    printf("Listening socket (fd=%ld) remains in LISTEN state forever.\n\n", listen_sock);

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ THEORY: TCP vs UDP - State Management                          │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * TCP (SOCK_STREAM):
     *   - Kernel maintains state machine (11 states)
     *   - listen() creates listening socket
     *   - accept() creates NEW socket per connection
     *   - Each connection has separate state
     *   - send() adds to stream (may not transmit immediately)
     *   - recv() reads from stream (no message boundaries)
     * 
     * UDP (SOCK_DGRAM):
     *   - Kernel has almost no state
     *   - No listen(), no accept() (connectionless!)
     *   - One socket handles all clients
     *   - sendto() specifies destination per packet
     *   - recvfrom() gets sender address per packet
     * 
     * Mental model:
     *   TCP = telephone call (connection, state)
     *   UDP = walkie-talkie (broadcast, no connection)
     */
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  TCP STATE MACHINE (simplified)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    printf("CLOSED      → socket() creates socket\n");
    printf("CLOSED      → bind() assigns local address\n");
    printf("LISTEN      → listen() enables accepting connections\n");
    printf("SYN_RCVD    → (internal) partial handshake\n");
    printf("ESTABLISHED → accept() returns connected socket\n");
    printf("FIN_WAIT1   → close() initiates shutdown\n");
    printf("FIN_WAIT2   → (internal) waiting for peer FIN\n");
    printf("TIME_WAIT   → (internal) 2*MSL wait\n");
    printf("CLOSED      → socket fully closed\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 4: CLEANUP                                                │
     * └────────────────────────────────────────────────────────────────┘
     */
    
    long close_ret = syscall(SYS_close, listen_sock);
    if (close_ret < 0) {
        perror("SYS_close failed");
        return 1;
    }
    
    printf("[SYSCALL] SYS_close(%ld) completed\n", listen_sock);
    printf("[KERNEL]  struct tcp_sock freed\n");
    printf("[KERNEL]  Accept queue drained\n");
    printf("[STATE]   TCP state: LISTEN → CLOSED\n\n");

    /*
     * ═══════════════════════════════════════════════════════════════════
     * KERNEL STRUCTS (for reference)
     * ═══════════════════════════════════════════════════════════════════
     * 
     * struct tcp_sock (extends struct sock):
     *   int state;                    // TCP_LISTEN, TCP_ESTABLISHED, etc.
     *   struct sk_buff_head write_queue;  // Unsent data
     *   struct sk_buff_head out_of_order_queue;  // Reordered packets
     *   u32 snd_una;                  // First unacknowledged byte
     *   u32 snd_nxt;                  // Next byte to send
     *   u32 rcv_nxt;                  // Next byte expected
     *   u32 snd_cwnd;                 // Congestion window
     *   // ... 100+ more fields for TCP state!
     * 
     * struct udp_sock (extends struct sock):
     *   // Almost empty! UDP has minimal state.
     *   struct sk_buff_head reader_queue;  // Just received packets
     *   // That's basically it!
     * 
     * KEY DIFFERENCE: TCP needs ~1KB struct, UDP needs ~100 bytes!
     */

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  COMPLETE\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    printf("You now understand:\n");
    printf("  ✓ TCP has explicit state machine (11 states)\n");
    printf("  ✓ listen() transitions CLOSED → LISTEN\n");
    printf("  ✓ accept() returns NEW socket (original stays LISTEN)\n");
    printf("  ✓ Each connection has separate kernel struct\n");
    printf("  ✓ TCP maintains queues (send, receive, out-of-order)\n\n");
    printf("Compare with UDP:\n");
    printf("  ✗ No listen(), no accept()\n");
    printf("  ✗ No connection state\n");
    printf("  ✗ Single socket handles all clients\n");
    printf("  ✗ Much simpler kernel implementation\n\n");

    return 0;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * COMPILE AND RUN
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Compile:
 *   gcc -o raw_tcp_syscall raw_tcp_syscall.c -std=c11 -Wall
 * 
 * Run:
 *   ./raw_tcp_syscall
 * 
 * Trace syscalls:
 *   strace -e socket,bind,listen,close ./raw_tcp_syscall
 * 
 * Expected strace output:
 *   socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
 *   bind(3, {sa_family=AF_INET, sin_port=htons(9999), ...}, 16) = 0
 *   listen(3, 128) = 0
 *   close(3) = 0
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * EXERCISES
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * 1. Add accept() and observe 3-way handshake with Wireshark
 * 2. Use SYS_getsockopt with SO_ACCEPTCONN to verify LISTEN state
 * 3. Check /proc/net/tcp to see socket in LISTEN state
 * 4. Compare struct sizes: TCP vs UDP (use pahole tool)
 * 5. Implement graceful shutdown (FIN handshake)
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */
