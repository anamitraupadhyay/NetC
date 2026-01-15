#include <stdint.h>
typedef enum {
    //tcp states
    TCP_ClOSED = 0,
    TCP_LISTEN,
    TCP_SENT, TCP_ESTABLISHED, TCP_REC
}tcp_states;

typedef enum {
	SOCK_STREAM	= 1,
	SOCK_DGRAM	= 2,
}sock_type;

typedef struct {
    uint16_t source;
    uint16_t destn;
    uint32_t sequenceofwhat;
    uint32_t ack_seq;
    uint8_t syn:1,ack:1;// bitfields for flags
}tcpheader;

struct sock{
    tcp_states sk_state; //for tcp specific
    uint32_t sk_source_addr; //source ip
    uint32_t sk_source_port; // source port
    uint32_t sk_dest_addr; // destination address
    uint32_t sk_dest_port; // destination port
    uint32_t sk_write_seq; // sequence number
    uint8_t sk_ack_seq; //ack counter what i expect next
};
#include <stdio.h>
#include <stdlib.h>

void
tcp_transmit_skb(struct sock *sk)
{
    tcpheader th;
    th.source = sk->sk_source_port;
    th.destn = sk->sk_dest_port;
    th.ack = 0;
    th.syn = 1;
    sk->sk_write_seq++;
}

void tcp_rcv_synack(struct sock *sk, tcpheader *th){
    //for acknowledgements
    if(th->ack_seq == sk->sk_write_seq){//valid ack
        sk->sk_state = TCP_ESTABLISHED;
        //and expect more bytes
        sk->sk_ack_seq = th->sequenceofwhat +1; //ok so seqofwhat is expecting one
    }
    else{
        perror("ack invalid");
    }
}

int main(void){
    struct sock *my_sk = (struct sock*)malloc(sizeof(struct sock));
    
    // Initialize (inet_create) kindof memset
    my_sk->sk_state = TCP_ClOSED;
    my_sk->sk_write_seq = 1000; // Random Initial Sequence Number
    my_sk->sk_dest_addr = 0x7F000001; // 127.0.0.1 (conceptually i looked it up)
    
    // 1. Change State
    my_sk->sk_state = TCP_SENT;
    
    // 2. Send SYN
    tcp_transmit_skb(my_sk);
    
    tcpheader server_packet;
    server_packet.syn = 1;
    server_packet.ack = 1;
    server_packet.sequenceofwhat = 5000;      // Server's random sequence
    server_packet.ack_seq = 1001;  // Server acknowledging our SYN (1000 + 1)
    
    // 3. Kernel processes the reply
    tcp_rcv_synack(my_sk, &server_packet);
    
    // F. Final State
    if (my_sk->sk_state == TCP_ESTABLISHED) {
        printf("\n[SUCCESS] Connection Established. User Space Socket is ready to Write.\n");
    }

    free(my_sk);
    return 0;
    
    return 0;
    
}