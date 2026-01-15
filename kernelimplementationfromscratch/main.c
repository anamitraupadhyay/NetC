#include "strcuts.h"
#include <stdio.h>
#include <stdlib.h>

/*static int*/ // as int socket is not applied here so void
void
tcp_transmit_skb(struct sock *sk/*, struct sk_buff *skb, 
    int clone_it, gfp_t gfp_mask, u32 rcv_nxt*/)
{
    // ok so i need the header to get init
    tcpheader th;
    // filling the packet though will use malloc instead sockmemalloc
    // th = (struct tcpheader)malloc(sizeof(tcpheader));
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
    //guess we will jump all the steps regarding selecting stream
    // or any other abstractions
    // will strictly mock net/ipv4/tcp_output.c
    // in my own constraints and might violate some rules
    // first we create scoket which is jumped
    // directly orchestrator sock is invoked
    struct sock *my_sk = (struct sock*)malloc(sizeof(struct sock));
    
    // Initialize (inet_create) kindof memset
    my_sk->sk_state = TCP_ClOSED;
    my_sk->sk_write_seq = 1000; // Random Initial Sequence Number
    my_sk->sk_dest_addr = 0x7F000001; // 127.0.0.1 (conceptually)
    
    // 1. Change State
    my_sk->sk_state = TCP_SENT;
    
    // 2. Send SYN
    tcp_transmit_skb(my_sk);// bad named should have been syn
    
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