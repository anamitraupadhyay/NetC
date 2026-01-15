//extern socket1();
//typedef enum tcp_states tcpstates; //ISO C++ forbids forward references to 'enum' types

#include <stdint.h>
typedef enum {
    //tcp states
    TCP_ClOSED = 0,
    TCP_LISTEN,
    TCP_SENT, TCP_ESTABLISHED, TCP_REC
}tcp_states;//i_guess_all_possible_tcp_states_though_took_refernce_from_linux

typedef enum {
	SOCK_STREAM	= 1,// here it will be default fixated 
	                // though this enum in this scope
					// is absolutely useless
	SOCK_DGRAM	= 2,
	/*SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,*/
}sock_type;

//need a struct to simu.ate tcp header of packets structure
// need to take inspiration from strcut mmsghdr
// but its mentioned that its specifically for recvmmsg and sendmmsg
// confirmed, it is not. so i need copy to copy reference from 
// protocol guidelines
typedef struct {
    uint16_t source;
    uint16_t destn;
    uint32_t sequenceofwhat;
    uint32_t ack_seq;
    uint8_t syn:1,ack:1;// bitfields for flags
}tcpheader;

typedef struct whatever whateverforcoketreturntype;
struct whatever{int i;};

//main orchestrator i suppose
struct sock{
    //int sk_state;
    //sock_type var;
    tcp_states sk_state; //for tcp specific
    uint32_t sk_source_addr; //source ip
    uint32_t sk_source_port; // source port
    uint32_t sk_dest_addr; // destination address
    uint32_t sk_dest_port; // destination port
    uint32_t sk_write_seq; // sequence number
    uint8_t sk_ack_seq; //ack counter what i expect next
};