#include "protocol.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void){
    FILE *fp = fopen("img.jpg","rb");
    int createUdpSocketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in sending;
    memset(&sending, 0, sizeof(sending));
    //sending.sin_addr = ;
    /*
    sin_addr expects a binary IPv4 address
    cannot assign "127.0.0.1" to it directly
    cannot guess its value
    */
    sending.sin_port = htons(9000);
    sending.sin_family = AF_INET;
    inet_pton(AF_INET ,"127.0.0.1", &sending.sin_addr);
    printf("%d\n", sending.sin_addr.s_addr);
    // 32 bit number
    /*
    Take the text IP address 127.0.0.1
    convert it into binary network format
    and store it inside sending.sin_addr
    */
    // now algorithmic approach starts here
    unsigned char buffer[DATA_SIZE];
    protopacket pkt;
    uint32_t seq = 0;
    while(1){
        int n = fread(buffer, 1, DATA_SIZE, fp);
        if(/*EOF*/ n==0){break;}
        /*else{
            // not necessary block
        }*/
        pkt.len = n;
        // compute parity
        unsigned char parity = 0;
        for (int i = 0; i<n; i++){
            parity = parity^buffer[i];
        }
        pkt.parity = parity;
        pkt.seq = seq; seq++;
        memcpy(pkt.data, buffer, n);
        sendto(createUdpSocketfd,
            &pkt,
            // sizeof(uint16_t) + sizeof(uint8_t) + n,
            sizeof(pkt.seq) +
            sizeof(pkt.len) +
            sizeof(pkt.parity) +
            n,// whole packet size
            0,
            (struct sockaddr*)&sending,
            sizeof(sending)
            /*
            not sizeof(struct packet)
            that would send garbage bytes
            */
        );
    }
    // EOF Signal that is image transfer done
    pkt.len = 0;
    sendto(createUdpSocketfd,
       &pkt,
       sizeof(pkt.seq) + sizeof(pkt.len),// no more parity
       0,
       (struct sockaddr*)&sending,
       sizeof(sending));
    fclose(fp);// not close(fp);
    close(createUdpSocketfd);
    return 0;
}