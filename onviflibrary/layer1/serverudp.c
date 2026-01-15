#include <stdint.h>
#define DATA_SIZE 1024

struct packet{
    uint32_t seq;
    uint16_t len;
    uint8_t parity;
    uint8_t data[DATA_SIZE];
};

typedef struct packet protopacket;
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void){
    protopacket pkt1;
    int recieversocketudp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recieversocketudp<0) {
    perror("socket");
    return 1;
}

    struct sockaddr_in recvside;
    memset(&recvside, 0, sizeof(recvside));
    recvside.sin_family = AF_INET;
    recvside.sin_port = htons(9000);
    recvside.sin_addr.s_addr = INADDR_ANY;
    if (bind(recieversocketudp,
             (struct sockaddr*)&recvside,
             sizeof(recvside)) < 0) {
        perror("bind");
        return 1;
    }


    FILE *fp = fopen("received.jpg", "wb");

    if (!fp) {
        perror("fopen");
        return 1;
    }

    while(1){
        ssize_t numofbytesrecv = recvfrom(recieversocketudp, &pkt1, sizeof(pkt1), 0 ,NULL, NULL);
        if(numofbytesrecv <= 0) continue;
        if(pkt1.len == 0) break;
        
    }
    fclose(fp);
    close(recieversocketudp);
    return 0;
}