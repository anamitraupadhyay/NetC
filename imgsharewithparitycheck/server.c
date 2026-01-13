#include "protocol.h"
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void){
    protopacket pkt1;
    int recieversocketudp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recieversocketudp<0/*!recieversocketudp is wrong*/) {
    perror("socket");
    return 1;
}

    struct sockaddr_in recvside;
    // oops forgot about memset 0
    memset(&recvside, 0, sizeof(recvside));
    recvside.sin_family = AF_INET;
    recvside.sin_port = htons(9000);
    // why this step here though it is for kernel to make it 
    // whatever there is
    recvside.sin_addr.s_addr = INADDR_ANY;
    //bind(recieversocketudp,(struct sockaddr*)&recvside, sizeof(recvside));
/*if (!&bind) {
    perror("bind");
    return 1;
}*/
if (bind(recieversocketudp,
         (struct sockaddr*)&recvside,
         sizeof(recvside)) < 0) {
    perror("bind");
    return 1;
}


    // how to open recieved file? this seems vague
    FILE *fp = fopen("received.jpg", "wb");

    if (!fp) {
    perror("fopen");
    return 1;
}

    while(1){
        ssize_t numofbytesrecv = recvfrom(recieversocketudp, &pkt1, sizeof(pkt1), 0 ,NULL, NULL);
        if(numofbytesrecv <= 0) continue;
        if(pkt1.len == 0) break;

        // compute parity
        unsigned char p = 0;
        for(int i = 0; i<pkt1.len; i++){
            p = p^pkt1.data[i];
        }
        // check parity
        if(p == pkt1.parity){
            fwrite(pkt1.data,1, pkt1.len, fp);
        }
    }
    fclose(fp);
    close(recieversocketudp);
    return 0;
}