#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*int main (void){
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    
    int opt = 1;
    setsockopt(sockfd,SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in clientsock; memset(&clientsock, 0, sizeof(clientsock));

    clientsock.sin_family = AF_INET;
    clientsock.sin_port = htons(9000);

    inet_pton(AF_INET, "127.0.0.1", &clientsock.sin_addr);


    if(bind(sockfd,(struct sockaddr *)&clientsock, sizeof(clientsock))){
        perror("bind");
        close(sockfd);
    }

    listen(sockfd, 5);

    socklen_t clientsocklen = sizeof(clientsock);

    accept(sockfd, (struct sockaddr *)&clientsock, &clientsocklen);
    if(connect(sockfd, (struct sockaddr *)&clientsock, sizeof(clientsock))){
        perror("connect");
        close(sockfd);
    }


    close(sockfd);
    return 0;
}*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 9000
#define BUF 4096

int main(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("connect"); return 1;
    }

    FILE *fp = fopen("img.jpg", "rb");
    if (!fp) { perror("fopen"); return 1; }

    char buf[BUF];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        send(sockfd, buf, n, 0);
    }

    fclose(fp);
    close(sockfd);
    return 0;
}
