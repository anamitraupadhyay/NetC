#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 9000
#define BUF 4096

int main(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }

    if (listen(sockfd, 1) < 0) {
        perror("listen"); return 1;
    }

    socklen_t len = sizeof(addr);
    int connfd = accept(sockfd, (struct sockaddr*)&addr, &len);
    if (connfd < 0) { perror("accept"); return 1; }

    FILE *fp = fopen("received.jpg", "wb");
    if (!fp) { perror("fopen"); return 1; }

    char buf[BUF];
    ssize_t n;

    while ((n = recv(connfd, buf, sizeof(buf), 0)) > 0) {
        fwrite(buf, 1, n, fp);
    }

    fclose(fp);
    close(connfd);
    close(sockfd);
    return 0;
}
