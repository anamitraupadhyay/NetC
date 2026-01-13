#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9000);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    char msg[] = "hello";
    sendto(fd, msg, strlen(msg) + 1, 0,
           (struct sockaddr *)&dst, sizeof(dst));
    close(fd);
    return 0;
}
