#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    char buf[64];
    recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    printf("Received: %s\n", buf);
    close(fd);
    return 0;
}
