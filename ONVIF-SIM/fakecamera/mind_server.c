/* Enable BSD and POSIX extensions for ip_mreq */
#define _DEFAULT_SOURCE
#define _BSD_SOURCE

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DISCOVERY_PORT 3702
#define MULTICAST_ADDR "239.255.255.250"
#define BUF_SIZE 8192

const char *RESPONSE =
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
"<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
"xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
"xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">"
"<s:Header>"
"<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>"
"<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
"</s:Header>"
"<s:Body>"
"<d:ProbeMatches>"
"<d:ProbeMatch>"
"<a:EndpointReference>"
"<a:Address>urn:uuid:fake-camera-1</a:Address>"
"</a:EndpointReference>"
"<d:Types>dn:NetworkVideoTransmitter</d:Types>"
"<d:XAddrs>http://127.0.0.1:8080/onvif/device_service</d:XAddrs>"
"</d:ProbeMatch>"
"</d:ProbeMatches>"
"</s:Body>"
"</s:Envelope>";

int main(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DISCOVERY_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = INADDR_ANY;

    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    printf("Listening for WS-Discovery probes...\n");

    char buf[BUF_SIZE];
    struct sockaddr_in client;
    socklen_t len = sizeof(client);

    while (1) {
        int n = recvfrom(sock, buf, sizeof(buf)-1, 0,
                         (struct sockaddr*)&client, &len);
        if (n <= 0) continue;

        buf[n] = 0;

        if (strstr(buf, "Probe")) {
            sendto(sock, RESPONSE, strlen(RESPONSE), 0,
                   (struct sockaddr*)&client, len);
            printf("Responded to probe\n");
        }
    }
}
