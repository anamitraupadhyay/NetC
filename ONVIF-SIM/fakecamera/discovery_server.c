#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>


#define DISCOVERY_PORT      3702
#define MULTICAST_ADDR      "239.255.255.250"
#define CAMERA_NAME         "MyFakeCamera"
#define CAMERA_HTTP_PORT    8080
#define BUFFER_SIZE         65536


// copied probe match template
const char *PROBE_MATCH_TEMPLATE = 
    "<? xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope "
        "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "  // NO SPACE! 
        "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"        // NO SPACE!
    "<s:Header>"
        "<a:Action s:mustUnderstand=\"1\">"
            "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches"
        "</a:Action>"
        "<a:MessageID>urn:uuid:%08x-%04x-%04x-%04x-%08x%04x</a:MessageID>"  // NO SPACE!
        "<a:RelatesTo>%s</a:RelatesTo>"
        "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a: To>"
    "</s:Header>"
    "<s:Body>"
        "<d:ProbeMatches>"     // NO SPACE!
            "<d:ProbeMatch>"
                "<a:EndpointReference>"    // NO SPACE!
                    "<a:Address>urn:uuid: fakecam-0001</a:Address>"  // NO SPACE!
                "</a:EndpointReference>"
                "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
                "<d:Scopes>"
                    "onvif://www.onvif.org/name/%s "
                    "onvif://www.onvif.org/hardware/FakeCam "
                    "onvif://www.onvif.org/type/video_encoder"
                "</d:Scopes>"
                "<d:XAddrs>http://%s:%d/onvif/device_service</d:XAddrs>"
                "<d:MetadataVersion>1</d:MetadataVersion>"
            "</d:ProbeMatch>"
        "</d:ProbeMatches>"
    "</s:Body>"
    "</s:Envelope>";

// from close observation there are 5 fields to be extracted
// 1. is it probe or discovery or not
// 2. uuid MEssageID from relatesTo
// 3. localip

// checking its probe or discovery 
bool isprobe(const char *msg);
bool isprobe(const char *msg) {
    //does it contain Probe and discovery
    if (strstr(msg, "Probe") && strstr(msg, "discovery")) {
        return true;
    }
    return false;
}

// copy pasted :(
void getmessageid(const char *msg, char *out, size_t outsize);
void getmessageid(const char *msg, char *out, size_t out_size) {
    // Look for <wsa:MessageID> first (most common)
    const char *start = strstr(msg, "<wsa:MessageID");
    if (!start) {
        // Try without namespace prefix
        start = strstr(msg, "<MessageID");
    }
    if (!start) {
        out[0] = '\0';
        return;
    }
    
    // Find the > after opening tag
    start = strchr(start, '>');
    if (!start) {
        out[0] = '\0';
        return;
    }
    start++;  // Skip >
    
    // Find closing tag
    const char *end = strstr(start, "</");
    if (!end) {
        out[0] = '\0';
        return;
    }
    
    size_t len = (size_t)(end - start);
    if (len >= out_size) len = out_size - 1;
    
    memcpy(out, start, len);
    out[len] = '\0';
    
    // Trim whitespace
    while (len > 0 && (out[len-1] == ' ' || out[len-1] == '\n' || out[len-1] == '\r')) {
        out[--len] = '\0';
    }
}

void getlocalip(char *buf, size_t size){
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd<0){
        perror("socket");
        return; 
    }

    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_port = htons(9000);
    sockaddr.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &sockaddr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
        close(sockfd);
        strncpy(buf, "127.0.0.1", size);
        return;
    }
    
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sockfd, (struct sockaddr*)&name, &namelen);
    
    inet_ntop(AF_INET, &name.sin_addr, buf, size);
    close(sockfd);
}


int build_response(const char *message_id, const char *local_ip,
                    char *buf, size_t size);
/* Build response copypasted*/
int build_response(const char *message_id, const char *local_ip,
                   char *buf, size_t size) {
    return snprintf(buf, size, PROBE_MATCH_TEMPLATE,
        (uint32_t)rand(), (uint32_t)rand() & 0xFFFF,
        (uint32_t)rand() & 0xFFFF, (uint32_t)rand() & 0xFFFF,
        (uint32_t)rand(), (uint32_t)rand() & 0xFFFF,
        message_id,
        CAMERA_NAME,
        local_ip, CAMERA_HTTP_PORT);
}

// Disclaimer printf stmts are added by llm
int main(void){

    printf("=== WS-Discovery Server ===\n");
    
    srand((unsigned)time(NULL));
    
    // Geting local IP
    char local_ip[64];
    getlocalip(local_ip, sizeof(local_ip));
    printf("Local IP: %s\n", local_ip);
    
    // always on udp server
    // setupped with port
    int recieversocketudp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recieversocketudp<0) {
        perror("socket");
        return -1;
    }
    printf("socket created\n");
    // explicitly mentioned
    // about address reuse in header
    int opt =1;
    if(setsockopt(recieversocketudp,SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
        perror("setsockopt failed");
        // not fatal no need for return
    }

    //bind to address server side
    struct sockaddr_in recvside;

    memset(&recvside, 0, sizeof(recvside));
    recvside.sin_family = AF_INET;
    recvside.sin_port = htons(DISCOVERY_PORT);
    recvside.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(recieversocketudp,
             (struct sockaddr*)&recvside,
             sizeof(recvside)) < 0) {
        perror("bind");
        return -2;
    }
    
    printf("Bound to port %d\n", DISCOVERY_PORT);
    
    /* Join multicast group - THIS IS THE KEY PART */
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(recieversocketudp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("multicast join");
        close(recieversocketudp);
        return -3;
    }
    printf("Joined multicast %s\n", MULTICAST_ADDR);
    
    printf("\nListening...  (Ctrl+C to stop)\n\n");

    // setting up buffers
    char recv_buf[BUFFER_SIZE];
    char send_buf[BUFFER_SIZE];
    //to represent client side and gonna iterate over
    struct sockaddr_in client_addr;
    socklen_t client_len;
    int probe_count = 0;

    while(1){
        client_len = sizeof(client_addr);
        memset(recv_buf, 0, sizeof(recv_buf));
        
        ssize_t n = recvfrom(recieversocketudp, recv_buf, sizeof(recv_buf) - 1, 0,
                             (struct sockaddr*)&client_addr, &client_len);
        
        if (n <= 0) continue;
        recv_buf[n] = '\0';
        
        // Check if it's a probe with error handling
        // will enhance the error handling later
        if (! isprobe(recv_buf)) {
            continue;
        }
        
        probe_count++;
        
        /* Get client IP for printing */
        char client_ip[64];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[Probe #%d] from %s\n", probe_count, client_ip);
        
        // GET message id
        char message_id[256];
        getmessageid(recv_buf, message_id, sizeof(message_id));
        
        // build response and send back
        int send_len = build_response(message_id, local_ip, send_buf, sizeof(send_buf));
        
        // Send back 
        ssize_t sent = sendto(recieversocketudp, send_buf, (size_t)send_len, 0,
                              (struct sockaddr*)&client_addr, client_len);
        
        if (sent > 0) {
            printf("         Sent ProbeMatch (%zd bytes)\n", sent);
        }
    }
    return 0;
}