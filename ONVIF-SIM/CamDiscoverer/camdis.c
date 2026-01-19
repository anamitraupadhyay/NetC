//
// Created by anamitra on 19/01/26.
//

#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DISCOVERY_PORT 3702
#define MULTICAST_ADDR "239.255.255.250"
#define BUFFER_SIZE 65536
#define DISCOVERY_TIMEOUT_SEC 5



const char *PROBE_MESSAGE =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope "
    "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "
    "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<s:Header>"
    "<a:Action s:mustUnderstand=\"1\">"
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
    "</a:Action>"
    "<a:MessageID>uuid:%s</a:MessageID>"
    "<a:To s:mustUnderstand=\"1\">"
    "urn:schemas-xmlsoap-org:ws:2005:04:discovery"
    "</a:To>"
    "</s:Header>"
    "<s:Body>"
    "<d:Probe>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "</d:Probe>"
    "</s:Body>"
    "</s:Envelope>";

void generate_uuid(char *uuid_buf, size_t size) {
    snprintf(uuid_buf, size,
             "%08x-%04x-4%03x-%04x-%012x",
             (unsigned)rand(), (unsigned)rand() & 0xFFFF,
             (unsigned)rand() & 0xFFF, (unsigned)rand() & 0xFFFF,
             (unsigned)rand());
}

int extract_xaddrs(const char *xml, char *xaddrs, size_t size) {
    const char *start = strstr(xml, "<d:XAddrs>");
    if (!start) start = strstr(xml, "<XAddrs>");
    if (!start) return -1;
    
    start = strchr(start, '>');
    if (!start) return -1;
    start++;
    
    const char *end = strstr(start, "</");
    if (!end) return -1;
    
    /* Validate bounds to prevent integer overflow */
    if (end <= start) return -1;
    
    size_t len = (size_t)(end - start);
    if (len >= size) len = size - 1;
    
    memcpy(xaddrs, start, len);
    xaddrs[len] = '\0';
    
    return 0;
}

/*
 * Extract device name from Scopes
 */
int extract_device_name(const char *xml, char *name, size_t size) {
    const char *scopes = strstr(xml, "<d:Scopes>");
    if (!scopes) scopes = strstr(xml, "<Scopes>");
    if (!scopes) return -1;
    
    const char *name_marker = strstr(scopes, "onvif://www.onvif.org/name/");
    if (!name_marker) return -1;
    
    name_marker += strlen("onvif://www.onvif.org/name/");
    
    size_t i;
    /* Add null terminator check to prevent buffer overrun */
    for (i = 0; i < size - 1 && name_marker[i] != '\0' && 
         name_marker[i] != ' ' && name_marker[i] != '<'; i++) {
        name[i] = name_marker[i];
    }
    name[i] = '\0';
    
    return 0;
}

int main() { 
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }
    
    struct timeval tv = { 
        .tv_sec = DISCOVERY_TIMEOUT_SEC, 
        .tv_usec = 0 
    };
    /*struct timeval.tv_sec = DISCOVERY_TIMEOUT_SEC;
    struct timeval.tv_usec = 0;*/
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO) failed");
    }
    int timetolive = 1;int loop = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop))<0){
        perror("setsocopt(IP_MULTICAST_LOOP)");
    }
    if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &timetolive, sizeof(timetolive))<0){
        perror("setsockopt(IPMULTICAST_TTL) failed");
    }
    //client side?!!
    /*
     *WHY JOIN AS CLIENT?
     *   - ProbeMatch responses are sent to multicast group (some devices do this)
     *   - Or they're sent unicast (most common)
     *   - Joining ensures we receive either way
     * 
    */
    struct sockaddr_in local_addr;// = {0};
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0;  // Let kernel pick teh po
    
    if (bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind() failed");
    }
    struct ip_mreq mreq = {0};
    mreq.imr_interface.s_addr = INADDR_ANY;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);

    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt(IP_ADD_MEMBERSHIP) failed");
    }
    char uuid[64];
    generate_uuid(uuid, sizeof(uuid));
    
    char probe_msg[4096];
    snprintf(probe_msg, sizeof(probe_msg), PROBE_MESSAGE, uuid);
    
    struct sockaddr_in multicast_addr = {0};
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_port = htons(DISCOVERY_PORT);
    multicast_addr.sin_addr.s_addr = inet_addr(MULTICAST_ADDR);
    
    ssize_t sent = sendto(sockfd, probe_msg, strlen(probe_msg), 0,
                          (struct sockaddr*)&multicast_addr,
                          sizeof(multicast_addr));
    
    if (sent < 0) {
        perror("sendto() failed");
        close(sockfd);
        return 1;
    }
    
    char recv_buf[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t sender_len;
    int response_count = 0;
    
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("  Discovered ONVIF Devices:\n");
    printf("═══════════════════════════════════════════════════════════════════\n\n");
    
    while (1) {
        sender_len = sizeof(sender_addr);
        memset(recv_buf, 0, sizeof(recv_buf));
        
        printf("[LAYER 2: LIBC] recvfrom() called → blocking on socket\n");
        printf("[LAYER 4: KERNEL] Waiting on socket receive queue...\n");

        ssize_t received =
            recvfrom(sockfd, recv_buf, sizeof(recv_buf) - 1, /*MSG_PEEK*/0,
                     (struct sockaddr *)&sender_addr, &sender_len);

        if (received < 0) {
            /*if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("[LAYER 4: KERNEL] Receive timeout reached\n");
                printf("[LAYER 1: APPLICATION] No more responses\n\n");
                break;
            }*/
            perror("recvfrom() failed");
            break;
        }
        
        recv_buf[received] = '\0';
        
        printf("[LAYER 4: KERNEL] Packet received:\n");
        printf("  - Source: %s:%d\n", 


               inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port));
        
               printf("  - Size: %zd bytes\n", received);
        printf("[LAYER 2: LIBC] Data copied to userspace buffer\n");
        printf("[LAYER 1: APPLICATION] Processing response...\n\n");
        
        /*
         * VALIDATE RESPONSE:
         *   - Check if it's a ProbeMatch (not our own Probe echo)
         *   - ProbeMatch contains device information
         */
        if (!strstr(recv_buf, "ProbeMatch")) {
            printf("  Not a ProbeMatch, ignoring\n\n");
            continue;
        }
        
        response_count++;

        char xaddrs[512] = {0};
        char device_name[256] = {0};
        
        extract_xaddrs(recv_buf, xaddrs, sizeof(xaddrs));
        extract_device_name(recv_buf, device_name, sizeof(device_name));
        
        printf("───────────────────────────────────────────────────────────────────\n");
        printf("  Device #%d:\n", response_count);
        printf("───────────────────────────────────────────────────────────────────\n");
        printf("  Name:      %s\n", device_name[0] ? device_name : "(unknown)");
        printf("  Address:   %s\n", inet_ntoa(sender_addr.sin_addr));
        printf("  XAddrs:    %s\n", xaddrs[0] ? xaddrs : "(not found)");
        printf("\n  NEXT STEPS:\n");
        printf("    1. HTTP GET to XAddrs URL for device capabilities\n");
        printf("    2. ONVIF GetDeviceInformation request\n");
        printf("    3. Query media profiles, stream URIs, etc.\n");
        printf("───────────────────────────────────────────────────────────────────\n\n");
    }
    close(sockfd);
    printf("[LAYER 2: LIBC] close() called\n");
    printf("[LAYER 4: KERNEL] Socket cleanup:\n");
    printf("  - IGMP Leave message sent\n");
    printf("  - Socket buffers freed\n");
    printf("  - File descriptor released\n\n");
    
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("  Discovery complete: %d device(s) found\n", response_count);
    printf("═══════════════════════════════════════════════════════════════════\n\n");
    
    if (response_count == 0) {
        printf("TROUBLESHOOTING: No devices found\n");
        printf("─────────────────────────────────────────────────────────────────\n");
        printf("1. Check if devices are on same subnet:\n");
        printf("   - Multicast TTL=1 limits to local subnet\n");
        printf("   - Run: ip route show\n");
        printf("\n");
        printf("2. Check multicast routing:\n");
        printf("   - Run: ip maddr show\n");
        printf("   - Should see 239.255.255.250 on active interface\n");
        printf("\n");
        printf("3. Check firewall:\n");
        printf("   - Run: sudo iptables -L -n | grep 3702\n");
        printf("   - Ensure UDP port 3702 is allowed\n");
        printf("\n");
        printf("4. Capture traffic to verify probe was sent:\n");
        printf("   - Run: sudo tcpdump -i any -n port 3702\n");
        printf("   - Should see outgoing Probe and incoming ProbeMatch\n");
        printf("\n");
        printf("5. Check interface selection:\n");
        printf("   - This tool uses INADDR_ANY (kernel chooses interface)\n");
        printf("   - If multiple interfaces, kernel picks one (usually default route)\n");
        printf("   - To force specific interface: bind to specific IP\n");
        printf("\n");
        printf("KERNEL DEBUGGING:\n");
        printf("  - Check if multicast group was joined: cat /proc/net/igmp\n");
        printf("  - Check socket state: ss -u -a | grep 3702\n");
        printf("  - Check routing: ip route get 239.255.255.250\n");
        printf("═══════════════════════════════════════════════════════════════════\n");
    }
    
    return 0;
}

    
    /*struct imr_multiaddr maddr = {0};
    memset(&maddr , 0, sizeof(maddr));*/
