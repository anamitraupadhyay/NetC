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

/*void *tcpserver1(void *arg) {
  (void)arg;

  // load config though unoptimal way
  config cfg1 = {0};
  load_config("config.xml", &cfg1);
  printf("Auth server started on port %d\n", cfg1.server_port);

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return NULL;

  int opt = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg1.server_port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
    perror("bind");
    close(sock);
    return NULL;
  }
  listen(sock, 5);

  char buf[BUFFER_SIZE];

  while (1) {
    struct sockaddr_in cl;
    socklen_t clen = sizeof(cl);
    int cs = accept(sock, (struct sockaddr *)&cl, &clen);
    if (cs < 0)
      continue;

    ssize_t n = recv(cs, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
      buf[n] = '\0';
      printf("[TCP] Received request (%zd bytes)\n", n);

      // Extract MessageID for RelatesTo
      char request_message_id[256] = {0};
      getmessageid1(buf, request_message_id, sizeof(request_message_id));

      // Auth

      // CASE 1: TIME SYNC (Public / Unauthenticated) needed
      if (strstr(buf, "GetSystemDateAndTime")) {
        printf("[TCP] Req: GetSystemDateAndTime -> ALLOWED (Public)\n");

        time_t now = time(NULL);
        struct tm *t = gmtime(&now);

        char soap_res[2048];
        // this snprintf copy pasted
        snprintf(soap_res, sizeof(soap_res), GET_DATE_TEMPLATE,
                 request_message_id, t->tm_hour, t->tm_min, t->tm_sec,
                 t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

        char http_res[4096];
        snprintf(http_res, sizeof(http_res),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n\r\n%s",
                 strlen(soap_res), soap_res);

        send(cs, http_res, strlen(http_res), 0);
      }

      // CASE 2: DEVICE INFO (Protected)
      else if (is_get_device_information(buf)) {

        // CHECK: Does the request have the Security Header?
        if (strstr(buf, "wsse:Security") == NULL) {
          // --- SUB-CASE 2A: NO AUTH HEADER most needed to appear
          // not "Not Authentication" also changed the
          printf("[TCP] Req: GetDeviceInformation (No Auth) -> DENY (Sending "
                 "401)\n");

          // send 401 the client
          char response[] = "HTTP/1.1 401 Unauthorized\r\n"
                            "Content-Length: 0\r\n"
                            "Connection: close\r\n\r\n";
          send(cs, response, strlen(response), 0);
        } else {
          // --- SUB-CASE 2B: HAS AUTH HEADER -> ALLOW ---
          printf("[TCP] Req: GetDeviceInformation (Has Auth) -> ALLOWED "
                 "(Sending 200)\n");

          // Load config for response data
          config cfg2 = {0};
          if (!load_config("config.xml", &cfg2)) {
            // Defaults if config fails
            strncpy(cfg2.manufacturer, "Videonetics",
                    sizeof(cfg2.manufacturer) - 1);
            strncpy(cfg2.model, "Videonetics_Camera_Emulator",
                    sizeof(cfg2.model) - 1);
            cfg2.firmware_version = 10.0;
            strncpy(cfg2.serial_number, "VN001",
                    sizeof(cfg2.serial_number) - 1);
            strncpy(cfg2.hardware, "1.0", sizeof(cfg2.hardware) - 1);
          }

          char firmware_str[32];
          snprintf(firmware_str, sizeof(firmware_str), "%.1f",
                   cfg2.firmware_version);
          char *response_message_id = device_uuid;

          char soap_response[BUFFER_SIZE];
          snprintf(soap_response, sizeof(soap_response),
                   GET_DEVICE_INFO_TEMPLATE, request_message_id,
                   response_message_id, cfg2.manufacturer, cfg2.model,
                   firmware_str, cfg2.serial_number, cfg2.hardware);

          char response[BUFFER_SIZE];
          snprintf(response, sizeof(response),
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                   "Content-Length: %zu\r\n"
                   "Connection: close\r\n\r\n%s",
                   strlen(soap_response), soap_response);

          send(cs, response, strlen(response), 0);
        }
      }

      // CASE 3: UNKNOWN REQUEST -> DENY
      else {
        printf("[TCP] Req: Unknown -> DENY (Sending 401)\n");
        char response[] = "HTTP/1.1 401 Unauthorized\r\n"
                          "Content-Length: 0\r\n"
                          "Connection: close\r\n\r\n";
        send(cs, response, strlen(response), 0);
      }
    }
    close(cs);
  }
  close(sock);
  return NULL;
}

void *tcpservernoauth(void *arg) {
  (void)arg;

  // for now a bit unoptimal way
  config cfg1 = {0};
  load_config("config.xml", &cfg1);
  printf("Auth server started on port %d\n", cfg1.server_port);


  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return NULL;

  int opt = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));


  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg1.server_port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
    perror("bind");
    close(sock);
  }
  listen(sock, 5);

  char buf[BUFFER_SIZE];

  while (1) {
    struct sockaddr_in cl;
    socklen_t clen = sizeof(cl);
    int cs = accept(sock, (struct sockaddr *)&cl, &clen);
    if (cs < 0)
      continue;

    ssize_t n = recv(cs, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
      buf[n] = '\0';

    printf("[TCP] Received request (%zd bytes)\n", n);
    // Extract MessageID from request for RelatesTo field
    char request_message_id[256] = {0};
    getmessageid1(buf, request_message_id, sizeof(request_message_id));


      // Check if this is a GetDeviceInformation request
      if (is_get_device_information(buf)) {
        printf("[TCP] GetDeviceInformation request detected\n");

        // Generate new UUID for response MessageID
        char *response_message_id = device_uuid;
        //generate_messageid1(response_message_id, sizeof(response_message_id));

        // Load configuration from config.xml using simpleparser in main for now
        config cfg2 = {0};
        if (!load_config("config.xml", &cfg2)) {
          printf("[TCP] Warning: Could not load config.xml, using defaults\n");
          // Set defaults for failure as suggested by llm as i forgot to do the macros
          strncpy(cfg2.manufacturer, "Videonetics", sizeof(cfg2.manufacturer) - 1);
          strncpy(cfg2.model, "Videonetics_Camera_Emulator", sizeof(cfg2.model) - 1);
          cfg2.firmware_version = 10.0;
          strncpy(cfg2.serial_number, "VN001", sizeof(cfg2.serial_number) - 1);
          strncpy(cfg2.hardware, "1.0", sizeof(cfg2.hardware) - 1);
        }

        // Build SOAP response with device information
        // weird had to add later :> dumbass of mine
        char firmware_str[32];
        snprintf(firmware_str, sizeof(firmware_str), "%.1f", cfg2.firmware_version);

        char soap_response[BUFFER_SIZE];
        snprintf(soap_response, sizeof(soap_response), GET_DEVICE_INFO_TEMPLATE,
                 request_message_id, response_message_id,
                 cfg2.manufacturer, cfg2.model, firmware_str,
                 cfg2.serial_number, cfg2.hardware);

        // Build HTTP response
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                 "Content-Length: %zu\r\n"
                          "Connection: close\r\n"  // <--- ADD by llm
                          "\r\n%s",
                 strlen(soap_response), soap_response);

        printf("[TCP] Sending GetDeviceInformation response\n");
        send(cs, response, strlen(response), 0);
      }
      else if(strstr(buf, "GetSystemDateAndTime")){
          printf("[TCP] Handling GetSystemDateAndTime\n");

          time_t now = time(NULL);
          struct tm *t = gmtime(&now);

          char soap_res[2048]; // Ensure buffer is large enough
          snprintf(soap_res, sizeof(soap_res), GET_DATE_TEMPLATE,
                   request_message_id, // RelatesTo
                   t->tm_hour, t->tm_min, t->tm_sec,
                   t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

          char http_res[4096];
          snprintf(http_res, sizeof(http_res),
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                   "Content-Length: %zu\r\n"
                            "Connection: close\r\n"  // <--- ADD by llm
                            "\r\n%s",
                   strlen(soap_res), soap_res);

          send(cs, http_res, strlen(http_res), 0);
      } else {
        // Not a GetDeviceInformation request - send 401 Unauthorized
        printf("[TCP] Not a GetDeviceInformation request\n");
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 401 Unauthorized\r\n"
                 "Content-Length: 0\r\n"
                 "Connection: close\r\n\r\n");
        send(cs, response, strlen(response), 0);
      }
    }

    close(cs);
  }

  close(sock);
  return NULL;
} */