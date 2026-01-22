#include <arpa/inet.h>
#include <asm-generic/socket.h>
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
#include <fcntl.h>


#define DISCOVERY_PORT      3702
#define MULTICAST_ADDR      "239.255.255.250"
#define CAMERA_NAME         "Videonetics_Camera_Emulator"
#define CAMERA_HTTP_PORT    8080
#define BUFFER_SIZE         65536

static char g_cached_xml[BUFFER_SIZE];
static size_t g_cached_xml_len = 0;

// copied probe match template
const char *PROBE_MATCH_TEMPLATE =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "
    "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<s:Header>"
    "<a:Action "
    "s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/"
    "ProbeMatches</a:Action>"
    "<a:MessageID>%s</a:MessageID>"
    "<a:RelatesTo>%s</a:RelatesTo>"
    "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</"
    "a:To>"
    "</s:Header>"
    "<s:Body>"
    "<d:ProbeMatches>"
    "<d:ProbeMatch>"
    "<a:EndpointReference>"
    "<a:Address>%s</a:Address>"
    "</a:EndpointReference>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "<d:Scopes>onvif://www.onvif.org/name/%s "
    "onvif://www.onvif.org/hardware/Videonetics_Camera_Emulator "
    "onvif://www.onvif.org/type/video_encoder</d:Scopes>"
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
    if (strstr(msg, "Probe") && strstr(msg, "http://schemas.xmlsoap.org/ws/2005/04/discovery")) {
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
      // Also trying <a:MessageID>
      start = strstr(msg, "<a:MessageID");
    }
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

void generate_uuid(char *buf, size_t size){
    memset(buf, 0, size);
    // for 1st part
    uint8_t first[16] = {0};
    int fd = open("/dev/urandom",O_RDONLY);
    if(fd>=0){
        ssize_t  readbuf= read(fd, first, sizeof(first)/*16*/); close(fd);
    }
    else{perror("open");}
    // for the 2nd part
    // 2 parts 1st 6 and then 8
    // Set standard UUID bits (Version 4)
    first[6] = (first[6] & 0x0f) | 0x40; // Version 4
    first[8] = (first[8] & 0x3f) | 0x80; // Variant 1

    // 4. Format string directly into the output buffer
    // Structure is 8-4-4-4-12 hex digits
    snprintf(buf, size, 
        "urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        first[0], first[1], first[2], first[3],
        first[4], first[5],
        first[6], first[7],
        first[8], first[9],
        first[10], first[11], first[12], first[13], first[14], first[15]
    );
}


int build_response(const char *message_id, const char * relates_to_id, const char *message_id1,const char *local_ip,
                    char *buf, size_t size, char *device_name);
/* Build response copypasted not anymore*/
int build_response(const char *message_id ,const char *relates_to_id, const char *message_id1,const char *local_ip,
                   char *buf, size_t size, char *device_name) {
  
  int len = snprintf(
      buf, size, PROBE_MATCH_TEMPLATE,
      message_id,  // 1. <a:MessageID> (UUID)
      relates_to_id,   // 2. <a:RelatesTo> (The ID from the request)
      message_id,
      device_name,     // 3. Device Name
      local_ip,        // 4. IP Address
      CAMERA_HTTP_PORT // 5. Port
  );
  return len;
}

void getdevicename(char *device_name, uint8_t buffersize){
    memset(device_name, 0, buffersize);

    if (gethostname(device_name, /*sizeof(*/ buffersize /*device_name*/) != 0) {
        perror("gethostname");
    }
}

bool is_xml_empty(FILE *fp) {
  int c = fgetc(fp);
  if (c == EOF) {
    return true;
  } else {
    ungetc(c, fp);
    return false;
  }
}

int parse_server_port(FILE *fp) {
  // so find the "<d:XAddrs>http://%s:%d/onvif/device_service</d:XAddrs>"
  // and go for the :%d part as it will be the port
  char line[1024]; // offcourse enough 1024
  int port = -1;

  while (fgets(line, sizeof(line), fp)) {
    char *xaddrs_start = strstr(line, "<d:XAddrs>");
    if (xaddrs_start) {
      // Find the colon before port number
      // Pattern: http://x.x.x.x:PORT/
      char *port_start = strstr(xaddrs_start, "://");
      if (port_start) {
        // Move past "://" and find the colon before port
        port_start = strchr(port_start + 3, ':');
        if (port_start) {// just using the same var to save space and to less complicate
          port = atoi(port_start + 1); // +1 to skip ':'
        }
      }
      break;
    }
  }

  // Reset file pointer to beginning for later use
  rewind(fp);
  return port;
}

void load_preloaded_xml() {
  FILE *fp = fopen("dis.xml", "r");
  if (!fp)
    perror("fopen load_preload_xml");
  int server_port = parse_server_port(fp);

  g_cached_xml_len = fread(g_cached_xml, 1, sizeof(g_cached_xml) - 1, fp);
  g_cached_xml[g_cached_xml_len] = '\0';
  fclose(fp);
  printf("[Preload] Loaded %zu bytes, HTTP port: %d\n", g_cached_xml_len,
         server_port);

  // build_response(const char *message_id, const char *relates_to_id, const
  // char *message_id1, const char *local_ip, char *buf, size_t size, char
  // *device_name)
  // 1 thing to clarify no need to build response =>
  // yes as xml is prebuilt just send it just get the server port and take that
  // into account
  // after this what else needs to be taken in account like where is t change
  // the server port in actual logic
  // now the normal audited network flow
  int recvsocketudp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int opt1 = 1;
  setsockopt(recvsocketudp, SOL_SOCKET, SO_REUSEADDR, &opt1, sizeof(&opt1));

  struct sockaddr_in recvaddr;
  memset(&recvaddr, 0, sizeof(recvaddr));
  recvaddr.sin_family = AF_INET;
  recvaddr.sin_port = htons(DISCOVERY_PORT);
  recvaddr.sin_addr.s_addr = INADDR_ANY;

  if (bind(recvsocketudp, (struct sockaddr *)&recvaddr, sizeof(recvaddr)) < 0) {
    perror("bind");
    close(recvsocketudp);
    return;
  }
  printf("[Preload] Bound to port %d\n", DISCOVERY_PORT);

  // 5. Join multicast
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
  mreq.imr_interface.s_addr = INADDR_ANY;

  if (setsockopt(recvsocketudp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) < 0) {
    perror("multicast join");
    close(recvsocketudp);
    return;
  }
  printf("[Preload] Joined multicast %s\n", MULTICAST_ADDR);
  printf("[Preload] Listening...  (FAST MODE)\n\n");

  // 6. Main loop - recv and send cached XML directly
  char recv_buf[BUFFER_SIZE];
  struct sockaddr_in client_addr;
  socklen_t client_len;
  int probe_count = 0;

  while (1) {
    client_len = sizeof(client_addr);
    memset(recv_buf, 0, sizeof(recv_buf));

    ssize_t n = recvfrom(recvsocketudp, recv_buf, sizeof(recv_buf) - 1, 0,
                         (struct sockaddr *)&client_addr, &client_len);

    if (n <= 0)
      continue;
    recv_buf[n] = '\0';

    if (!isprobe(recv_buf))
      continue;

    probe_count++;

    char client_ip[64];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("[Probe #%d] from %s\n", probe_count, client_ip);

    // *** FAST:  Just send cached XML, no building!  ***
    ssize_t sent = sendto(recvsocketudp, g_cached_xml, g_cached_xml_len, 0,
                          (struct sockaddr *)&client_addr, client_len);

    if (sent > 0) {
      printf("         Sent ProbeMatch (%zd bytes) [CACHED]\n", sent);
    }
  }
}

// Disclaimer printf stmts are added by llm
void *discovery(void *arg) {

  printf("=== WS-Discovery Server ===\n");

  srand((unsigned)time(NULL));

  // Always use dynamic mode to ensure correct RelatesTo for each probe

  // Geting local IP
  char local_ip[64];
  getlocalip(local_ip, sizeof(local_ip));
  printf("Local IP: %s\n", local_ip);

  // Getting device name
  char device_name[64] = CAMERA_NAME;
  // getdevicename(device_name, 64);
  printf("device %s", device_name);

  // always on udp server
  // setupped with port
  int recieversocketudp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (recieversocketudp < 0) {
    perror("socket");
    return NULL;
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
        return NULL;
    }
    
    printf("Bound to port %d\n", DISCOVERY_PORT);
    
    /* Join multicast group - THIS IS THE KEY PART */
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(recieversocketudp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("multicast join");
        close(recieversocketudp);
        return NULL;
    }
    printf("Joined multicast %s\n", MULTICAST_ADDR);
    
    printf("\nListening...  (Ctrl+C to stop)\n\n");

    // setting up buffers
    char recv_buf[BUFFER_SIZE];
    char send_buf[BUFFER_SIZE];

    // GET message id that is for relates to id
    char relates_to_id[256];

    char message_id[46];//urn:uuid(9)+36chars(uuid)+1\0
    
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

        getmessageid(recv_buf, relates_to_id, sizeof(relates_to_id));

        // these 2 up and down function calls should
        // be inside here for each m=usnique message parse

        generate_uuid(message_id, 46);

        
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

        
        // build response and send back
        int send_len =
            build_response(message_id, relates_to_id, message_id, local_ip,
                           send_buf, sizeof(send_buf), device_name);
        // Note: Not saving to dis.xml to ensure each probe gets fresh response with correct RelatesTo

        // Send back 
        ssize_t sent = sendto(recieversocketudp, send_buf, (size_t)send_len, 0,
                              (struct sockaddr*)&client_addr, client_len);
        
        if (sent > 0) {
            printf("         Sent ProbeMatch (%zd bytes)\n", sent);
        }
    }
    return NULL;
}
