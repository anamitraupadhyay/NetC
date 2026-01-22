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

// Fixed device endpoint UUID - this should be consistent for the same device
// Using a deterministic format based on device identity
static char g_device_uuid[64] = {0};
static bool g_device_uuid_initialized = false;

// Generate a fixed device UUID based on machine identity (consistent across restarts)
void init_device_uuid() {
    if (g_device_uuid_initialized) return;
    
    // Try to read machine-id for consistent UUID
    FILE *fp = fopen("/etc/machine-id", "r");
    if (fp) {
        char machine_id[64] = {0};
        if (fgets(machine_id, sizeof(machine_id), fp)) {
            // Remove newline
            size_t len = strlen(machine_id);
            if (len > 0 && machine_id[len-1] == '\n') machine_id[len-1] = '\0';
            
            // Format as UUID using first 32 chars of machine-id
            if (strlen(machine_id) >= 32) {
                snprintf(g_device_uuid, sizeof(g_device_uuid),
                    "urn:uuid:%.8s-%.4s-%.4s-%.4s-%.12s",
                    machine_id, machine_id+8, machine_id+12, machine_id+16, machine_id+20);
                g_device_uuid_initialized = true;
                fclose(fp);
                printf("[DEBUG] Device UUID from machine-id: %s\n", g_device_uuid);
                return;
            }
        }
        fclose(fp);
    }
    
    // Fallback: generate a random but persistent UUID
    uint8_t bytes[16] = {0};
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, bytes, sizeof(bytes));
        (void)r; // suppress unused warning
        close(fd);
    }
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    
    snprintf(g_device_uuid, sizeof(g_device_uuid),
        "urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]);
    
    g_device_uuid_initialized = true;
    printf("[DEBUG] Device UUID (generated): %s\n", g_device_uuid);
}

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


int build_response(const char *message_id, const char *relates_to_id, const char *endpoint_uuid, const char *local_ip,
                    char *buf, size_t size, const char *device_name);
/* Build response - properly uses fixed endpoint UUID */
int build_response(const char *message_id, const char *relates_to_id, const char *endpoint_uuid, const char *local_ip,
                   char *buf, size_t size, const char *device_name) {
  
  int len = snprintf(
      buf, size, PROBE_MATCH_TEMPLATE,
      message_id,      // 1. <a:MessageID> - new UUID for this response
      relates_to_id,   // 2. <a:RelatesTo> - matches the probe's MessageID
      endpoint_uuid,   // 3. <a:Address> - FIXED device endpoint UUID
      device_name,     // 4. Device Name in Scopes
      local_ip,        // 5. IP Address in XAddrs
      CAMERA_HTTP_PORT // 6. Port in XAddrs
  );
  return len;
}

void getdevicename(char *device_name, uint8_t buffersize){
    memset(device_name, 0, buffersize);

    if (gethostname(device_name, /*sizeof(*/ buffersize /*device_name*/) != 0) {
        perror("gethostname");
    }
}

// Disclaimer printf stmts are added by llm
void *discovery(void *arg) {
  (void)arg; // suppress unused warning

  printf("=== WS-Discovery Server ===\n");

  srand((unsigned)time(NULL));

  // Initialize fixed device UUID (consistent across restarts)
  init_device_uuid();
  printf("[DEBUG] Using device endpoint UUID: %s\n", g_device_uuid);

  // Getting local IP
  char local_ip[64];
  getlocalip(local_ip, sizeof(local_ip));
  printf("Local IP: %s\n", local_ip);

  // Getting device name
  char device_name[64] = CAMERA_NAME;
  printf("Device name: %s\n", device_name);

  // Create UDP socket
  int recieversocketudp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (recieversocketudp < 0) {
    perror("socket");
    return NULL;
  }
  printf("Socket created (fd=%d)\n", recieversocketudp);
  
  // Enable address reuse
  int opt = 1;
  if (setsockopt(recieversocketudp, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt SO_REUSEADDR failed");
  }

  // Bind to address
  struct sockaddr_in recvside;
  memset(&recvside, 0, sizeof(recvside));
  recvside.sin_family = AF_INET;
  recvside.sin_port = htons(DISCOVERY_PORT);
  recvside.sin_addr.s_addr = INADDR_ANY;
    
  if (bind(recieversocketudp, (struct sockaddr*)&recvside, sizeof(recvside)) < 0) {
    perror("bind");
    close(recieversocketudp);
    return NULL;
  }
  printf("Bound to port %d\n", DISCOVERY_PORT);
    
  // Join multicast group - THIS IS THE KEY PART
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

  // Setting up buffers
  char recv_buf[BUFFER_SIZE];
  char send_buf[BUFFER_SIZE];
  char relates_to_id[256];
  char message_id[64]; // Response message ID (new for each response)
    
  struct sockaddr_in client_addr;
  socklen_t client_len;
  int probe_count = 0;

  while (1) {
    client_len = sizeof(client_addr);
    memset(recv_buf, 0, sizeof(recv_buf));
        
    ssize_t n = recvfrom(recieversocketudp, recv_buf, sizeof(recv_buf) - 1, 0,
                         (struct sockaddr*)&client_addr, &client_len);
        
    if (n <= 0) continue;
    recv_buf[n] = '\0';

    // Check if it's a probe first before processing
    if (!isprobe(recv_buf)) {
      continue;
    }
        
    probe_count++;
        
    // Get client IP for logging
    char client_ip[64];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("\n[Probe #%d] from %s\n", probe_count, client_ip);

    // Extract MessageID from incoming probe for RelatesTo
    getmessageid(recv_buf, relates_to_id, sizeof(relates_to_id));
    printf("[DEBUG] Incoming MessageID (for RelatesTo): %s\n", relates_to_id);

    // Generate new UUID for this response's MessageID
    generate_uuid(message_id, sizeof(message_id));
    printf("[DEBUG] Response MessageID: %s\n", message_id);
    printf("[DEBUG] Device Endpoint UUID: %s\n", g_device_uuid);
    printf("[DEBUG] Local IP: %s\n", local_ip);
    printf("[DEBUG] Device Name: %s\n", device_name);
        
    // Build response using fixed device UUID for endpoint
    int send_len = build_response(message_id, relates_to_id, g_device_uuid, local_ip,
                                  send_buf, sizeof(send_buf), device_name);

    // Save the XML to file for debugging
    FILE *xml = fopen("last_response.xml", "w");
    if (xml) {
      fprintf(xml, "%s", send_buf);
      fclose(xml);
      printf("[DEBUG] Saved response to last_response.xml\n");
    }

    // Send response
    ssize_t sent = sendto(recieversocketudp, send_buf, (size_t)send_len, 0,
                          (struct sockaddr*)&client_addr, client_len);
        
    if (sent > 0) {
      printf("[DEBUG] Sent ProbeMatch (%zd bytes) to %s\n", sent, client_ip);
    } else {
      perror("[ERROR] sendto failed");
    }
  }
  return NULL;
}
