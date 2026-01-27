#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

//#include "config.h"
#include "simpleparser.h"

static char g_cached_xml[BUFFER_SIZE];
static size_t g_cached_xml_len = 0;
static config g_config = {0};
static bool g_config_inited = false;
static char device_uuid[64] = {0};
static bool device_uuid_inited = false;


bool isprobe(const char *msg);
void getmessageid(const char *msg, char *out, size_t out_size);

bool isprobe(const char *msg) {
    //does it contain Probe and discovery
    if (strstr(msg, "Probe") && strstr(msg, "http://schemas.xmlsoap.org/ws/2005/04/discovery")) {
        return true;
    }
    return false;
}

void generate_messageid(char *buf, size_t size){
    memset(buf, 0, size);
    uint8_t bytes[16] = {0};
    int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            ssize_t bytes_read = read(fd, bytes, sizeof(bytes));
            close(fd);
            if (bytes_read != sizeof(bytes)) {
                // If read failed, use time-based fallback
                srand((unsigned)time(NULL) ^ (unsigned)getpid());
                for (size_t i = 0; i < sizeof(bytes); i++) {
                    bytes[i] = (uint8_t)(rand() & 0xFF);
                }
            }
        } else {
            // /dev/urandom not available, use time-based fallback
            srand((unsigned)time(NULL) ^ (unsigned)getpid());
            for (size_t i = 0; i < sizeof(bytes); i++) {
                bytes[i] = (uint8_t)(rand() & 0xFF);
            }
        }
        
        // Set standard UUID bits (Version 4, Variant 1)
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1
    
        // Format as UUID string (8-4-4-4-12 hex digits)
        snprintf(buf, size, 
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]);
}

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

void initdevice_uuid(){
    if(g_config_inited) return;
    
    FILE *fp = fopen("/etc/machine-id","r");
    if(fp){
        char machine_id[64] = {0};
        if(fgets(machine_id, sizeof(machine_id), fp)){
            // remove the \n by \0
            size_t len = strlen(machine_id);/*int last = len -1;*/
            if(len>0 && machine_id[len -1]=='\n') machine_id[len -1] = '\0';
            
            // machine_id has the info in correct format now
            // now take only the 1st 32 chars of machine_id
            if(strlen(machine_id)>=32){
                snprintf(device_uuid, sizeof(device_uuid),
                                    "%.8s-%.4s-%.4s-%.4s-%.12s",
                                    machine_id, machine_id+8, machine_id+12, machine_id+16, machine_id+20);
                                device_uuid_inited = true;
                                fclose(fp);
                                printf("[DEBUG] Device UUID from machine-id: %s\n", device_uuid);
                                return;
            }
        }
    }
    fclose(fp);
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


int build_response(const char *message_id ,const char *relates_to_id, 
                   const char *message_id1,
                   const char *manufacturer, const char *hardware,
                   const char *location, const char *profile, const char *type,
                   const char *local_ip,
                   char *buf, size_t size, char *device_name);
/* Build response*/

int build_response(const char *message_id ,const char *relates_to_id, 
                   const char *message_id1,
                   const char *manufacturer, const char *hardware,
                   const char *location, const char *profile, const char *type,
                   const char *local_ip,
                   char *buf, size_t size, char *device_name) {
                       
  config cfg = {0};
  load_config("config.xml", &cfg);
  /*if(!load_config("config.xml", &cfg)){// error prone needs serious field 
                                    // repopulation, became more erred
      perror("config.xml");
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
  }*/
  // this acts form 
  int len1 = snprintf(
      buf, size, PROBE_MATCH_TEMPLATE,
      message_id, //uuid
      relates_to_id, //relatesto
      device_uuid, //etc/machine-id
      cfg.model, //xml model
      cfg.manufacturer,
      cfg.hardware,
      cfg.location,
      cfg.profile,
      cfg.type,
      local_ip, //not xml ip for now
      cfg.server_port //xml server port
  );
  return len1;
  
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
