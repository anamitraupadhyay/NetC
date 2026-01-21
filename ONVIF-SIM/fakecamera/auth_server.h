#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DISCOVERY_PORT 3702
#define MULTICAST_ADDR "239.255.255.250"
#define CAMERA_HTTP_PORT 8080
#define BUFFER_SIZE 65536
#define AUTH_PORT 8080
#define MAX_CREDENTIALS 1024

/* ONVIF GetCapabilitiesResponse template for ONVIF Test Tool compatibility */
const char *auth_template =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Body>"
    "<tds:GetCapabilitiesResponse>"
    "<tds:Capabilities>"
    "<tt:Device>"
    "<tt:XAddr>http://%s:%d/onvif/device_service</tt:XAddr>"
    "<tt:Network><tt:IPFilter>false</tt:IPFilter></tt:Network>"
    "<tt:System>"
    "<tt:DiscoveryResolve>true</tt:DiscoveryResolve>"
    "<tt:DiscoveryBye>true</tt:DiscoveryBye>"
    "<tt:RemoteDiscovery>false</tt:RemoteDiscovery>"
    "<tt:SystemBackup>false</tt:SystemBackup>"
    "<tt:FirmwareUpgrade>false</tt:FirmwareUpgrade>"
    "</tt:System>"
    "</tt:Device>"
    "<tt:Media><tt:XAddr>http://%s:%d/onvif/media_service</tt:XAddr>"
    "<tt:StreamingCapabilities>"
    "<tt:RTPMulticast>false</tt:RTPMulticast>"
    "<tt:RTP_TCP>true</tt:RTP_TCP>"
    "<tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>"
    "</tt:StreamingCapabilities>"
    "</tt:Media>"
    "</tds:Capabilities>"
    "</tds:GetCapabilitiesResponse>"
    "</s:Body>"
    "</s:Envelope>";

/* GetDeviceInformationResponse template for ONVIF Test Tool */
const char *device_info_template =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Body>"
    "<tds:GetDeviceInformationResponse>"
    "<tds:Manufacturer>Videonetics</tds:Manufacturer>"
    "<tds:Model>Camera Emulator</tds:Model>"
    "<tds:FirmwareVersion>10.0</tds:FirmwareVersion>"
    "<tds:SerialNumber>VN-SIM-001</tds:SerialNumber>"
    "<tds:HardwareId>VN-HW-001</tds:HardwareId>"
    "</tds:GetDeviceInformationResponse>"
    "</s:Body>"
    "</s:Envelope>";

/* GetProfilesResponse template for media service */  
const char *profiles_template =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Body>"
    "<trt:GetProfilesResponse>"
    "<trt:Profiles token=\"profile_1\" fixed=\"true\">"
    "<tt:Name>MainStream</tt:Name>"
    "<tt:VideoSourceConfiguration token=\"vsc_1\">"
    "<tt:Name>VideoSource_1</tt:Name>"
    "<tt:UseCount>1</tt:UseCount>"
    "<tt:SourceToken>vs_1</tt:SourceToken>"
    "<tt:Bounds x=\"0\" y=\"0\" width=\"1920\" height=\"1080\"/>"
    "</tt:VideoSourceConfiguration>"
    "<tt:VideoEncoderConfiguration token=\"vec_1\">"
    "<tt:Name>H264_Encoder</tt:Name>"
    "<tt:UseCount>1</tt:UseCount>"
    "<tt:Encoding>H264</tt:Encoding>"
    "<tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>"
    "<tt:RateControl><tt:FrameRateLimit>30</tt:FrameRateLimit><tt:BitrateLimit>4096</tt:BitrateLimit></tt:RateControl>"
    "</tt:VideoEncoderConfiguration>"
    "</trt:Profiles>"
    "</trt:GetProfilesResponse>"
    "</s:Body>"
    "</s:Envelope>";

/* GetStreamUriResponse template for RTSP streaming */
const char *stream_uri_template =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Body>"
    "<trt:GetStreamUriResponse>"
    "<trt:MediaUri>"
    "<tt:Uri>rtsp://%s:%d/stream1</tt:Uri>"
    "<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>"
    "<tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>"
    "<tt:Timeout>PT0S</tt:Timeout>"
    "</trt:MediaUri>"
    "</trt:GetStreamUriResponse>"
    "</s:Body>"
    "</s:Envelope>";

void extract_username(const char *msg, char *out, size_t out_size);
void extract_username(const char *msg, char *out, size_t out_size) {
  out[0] = '\0';
  const char *start = strstr(msg, "Username>");
  if (!start)
    return;
  start += 9; // skip "Username>"

  const char *end = strstr(start, "</");
  if (!end)
    return;

  size_t len = end - start;
  if (len >= out_size)
    len = out_size - 1;
  memcpy(out, start, len);
  out[len] = '\0';
}

void extract_passwd(const char *msg, char *out, size_t out_size);
void extract_passwd(const char *msg, char *out, size_t out_size) {
  out[0] = '\0';
  const char *start = strstr(msg, "<wsse:Password");
  if (!start)
    start = strstr(msg, "<Password");
  if (!start)
    return;

  start = strchr(start, '>');
  if (!start)
    return;
  start++;

  const char *end = strstr(start, "</wsse:Password>");
  if (!end)
    end = strstr(start, "</Password>");
  if (!end)
    return;

  size_t len = end - start;
  if (len >= out_size)
    len = out_size - 1;
  memcpy(out, start, len);
  out[len] = '\0';
}

bool csvparser(char *user, char *pass) {
  //
  FILE *fp = fopen("Credentials.csv", "a");
  char line[256];
  char expected[256];

  snprintf(expected, sizeof(expected), "%s%s", user, pass);// "username,password"

  while (fgets(line, sizeof(line), fp)) {

    /*
    // Remove trailing newline if present
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
      line[len - 1] = '\0';
    }
    */

    // Exact line match and compare tby line by line
    // for same string "username,password" format
    // also comma is included in design it fails adv parsing
    if (strcmp(line, expected) == 0) {
      fclose(fp);
      return true; 
    }
  }

  fclose(fp);
  return false;
}

/* Request type detection for ONVIF operations */
typedef enum {
  REQ_GET_CAPABILITIES,
  REQ_GET_DEVICE_INFO,
  REQ_GET_PROFILES,
  REQ_GET_STREAM_URI,
  REQ_UNKNOWN
} onvif_request_type;

onvif_request_type detect_request_type(const char *buf) {
  if (strstr(buf, "GetCapabilities"))
    return REQ_GET_CAPABILITIES;
  if (strstr(buf, "GetDeviceInformation"))
    return REQ_GET_DEVICE_INFO;
  if (strstr(buf, "GetProfiles"))
    return REQ_GET_PROFILES;
  if (strstr(buf, "GetStreamUri"))
    return REQ_GET_STREAM_URI;
  return REQ_UNKNOWN;
}

/* Get local IP for response templates */
void auth_getlocalip(char *buf, size_t size) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sockfd < 0) {
    strncpy(buf, "127.0.0.1", size);
    return;
  }
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_port = htons(9000);
  sockaddr.sin_family = AF_INET;
  inet_pton(AF_INET, "8.8.8.8", &sockaddr.sin_addr);

  if (connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
    close(sockfd);
    strncpy(buf, "127.0.0.1", size);
    return;
  }
  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  getsockname(sockfd, (struct sockaddr *)&name, &namelen);
  inet_ntop(AF_INET, &name.sin_addr, buf, size);
  close(sockfd);
}

void *authentication(void *arg) {
  (void)arg;
  printf("ONVIF Device Service started on port %d\n", AUTH_PORT);

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return NULL;

  int opt = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(AUTH_PORT);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
    perror("bind");
    close(sock);
    return NULL;
  }
  listen(sock, 5);

  char buf[BUFFER_SIZE];
  char user[MAX_CREDENTIALS] = {0};
  char pass[MAX_CREDENTIALS] = {0};
  char local_ip[64];
  auth_getlocalip(local_ip, sizeof(local_ip));
  printf("Local IP: %s\n", local_ip);

  while (1) {
    struct sockaddr_in cl;
    socklen_t clen = sizeof(cl);
    int cs = accept(sock, (struct sockaddr *)&cl, &clen);
    if (cs < 0)
      continue;

    ssize_t n = recv(cs, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
      buf[n] = '\0';

      extract_username(buf, user, sizeof(user));
      extract_passwd(buf, pass, sizeof(pass));

      // Log every attempt
      FILE *f = fopen("Attempts.csv", "a");
      if (f) {
        fprintf(f, "%s,%s\n", user, pass);
        fclose(f);
      }

      if (user[0] != '\0')
        printf("Login attempt user: %s   pass: %s\n", user, pass);
    }

    // Hardcoded check — only this matters for ONVIF tool
    int is_valid =
        (strcmp(user, "admin") == 0 && strcmp(pass, "password") == 0) ||
        (user[0] == '\0'); // Allow unauthenticated for discovery

    char response[BUFFER_SIZE];
    char body[BUFFER_SIZE];

    if (is_valid) {
      onvif_request_type req_type = detect_request_type(buf);
      const char *response_body;

      switch (req_type) {
      case REQ_GET_CAPABILITIES:
        snprintf(body, sizeof(body), auth_template, local_ip, AUTH_PORT,
                 local_ip, AUTH_PORT);
        response_body = body;
        printf("  -> GetCapabilities response\n");
        break;
      case REQ_GET_DEVICE_INFO:
        response_body = device_info_template;
        printf("  -> GetDeviceInformation response\n");
        break;
      case REQ_GET_PROFILES:
        response_body = profiles_template;
        printf("  -> GetProfiles response\n");
        break;
      case REQ_GET_STREAM_URI:
        snprintf(body, sizeof(body), stream_uri_template, local_ip, 554);
        response_body = body;
        printf("  -> GetStreamUri response\n");
        break;
      default:
        snprintf(body, sizeof(body), auth_template, local_ip, AUTH_PORT,
                 local_ip, AUTH_PORT);
        response_body = body;
        printf("  -> Default capabilities response\n");
        break;
      }

      snprintf(response, sizeof(response),
               "HTTP/1.1 200 OK\r\n"
               "Content-Type: application/soap+xml; charset=utf-8\r\n"
               "Content-Length: %zu\r\n\r\n%s",
               strlen(response_body), response_body);
    } else {
      // Fail 401
      snprintf(response, sizeof(response),
               "HTTP/1.1 401 Unauthorized\r\n"
               "Content-Length: 0\r\n\r\n");
    }

    send(cs, response, strlen(response), 0);
    close(cs);
  }

  close(sock);
  return NULL;
}
