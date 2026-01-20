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
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define DISCOVERY_PORT 3702
#define MULTICAST_ADDR "239.255.255.250"
#define CAMERA_HTTP_PORT 8080
#define BUFFER_SIZE 65536
#define AUTH_PORT CAMERA_HTTP_PORT  // Same port - ONVIF device service
#define MAX_CREDENTIALS 1024

// Hardcoded credentials for ONVIF test tool
#define VALID_USERNAME "admin"
#define VALID_PASSWORD "password"

// Proper ONVIF GetCapabilitiesResponse
const char *CAPABILITIES_RESPONSE_TEMPLATE =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Body>"
    "<tds:GetCapabilitiesResponse>"
    "<tds:Capabilities>"
    "<tt:Device>"
    "<tt:XAddr>http://%s:%d/onvif/device_service</tt:XAddr>"
    "<tt:Network><tt:IPFilter>false</tt:IPFilter><tt:ZeroConfiguration>false</tt:ZeroConfiguration></tt:Network>"
    "<tt:System><tt:DiscoveryResolve>false</tt:DiscoveryResolve><tt:DiscoveryBye>true</tt:DiscoveryBye>"
    "<tt:RemoteDiscovery>false</tt:RemoteDiscovery><tt:SystemBackup>false</tt:SystemBackup>"
    "<tt:FirmwareUpgrade>false</tt:FirmwareUpgrade></tt:System>"
    "</tt:Device>"
    "</tds:Capabilities>"
    "</tds:GetCapabilitiesResponse>"
    "</s:Body>"
    "</s:Envelope>";

// Simple SOAP fault response
const char *SOAP_FAULT_AUTH =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
    "<s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value>"
    "<s:Subcode><s:Value>ter:NotAuthorized</s:Value></s:Subcode></s:Code>"
    "<s:Reason><s:Text xml:lang=\"en\">Sender not authorized</s:Text></s:Reason>"
    "</s:Fault></s:Body></s:Envelope>";

// GetDeviceInformation response
const char *DEVICE_INFO_RESPONSE =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Body>"
    "<tds:GetDeviceInformationResponse>"
    "<tds:Manufacturer>FakeCam</tds:Manufacturer>"
    "<tds:Model>FakeCam-1000</tds:Model>"
    "<tds:FirmwareVersion>1.0.0</tds:FirmwareVersion>"
    "<tds:SerialNumber>FAKE-0001</tds:SerialNumber>"
    "<tds:HardwareId>FakeCam-HW-001</tds:HardwareId>"
    "</tds:GetDeviceInformationResponse>"
    "</s:Body>"
    "</s:Envelope>";

// GetSystemDateAndTime response (no auth required)
const char *DATETIME_RESPONSE_TEMPLATE =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Body>"
    "<tds:GetSystemDateAndTimeResponse>"
    "<tds:SystemDateAndTime>"
    "<tt:DateTimeType>NTP</tt:DateTimeType>"
    "<tt:DaylightSavings>false</tt:DaylightSavings>"
    "<tt:UTCDateTime>"
    "<tt:Time><tt:Hour>%d</tt:Hour><tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second></tt:Time>"
    "<tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day></tt:Date>"
    "</tt:UTCDateTime>"
    "</tds:SystemDateAndTime>"
    "</tds:GetSystemDateAndTimeResponse>"
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

// Extract PasswordDigest from WS-Security
void extract_password_digest(const char *msg, char *out, size_t out_size);
void extract_password_digest(const char *msg, char *out, size_t out_size) {
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

// Extract Nonce from WS-Security
void extract_nonce(const char *msg, char *out, size_t out_size);
void extract_nonce(const char *msg, char *out, size_t out_size) {
  out[0] = '\0';
  const char *start = strstr(msg, "<wsse:Nonce");
  if (!start)
    start = strstr(msg, "<Nonce");
  if (!start)
    return;

  start = strchr(start, '>');
  if (!start)
    return;
  start++;

  const char *end = strstr(start, "</wsse:Nonce>");
  if (!end)
    end = strstr(start, "</Nonce>");
  if (!end)
    return;

  size_t len = end - start;
  if (len >= out_size)
    len = out_size - 1;
  memcpy(out, start, len);
  out[len] = '\0';
}

// Extract Created timestamp from WS-Security
void extract_created(const char *msg, char *out, size_t out_size);
void extract_created(const char *msg, char *out, size_t out_size) {
  out[0] = '\0';
  const char *start = strstr(msg, "<wsu:Created");
  if (!start)
    start = strstr(msg, "<Created");
  if (!start)
    return;

  start = strchr(start, '>');
  if (!start)
    return;
  start++;

  const char *end = strstr(start, "</wsu:Created>");
  if (!end)
    end = strstr(start, "</Created>");
  if (!end)
    return;

  size_t len = end - start;
  if (len >= out_size)
    len = out_size - 1;
  memcpy(out, start, len);
  out[len] = '\0';
}

// Base64 decode
int base64_decode(const char *input, unsigned char *output, size_t out_size);
int base64_decode(const char *input, unsigned char *output, size_t out_size) {
  BIO *bio = NULL;
  BIO *b64 = NULL;
  int len = 0;
  
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(input, -1);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  
  len = BIO_read(bio, output, out_size);
  BIO_free_all(bio);
  
  return len > 0 ? len : 0;
}

// Base64 encode
void base64_encode(const unsigned char *input, size_t len, char *output, size_t out_size);
void base64_encode(const unsigned char *input, size_t len, char *output, size_t out_size) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;
  
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, input, len);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  
  size_t copy_len = bufferPtr->length < out_size - 1 ? bufferPtr->length : out_size - 1;
  memcpy(output, bufferPtr->data, copy_len);
  output[copy_len] = '\0';
  
  BIO_free_all(bio);
}

// Verify WS-Security PasswordDigest
// PasswordDigest = Base64(SHA1(Nonce + Created + Password))
bool verify_ws_security(const char *username, const char *password_digest,
                        const char *nonce_b64, const char *created);
bool verify_ws_security(const char *username, const char *password_digest,
                        const char *nonce_b64, const char *created) {
  // Check username
  if (strcmp(username, VALID_USERNAME) != 0) {
    printf("  [Auth] Username mismatch: got '%s', expected '%s'\n", username, VALID_USERNAME);
    return false;
  }

  // If no digest provided, authentication fails
  if (!password_digest || strlen(password_digest) == 0) {
    printf("  [Auth] No password digest provided\n");
    return false;
  }
  
  // If no nonce or created, cannot verify digest
  if (!nonce_b64 || strlen(nonce_b64) == 0 || !created || strlen(created) == 0) {
    printf("  [Auth] Missing nonce or created timestamp\n");
    return false;
  }

  // Decode nonce from base64 (max 64 bytes for standard ONVIF nonces)
  unsigned char nonce[256];
  memset(nonce, 0, sizeof(nonce));
  
  // Validate nonce_b64 length (base64 encoded 64 bytes = ~88 chars max)
  if (strlen(nonce_b64) > 128) {
    printf("  [Auth] Nonce too long\n");
    return false;
  }
  
  int nonce_len = base64_decode(nonce_b64, nonce, sizeof(nonce) - 1);
  if (nonce_len <= 0 || nonce_len > 64) {
    printf("  [Auth] Failed to decode nonce or nonce too large\n");
    return false;
  }

  // Compute expected digest: SHA1(nonce + created + password)
  // Max: 64 (nonce) + 30 (timestamp) + 256 (password) = 350 bytes, well under 1024
  unsigned char sha_input[1024];
  size_t sha_input_len = 0;
  
  size_t created_len = strlen(created);
  size_t pass_len = strlen(VALID_PASSWORD);
  
  // Bounds check
  if ((size_t)nonce_len + created_len + pass_len >= sizeof(sha_input)) {
    printf("  [Auth] Combined input too large\n");
    return false;
  }
  
  memcpy(sha_input, nonce, nonce_len);
  sha_input_len += nonce_len;
  
  memcpy(sha_input + sha_input_len, created, created_len);
  sha_input_len += created_len;
  
  memcpy(sha_input + sha_input_len, VALID_PASSWORD, pass_len);
  sha_input_len += pass_len;

  unsigned char sha_result[SHA_DIGEST_LENGTH];
  SHA1(sha_input, sha_input_len, sha_result);

  // Base64 encode the SHA1 result
  char expected_digest[256];
  base64_encode(sha_result, SHA_DIGEST_LENGTH, expected_digest, sizeof(expected_digest));

  printf("  [Auth] Received digest: %s\n", password_digest);
  printf("  [Auth] Expected digest: %s\n", expected_digest);

  // Compare
  if (strcmp(password_digest, expected_digest) == 0) {
    printf("  [Auth] *** AUTHENTICATION SUCCESSFUL ***\n");
    return true;
  }

  printf("  [Auth] Digest mismatch\n");
  return false;
}

// Check if request contains WS-Security header
bool has_ws_security(const char *msg);
bool has_ws_security(const char *msg) {
  return strstr(msg, "wsse:Security") != NULL || strstr(msg, "Security") != NULL;
}

// Check which ONVIF operation is being requested
typedef enum {
  OP_GET_CAPABILITIES,
  OP_GET_DEVICE_INFO,
  OP_GET_SYSTEM_DATE_TIME,
  OP_UNKNOWN
} OnvifOperation;

OnvifOperation get_operation(const char *msg);
OnvifOperation get_operation(const char *msg) {
  if (strstr(msg, "GetCapabilities"))
    return OP_GET_CAPABILITIES;
  if (strstr(msg, "GetDeviceInformation"))
    return OP_GET_DEVICE_INFO;
  if (strstr(msg, "GetSystemDateAndTime"))
    return OP_GET_SYSTEM_DATE_TIME;
  return OP_UNKNOWN;
}

// Get local IP for response
void auth_getlocalip(char *buf, size_t size);
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

bool csvparser(char *user, char *pass) {
  //
  FILE *fp = fopen("Credentials.csv", "a");
  char line[256];
  char expected[256];

  snprintf(expected, sizeof(expected), "%s%s", user,
           pass); // "username,password"

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

void *authentication(void *arg) {
  (void)arg;
  printf("Auth server started on port %d\n", AUTH_PORT);
  printf("Expected credentials: username='%s', password='%s'\n", VALID_USERNAME, VALID_PASSWORD);

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
  char password_digest[MAX_CREDENTIALS] = {0};
  char nonce[MAX_CREDENTIALS] = {0};
  char created[MAX_CREDENTIALS] = {0};
  char local_ip[64];
  
  auth_getlocalip(local_ip, sizeof(local_ip));

  while (1) {
    struct sockaddr_in cl;
    socklen_t clen = sizeof(cl);
    int cs = accept(sock, (struct sockaddr *)&cl, &clen);
    if (cs < 0)
      continue;

    ssize_t n = recv(cs, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
      close(cs);
      continue;
    }
    buf[n] = '\0';

    // Get client IP for logging
    char client_ip[64];
    inet_ntop(AF_INET, &cl.sin_addr, client_ip, sizeof(client_ip));
    
    OnvifOperation op = get_operation(buf);
    printf("\n[Request] from %s - Operation: ", client_ip);
    
    char response[BUFFER_SIZE];
    char body[BUFFER_SIZE];
    bool authenticated = false;

    switch (op) {
      case OP_GET_SYSTEM_DATE_TIME:
        printf("GetSystemDateAndTime (no auth required)\n");
        // This operation doesn't require authentication
        {
          time_t now = time(NULL);
          struct tm *utc = gmtime(&now);
          snprintf(body, sizeof(body), DATETIME_RESPONSE_TEMPLATE,
                   utc->tm_hour, utc->tm_min, utc->tm_sec,
                   utc->tm_year + 1900, utc->tm_mon + 1, utc->tm_mday);
          snprintf(response, sizeof(response),
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                   "Content-Length: %zu\r\n\r\n%s",
                   strlen(body), body);
          send(cs, response, strlen(response), 0);
        }
        break;

      case OP_GET_CAPABILITIES:
      case OP_GET_DEVICE_INFO:
        printf("%s (auth required)\n", 
               op == OP_GET_CAPABILITIES ? "GetCapabilities" : "GetDeviceInformation");
        
        // Extract WS-Security credentials
        extract_username(buf, user, sizeof(user));
        extract_password_digest(buf, password_digest, sizeof(password_digest));
        extract_nonce(buf, nonce, sizeof(nonce));
        extract_created(buf, created, sizeof(created));

        printf("  [Auth] Username: %s\n", user);
        printf("  [Auth] Nonce: %s\n", nonce);
        printf("  [Auth] Created: %s\n", created);

        // Log every attempt
        FILE *f = fopen("Attempts.csv", "a");
        if (f) {
          fprintf(f, "%s,%s,%s,%s\n", user, password_digest, nonce, created);
          fclose(f);
        }

        // Verify WS-Security
        authenticated = verify_ws_security(user, password_digest, nonce, created);

        if (authenticated) {
          if (op == OP_GET_CAPABILITIES) {
            snprintf(body, sizeof(body), CAPABILITIES_RESPONSE_TEMPLATE, local_ip, CAMERA_HTTP_PORT);
          } else {
            snprintf(body, sizeof(body), "%s", DEVICE_INFO_RESPONSE);
          }
          snprintf(response, sizeof(response),
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                   "Content-Length: %zu\r\n\r\n%s",
                   strlen(body), body);
        } else {
          // Return SOAP fault for authentication failure
          snprintf(response, sizeof(response),
                   "HTTP/1.1 400 Bad Request\r\n"
                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                   "Content-Length: %zu\r\n\r\n%s",
                   strlen(SOAP_FAULT_AUTH), SOAP_FAULT_AUTH);
        }
        send(cs, response, strlen(response), 0);
        break;

      default:
        printf("Unknown operation\n");
        snprintf(response, sizeof(response),
                 "HTTP/1.1 500 Internal Server Error\r\n"
                 "Content-Length: 0\r\n\r\n");
        send(cs, response, strlen(response), 0);
        break;
    }

    close(cs);
  }

  close(sock);
  return NULL;
}
