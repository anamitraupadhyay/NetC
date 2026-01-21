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

const char *auth_template =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Body>"
    "<tds:GetDeviceInformationResponse>"
    "<tds:Manufacturer>Videonetics</tds:Manufacturer>"
    "<tds:Model>Videonetics_Camera_Emulator</tds:Model>"
    "<tds:FirmwareVersion>10.0</tds:FirmwareVersion>"
    "<tds:SerialNumber>1</tds:SerialNumber>"
    "<tds:HardwareId>1.0</tds:HardwareId>"
    "</tds:GetDeviceInformationResponse>"
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
  FILE *fp = fopen("Credentials.csv", "r");
  if(!fp){return false;}
  char line[256];
  char expected[256];

  snprintf(expected, sizeof(expected), "%s,%s", user, pass);// "username,password"

  while (fgets(line, sizeof(line), fp)) {

    
    // Remove trailing newline if present
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
      line[len - 1] = '\0';
    }

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
  }
  listen(sock, 5);

  char buf[BUFFER_SIZE];
  char user[MAX_CREDENTIALS] = {0};
  char pass[MAX_CREDENTIALS] = {0};

  while (1) {
    FILE *xml = fopen("auth.xml", "w");
    fprintf(xml, "%s", auth_template);fclose(xml);
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

      printf("Login attempt user: %s   pass: %s\n", user, pass);
    }

    // Hardcoded check — only this matters for ONVIF tool
    int is_valid =
        (strcmp(user, "admin") == 0 && strcmp(pass, "password") == 0);

    // If hardcoded fails, check CSV later this will be locked instead of above
    if (!is_valid) {
      is_valid = csvparser(user, pass);
    }

    char response[BUFFER_SIZE];
    if (is_valid) {
      // Success 200
      snprintf(response, sizeof(response),
               "HTTP/1.1 200 OK\r\n"
               "Content-Type: application/soap+xml; charset=utf-8\r\n"
               "Content-Length: %zu\r\n\r\n%s",
               strlen(auth_template), auth_template);
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
