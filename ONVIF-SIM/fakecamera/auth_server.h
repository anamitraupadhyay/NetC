#include "auth_utils.h"

void *tcpserver(void *arg) {
  (void)arg;
  printf("Auth server started on port %d\n", AUTH_PORT);

  // can be added at first as xml is hardcoded
  FILE *xml = fopen("auth.xml", "w");
  fprintf(xml, "%s", auth_template);
  fclose(xml);

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
