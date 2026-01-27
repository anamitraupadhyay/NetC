#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tcp_config.h"

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
