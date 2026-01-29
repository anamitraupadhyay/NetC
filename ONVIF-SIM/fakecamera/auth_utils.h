#ifndef AUTH_UTILS_H
#define AUTH_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include "tcp_config.h"

static inline bool is_get_device_information(const char *msg) {
    if (strstr(msg, "GetDeviceInformation") && 
        strstr(msg, "http://www.onvif.org/ver10/device/wsdl")) {
        return true;
    }
    return false;
}

void extract_usernamexml(const char *msg, char *out, size_t out_size);
void extract_usernamexml(const char *msg, char *out, size_t out_size) {
  out[0] = '\0';
  // the below line works for both <Username> and <wsse:Username>
  // in extract_passwdigest kept the old way just for an idea
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

void extract_passwdigest(const char *msg, char *out, size_t out_size);
void extract_passwdigest(const char *msg, char *out, size_t out_size) {
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

  size_t len = (size_t)(end - start);
  if (len >= out_size)
    len = out_size - 1;
  memcpy(out, start, len);
  out[len] = '\0';

  // learnt that passwd can be sent in plaintext the requirement is
  // "Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\""
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

void generate_messageid1(char *buf, size_t size){
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

void getmessageid1(const char *msg, char *out, size_t out_size) {
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
#endif /* AUTH_UTILS_H */