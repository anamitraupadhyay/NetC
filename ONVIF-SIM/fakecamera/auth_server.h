#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "auth_utils.h"
//#include "simpleparser.h"
#include "dis_utils.h"


void *tcpserver(void *arg) {
  (void)arg;

  // for now a bit unoptimal way
  config cfg1 = {0};
  load_config("config.xml", &cfg1);
  printf("Auth server started on port %d\n", cfg1.server_port);


  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return NULL;

  int opt = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));


  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg1.server_port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
    perror("bind");
    close(sock);
  }
  listen(sock, 5);

  char buf[BUFFER_SIZE];

  while (1) {
    struct sockaddr_in cl;
    socklen_t clen = sizeof(cl);
    int cs = accept(sock, (struct sockaddr *)&cl, &clen);
    if (cs < 0)
      continue;

    ssize_t n = recv(cs, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
      buf[n] = '\0';

    printf("[TCP] Received request (%zd bytes)\n", n);
    // Extract MessageID from request for RelatesTo field
    char request_message_id[256] = {0};
    getmessageid1(buf, request_message_id, sizeof(request_message_id));
      
      
      // Check if this is a GetDeviceInformation request
      if (is_get_device_information(buf)) {
        printf("[TCP] GetDeviceInformation request detected\n");
        
        // Generate new UUID for response MessageID
        char *response_message_id = device_uuid;
        //generate_messageid1(response_message_id, sizeof(response_message_id));
        
        // Load configuration from config.xml using simpleparser in main for now
        config cfg2 = {0};
        if (!load_config("config.xml", &cfg2)) {
          printf("[TCP] Warning: Could not load config.xml, using defaults\n");
          // Set defaults for failure as suggested by llm as i forgot to do the macros
          strncpy(cfg2.manufacturer, "Videonetics", sizeof(cfg2.manufacturer) - 1);
          strncpy(cfg2.model, "Videonetics_Camera_Emulator", sizeof(cfg2.model) - 1);
          cfg2.firmware_version = 10.0;
          strncpy(cfg2.serial_number, "VN001", sizeof(cfg2.serial_number) - 1);
          strncpy(cfg2.hardware, "1.0", sizeof(cfg2.hardware) - 1);
        }
        
        // Build SOAP response with device information
        // weird had to add later :> dumbass of mine
        char firmware_str[32];
        snprintf(firmware_str, sizeof(firmware_str), "%.1f", cfg2.firmware_version);
        
        char soap_response[BUFFER_SIZE];
        snprintf(soap_response, sizeof(soap_response), GET_DEVICE_INFO_TEMPLATE,
                 request_message_id, response_message_id,
                 cfg2.manufacturer, cfg2.model, firmware_str,
                 cfg2.serial_number, cfg2.hardware);
        
        // Build HTTP response
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                 "Content-Length: %zu\r\n"
                          "Connection: close\r\n"  // <--- ADD by llm
                          "\r\n%s",
                 strlen(soap_response), soap_response);
        
        printf("[TCP] Sending GetDeviceInformation response\n");
        send(cs, response, strlen(response), 0);
      }
      else if(strstr(buf, "GetSystemDateAndTime")){
          printf("[TCP] Handling GetSystemDateAndTime\n");
          
          time_t now = time(NULL);
          struct tm *t = gmtime(&now);

          char soap_res[2048]; // Ensure buffer is large enough
          snprintf(soap_res, sizeof(soap_res), GET_DATE_TEMPLATE,
                   request_message_id, // RelatesTo
                   t->tm_hour, t->tm_min, t->tm_sec,
                   t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

          char http_res[4096];
          snprintf(http_res, sizeof(http_res),
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                   "Content-Length: %zu\r\n"
                            "Connection: close\r\n"  // <--- ADD by llm
                            "\r\n%s",
                   strlen(soap_res), soap_res);

          send(cs, http_res, strlen(http_res), 0);
      } else {
        // Not a GetDeviceInformation request - send 401 Unauthorized
        printf("[TCP] Not a GetDeviceInformation request\n");
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 401 Unauthorized\r\n"
                 "Content-Length: 0\r\n"
                 "Connection: close\r\n\r\n");
        send(cs, response, strlen(response), 0);
      }
    }

    close(cs);
  }

  close(sock);
  return NULL;
}
#endif /* AUTH_SERVER_H */