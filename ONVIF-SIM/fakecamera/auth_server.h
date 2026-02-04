#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H


#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "authhandler/digest_auth.h"
#include "authhandler/auth_utils.h"
#include "authhandler/getuser.h"
#include "authhandler/createuser.h"
#include "authhandler/set_delete.h"
#include "dis_utils.h"

// just blind trust for now
// now some necessary altercations
// integration of csvparser and also checking if that user exist or not
int has_any_authentication(const char *request) {

    // 1. WS-UsernameToken (XML Body)
        if (strstr(request, "wsse:Security") || strstr(request, "<Security")) {
            printf("[Auth] Checking WS-UsernameToken...\n");
            if (verify_ws_security(request)) {
                printf("[Auth] WS-Security Verified!\n");
                return 1;
            }
            printf("[Auth] WS-Security Failed.\n");
        }

        // 2. HTTP Digest (Header)
        if (strstr(request, "Authorization: Digest")) {
            printf("[Auth] Checking HTTP Digest...\n");
            // We assume POST for SOAP requests
            if (verify_http_digest(request, "POST")) {
                printf("[Auth] HTTP Digest Verified!\n");
                return 1;
            }
            printf("[Auth] HTTP Digest Failed.\n");
        }

        return 0;

    // Check for ONVIF WS-Security (XML Body)
    /*if (strstr(request, "wsse:Security") != NULL ||
        strstr(request, "<Security") != NULL) {
            char user[64] = {0};// out user
            char pass[64] = {0};// out pass
            //char passFromCsv[64]; // better impl this in separate function
            // change of plans already implemented the strcmp
            extract_passwd(request , pass, sizeof(pass));
            extract_username(request, user, sizeof(user));
            if(csvparser(user, pass) == true) return 1;
            else return 0;
    }
    // Check for HTTP Standard Auth
    // main if stmt for now as http digest is the first target
    if (strstr(request, "Authorization: Digest") != NULL ||
        strstr(request, "Authorization: Basic") != NULL) {
            //utilities i have bool csvparser but do i have user exist?
            // no i have to implement it
            // but i do have extract user and password from req body
            char user[64] = {0};
            char pass[64] = {0};
            //char passFromCsv[64]; // better impl this in separate function
            // change of plans already implemented the strcmp
            extract_passwd(request , pass, sizeof(pass));
            extract_username(request, user, sizeof(user));
            if(csvparser(user, pass) == true) return 1;
            else return 0;
    }*/

    return 0;
}

void *tcpserver(void *arg) {
    (void)arg;
    loadUsers();

    config cfg1 = {0};
    load_config("config.xml", &cfg1);
    printf("ONVIF Server started on port %d\n", cfg1.server_port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return NULL; }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg1.server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind");
        close(sock);
        return NULL;
    }
    listen(sock, 5);

    char buf[BUFFER_SIZE];

    while (1) {
        struct sockaddr_in cl;
        socklen_t clen = sizeof(cl);
        int cs = accept(sock, (struct sockaddr *)&cl, &clen);
        if (cs < 0) continue;

        memset(buf, 0, sizeof(buf));
        ssize_t n = recv(cs, buf, sizeof(buf) - 1, 0);
        if (n <= 0) { close(cs); continue; }

        buf[n] = '\0';
        printf("\n[TCP] Received Request (%zd bytes)\n", n);

        // messageID for RelatesTo
        char request_message_id[256] = {0};
        getmessageid1(buf, request_message_id, sizeof(request_message_id));


        // CASE 1: GetSystemDateAndTime (Unauthenticated) DUH!
        if (strstr(buf, "GetSystemDateAndTime")) {
            printf("[TCP] Req: GetSystemDateAndTime -> ALLOWED\n");

            time_t now = time(NULL);
            struct tm *t = gmtime(&now);

            char soap_res[2048];
            snprintf(soap_res, sizeof(soap_res), GET_DATE_TEMPLATE,
                     request_message_id, t->tm_hour, t->tm_min, t->tm_sec,
                     t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

            char http_res[4096];
            snprintf(http_res, sizeof(http_res),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/soap+xml; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n\r\n%s",
                     strlen(soap_res), soap_res);

            send(cs, http_res, strlen(http_res), 0);
        }

        // CASE 2: GetDeviceInformation (Protected)
        else if (strstr(buf, "GetDeviceInformation")) {

            if (has_any_authentication(buf)) {
                // --- SUB-CASE 2A: HAS AUTH -> PASS (Blind Trust) ---
                printf("[TCP] Req: GetDeviceInformation (Auth Present) -> ALLOWED\n");

                config cfg2 = {0};
                if (!load_config("config.xml", &cfg2)) {
                     // Fallback defaults
                     strncpy(cfg2.manufacturer, "Videonetics", sizeof(cfg2.manufacturer)-1);
                     strncpy(cfg2.model, "Emulator_Cam", sizeof(cfg2.model)-1);
                     cfg2.firmware_version = 1.0;
                     strncpy(cfg2.serial_number, "VN12345", sizeof(cfg2.serial_number)-1);
                     strncpy(cfg2.hardware, "1.0", sizeof(cfg2.hardware)-1);
                }

                char firmware_str[32];
                snprintf(firmware_str, sizeof(firmware_str), "%.1f", cfg2.firmware_version);

                char soap_response[2048];
                snprintf(soap_response, sizeof(soap_response),
                         GET_DEVICE_INFO_TEMPLATE, request_message_id,
                         device_uuid, cfg2.manufacturer, cfg2.model,
                         firmware_str, cfg2.serial_number, cfg2.hardware);

                char response[4096];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/soap+xml; charset=utf-8\r\n"
                         "Content-Length: %zu\r\n"
                         "Connection: close\r\n\r\n%s",
                         strlen(soap_response), soap_response);

                send(cs, response, strlen(response), 0);
            }
            else {
                // --- SUB-CASE 2B: NO AUTH -> CHALLENGE (Send 401 + WWW-Authenticate) ---
                // We MUST send WWW-Authenticate or the client will stop trying.
                printf("[TCP] Req: GetDeviceInformation (No Auth) -> CHALLENGE\n");

                // Random nonce generation
                char nonce[33];
                snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x",
                        rand(), rand(), rand(), rand());

                char response[1024];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 401 Unauthorized\r\n"
                         "WWW-Authenticate: Digest realm=\"ONVIF_Device\", qop=\"auth\", nonce=\"%s\", algorithm=MD5\r\n"
                         "Content-Type: application/soap+xml; charset=utf-8\r\n"
                         "Content-Length: 0\r\n"
                         "Connection: close\r\n\r\n",
                         nonce);

                send(cs, response, strlen(response), 0);
            }
        }
        // CASE 3: GetUser (3 way handshake as ususal)
        else if(strstr(buf, "GetUsers")){
          if(has_any_authentication(buf)) {
              // check if its admin or not from CredWithLevel.csv
              //static bool is_admin_user = false;
              char user[256] = {0};
              extract_header_val(buf, "username", user, sizeof(user));

              if(is_admin(buf, user /*,is_admin_user*/)){ // how will i get this user

            // if(is_admin(buf)){ ok just chnage the has any auth and later do enum
                // --- SUB-CASE 3C: HAS AUTH + IS ADMIN -> PASS ---
                printf("[TCP] Req: GetUsers (Auth Present + Admin) -> ALLOWED\n");
                char soap_response[8192];  // Large buffer for multiple users
                GenerateGetUsersResponse1(soap_response, sizeof(soap_response));

                // <--- Build HTTP response
                char getuser_response[16384]; // a bit smaller size this time, have to manage this
                snprintf(getuser_response, sizeof(getuser_response),
                         "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n\r\n%s",
                                 strlen(soap_response), soap_response);

                send(cs, getuser_response, strlen(getuser_response), 0);
              }
              else{//isadmin failure
                  char getuser_response[16384]; // a bit smaller size this time, have to manage this
                snprintf(getuser_response, sizeof(getuser_response),
                         "HTTP/1.1 403 Forbidden\r\n"
                                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                 "Content-Length: 0\r\n"
                                 "Connection: close\r\n\r\n");

                send(cs, getuser_response, strlen(getuser_response), 0);
              }
            // --- SUB-CASE 3A: HAS AUTH -> PASS ---
            printf("[TCP] Req: GetUsers (Auth Present) -> ALLOWED\n");
            char soap_response[8192];  // Large buffer for multiple users
            GenerateGetUsersResponse1(soap_response, sizeof(soap_response));

            // <--- Build HTTP response
            char getuser_response[16384]; // a bit smaller size this time, have to manage this
            snprintf(getuser_response, sizeof(getuser_response),
                     "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/soap+xml; charset=utf-8\r\n"
                             "Content-Length: %zu\r\n"
                             "Connection: close\r\n\r\n%s",
                             strlen(soap_response), soap_response);

            send(cs, getuser_response, strlen(getuser_response), 0);
          }
          else {
            // --- SUB-CASE 3B: NO AUTH -> CHALLENGE (Send 401 + WWW-Authenticate) ---
                // We MUST send WWW-Authenticate or the client will stop trying.
                printf("[TCP] Req: GetUsers (No Auth) -> CHALLENGE\n");

                // Random nonce generation
                char nonce[33];
                snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x",
                        rand(), rand(), rand(), rand());

                char response[1024];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 401 Unauthorized\r\n"
                         "WWW-Authenticate: Digest realm=\"ONVIF_Device\", qop=\"auth\", nonce=\"%s\", algorithm=MD5\r\n"
                         "Content-Type: application/soap+xml; charset=utf-8\r\n"
                         "Content-Length: 0\r\n"
                         "Connection: close\r\n\r\n",
                         nonce);

                send(cs, response, strlen(response), 0);
          }
        }
        // CASE 4 : SetUsers
        else if(strstr(buf,"SetUsers")){
            if(has_any_authentication(buf)){
                printf("[TCP] Req: SetUsers (Auth Present) -> ALLOWED\n");
                char soap_response[8192];  // Large buffer for multiple users
                //create users specific here
                // this also requires admin privilege
                char user[256] = {0};
                // Try lowercase first
                extract_header_val1(buf, "username", user, sizeof(user));
  
                // If empty, try Capitalized "Username"
                if (user[0] == '\0') {
                    extract_header_val(buf, "Username", user, sizeof(user));
                    printf("extract_header_val1");
                }
  
                printf("[DEBUG] Extracted User: '%s'\n", user); // Debug print
                if(user[0] != '\0' && is_admin(buf, user)){
                    parseSetUsers(buf); setuserscsv();
                  
  
                // taken template
                       // ONVIF Spec: CreateUsersResponse is empty on success
                       const char *soap_body =
                           "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                           "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                               "<soap:Body>"
                                   "<tds:SetUsersResponse></tds:SetUsersResponse>"
                               "</soap:Body>"
                           "</soap:Envelope>";
  
                       char http_response[4096]; // Buffer size should be sufficient for this
                       int len = snprintf(http_response, sizeof(http_response),
                                   "HTTP/1.1 200 OK\r\n"
                                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                   "Content-Length: %zu\r\n"
                                   "Connection: close\r\n"
                                   "\r\n"
                                   "%s",
                                   strlen(soap_body),
                                   soap_body);
  
                       // 4. Send the response
                       send(cs, http_response, len, 0);
            }
            
                else{
                // User is not admin, send error response
                char getuser_response[16384]; // a bit smaller size this time, have to manage this
              snprintf(getuser_response, sizeof(getuser_response),
                       "HTTP/1.1 403 Forbidden\r\n"
                               "Content-Type: application/soap+xml; charset=utf-8\r\n"
                               "Content-Length: 0\r\n"
                               "Connection: close\r\n\r\n");

              send(cs, getuser_response, strlen(getuser_response), 0);
            }
        }
            else{
                //
                // // --- SUB-CASE 4B: NO AUTH -> CHALLENGE (Send 401 + WWW-Authenticate) ---
                    // We MUST send WWW-Authenticate or the client will stop trying.
                    printf("[TCP] Req: GetUsers (No Auth) -> CHALLENGE\n");
    
                    // Random nonce generation
                    char nonce[33];
                    snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x",
                            rand(), rand(), rand(), rand());
    
                    char response[1024];
                    snprintf(response, sizeof(response),
                             "HTTP/1.1 401 Unauthorized\r\n"
                             "WWW-Authenticate: Digest realm=\"ONVIF_Device\", qop=\"auth\", nonce=\"%s\", algorithm=MD5\r\n"
                             "Content-Type: application/soap+xml; charset=utf-8\r\n"
                             "Content-Length: 0\r\n"
                             "Connection: close\r\n\r\n",
                             nonce);
    
                    send(cs, response, strlen(response), 0);
            }
    }
        // CASE 5 : DeleteUsers
        else if(strstr(buf, "DeleteUsers")){
            if(has_any_authentication(buf)){
                printf("[TCP] Req: SetUsers (Auth Present) -> ALLOWED\n");
                char soap_response[8192];  // Large buffer for multiple users
                //create users specific here
                // this also requires admin privilege
                char user[256] = {0};
                // Try lowercase first
                extract_header_val1(buf, "username", user, sizeof(user));
  
                // If empty, try Capitalized "Username"
                if (user[0] == '\0') {
                    extract_header_val(buf, "Username", user, sizeof(user));
                    printf("extract_header_val1");
                }
  
                printf("[DEBUG] Extracted User: '%s'\n", user); // Debug print
                if(user[0] != '\0' && is_admin(buf, user)){
                    parse_delete_users_xml(buf);
                    for(int i = 0; i<numofuserssentdelete;i++){
                        deluserscsv(usersdelarray[i].username);
                    }
                  
  
                // taken template
                       // ONVIF Spec: CreateUsersResponse is empty on success
                       const char *soap_body =
                           "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                           "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                               "<soap:Body>"
                                   "<tds:DeleteUsersResponse></tds:DeleteUsersResponse>"
                               "</soap:Body>"
                           "</soap:Envelope>";
  
                       char http_response[4096]; // Buffer size should be sufficient for this
                       int len = snprintf(http_response, sizeof(http_response),
                                   "HTTP/1.1 200 OK\r\n"
                                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                   "Content-Length: %zu\r\n"
                                   "Connection: close\r\n"
                                   "\r\n"
                                   "%s",
                                   strlen(soap_body),
                                   soap_body);
  
                       // 4. Send the response
                       send(cs, http_response, len, 0);
            }
            
                else{
                // User is not admin, send error response
                char getuser_response[16384]; // a bit smaller size this time, have to manage this
              snprintf(getuser_response, sizeof(getuser_response),
                       "HTTP/1.1 403 Forbidden\r\n"
                               "Content-Type: application/soap+xml; charset=utf-8\r\n"
                               "Content-Length: 0\r\n"
                               "Connection: close\r\n\r\n");

              send(cs, getuser_response, strlen(getuser_response), 0);
            }
        }
            else{
                //
                // // --- SUB-CASE 4B: NO AUTH -> CHALLENGE (Send 401 + WWW-Authenticate) ---
                    // We MUST send WWW-Authenticate or the client will stop trying.
                    printf("[TCP] Req: GetUsers (No Auth) -> CHALLENGE\n");
    
                    // Random nonce generation
                    char nonce[33];
                    snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x",
                            rand(), rand(), rand(), rand());
    
                    char response[1024];
                    snprintf(response, sizeof(response),
                             "HTTP/1.1 401 Unauthorized\r\n"
                             "WWW-Authenticate: Digest realm=\"ONVIF_Device\", qop=\"auth\", nonce=\"%s\", algorithm=MD5\r\n"
                             "Content-Type: application/soap+xml; charset=utf-8\r\n"
                             "Content-Length: 0\r\n"
                             "Connection: close\r\n\r\n",
                             nonce);
    
                    send(cs, response, strlen(response), 0);
            }
        }
        // CASE 6 : CreateUsers
        else if (strstr(buf, "CreateUsers")) {
          if(has_any_authentication(buf)){
              printf("[TCP] Req: CreateUsers (Auth Present) -> ALLOWED\n");
              char soap_response[8192];  // Large buffer for multiple users
              //create users specific here
              // this also requires admin privilege
              char user[256] = {0};
              // Try lowercase first
              extract_header_val1(buf, "username", user, sizeof(user));

              // If empty, try Capitalized "Username"
              if (user[0] == '\0') {
                  extract_header_val(buf, "Username", user, sizeof(user));
                  printf("extract_header_val1");
              }

              printf("[DEBUG] Extracted User: '%s'\n", user); // Debug print
              if(user[0] != '\0' && is_admin(buf, user)){
                appendusers(buf);

              // taken template
                     // ONVIF Spec: CreateUsersResponse is empty on success
                     const char *soap_body =
                         "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                         "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                             "<soap:Body>"
                                 "<tds:CreateUsersResponse></tds:CreateUsersResponse>"
                             "</soap:Body>"
                         "</soap:Envelope>";

                     char http_response[4096]; // Buffer size should be sufficient for this
                     int len = snprintf(http_response, sizeof(http_response),
                                 "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n"
                                 "\r\n"
                                 "%s",
                                 strlen(soap_body),
                                 soap_body);

                     // 4. Send the response
                     send(cs, http_response, len, 0);
              }
              else {
                  // User is not admin, send error response
                  char getuser_response[16384]; // a bit smaller size this time, have to manage this
                snprintf(getuser_response, sizeof(getuser_response),
                         "HTTP/1.1 403 Forbidden\r\n"
                                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                 "Content-Length: 0\r\n"
                                 "Connection: close\r\n\r\n");

                send(cs, getuser_response, strlen(getuser_response), 0);
              }
          }
          else {
            // --- SUB-CASE 4B: NO AUTH -> CHALLENGE (Send 401 + WWW-Authenticate) ---
                // We MUST send WWW-Authenticate or the client will stop trying.
                printf("[TCP] Req: GetUsers (No Auth) -> CHALLENGE\n");

                // Random nonce generation
                char nonce[33];
                snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x",
                        rand(), rand(), rand(), rand());

                char response[1024];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 401 Unauthorized\r\n"
                         "WWW-Authenticate: Digest realm=\"ONVIF_Device\", qop=\"auth\", nonce=\"%s\", algorithm=MD5\r\n"
                         "Content-Type: application/soap+xml; charset=utf-8\r\n"
                         "Content-Length: 0\r\n"
                         "Connection: close\r\n\r\n",
                         nonce);

                send(cs, response, strlen(response), 0);
        }
    }

        // CASE 5: Unknown Request -> 400 Bad Request
        else {
            printf("[TCP] Req: Unknown -> DENY\n");
            char response[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(cs, response, strlen(response), 0);
        }

        close(cs);
    }
    close(sock);
    return NULL;
}

void *tcpserver1(void *arg) {
  (void)arg;

  // load config though unoptimal way
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
    return NULL;
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

      // Extract MessageID for RelatesTo
      char request_message_id[256] = {0};
      getmessageid1(buf, request_message_id, sizeof(request_message_id));

      // Auth

      // CASE 1: TIME SYNC (Public / Unauthenticated) needed
      if (strstr(buf, "GetSystemDateAndTime")) {
        printf("[TCP] Req: GetSystemDateAndTime -> ALLOWED (Public)\n");

        time_t now = time(NULL);
        struct tm *t = gmtime(&now);

        char soap_res[2048];
        // this snprintf copy pasted
        snprintf(soap_res, sizeof(soap_res), GET_DATE_TEMPLATE,
                 request_message_id, t->tm_hour, t->tm_min, t->tm_sec,
                 t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

        char http_res[4096];
        snprintf(http_res, sizeof(http_res),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n\r\n%s",
                 strlen(soap_res), soap_res);

        send(cs, http_res, strlen(http_res), 0);
      }

      // CASE 2: DEVICE INFO (Protected)
      else if (is_get_device_information(buf)) {

        // CHECK: Does the request have the Security Header?
        if (strstr(buf, "wsse:Security") == NULL) {
          // --- SUB-CASE 2A: NO AUTH HEADER most needed to appear
          // not "Not Authentication" also changed the
          printf("[TCP] Req: GetDeviceInformation (No Auth) -> DENY (Sending "
                 "401)\n");

          // send 401 the client
          char response[] = "HTTP/1.1 401 Unauthorized\r\n"
                            "Content-Length: 0\r\n"
                            "Connection: close\r\n\r\n";
          send(cs, response, strlen(response), 0);
        } else {
          // --- SUB-CASE 2B: HAS AUTH HEADER -> ALLOW ---
          printf("[TCP] Req: GetDeviceInformation (Has Auth) -> ALLOWED "
                 "(Sending 200)\n");

          // Load config for response data
          config cfg2 = {0};
          if (!load_config("config.xml", &cfg2)) {
            // Defaults if config fails
            strncpy(cfg2.manufacturer, "Videonetics",
                    sizeof(cfg2.manufacturer) - 1);
            strncpy(cfg2.model, "Videonetics_Camera_Emulator",
                    sizeof(cfg2.model) - 1);
            cfg2.firmware_version = 10.0;
            strncpy(cfg2.serial_number, "VN001",
                    sizeof(cfg2.serial_number) - 1);
            strncpy(cfg2.hardware, "1.0", sizeof(cfg2.hardware) - 1);
          }

          char firmware_str[32];
          snprintf(firmware_str, sizeof(firmware_str), "%.1f",
                   cfg2.firmware_version);
          char *response_message_id = device_uuid;

          char soap_response[BUFFER_SIZE];
          snprintf(soap_response, sizeof(soap_response),
                   GET_DEVICE_INFO_TEMPLATE, request_message_id,
                   response_message_id, cfg2.manufacturer, cfg2.model,
                   firmware_str, cfg2.serial_number, cfg2.hardware);

          char response[BUFFER_SIZE];
          snprintf(response, sizeof(response),
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/soap+xml; charset=utf-8\r\n"
                   "Content-Length: %zu\r\n"
                   "Connection: close\r\n\r\n%s",
                   strlen(soap_response), soap_response);

          send(cs, response, strlen(response), 0);
        }
      }

      // CASE 3: UNKNOWN REQUEST -> DENY
      else {
        printf("[TCP] Req: Unknown -> DENY (Sending 401)\n");
        char response[] = "HTTP/1.1 401 Unauthorized\r\n"
                          "Content-Length: 0\r\n"
                          "Connection: close\r\n\r\n";
        send(cs, response, strlen(response), 0);
      }
    }
    close(cs);
  }
  close(sock);
  return NULL;
}

void *tcpservernoauth(void *arg) {
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
