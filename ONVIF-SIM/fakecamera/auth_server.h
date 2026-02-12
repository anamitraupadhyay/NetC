#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H


#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h> // For HOST_NAME_MAX


//#include "authhandler/digest_auth.h"
#include "authhandler/auth_utils.h"
#include "authhandler/getuser.h"
#include "authhandler/createuser.h"
#include "authhandler/set_delete.h"
#include "config.h"
#include "dis_utils.h"
#include "simpleparser.h"

// HTTP/SOAP response macros to reduce inline string clutter
#define SOAP_CONTENT_TYPE "Content-Type: application/soap+xml; charset=utf-8\r\n"
#define HTTP_200_SOAP_HDR \
    "HTTP/1.1 200 OK\r\n" \
    SOAP_CONTENT_TYPE \
    "Content-Length: %zu\r\n" \
    "Connection: close\r\n\r\n%s"

// Delay before exit to allow Bye and response to flush to network
#define SHUTDOWN_FLUSH_DELAY_SEC 1

// Helper: Send a 401 Digest challenge response
static void send_digest_challenge(int cs) {
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

// Helper: Send a SOAP success response with given body
static void send_soap_ok(int cs, const char *soap_body) {
    char http_response[4096];
    int len = snprintf(http_response, sizeof(http_response),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/soap+xml; charset=utf-8\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s",
                strlen(soap_body),
                soap_body);

    send(cs, http_response, len, 0);
}

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
    addr.sin_addr.s_addr = INADDR_ANY;// here about setting the ip?
    // need to change the config loading and what about affect of the dhcp

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

        // Reload users from CSV on every request for guaranteed fresh state
        loadUsers();

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
        else if(strstr(buf, "SetHostname")){
            // admin priviledges is mandatory
            if(has_any_authentication(buf)){
                char user[256] = {0};
                extract_header_val(buf, "username", user, sizeof(user));
                
                if(is_admin(buf, user)){
                    // processing function
                    // loadxml and edit there and success response
                    //sethostname exist in unistd.h, what? superuser is required
                    char hostnamearr[64];
                    //parsexml for hostname
                    extract_tag_value(buf, "hostname", hostnamearr, sizeof(hostnamearr));
                    sethostnameinxml(hostnamearr);
                    const char *soap_body =
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                            "<soap:Body>"
                                "<tds:SetHostnameResponse></tds:SetHostnameResponse>"
                            "</soap:Body>"
                        "</soap:Envelope>";

                    send_soap_ok(cs, soap_body);
                }
                else{
                    send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
                }
            }
            else{
                send_digest_challenge(cs);
            }
        }
        else if(strstr(buf, "GetHostname")){
            // no admin required
            // ok return devices hostname actual also later setting it actually
            // for now shifiting towards actual devicename or changing it really
            /*
            config cfggethost = {0};
            if(!load_config("config.xml", &cfggethost)){
                // fallback default
                strncpy(cfggethost.hostname, "defhostname", sizeof(cfggethost.hostname)-1);
                strncpy(cfggethost.fromdhcp, "false", sizeof(cfggethost.fromdhcp)-1);
            }*/
            char hostname[HOST_NAME_MAX];
            gethostname(hostname, sizeof(hostname));
            char soap_response[2048];
            snprintf(soap_response, sizeof(soap_response),
                     GET_HOSTNAME_RESPONSE_TEMPLATE, request_message_id, /*cfggethost.fromdhcp,cfggethost.hostname*/ cfg1.fromdhcp, hostname);

            char response[4096];
            snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/soap+xml; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n\r\n%s",
                     strlen(soap_response), soap_response);

            send(cs, response, strlen(response), 0);
            //
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
                send_digest_challenge(cs);
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
                loadUsers();
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
                  send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
              }
          }
          else {
            // --- SUB-CASE 3B: NO AUTH -> CHALLENGE (Send 401 + WWW-Authenticate) ---
                // We MUST send WWW-Authenticate or the client will stop trying.
                printf("[TCP] Req: GetUsers (No Auth) -> CHALLENGE\n");
                send_digest_challenge(cs);
          }
        }
        // CASE 4 : SetUsers
        else if(strstr(buf,"<tds:SetUser>")){
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
                    setusers(buf, cs);// handles the 
                    // parsesetusers also the edgecases too
                    // now addition of that case that if any user 
                    // doesnt exist in csv the whole process will fail
                    // also need to add the error faults
            }
            
                else{
                // User is not admin, send error response
                send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
            }
        }
            else{
                printf("[TCP] Req: SetUsers (No Auth) -> CHALLENGE\n");
                send_digest_challenge(cs);
            }
    }
        // CASE 5 : DeleteUsers
        else if (strstr(buf, "DeleteUsers")) {
                    if (has_any_authentication(buf)) {
                        printf("[TCP] Req: DeleteUsers (Auth Present) -> ALLOWED\n");
                        
                        char user[256] = {0};
                        // Extract the authenticated user to check for Admin privileges
                        extract_header_val1(buf, "username", user, sizeof(user));
                        if (user[0] == '\0') {
                            extract_header_val(buf, "Username", user, sizeof(user));
                        }
        
                        if (user[0] != '\0' && is_admin(buf, user)) {
                            parse_delete_users_xml(buf);
        
                            for (int i = 0; i < numofuserssentdelete; i++) {
                                deluserscsv(usersdelarray[i].username);
                            }
                            loadUsers();
        
                            // 3. Build the ONVIF-compliant SOAP Success Response
                            const char *soap_body =
                                "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                                "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
                                "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                                    "<soap:Body>"
                                        "<tds:DeleteUsersResponse></tds:DeleteUsersResponse>"
                                    "</soap:Body>"
                                "</soap:Envelope>";
        
                            send_soap_ok(cs, soap_body);
                        }
                        else {
                            // Authenticated but not an Admin
                            printf("[TCP] Req: DeleteUsers (Not Admin) -> FORBIDDEN\n");
                            send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
                        }
                    }
                    else {
                        // No authentication provided -> Challenge the client
                        printf("[TCP] Req: DeleteUsers (No Auth) -> CHALLENGE\n");
                        send_digest_challenge(cs);
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
                appendusers(buf,cs);
              }
              else {

                send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
              }
          }
          else {
            // --- SUB-CASE 4B: NO AUTH -> CHALLENGE (Send 401 + WWW-Authenticate) ---
                // We MUST send WWW-Authenticate or the client will stop trying.
                printf("[TCP] Req: CreateUsers (No Auth) -> CHALLENGE\n");
                send_digest_challenge(cs);
        }
    }

        else if(strstr(buf, "SetDNS")){
            // its kinda ready but study of acttual pipeline
            // effect is yet to be studied
            if(has_any_authentication(buf)){
                char user[256];
                extract_header_val(buf, "username", user, sizeof(user));
                if(is_admin(buf, user)){
                    //actual operations with send success
                    char thattobeset[256];
                    extract_tag_value(buf, "FromDHCP", thattobeset, sizeof(thattobeset)); // mandatory
                    char tagopen[] = "<fromdhcp>";
                    char tagclose[] = "</fromdhcp>";
                    setdnsinxml(thattobeset, tagopen, tagclose);
                    // for optional handling need a whole checkflow
                    optionalhandlingsdns(buf);
                    applydnstoservice();
                   
                    const char *soap_body =
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                            "<soap:Body>"
                                "<tds:SetDNSResponse></tds:SetDNSResponse>"
                            "</soap:Body>"
                        "</soap:Envelope>";
                    send_soap_ok(cs, soap_body);
                }
                else{// soapfault - try with admin priviledges}
                    send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
                }
            }
            else{
                printf("[TCP] Req: SetDNS (No Auth) -> CHALLENGE\n");
                send_digest_challenge(cs);
            }
        }
        else if(strstr(buf, "GetDNS")){
            // no admin required, same pattern as GetHostname
                        config cfgdns = {0};
                        load_config("config.xml", &cfgdns);
                        // dns fields at top level need direct extraction
                        char searchdomain[256] = {0}, dnsaddr[64] = {0}, dnstype[16] = {0};
                        FILE *dnsfp = fopen("config.xml", "r");
                        if(dnsfp){
                            char dnsline[256];
                            while(fgets(dnsline, sizeof(dnsline), dnsfp)){
                                get_the_tag(dnsline, "searchdomain", searchdomain, sizeof(searchdomain));
                                get_the_tag(dnsline, "addr", dnsaddr, sizeof(dnsaddr));
                                // only grab top-level type before <device>
                                if(!dnstype[0]) get_the_tag(dnsline, "type", dnstype, sizeof(dnstype));
                                if(strstr(dnsline, "<device>")) break;
                            }
                            fclose(dnsfp);
                        }
                        char soap_response[2048];
                        snprintf(soap_response, sizeof(soap_response),
                                 GET_DNS_RESPONSE_TEMPLATE, cfgdns.fromdhcp,
                                 searchdomain, dnstype, dnsaddr);
            
                        char response[4096];
                        snprintf(response, sizeof(response),
                                 "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n\r\n%s",
                                 strlen(soap_response), soap_response);
            
                        send(cs, response, strlen(response), 0);
        }
        // CASE: GetNetworkDefaultGateway
        else if(strstr(buf, "GetNetworkDefaultGateway")){
            printf("[TCP] Req: GetNetworkDefaultGateway\n");
            config cfg_net = {0};
            if(!load_config("config.xml", &cfg_net)){
                // Fallback defaults if config fails
                strncpy(cfg_net.gateway, "192.168.1.1", sizeof(cfg_net.gateway)-1);
            }
        
            char soap_response[2048];
            snprintf(soap_response, sizeof(soap_response),
                     GET_NET_GATEWAY_TEMPLATE, cfg_net.gateway);
        
            char response[4096];
            snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/soap+xml; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n\r\n%s",
                     strlen(soap_response), soap_response);
        
            send(cs, response, strlen(response), 0);
        }
        // CASE: SetNetworkDefaultGateway
        else if(strstr(buf, "SetNetworkDefaultGateway")){
            if (has_any_authentication(buf)) {
                char user[256] = {0};
                extract_header_val(buf, "username", user, sizeof(user));

                if (is_admin(buf, user)) {
                    printf("[TCP] Req: SetNetworkDefaultGateway (Auth+Admin) -> ALLOWED\n");
                    char new_gw[64] = {0};
                    extract_tag_value(buf, "IPv4Address", new_gw, sizeof(new_gw));

                    if (new_gw[0]) {
                        // setdnsinxml is a generic XML tag value setter, reused here for gateway
                        setdnsinxml(new_gw, "<gateway>", "</gateway>");
                    }

                    const char *soap_body =
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
                        "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                            "<soap:Body>"
                                "<tds:SetNetworkDefaultGatewayResponse></tds:SetNetworkDefaultGatewayResponse>"
                            "</soap:Body>"
                        "</soap:Envelope>";
                    send_soap_ok(cs, soap_body);
                } else {
                    send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
                }
            } else {
                printf("[TCP] Req: SetNetworkDefaultGateway (No Auth) -> CHALLENGE\n");
                send_digest_challenge(cs);
            }
        }
        
        // CASE: GetNetworkInterfaces
        else if (strstr(buf, "GetNetworkInterfaces")) {
            if (has_any_authentication(buf)) {
                char user[256] = {0};
                extract_header_val(buf, "username", user, sizeof(user));

                // Check for Admin privileges
                if (is_admin(buf, user)) {
                    printf("[TCP] Req: GetNetworkInterfaces (Auth+Admin) -> ALLOWED\n");
                    
                    Interfacedata ifaces[3];
                    int count = scan_interfaces(ifaces, 3);
                    char *xml_buf = (char *)malloc(8192);
                    strcpy(xml_buf, NET_IF_HEADER);

                    char soap_response[16384];
                    char eachtime[2048];
                    char token_name[64];
                    for (int i = 0; i < count; i++) {
                        snprintf(token_name, sizeof(token_name), "%s_token", ifaces[i].name);
                        snprintf(eachtime, sizeof(eachtime), NET_IF_ITEM,
                                 token_name,          // token (e.g. eth0_token)
                                 ifaces[i].name,      // Info Name
                                 ifaces[i].mac,       // Info Mac
                                 ifaces[i].mtu,       // Info MTU
                                 ifaces[i].ip,        // IPv4 Address
                                 ifaces[i].prefix_len,// IPv4 Prefix
                                 cfg1.fromdhcp        // DHCP from config
                        );
                        strcat(xml_buf, eachtime);
                    }
                    strcat(xml_buf, NET_IF_FOOTER);

                    snprintf(soap_response, sizeof(soap_response),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/soap+xml; charset=utf-8\r\n"
                             "Content-Length: %zu\r\n"
                             "Connection: close\r\n\r\n%s",
                             strlen(xml_buf), xml_buf);

                    send(cs, soap_response, strlen(soap_response), 0);
                    free(xml_buf);
                } else {
                    // Authenticated but NOT Admin
                    printf("[TCP] Req: GetNetworkInterfaces (Not Admin) -> FORBIDDEN\n");
                    send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
                }
            } else {
                // No Authentication -> Challenge
                printf("[TCP] Req: GetNetworkInterfaces (No Auth) -> CHALLENGE\n");
                send_digest_challenge(cs);
            }
        }
        else if(strstr(buf, "SetNetworkInterfaces")){
            if (has_any_authentication(buf)) {
                char user[256] = {0};
                extract_header_val(buf, "username", user, sizeof(user));

                if (is_admin(buf, user)) {
                    printf("[TCP] Req: SetNetworkInterfaces (Auth+Admin) -> ALLOWED\n");

                    // Extract interface token from request to identify which interface
                    char req_token[64] = {0};
                    extract_tag_value(buf, "InterfaceToken", req_token, sizeof(req_token));
                    if (req_token[0]) {
                        printf("[TCP] SetNetworkInterfaces for token: %s\n", req_token);
                    }

                    // Extract IPv4 settings if present
                    char new_ip[64] = {0};
                    char new_prefix[16] = {0};
                    char new_dhcp[8] = {0};
                    extract_tag_value(buf, "tt:Address", new_ip, sizeof(new_ip));
                    extract_tag_value(buf, "tt:PrefixLength", new_prefix, sizeof(new_prefix));
                    extract_tag_value(buf, "tt:DHCP", new_dhcp, sizeof(new_dhcp));

                    // Update config.xml with new network settings
                    if (new_ip[0]) {
                        setdnsinxml(new_ip, "<addr>", "</addr>");
                    }
                    if (new_prefix[0]) {
                        setdnsinxml(new_prefix, "<subnet>", "</subnet>");
                    }
                    if (new_dhcp[0]) {
                        setdnsinxml(new_dhcp, "<fromdhcp>", "</fromdhcp>");
                    }

                    // Send SOAP success response before shutdown
                    const char *soap_body =
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
                        "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                            "<soap:Body>"
                                "<tds:SetNetworkInterfacesResponse>"
                                    "<tds:RebootNeeded>true</tds:RebootNeeded>"
                                "</tds:SetNetworkInterfacesResponse>"
                            "</soap:Body>"
                        "</soap:Envelope>";
                    send_soap_ok(cs, soap_body);

                    // Send WS-Discovery Bye multicast message
                    int bye_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    if (bye_sock >= 0) {
                        struct sockaddr_in mcast_addr = {0};
                        mcast_addr.sin_family = AF_INET;
                        mcast_addr.sin_port = htons(DISCOVERY_PORT);
                        inet_pton(AF_INET, MULTICAST_ADDR, &mcast_addr.sin_addr);

                        char bye_msg_id[46];
                        generate_messageid(bye_msg_id, sizeof(bye_msg_id));

                        char bye_buf[2048];
                        snprintf(bye_buf, sizeof(bye_buf), WS_DISCOVERY_BYE_TEMPLATE,
                                 bye_msg_id, device_uuid);

                        sendto(bye_sock, bye_buf, strlen(bye_buf), 0,
                               (struct sockaddr *)&mcast_addr, sizeof(mcast_addr));
                        printf("[TCP] Sent WS-Discovery Bye message\n");
                        close(bye_sock);
                    } else {
                        perror("[TCP] Failed to create Bye socket");
                    }

                    close(cs);
                    close(sock);
                    printf("[TCP] Network interface changed, shutting down for restart\n");
                    sleep(SHUTDOWN_FLUSH_DELAY_SEC);
                    exit(0);
                } else {
                    printf("[TCP] Req: SetNetworkInterfaces (Not Admin) -> FORBIDDEN\n");
                    send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
                }
            } else {
                printf("[TCP] Req: SetNetworkInterfaces (No Auth) -> CHALLENGE\n");
                send_digest_challenge(cs);
            }
        }

        // CASE: Unknown Request -> SOAP Fault
        else {
            printf("[TCP] Req: Unknown -> DENY\n");
            send_soap_fault(cs, FAULT_ACTION_NOT_SUP, "The requested action is not supported");
        }

        close(cs);
    }
    close(sock);
    return NULL;
}

#endif /* AUTH_SERVER_H */
