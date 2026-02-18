#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H


#include <stddef.h>
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
#include "network_config/include/netplan_manager_c_api.h"

#define NETPLAN_CONFIG_PATH "/etc/netplan/60-onvif-custom.yaml"

// HTTP/SOAP response macros to reduce inline string clutter
#define SOAP_CONTENT_TYPE "Content-Type: application/soap+xml; charset=utf-8\r\n"
#define HTTP_200_SOAP_HDR \
    "HTTP/1.1 200 OK\r\n" \
    SOAP_CONTENT_TYPE \
    "Content-Length: %zu\r\n" \
    "Connection: close\r\n\r\n%s"

// Delay before exit to allow Bye and response to flush to network
#define SHUTDOWN_FLUSH_DELAY_SEC 1

int get_dhcp_sts(char *ifa_name){
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip route list dev %s | grep -q 'proto dhcp'", ifa_name);
    if(system(cmd)==0){return 1;}
    return 0;
}

// Netplan C API based DHCP status check
int get_dhcp_sts_netplan(void *np_mgr, const char *ifa_name){
    if (!np_mgr || !ifa_name) return 0;
    bool dhcp4 = false;
    netplan_manager_get_config(np_mgr, ifa_name, &dhcp4);
    return dhcp4 ? 1 : 0;
}

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

// Helper: Send WS-Discovery Bye multicast and exit(0) after a flush delay.
// Used by SetNetworkInterfaces, SetDNS, SetNetworkDefaultGateway — any
// network-altering operation that requires a process restart.
static void send_bye_and_exit(int cs) {
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
        close(bye_sock);
    }
    close(cs);
    printf("[TCP] Configuration applied. Restarting.\n");
    sleep(SHUTDOWN_FLUSH_DELAY_SEC);
    exit(0);
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

// Validate that a string looks like a valid IPv4 address (digits and dots only)
static int is_valid_ipv4(const char *s) {
    if (!s || !s[0]) return 0;
    for (int i = 0; s[i]; i++) {
        if (s[i] != '.' && (s[i] < '0' || s[i] > '9')) return 0;
    }
    struct in_addr tmp;
    return inet_pton(AF_INET, s, &tmp) == 1;
}

// Validate that a string is a numeric prefix length (0-32)
static int is_valid_prefix(const char *s) {
    if (!s || !s[0]) return 0;
    for (int i = 0; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
    }
    int val = atoi(s);
    return val >= 0 && val <= 32;
}

// Validate that an interface name contains only safe characters (alphanumeric, dash, underscore)
static int is_valid_iface_name(const char *s) {
    if (!s || !s[0]) return 0;
    for (int i = 0; s[i]; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    return 1;
}
int write_netplan_file(const char *iface, const char *ip, const char *prefix, int use_dhcp) {
    void *mgr = netplan_manager_create(NETPLAN_CONFIG_PATH);
    if (!mgr) return -1;
    if (netplan_manager_read_config(mgr) != 0) {
        printf("[TCP] Warning: netplan read_config failed, proceeding with update\n");
    }
    int prefix_len = prefix ? atoi(prefix) : 24;
    netplan_manager_update_config(mgr, iface, use_dhcp ? true : false,
                                  ip ? ip : "", prefix_len,
                                  "", "");
    int ret = netplan_manager_apply_changes(mgr);
    netplan_manager_destroy(mgr);
    return ret;
}

// Handler for GetServices - returns Device and Media service endpoints
static void handle_GetServices(int cs, const char *msg_id, const char *req_buf, config *cfg) {
    // Use live OS IP so XAddrs reflect actual reachable address
    char live_ip[INET_ADDRSTRLEN] = {0};
        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);

        if (getsockname(cs, (struct sockaddr *)&local_addr, &addr_len) == 0) {
            inet_ntop(AF_INET, &local_addr.sin_addr, live_ip, sizeof(live_ip));
        } else {
            // Fallback if getsockname fails (unlikely)
            getlocalip(live_ip, sizeof(live_ip));
        }

        // Now generate URLs using the CORRECT interface IP
        char device_url[256], media_url[256];
        snprintf(device_url, sizeof(device_url), "http://%s:%d/onvif/device_service",
                 live_ip, cfg->server_port);
        snprintf(media_url, sizeof(media_url), "http://%s:%d/onvif/media_service",
                 live_ip, cfg->server_port);

    // Check if client wants capabilities included
    int include_caps = 0;
    if (strstr(req_buf, "IncludeCapability>true</") ||
        strstr(req_buf, "IncludeCapability>true<")) {
        include_caps = 1;
    }

    const char *dev_caps = include_caps ?
        "<tds:Capabilities>"
            "<tds:Network><tds:IPFilter>false</tds:IPFilter></tds:Network>"
        "</tds:Capabilities>" : "";
    const char *med_caps = include_caps ?
        "<tds:Capabilities>"
            "<trt:ProfileCapabilities>"
                "<trt:MaximumNumberOfProfiles>0</trt:MaximumNumberOfProfiles>"
            "</trt:ProfileCapabilities>"
        "</tds:Capabilities>" : "";

    char body[8192];
    snprintf(body, sizeof(body),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
        "xmlns:tt=\"http://www.onvif.org/ver10/schema\" "
        "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">"
        "<s:Header>"
            "<a:Action>http://www.onvif.org/ver10/device/wsdl/GetServicesResponse</a:Action>"
            "<a:RelatesTo>%s</a:RelatesTo>"
        "</s:Header>"
        "<s:Body>"
            "<tds:GetServicesResponse>"
                "<tds:Service>"
                    "<tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>"
                    "<tds:XAddr>%s</tds:XAddr>"
                    "<tds:Version><tt:Major>0</tt:Major><tt:Minor>5</tt:Minor></tds:Version>"
                    "%s"
                "</tds:Service>"
                "<tds:Service>"
                    "<tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>"
                    "<tds:XAddr>%s</tds:XAddr>"
                    "<tds:Version><tt:Major>0</tt:Major><tt:Minor>0</tt:Minor></tds:Version>"
                    "%s"
                "</tds:Service>"
            "</tds:GetServicesResponse>"
        "</s:Body>"
        "</s:Envelope>",
        msg_id, device_url, dev_caps, media_url, med_caps);

    send_soap_ok(cs, body);
}

void *tcpserver(void *arg) {
    (void)arg;
    loadUsers();

    config cfg1 = {0};
    load_config("config.xml", &cfg1);
    printf("ONVIF Server started on port %d\n", cfg1.server_port);

    // Initialize NetPlan manager for network config operations
    void *np_mgr = netplan_manager_create(NETPLAN_CONFIG_PATH);
    if (np_mgr) {
        if (netplan_manager_read_config(np_mgr) == 0) {
            printf("[TCP] NetPlan manager initialized from %s\n", NETPLAN_CONFIG_PATH);
        } else {
            printf("[TCP] Warning: NetPlan manager created but config read failed from %s\n", NETPLAN_CONFIG_PATH);
        }
    } else {
        printf("[TCP] Warning: Could not create NetPlan manager, falling back to system commands\n");
    }

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

        // Reload config to detect auth toggle changes (flicking <auth> to 0 or 1)
        config cfg_live = {0};
        cfg_live.auth_enabled = 1; // Default: auth required
        load_config("config.xml", &cfg_live);
        int no_auth_mode = (cfg_live.auth_enabled == 0);
        if (no_auth_mode) {
            printf("[TCP] Auth disabled via config.xml (<auth>0</auth>)\n");
        }

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
            if(no_auth_mode || has_any_authentication(buf)){
                char user[256] = {0};
                extract_header_val(buf, "username", user, sizeof(user));

                if(no_auth_mode || is_admin(buf, user)){
                    char hostnamearr[64];
                    extract_tag_value(buf, "hostname", hostnamearr, sizeof(hostnamearr));
                    sethostnameinxml(hostnamearr);
                    // Also attempt to set OS hostname (requires root/CAP_SYS_ADMIN)
                    if (sethostname(hostnamearr, strlen(hostnamearr)) != 0) {
                        perror("[TCP] Failed to set OS hostname");
                    }
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
                    char hostname[HOST_NAME_MAX];
                    gethostname(hostname, sizeof(hostname));
                    
                    char is_dhcp_str[10] = "false";
                    char def_iface[32] = {0};
                    
                    // Use netplan C API for DHCP status if manager is available
                    if (np_mgr) {
                        // Get first interface from scan
                        Interfacedata ifaces_hn[3];
                        int cnt_hn = scan_interfaces(ifaces_hn, 3);
                        if (cnt_hn > 0) {
                            strncpy(def_iface, ifaces_hn[0].name, sizeof(def_iface) - 1);
                            if (get_dhcp_sts_netplan(np_mgr, def_iface)) {
                                strcpy(is_dhcp_str, "true");
                            }
                        }
                    } else {
                        // Fallback to system command
                        FILE *fp = popen("ip route show default | awk '/dev/ {print $5}' | head -n 1", "r");
                        if (fp) {
                            if (fgets(def_iface, sizeof(def_iface), fp)) {
                                 def_iface[strcspn(def_iface, "\n")] = 0;
                                 if (get_dhcp_sts(def_iface)) {
                                     strcpy(is_dhcp_str, "true");
                                 }
                            }
                            pclose(fp);
                        }
                    }
        
                    char soap_response[2048];
                    snprintf(soap_response, sizeof(soap_response),
                             GET_HOSTNAME_RESPONSE_TEMPLATE, 
                             request_message_id, 
                             is_dhcp_str, // not cfg_live.fromdhcp
                             hostname);
        
                    char response[4096];
                    snprintf(response, sizeof(response),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/soap+xml; charset=utf-8\r\n"
                             "Content-Length: %zu\r\n"
                             "Connection: close\r\n\r\n%s",
                             strlen(soap_response), soap_response);
        
                    send(cs, response, strlen(response), 0);
                }

        // CASE 2: GetDeviceInformation (Protected)
        else if (strstr(buf, "GetDeviceInformation")) {

            if (no_auth_mode || has_any_authentication(buf)) {
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

                // Prefer serial from generated cnf file; fall back to config.xml
                char serial_buf[sizeof(cfg2.serial_number)] = {0};
                if (load_serial_from_cnf(serial_buf, sizeof(serial_buf))) {
                    strncpy(cfg2.serial_number, serial_buf, sizeof(cfg2.serial_number)-1);
                    cfg2.serial_number[sizeof(cfg2.serial_number)-1] = '\0';
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
          if(no_auth_mode || has_any_authentication(buf)) {
              // check if its admin or not from CredWithLevel.csv
              //static bool is_admin_user = false;
              char user[256] = {0};
              extract_header_val(buf, "username", user, sizeof(user));

              if(no_auth_mode || is_admin(buf, user /*,is_admin_user*/)){ // how will i get this user

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
            if(no_auth_mode || has_any_authentication(buf)){
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
                if(no_auth_mode || (user[0] != '\0' && is_admin(buf, user))){
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
                    if (no_auth_mode || has_any_authentication(buf)) {
                        printf("[TCP] Req: DeleteUsers (Auth Present) -> ALLOWED\n");

                        char user[256] = {0};
                        // Extract the authenticated user to check for Admin privileges
                        extract_header_val1(buf, "username", user, sizeof(user));
                        if (user[0] == '\0') {
                            extract_header_val(buf, "Username", user, sizeof(user));
                        }

                        if (no_auth_mode || (user[0] != '\0' && is_admin(buf, user))) {
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
          if(no_auth_mode || has_any_authentication(buf)){
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
              if(no_auth_mode || (user[0] != '\0' && is_admin(buf, user))){
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
            if(no_auth_mode || has_any_authentication(buf)){
                char user[256] = {0};
                extract_header_val(buf, "username", user, sizeof(user));
                if(no_auth_mode || is_admin(buf, user)){
                    printf("[TCP] Req: SetDNS (Auth+Admin) -> ALLOWED\n");

                    // 1. Extract mandatory FromDHCP flag
                    char thattobeset[256] = {0};
                    extract_tag_value(buf, "FromDHCP", thattobeset, sizeof(thattobeset));
                    int use_dhcp = (strncmp(thattobeset, "true", 4) == 0);

                    // 2. Persist preference to config.xml
                    setdnsinxml(thattobeset, "<FromDHCP>", "</FromDHCP>");

                    // 3. Handle optional DNS fields (searchdomain, manual addresses)
                    optionalhandlingsdns(buf);

                    // 4. Apply DNS changes using NetPlan C API or fallback
                    if (np_mgr) {
                        // Extract DNS address for netplan update
                        char dns_addr[64] = {0};
                        extract_tag_value(buf, "tt:IPv4Address", dns_addr, sizeof(dns_addr));
                        // Update the first NIC's config with new DNS
                        Interfacedata ifaces_dns_set[3];
                        int cnt_dns_set = scan_interfaces(ifaces_dns_set, 3);
                        if (cnt_dns_set > 0) {
                            bool cur_dhcp = false;
                            netplan_manager_get_config(np_mgr, ifaces_dns_set[0].name, &cur_dhcp);
                            netplan_manager_update_config(np_mgr, ifaces_dns_set[0].name,
                                use_dhcp ? true : cur_dhcp,
                                ifaces_dns_set[0].ip, ifaces_dns_set[0].prefix_len,
                                "", dns_addr[0] ? dns_addr : "");
                            netplan_manager_apply_changes(np_mgr);
                            netplan_manager_read_config(np_mgr);
                        }
                        if (!use_dhcp) {
                            applydnstoservice();
                        }
                    } else {
                        system("dhclient -r 2>/dev/null");
                        if (use_dhcp) {
                            system("dhclient -nw 2>/dev/null");
                        } else {
                            applydnstoservice();
                        }
                    }

                    // 5. Send response before restart
                    const char *soap_body =
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                            "<soap:Body>"
                                "<tds:SetDNSResponse></tds:SetDNSResponse>"
                            "</soap:Body>"
                        "</soap:Envelope>";
                    send_soap_ok(cs, soap_body);

                    // 6. Restart: DNS change affects discovery addressing
                    send_bye_and_exit(cs);
                }
                else{
                    send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized to perform this action");
                }
            }
            else{
                printf("[TCP] Req: SetDNS (No Auth) -> CHALLENGE\n");
                send_digest_challenge(cs);
            }
        }
        else if(strstr(buf, "GetDNS")){
            printf("[TCP] Req: GetDNS\n");

            // 1. Read 'FromDHCP' using netplan C API
            char is_dhcp_str[10] = "false"; // Default to false
            char def_iface[32] = {0};

            if (np_mgr) {
                // Use netplan C API for DHCP status
                Interfacedata ifaces_dns[3];
                int cnt_dns = scan_interfaces(ifaces_dns, 3);
                if (cnt_dns > 0) {
                    strncpy(def_iface, ifaces_dns[0].name, sizeof(def_iface) - 1);
                    if (get_dhcp_sts_netplan(np_mgr, def_iface)) {
                        strcpy(is_dhcp_str, "true");
                    }
                }
            } else {
                FILE *fp = popen("ip route show default | awk '/dev/ {print $5}' | head -n 1", "r");
                if (fp) {
                    if (fgets(def_iface, sizeof(def_iface), fp)) {
                        def_iface[strcspn(def_iface, "\n")] = 0;
                        if (get_dhcp_sts(def_iface)) {
                            strcpy(is_dhcp_str, "true");
                        }
                    }
                    pclose(fp);
                }
            }

            // 2. Read SearchDomain
            char searchdomain[256] = {0};

            FILE *resolv_fp = fopen("/etc/resolv.conf", "r");
            if (resolv_fp) {
                char rline[256];
                while (fgets(rline, sizeof(rline), resolv_fp)) {
                    // Look for "search " or "domain "
                    if (strncmp(rline, "search ", 7) == 0) {
                        strncpy(searchdomain, rline + 7, sizeof(searchdomain) - 1);
                        searchdomain[strcspn(searchdomain, "\n")] = 0; // Remove newline
                        break;
                    }
                    if (strncmp(rline, "domain ", 7) == 0) {
                        strncpy(searchdomain, rline + 7, sizeof(searchdomain) - 1);
                        searchdomain[strcspn(searchdomain, "\n")] = 0;
                        break;
                    }
                }
                fclose(resolv_fp);
            }

            // Fallback: If OS has none, try config.xml (Optional)
            if (searchdomain[0] == '\0') {
                FILE *dnsfp = fopen("config.xml", "r");
                if (dnsfp) {
                    char dnsline[256];
                    while (fgets(dnsline, sizeof(dnsline), dnsfp)) {
                        get_the_tag(dnsline, "searchdomain", searchdomain, sizeof(searchdomain));
                        if (strstr(dnsline, "<device>")) break;
                    }
                    fclose(dnsfp);
                }
            }

            // 2. THE FIX i.e DNS List from /etc/resolv.conf
            char dns_items_xml[1024] = {0}; // Buffer for multiple DNS entries
            // Renaming it to avoid dangling pointer and above all that can be included in single
            // pass above in if block
            FILE *resolv_fp1 = fopen("/etc/resolv.conf", "r");
            if (resolv_fp) {
                char rline[256];
                while (fgets(rline, sizeof(rline), resolv_fp1)) {
                    if (strncmp(rline, "nameserver ", 11) == 0) {
                        char *ns = rline + 11;
                        char *end = ns + strlen(ns) - 1;
                        // Trim all endline chars thats it
                        while (end > ns && (*end == '\n' || *end == '\r' || *end == ' ')) *end-- = '\0';

                        // Append a new XML block for THIS server
                        char entry[256];
                        snprintf(entry, sizeof(entry),
                            "<tds:DNSManual>"
                                "<tt:Type>IPv4</tt:Type>"
                                "<tt:IPv4Address>%s</tt:IPv4Address>"
                            "</tds:DNSManual>",
                            ns);
                        strncat(dns_items_xml, entry, sizeof(dns_items_xml) - strlen(dns_items_xml) - 1);
                    }
                }
                fclose(resolv_fp1);
            }

            // Fallback if no DNS found, unlikely it should be
            if (dns_items_xml[0] == '\0') {
                strcpy(dns_items_xml,
                    "<tds:DNSManual><tt:Type>IPv4</tt:Type><tt:IPv4Address>8.8.8.8</tt:IPv4Address></tds:DNSManual>");
            }

            // 3. Send Response
            char soap_response[4096];
            snprintf(soap_response, sizeof(soap_response),
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
                "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
                "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
                "<s:Body>"
                    "<tds:GetDNSResponse>"
                        "<tds:DNSInformation>"
                            "<tt:FromDHCP>%s</tt:FromDHCP>"
                            "<tds:SearchDomain>%s</tds:SearchDomain>"
                            "%s"
                        "</tds:DNSInformation>"
                    "</tds:GetDNSResponse>"
                "</s:Body>"
                "</s:Envelope>",
                //cfgdns.fromdhcp[0] ? cfgdns.fromdhcp : "false",
                is_dhcp_str,
                searchdomain,
                dns_items_xml);
                // still doing dhcp from config as am setting it in set and writing in config
                // thing is one setting is universal

            send_soap_ok(cs, soap_response);
        }
        // CASE: GetNetworkDefaultGateway
        else if(strstr(buf, "GetNetworkDefaultGateway")){
            printf("[TCP] Req: GetNetworkDefaultGateway\n");
            // Read gateway from OS (not config.xml — network state lives in the OS)
            char os_gateway[64] = {0};
            FILE *route_fp = popen("ip route show default 2>/dev/null", "r");
            if (route_fp) {
                char route_line[256];
                if (fgets(route_line, sizeof(route_line), route_fp)) {
                    // Parse "default via 192.168.1.1 dev eth0 ..."
                    char *via = strstr(route_line, "via ");
                    if (via) {
                        via += 4;
                        char *end = strchr(via, ' ');
                        if (end) {
                            size_t len = end - via;
                            if (len < sizeof(os_gateway)) {
                                strncpy(os_gateway, via, len);
                                os_gateway[len] = '\0';
                            }
                        }
                    }
                }
                pclose(route_fp);
            }
            if (!os_gateway[0]) {
                strncpy(os_gateway, "0.0.0.0", sizeof(os_gateway) - 1);
            }

            char soap_response[2048];
            snprintf(soap_response, sizeof(soap_response),
                     GET_NET_GATEWAY_TEMPLATE, os_gateway);

            send_soap_ok(cs, soap_response);
        }
        // CASE: SetNetworkDefaultGateway
        else if(strstr(buf, "SetNetworkDefaultGateway")){
            if (no_auth_mode || has_any_authentication(buf)) {
                char user[256] = {0};
                extract_header_val(buf, "username", user, sizeof(user));

                if (no_auth_mode || is_admin(buf, user)) {
                    printf("[TCP] Req: SetNetworkDefaultGateway (Auth+Admin) -> ALLOWED\n");
                    char new_gw[64] = {0};
                    extract_tag_value(buf, "IPv4Address", new_gw, sizeof(new_gw));

                    if (new_gw[0]) {
                        if (is_valid_ipv4(new_gw)) {
                            // Use NetPlan C API to update gateway via config
                            if (np_mgr) {
                                Interfacedata ifaces_gw[3];
                                int cnt_gw = scan_interfaces(ifaces_gw, 3);
                                if (cnt_gw > 0) {
                                    bool dhcp4 = false;
                                    netplan_manager_get_config(np_mgr, ifaces_gw[0].name, &dhcp4);
                                    if (!dhcp4) {
                                        netplan_manager_update_config(np_mgr, ifaces_gw[0].name,
                                            false, ifaces_gw[0].ip, ifaces_gw[0].prefix_len,
                                            new_gw, "");
                                        int ret = netplan_manager_apply_changes(np_mgr);
                                        if (ret != 0) {
                                            fprintf(stderr, "[TCP] NetPlan apply failed for gateway (ret %d)\n", ret);
                                        }
                                        netplan_manager_read_config(np_mgr);
                                    }
                                }
                            } else {
                                char cmd[256];
                                snprintf(cmd, sizeof(cmd),
                                         "ip route del default 2>/dev/null; ip route add default via %s",
                                         new_gw);
                                int ret = system(cmd);
                                if (ret != 0) {
                                    fprintf(stderr, "[TCP] Failed to apply gateway to OS (exit %d, requires root)\n", ret);
                                }
                            }
                        } else {
                                                    fprintf(stderr, "[TCP] Invalid gateway format (IPv6/Bad), sending Fault\n");
                                                    const char *fault_body = 
                                                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                                        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
                                                        "xmlns:ter=\"http://www.onvif.org/ver10/error\">"
                                                            "<s:Body>"
                                                                "<s:Fault>"
                                                                    "<s:Code>"
                                                                        "<s:Value>s:Sender</s:Value>"
                                                                        "<s:Subcode>"
                                                                            "<s:Value>ter:InvalidArgVal</s:Value>"
                                                                            "<s:Subcode>"
                                                                                "<s:Value>ter:InvalidGatewayAddress</s:Value>"
                                                                            "</s:Subcode>"
                                                                        "</s:Subcode>"
                                                                    "</s:Code>"
                                                                    "<s:Reason>"
                                                                        "<s:Text xml:lang=\"en\">Invalid Gateway Address</s:Text>"
                                                                    "</s:Reason>"
                                                                "</s:Fault>"
                                                            "</s:Body>"
                                                        "</s:Envelope>";
                        
                                                    // Send HTTP 500 (Required for SOAP Faults)
                                                    char response[4096];
                                                    snprintf(response, sizeof(response),
                                                             "HTTP/1.1 500 Internal Server Error\r\n"
                                                             "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                                             "Content-Length: %zu\r\n"
                                                             "Connection: close\r\n\r\n%s",
                                                             strlen(fault_body), fault_body);
                                                    
                                                    send(cs, response, strlen(response), 0);
                                                    close(cs); continue; // these lines to jump exit later
                                                }
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

                    // Gateway change affects routing — restart for clean state
                    send_bye_and_exit(cs);
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
                    if (no_auth_mode || has_any_authentication(buf)) {
                        char user[256] = {0};
                        extract_header_val(buf, "username", user, sizeof(user));

                        if (no_auth_mode || is_admin(buf, user)) {
                            printf("[TCP] Req: GetNetworkInterfaces (Auth+Admin) -> ALLOWED\n");

                            Interfacedata ifaces[3];
                            int count = scan_interfaces(ifaces, 3);

                            // [FIX] Declare the response buffer here
                            char soap_response[16384];

                            char *xml_buf = (char *)malloc(8192);
                            // Standard ONVIF Header
                            strcpy(xml_buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
                                            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
                                            "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
                                            "<s:Body><tds:GetNetworkInterfacesResponse>");

                            char eachtime[4096];
                            char token_name[64];
                            char is_dhcp_str[10];

                            for (int i = 0; i < count; i++) {
                                snprintf(token_name, sizeof(token_name), "%s_token", ifaces[i].name);

                                if (np_mgr) {
                                    if(get_dhcp_sts_netplan(np_mgr, ifaces[i].name)){
                                        strncpy(is_dhcp_str, "true", sizeof(is_dhcp_str));
                                    }
                                    else{strncpy(is_dhcp_str, "false", sizeof(is_dhcp_str));}
                                } else {
                                    if(get_dhcp_sts(ifaces[i].name)){
                                        strncpy(is_dhcp_str, "true", sizeof(is_dhcp_str));
                                    }
                                    else{strncpy(is_dhcp_str, "false", sizeof(is_dhcp_str));}
                                }
                                is_dhcp_str[sizeof(is_dhcp_str) - 1] = '\0';

                                // Build XML with Link Capabilities
                                snprintf(eachtime, sizeof(eachtime),
                                    "<tds:NetworkInterfaces token=\"%s\">"
                                            "<tt:Enabled>true</tt:Enabled>"
                                            "<tt:Link>"
                                                "<tt:AdminSettings>"
                                                    "<tt:AutoNegotiation>true</tt:AutoNegotiation>"
                                                    "<tt:Speed>100</tt:Speed>"
                                                    "<tt:Duplex>Full</tt:Duplex>"
                                                "</tt:AdminSettings>"
                                                "<tt:OperSettings>"
                                                    "<tt:AutoNegotiation>true</tt:AutoNegotiation>"
                                                    "<tt:Speed>1000</tt:Speed>"
                                                    "<tt:Duplex>Full</tt:Duplex>"
                                                "</tt:OperSettings>"
                                                "<tt:InterfaceType>6</tt:InterfaceType>"
                                            "</tt:Link>"
                                            "<tt:Info>"
                                                "<tt:Name>%s</tt:Name>"
                                                "<tt:HwAddress>%s</tt:HwAddress>"
                                                "<tt:MTU>%d</tt:MTU>"
                                            "</tt:Info>"
                                            "<tt:IPv4>"
                                                "<tt:Enabled>true</tt:Enabled>"
                                                "<tt:Config>"
                                                    "<tt:Manual>"
                                                        "<tt:Address>%s</tt:Address>"
                                                        "<tt:PrefixLength>%d</tt:PrefixLength>"
                                                    "</tt:Manual>"
                                                    "<tt:DHCP>%s</tt:DHCP>"
                                                "</tt:Config>"
                                            "</tt:IPv4>"
                                        "</tds:NetworkInterfaces>",
                                    token_name,          // Token
                                    ifaces[i].name,      // Name
                                    ifaces[i].mac,       // MAC
                                    ifaces[i].mtu,       // MTU
                                    ifaces[i].ip,        // IP
                                    ifaces[i].prefix_len,// Prefix
                                    is_dhcp_str          // DYNAMIC STATUS
                                );
                                strcat(xml_buf, eachtime);
                            }
                            strcat(xml_buf, "</tds:GetNetworkInterfacesResponse></s:Body></s:Envelope>");

                            // Now soap_response is declared and ready to use
                            snprintf(soap_response, sizeof(soap_response),
                                     "HTTP/1.1 200 OK\r\n"
                                     "Content-Type: application/soap+xml; charset=utf-8\r\n"
                                     "Content-Length: %zu\r\n"
                                     "Connection: close\r\n\r\n%s",
                                     strlen(xml_buf), xml_buf);

                            send(cs, soap_response, strlen(soap_response), 0);
                            free(xml_buf);
                        } else {
                            printf("[TCP] Req: GetNetworkInterfaces (Not Admin) -> FORBIDDEN\n");
                            send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized");
                        }
                    } else {
                        printf("[TCP] Req: GetNetworkInterfaces (No Auth) -> CHALLENGE\n");
                        send_digest_challenge(cs);
                    }
                }
                // CASE: SetNetworkInterfaces
                else if (strstr(buf, "SetNetworkInterfaces")) {
                    if (no_auth_mode || has_any_authentication(buf)) {
                        char user[256] = {0};
                        extract_header_val(buf, "username", user, sizeof(user));

                        if (no_auth_mode || is_admin(buf, user)) {
                            printf("[TCP] Req: SetNetworkInterfaces -> ALLOWED\n");

                            char req_token[64] = {0};
                            extract_tag_value(buf, "InterfaceToken", req_token, sizeof(req_token));

                            char iface_name[32] = {0};
                            if (req_token[0] != '\0') {
                                char *suffix = strstr(req_token, "_token");
                                if (suffix) {
                                    size_t len = suffix - req_token;
                                    if (len < sizeof(iface_name)) strncpy(iface_name, req_token, len);
                                } else {
                                    strncpy(iface_name, req_token, sizeof(iface_name) - 1);
                                }
                            } else {
                                // Fallback: get first physical interface from scan
                                Interfacedata ifaces_sni[3];
                                int cnt_sni = scan_interfaces(ifaces_sni, 3);
                                if (cnt_sni > 0) {
                                    strncpy(iface_name, ifaces_sni[0].name, sizeof(iface_name) - 1);
                                }
                            }

                            if (!is_valid_iface_name(iface_name)) {
                                send_soap_fault(cs, FAULT_INVALID_ARG, "Invalid Interface Token");
                                close(cs);
                                continue;
                            }

                            char new_ip[64] = {0}, new_prefix[16] = {0}, new_dhcp[8] = {0};
                            extract_tag_value(buf, "tt:Address", new_ip, sizeof(new_ip));
                            extract_tag_value(buf, "tt:PrefixLength", new_prefix, sizeof(new_prefix));
                            extract_tag_value(buf, "tt:DHCP", new_dhcp, sizeof(new_dhcp));

                            int use_dhcp = (strncmp(new_dhcp, "true", 4) == 0);

                            // FIX: Force /24 if client sends invalid prefix like /32-llm suggestion
                            int prefix_val = atoi(new_prefix);
                            if (!use_dhcp && (prefix_val <= 0 || prefix_val >= 32)) {
                                strcpy(new_prefix, "24");
                                prefix_val = 24;
                            }

                            // 1. Use NetPlan C API to update and apply config
                            int apply_ret = -1;
                            if (np_mgr) {
                                netplan_manager_update_config(np_mgr, iface_name,
                                    use_dhcp ? true : false,
                                    new_ip[0] ? new_ip : "",
                                    prefix_val,
                                    "", "");
                                apply_ret = netplan_manager_apply_changes(np_mgr);
                                // Reload config after apply
                                netplan_manager_read_config(np_mgr);
                            } else {
                                // Fallback to the old write_netplan_file function
                                apply_ret = write_netplan_file(iface_name, new_ip, new_prefix, use_dhcp);
                            }

                            // 2. Update XML prefs
                            setdnsinxml(use_dhcp ? "true" : "false", "<FromDHCP>", "</FromDHCP>");

                            // 3. SEND RESPONSE FIRST (Before killing network)
                            const char *soap_body =
                                "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                                "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                                    "<soap:Body>"
                                        "<tds:SetNetworkInterfacesResponse>"
                                            "<tds:RebootNeeded>true</tds:RebootNeeded>"
                                        "</tds:SetNetworkInterfacesResponse>"
                                    "</soap:Body>"
                                "</soap:Envelope>";
                            send_soap_ok(cs, soap_body);

                            // Allow buffer flush
                            usleep(10000);

                            if (apply_ret != 0) {
                                printf("[TCP] NetPlan apply returned %d\n", apply_ret);
                            }

                            send_bye_and_exit(cs);

                        } else {
                            send_soap_fault(cs, FAULT_NOT_AUTHORIZED, "Sender not authorized");
                        }
                    } else {
                        send_digest_challenge(cs);
                    }
                }

        // CASE: GetServices
        else if (strstr(buf, "GetServices")) {
            printf("[TCP] Req: GetServices -> ALLOWED\n");
            handle_GetServices(cs, request_message_id, buf, &cfg_live);
        }

        // CASE: Unknown Request -> SOAP Fault
        else {
            printf("[TCP] Req: Unknown -> DENY\n");
            send_soap_fault(cs, FAULT_ACTION_NOT_SUP, "The requested action is not supported");
        }

        close(cs);
    }
    if (np_mgr) {
        netplan_manager_destroy(np_mgr);
        np_mgr = NULL;
    }
    close(sock);
    return NULL;
}

#endif /* AUTH_SERVER_H */
