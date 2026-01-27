#include "auth_utils.h"
#include "simpleparser.h"
#include <fcntl.h>

// Function to check if incoming request is GetDeviceInformation
static inline bool is_get_device_information(const char *msg) {
    if (strstr(msg, "GetDeviceInformation") && 
        strstr(msg, "http://www.onvif.org/ver10/device/wsdl")) {
        return true;
    }
    return false;
}

// Function to generate a UUID for response MessageID
static inline void generate_uuid(char *buf, size_t size) {
    uint8_t bytes[16] = {0};
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t bytes_read = read(fd, bytes, sizeof(bytes));
        close(fd);
        if (bytes_read != sizeof(bytes)) {
            // Fallback to time-based generation
            srand((unsigned)time(NULL) ^ (unsigned)getpid());
            for (size_t i = 0; i < sizeof(bytes); i++) {
                bytes[i] = (uint8_t)(rand() & 0xFF);
            }
        }
    } else {
        // Fallback to time-based generation
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

// Function to extract MessageID from incoming request
static inline void extract_message_id(const char *msg, char *out, size_t out_size) {
    // Look for <wsa:MessageID> first (most common)
    const char *start = strstr(msg, "<wsa:MessageID");
    if (!start) {
        // Also try <a:MessageID>
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

void *tcpserver(void *arg) {
  (void)arg;
  printf("Auth server started on port %d\n", AUTH_PORT);

  // can be added at first as xml is hardcoded
  /*FILE *xml = fopen("auth.xml", "w");
  fprintf(xml, "%s", auth_template);
  fclose(xml);*/

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
      
      // Check if this is a GetDeviceInformation request
      if (is_get_device_information(buf)) {
        printf("[TCP] GetDeviceInformation request detected\n");
        
        // Extract MessageID from request for RelatesTo field
        char request_message_id[256] = {0};
        extract_message_id(buf, request_message_id, sizeof(request_message_id));
        
        // Generate new UUID for response MessageID
        char response_message_id[64] = {0};
        generate_uuid(response_message_id, sizeof(response_message_id));
        
        // Load configuration from config.xml using simpleparser
        config cfg = {0};
        if (!load_config("config.xml", &cfg)) {
          printf("[TCP] Warning: Could not load config.xml, using defaults\n");
          // Set defaults
          strncpy(cfg.manufacturer, "Videonetics", sizeof(cfg.manufacturer) - 1);
          strncpy(cfg.model, "Videonetics_Camera_Emulator", sizeof(cfg.model) - 1);
          cfg.firmware_version = 10.0;
          strncpy(cfg.serial_number, "VN001", sizeof(cfg.serial_number) - 1);
          strncpy(cfg.hardware, "1.0", sizeof(cfg.hardware) - 1);
        }
        
        // Build SOAP response using GET_DEVICE_INFO_TEMPLATE
        char soap_body[BUFFER_SIZE];
        char firmware_str[32];
        snprintf(firmware_str, sizeof(firmware_str), "%.1f", cfg.firmware_version);
        
        snprintf(soap_body, sizeof(soap_body),
                 GET_DEVICE_INFO_TEMPLATE,
                 request_message_id,     // RelatesTo (request MessageID)
                 response_message_id,     // New MessageID for response
                 cfg.manufacturer,        // Manufacturer
                 cfg.model,               // Model
                 firmware_str,            // FirmwareVersion
                 cfg.serial_number,       // SerialNumber
                 cfg.hardware);           // HardwareId
        
        // Add missing namespace declaration for addressing
        char soap_with_namespace[BUFFER_SIZE];
        snprintf(soap_with_namespace, sizeof(soap_with_namespace),
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                 "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
                 "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
                 "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
                 "<s:Header>"
                 "<a:Action s:mustUnderstand=\"1\">http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse</a:Action>"
                 "<a:RelatesTo>%s</a:RelatesTo>"
                 "<a:MessageID>urn:uuid:%s</a:MessageID>"
                 "</s:Header>"
                 "<s:Body>"
                 "<tds:GetDeviceInformationResponse>"
                 "<tds:Manufacturer>%s</tds:Manufacturer>"
                 "<tds:Model>%s</tds:Model>"
                 "<tds:FirmwareVersion>%s</tds:FirmwareVersion>"
                 "<tds:SerialNumber>%s</tds:SerialNumber>"
                 "<tds:HardwareId>%s</tds:HardwareId>"
                 "</tds:GetDeviceInformationResponse>"
                 "</s:Body>"
                 "</s:Envelope>",
                 request_message_id, response_message_id,
                 cfg.manufacturer, cfg.model, firmware_str,
                 cfg.serial_number, cfg.hardware);
        
        // Build HTTP response
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                 "Content-Length: %zu\r\n\r\n%s",
                 strlen(soap_with_namespace), soap_with_namespace);
        
        printf("[TCP] Sending GetDeviceInformation response\n");
        send(cs, response, strlen(response), 0);
      } else {
        // Not a GetDeviceInformation request - send 401 Unauthorized
        printf("[TCP] Not a GetDeviceInformation request\n");
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 401 Unauthorized\r\n"
                 "Content-Length: 0\r\n\r\n");
        send(cs, response, strlen(response), 0);
      }
    }

    close(cs);
  }

  close(sock);
  return NULL;
}
