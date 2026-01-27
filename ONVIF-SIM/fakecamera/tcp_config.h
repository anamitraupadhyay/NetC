#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>

#define DISCOVERY_PORT 3702
#define MULTICAST_ADDR "239.255.255.250"
#define CAMERA_HTTP_PORT 8080
#define BUFFER_SIZE 65536
#define AUTH_PORT 8080
#define MAX_CREDENTIALS 1024


const char *GET_DEVICE_INFO_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Header>"
    "<a:Action s:mustUnderstand=\"1\">http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse</a:Action>"
    "<a:RelatesTo>%s</a:RelatesTo>"      /* 1. Matches Incoming MessageID */
    "<a:MessageID>urn:uuid:%s</a:MessageID>" /* 2. New Random UUID */
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
    "</s:Envelope>";

// donot use the below auth_template and GET_SERVICES_TEMPLATE for now

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



const char *GET_SERVICES_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Header>"
    "<a:Action s:mustUnderstand=\"1\">http://www.onvif.org/ver10/device/wsdl/GetServicesResponse</a:Action>"
    "<a:RelatesTo>%s</a:RelatesTo>"      /* 1. Request MessageID */
    "<a:MessageID>urn:uuid:%s</a:MessageID>" /* 2. New Response UUID */
    "</s:Header>"
    "<s:Body>"
    "<tds:GetServicesResponse>"
        /* --- Service 1: Device (Management) --- */
        "<tds:Service>"
            "<tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>"
            "<tds:XAddr>http://%s:%d/onvif/device_service</tds:XAddr>" /* 3. IP, 4. Port */
            "<tds:Version>"
                "<tt:Major>2</tt:Major><tt:Minor>50</tt:Minor>"
            "</tds:Version>"
        "</tds:Service>"
        /* --- Service 2: Media (Video) --- */
        "<tds:Service>"
            "<tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>"
            "<tds:XAddr>http://%s:%d/onvif/media_service</tds:XAddr>" /* 5. IP, 6. Port */
            "<tds:Version>"
                "<tt:Major>2</tt:Major><tt:Minor>60</tt:Minor>"
            "</tds:Version>"
        "</tds:Service>"
    "</tds:GetServicesResponse>"
    "</s:Body>"
    "</s:Envelope>";