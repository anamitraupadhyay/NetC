#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>

//#define DISCOVERY_PORT 3702
//#define MULTICAST_ADDR "239.255.255.250"
//#define CAMERA_HTTP_PORT 8080
//#define BUFFER_SIZE 65536
#define AUTH_PORT 8080
#define MAX_CREDENTIALS 1024

/* Add this to tcp_config.h */
const char *GET_DATE_TEMPLATE1 = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Header>"
        "<a:Action xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" s:mustUnderstand=\"1\">http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse</a:Action>"
        "<a:RelatesTo xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">%s</a:RelatesTo>"
    "</s:Header>"
    "<s:Body>"
        "<tds:GetSystemDateAndTimeResponse>"
            "<tds:SystemDateAndTime>"
                "<tt:DateTimeType>Manual</tt:DateTimeType>"
                "<tt:DaylightSavings>false</tt:DaylightSavings>"
                "<tt:TimeZone><tt:TZ>GMT+05:30</tt:TZ></tt:TimeZone>"
                "<tt:UTCDateTime>"
                    "<tt:Time><tt:Hour>%d</tt:Hour><tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second></tt:Time>"
                    "<tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day></tt:Date>"
                "</tt:UTCDateTime>"
            "</tds:SystemDateAndTime>"
        "</tds:GetSystemDateAndTimeResponse>"
    "</s:Body>"
"</s:Envelope>";

const char *GET_DATE_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Header>"
        "<a:Action xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse</a:Action>"
        "<a:RelatesTo xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">%s</a:RelatesTo>"
    "</s:Header>"
    "<s:Body>"
        "<tds:GetSystemDateAndTimeResponse>"
            "<tds:SystemDateAndTime>"
                "<tt:DateTimeType>Manual</tt:DateTimeType>"
                "<tt:DaylightSavings>false</tt:DaylightSavings>"
                "<tt:TimeZone><tt:TZ>GMT+05:30</tt:TZ></tt:TimeZone>"
                "<tt:UTCDateTime>"
                    "<tt:Time><tt:Hour>%d</tt:Hour><tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second></tt:Time>"
                    "<tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day></tt:Date>"
                "</tt:UTCDateTime>"
            "</tds:SystemDateAndTime>"
        "</tds:GetSystemDateAndTimeResponse>"
    "</s:Body>"
"</s:Envelope>";


const char *GET_DEVICE_INFO_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Header>"
    "<a:Action>http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse</a:Action>"
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
    
    const char *GET_DNS_RESPONSE_TEMPLATE = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
        "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
        "<s:Body>"
            "<tds:GetDNSResponse>"
                "<tds:DNSInformation>"
                    "<tt:FromDHCP>%s</tt:FromDHCP>"
                    "<tt:SearchDomain>%s</tt:SearchDomain>"
                    "<tt:DNSManual>"
                        "<tt:Type>%s</tt:Type>"
                        "<tt:IPv4Address>%s</tt:IPv4Address>"
                    "</tt:DNSManual>"
                "</tds:DNSInformation>"
            "</tds:GetDNSResponse>"
        "</s:Body>"
        "</s:Envelope>";
        
        const char *GET_NET_GATEWAY_TEMPLATE = 
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
            "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
            "<s:Body>"
                "<tds:GetNetworkDefaultGatewayResponse>"
                    "<tds:NetworkGateway>"
                        "<tt:IPv4Address>%s</tt:IPv4Address>"
                    "</tds:NetworkGateway>"
                "</tds:GetNetworkDefaultGatewayResponse>"
            "</s:Body>"
            "</s:Envelope>";
        
        const char *GET_NET_INTERFACES_TEMPLATE = 
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
            "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
            "<s:Body>"
                "<tds:GetNetworkInterfacesResponse>"
                    "<tds:NetworkInterfaces token=\"%s\">"
                        "<tds:Enabled>true</tds:Enabled>"
                        "<tds:Info>"
                            "<tt:Name>%s</tt:Name>"
                            "<tt:HwAddress>%s</tt:HwAddress>"
                            "<tt:MTU>%d</tt:MTU>"
                        "</tds:Info>"
                        "<tds:IPv4>"
                            "<tt:Enabled>true</tt:Enabled>"
                            "<tt:Config>"
                                "<tt:Manual>"
                                    "<tt:Address>%s</tt:Address>"
                                    "<tt:PrefixLength>%d</tt:PrefixLength>"
                                "</tt:Manual>"
                                "<tt:DHCP>%s</tt:DHCP>"
                            "</tt:Config>"
                        "</tds:IPv4>"
                    "</tds:NetworkInterfaces>"
                "</tds:GetNetworkInterfacesResponse>"
            "</s:Body>"
            "</s:Envelope>";