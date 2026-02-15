#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <ifaddrs.h>

#define DISCOVERY_PORT      3702
#define MULTICAST_ADDR      "239.255.255.250"
#define CAMERA_NAME         "Videonetics_Camera_Emulator"
#define CAMERA_HTTP_PORT    8080 // not udp multicast, for the tcp server that
                                // handle the all dedicated connectivities
#define BUFFER_SIZE         65536


struct datafromxml{
    uint16_t server_port;
    char manufacturer[64];
    char model[64];
    float firmware_version;
    char serial_number[32];
    float hardware_id;
    char type[64];
    char profile[64];
    char hardware[64];
    char location[64];
    int auth_enabled;
    char hostname[64];
    char fromdhcp[8];
    char scopes[1024];
};
/*datafromxml placing here was giving error 
so instead declared beside struct*/

typedef struct datafromxml config;


typedef struct{
    char name[32];//eth0, eth1 ...
    char ip[64];//192.168.1.5, ...
    char mac[64];// "AA BB CC"
    int mtu;//1500
    int prefix_len;//24
    int i_up;// 1 or 0
}Interfacedata;


const char *NET_IF_HEADER = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Body>"
        "<tds:GetNetworkInterfacesResponse>";

// This template is reused for EVERY interface found
const char *NET_IF_ITEM = 
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
        "</tds:NetworkInterfaces>";

const char *NET_IF_FOOTER = 
        "</tds:GetNetworkInterfacesResponse>"
    "</s:Body>"
    "</s:Envelope>";



// copied probe match template
const char *PROBE_MATCH_TEMPLATE =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "
    "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<s:Header>"
    "<a:Action "
    "s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/"
    "ProbeMatches</a:Action>"
    "<a:MessageID>%s</a:MessageID>"
    "<a:RelatesTo>%s</a:RelatesTo>"
    "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</"
    "a:To>"
    "</s:Header>"
    "<s:Body>"
    "<d:ProbeMatches>"
    "<d:ProbeMatch>"
    "<a:EndpointReference>"
    "<a:Address>urn:uuid:%s</a:Address>"
    "</a:EndpointReference>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "<d:Scopes>%s</d:Scopes>"
    "<d:XAddrs>%s</d:XAddrs>"
    "<d:MetadataVersion>1</d:MetadataVersion>"
    "</d:ProbeMatch>"
    "</d:ProbeMatches>"
    "</s:Body>"
    "</s:Envelope>";

    const char *GET_HOSTNAME_RESPONSE_TEMPLATE = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">"
        "<s:Header>"
            "<a:Action>http://www.onvif.org/ver10/device/wsdl/GetHostnameResponse</a:Action>"
            "<a:RelatesTo>%s</a:RelatesTo>"
        "</s:Header>"
        "<s:Body>"
            "<tds:GetHostnameResponse>"
                "<tds:HostnameInformation>"
                    "<tds:FromDHCP>%s</tds:FromDHCP>"
                    "<tds:Name>%s</tds:Name>"
                "</tds:HostnameInformation>"
            "</tds:GetHostnameResponse>"
        "</s:Body>"
        "</s:Envelope>";

    const char *WS_DISCOVERY_BYE_TEMPLATE =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">"
        "<s:Header>"
            "<a:Action s:mustUnderstand=\"1\">"
                "http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye"
            "</a:Action>"
            "<a:MessageID>urn:uuid:%s</a:MessageID>"
            "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
        "</s:Header>"
        "<s:Body>"
            "<d:Bye>"
                "<a:EndpointReference>"
                    "<a:Address>urn:uuid:%s</a:Address>"
                "</a:EndpointReference>"
            "</d:Bye>"
        "</s:Body>"
        "</s:Envelope>";

#endif /* CONFIG_H */
