#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include <stdint.h>

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
};
/*datafromxml placing here was giving error 
so instead declared beside struct*/

typedef struct datafromxml config;

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
    "<d:Scopes>onvif://www.onvif.org/name/%s "
    "onvif://www.onvif.org/manufacturer/%s "
    "onvif://www.onvif.org/hardware/%s "
    "onvif://www.onvif.org/location/%s "
    "onvif://www.onvif.org/profile/%s "
    "onvif://www.onvif.org/type/%s</d:Scopes>"
    "<d:XAddrs>http://%s:%d/onvif/device_service</d:XAddrs>"
    "<d:MetadataVersion>1</d:MetadataVersion>"
    "</d:ProbeMatch>"
    "</d:ProbeMatches>"
    "</s:Body>"
    "</s:Envelope>";

#endif // CONFIG_H