#include "discovery_server.h"
#include "auth_server.h"
#include <pthread.h>

// Define PROBE_MATCH_TEMPLATE that is declared extern in config.h
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

int main(void) {
  pthread_t t_disc, tcpserv; // t_auth;
  // t_auth to be later changed as tcp_server *IMPORTANT*

  if (pthread_create(&t_disc, 
    NULL, discovery, NULL) != 0) {
    perror("pthread_create discovery");
    return 1;
  }

  if (pthread_create(&tcpserv, 
    NULL, tcpserver1, NULL) != 0) {
    perror("pthread_create auth");
    pthread_cancel(t_disc);
    return 1;
  }

  printf("Both servers running. Press Ctrl+C to stop.\n");

  pthread_join(t_disc, NULL);
  pthread_join(tcpserv, NULL);

  printf("Clean exit.\n");
  return 0;
}