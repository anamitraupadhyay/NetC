#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "auth.h"

/**
 * Simple integration example: Discover camera and send authenticated request
 * 
 * This demonstrates how to combine the discovery functionality from 
 * camdis.c/discovery_server.c with the authentication from auth.c
 */

void print_authenticated_request_for_device(const char *device_ip, 
                                           const char *username, 
                                           const char *password) {
    printf("\n=== Authenticated Request for Device: %s ===\n\n", device_ip);
    
    /* Example 1: Get Device Information */
    char request[4096];
    const char *get_device_info = 
        "<tds:GetDeviceInformation xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>";
    
    if (build_authenticated_request(username, password, get_device_info,
                                   request, sizeof(request)) == 0) {
        printf("Request Type: GetDeviceInformation\n");
        printf("Endpoint: http://%s:8080/onvif/device_service\n", device_ip);
        printf("Method: POST\n");
        printf("Content-Type: application/soap+xml; charset=utf-8\n");
        printf("\nRequest Body:\n%s\n", request);
        
        printf("\n--- To send this request using curl: ---\n");
        printf("curl -X POST \\\n");
        printf("  -H \"Content-Type: application/soap+xml; charset=utf-8\" \\\n");
        printf("  -d '%s' \\\n", request);
        printf("  http://%s:8080/onvif/device_service\n", device_ip);
    }
}

int main(void) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║   ONVIF Authentication Integration Example                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    printf("\nThis example shows how to use authentication after discovering\n");
    printf("an ONVIF camera using the discovery_server.c or camdis.c code.\n");
    
    /* Simulated discovered device */
    const char *discovered_ip = "192.168.1.100";
    const char *device_name = "FakeCamera";
    
    printf("\n--- Step 1: Device Discovery ---\n");
    printf("(Using discovery_server.c or camdis.c)\n");
    printf("Discovered device: %s at %s\n", device_name, discovered_ip);
    
    printf("\n--- Step 2: Authenticate and Query ---\n");
    
    /* Generate authenticated requests */
    print_authenticated_request_for_device(discovered_ip, "admin", "password");
    
    printf("\n\n--- Integration Flow ---\n");
    printf("1. Run camdis to discover cameras on network\n");
    printf("2. Extract XAddrs URL from discovery response\n");
    printf("3. Use auth.c functions to create authenticated requests\n");
    printf("4. Send HTTP POST with SOAP request to device\n");
    printf("5. Parse SOAP response to get device information\n");
    
    printf("\n--- Example Integration Code ---\n");
    printf("// After discovering device with IP from camdis.c:\n");
    printf("#include \"auth.h\"\n\n");
    printf("char request[4096];\n");
    printf("const char *body = \"<tds:GetDeviceInformation "
           "xmlns:tds=\\\"http://www.onvif.org/ver10/device/wsdl\\\"/>\";\n");
    printf("build_authenticated_request(\"admin\", \"password\", body, request, sizeof(request));\n");
    printf("// Now send 'request' via HTTP POST to the device\n");
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║   See README_AUTH.md for complete documentation              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    return 0;
}
