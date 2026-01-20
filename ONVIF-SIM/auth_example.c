#include <stdio.h>
#include <string.h>
#include "auth.h"

/**
 * Example: How to use ONVIF authentication
 * 
 * This program demonstrates creating authenticated ONVIF requests
 * using WS-Security UsernameToken authentication.
 */

int main(void) {
    /* Example 1: Generate just the authentication header */
    printf("=== Example 1: Authentication Header Only ===\n\n");
    
    char auth_header[2048];
    if (generate_auth_header("admin", "password", auth_header, sizeof(auth_header)) == 0) {
        printf("Authentication Header:\n%s\n\n", auth_header);
    } else {
        printf("Failed to generate authentication header\n");
        return 1;
    }
    
    /* Example 2: Build complete authenticated SOAP request */
    printf("=== Example 2: Complete Authenticated Request ===\n\n");
    
    /* SOAP body for GetDeviceInformation request */
    const char *get_device_info = 
        "<tds:GetDeviceInformation xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>";
    
    char soap_request[4096];
    if (build_authenticated_request("admin", "password", get_device_info, 
                                   soap_request, sizeof(soap_request)) == 0) {
        printf("Complete SOAP Request:\n%s\n\n", soap_request);
    } else {
        printf("Failed to build authenticated request\n");
        return 1;
    }
    
    /* Example 3: Different request types */
    printf("=== Example 3: GetSystemDateAndTime Request ===\n\n");
    
    const char *get_date_time = 
        "<tds:GetSystemDateAndTime xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/>";
    
    char date_request[4096];
    if (build_authenticated_request("admin", "password", get_date_time,
                                   date_request, sizeof(date_request)) == 0) {
        printf("Request created successfully (%zu bytes)\n", strlen(date_request));
        printf("Ready to send via HTTP POST to: http://<device-ip>/onvif/device_service\n\n");
    }
    
    /* Example 4: Media profile request */
    printf("=== Example 4: GetProfiles Request (Media) ===\n\n");
    
    const char *get_profiles = 
        "<trt:GetProfiles xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"/>";
    
    char profiles_request[4096];
    if (build_authenticated_request("admin", "password", get_profiles,
                                   profiles_request, sizeof(profiles_request)) == 0) {
        printf("Request created successfully (%zu bytes)\n", strlen(profiles_request));
        printf("Ready to send via HTTP POST to: http://<device-ip>/onvif/media_service\n\n");
    }
    
    printf("=== Usage Summary ===\n\n");
    printf("To send authenticated requests to an ONVIF device:\n");
    printf("1. Build the authenticated request using build_authenticated_request()\n");
    printf("2. Send it via HTTP POST to the appropriate endpoint\n");
    printf("3. Set Content-Type header to: application/soap+xml\n");
    printf("4. Set Accept header to: application/soap+xml\n\n");
    
    printf("Common ONVIF endpoints:\n");
    printf("- Device Service:  http://<ip>:<port>/onvif/device_service\n");
    printf("- Media Service:   http://<ip>:<port>/onvif/media_service\n");
    printf("- PTZ Service:     http://<ip>:<port>/onvif/ptz_service\n");
    printf("- Imaging Service: http://<ip>:<port>/onvif/imaging_service\n\n");
    
    return 0;
}
