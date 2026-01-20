#ifndef ONVIF_AUTH_H
#define ONVIF_AUTH_H

#include <stddef.h>

/**
 * Generate WS-Security UsernameToken authentication header for ONVIF
 * 
 * @param username The username for authentication
 * @param password The password for authentication
 * @param buffer Output buffer for the authentication header
 * @param buffer_size Size of the output buffer
 * @return 0 on success, -1 on error
 */
int generate_auth_header(const char *username, const char *password, 
                        char *buffer, size_t buffer_size);

/**
 * Build authenticated SOAP request with WS-Security header
 * 
 * @param username The username for authentication
 * @param password The password for authentication
 * @param soap_body The SOAP body content
 * @param buffer Output buffer for complete SOAP message
 * @param buffer_size Size of the output buffer
 * @return 0 on success, -1 on error
 */
int build_authenticated_request(const char *username, const char *password,
                               const char *soap_body, char *buffer, 
                               size_t buffer_size);

#endif /* ONVIF_AUTH_H */
