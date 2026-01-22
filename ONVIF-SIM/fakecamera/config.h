/*
 * config.h - Shared configuration for ONVIF Fake Camera
 * 
 * This header centralizes port configuration used across:
 *   - discovery_server.h (UDP multicast discovery)
 *   - auth_server.h (TCP HTTP server for authentication)
 *   - main.c (orchestration)
 */

#ifndef CONFIG_H
#define CONFIG_H

/* 
 * CAMERA_HTTP_PORT: The TCP port where the camera's HTTP/SOAP services run.
 * 
 * Per ONVIF specification:
 * - Discovery (WS-Discovery) uses UDP port 3702 (fixed, multicast)
 * - Device services (GetDeviceInformation, etc.) use HTTP over TCP
 * - The HTTP port is flexible and advertised in discovery XAddrs
 * 
 * This port is:
 * - Used in discovery responses to tell clients where to connect
 * - Used by auth_server to bind the HTTP server
 */
#define CAMERA_HTTP_PORT 8080

/*
 * DISCOVERY_PORT: The WS-Discovery multicast port (fixed per spec)
 */
#define DISCOVERY_PORT 3702

/*
 * MULTICAST_ADDR: WS-Discovery multicast address (fixed per spec)
 */
#define MULTICAST_ADDR "239.255.255.250"

/*
 * Buffer and credential limits
 */
#define BUFFER_SIZE 65536
#define MAX_CREDENTIALS 1024

/*
 * Camera identification
 */
#define CAMERA_NAME "Videonetics_Camera_Emulator"

#endif /* CONFIG_H */
