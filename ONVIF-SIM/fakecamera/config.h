#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Default port if config.xml cannot be read
#define DEFAULT_CAMERA_HTTP_PORT 8080

// Global variable to hold the configured port
static int g_camera_http_port = 0;
static int g_port_initialized = 0;

// Read the server port from config.xml
// Returns the port number, or DEFAULT_CAMERA_HTTP_PORT if config cannot be read
static int read_config_port(void) {
    if (g_port_initialized) {
        return g_camera_http_port;
    }

    FILE *fp = fopen("config.xml", "r");
    if (!fp) {
        // Try parent directory
        fp = fopen("../config.xml", "r");
    }
    
    if (!fp) {
        g_camera_http_port = DEFAULT_CAMERA_HTTP_PORT;
        g_port_initialized = 1;
        printf("[CONFIG] config.xml not found, using default port: %d\n", g_camera_http_port);
        return g_camera_http_port;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *port_start = strstr(line, "<server_port>");
        if (port_start) {
            port_start += strlen("<server_port>");
            char *port_end = strstr(port_start, "</server_port>");
            if (port_end) {
                *port_end = '\0';
                g_camera_http_port = atoi(port_start);
                if (g_camera_http_port <= 0 || g_camera_http_port > 65535) {
                    g_camera_http_port = DEFAULT_CAMERA_HTTP_PORT;
                }
                g_port_initialized = 1;
                fclose(fp);
                printf("[CONFIG] Loaded server_port from config.xml: %d\n", g_camera_http_port);
                return g_camera_http_port;
            }
        }
    }

    fclose(fp);
    g_camera_http_port = DEFAULT_CAMERA_HTTP_PORT;
    g_port_initialized = 1;
    printf("[CONFIG] server_port not found in config.xml, using default: %d\n", g_camera_http_port);
    return g_camera_http_port;
}

// Get the camera HTTP port (reads from config on first call, cached thereafter)
static int get_camera_http_port(void) {
    if (!g_port_initialized) {
        return read_config_port();
    }
    return g_camera_http_port;
}

#endif // CONFIG_H
