/**
 * @file config.h
 * @brief Configuration parsing for ONVIF Camera Emulator
 * 
 * This file provides configuration loading using libxml2 for reliable XML parsing.
 * Falls back to simple parsing if libxml2 is not available.
 * 
 * Configuration file: config.xml
 * Format:
 * <?xml version="1.0" encoding="utf-8"?>
 * <config>
 *     <server_port>8080</server_port>
 *     <device>
 *         <manufacturer>Videonetics</manufacturer>
 *         <model>Camera_Emulator</model>
 *     </device>
 * </config>
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Check if we should use libxml2 (define USE_LIBXML2 to enable)
#ifdef USE_LIBXML2
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif

// Default values
#define DEFAULT_CAMERA_HTTP_PORT 8080
#define DEFAULT_MANUFACTURER "Videonetics"
#define DEFAULT_MODEL "Videonetics_Camera_Emulator"
#define DEFAULT_FIRMWARE_VERSION "10.0"
#define DEFAULT_SERIAL_NUMBER "1"
#define DEFAULT_HARDWARE_ID "1.0"

// Configuration structure
typedef struct {
    int server_port;
    char manufacturer[128];
    char model[128];
    char firmware_version[64];
    char serial_number[64];
    char hardware_id[64];
} device_config_t;

// Global configuration instance
static device_config_t g_config = {0};
static int g_config_initialized = 0;

#ifdef USE_LIBXML2
/**
 * @brief Extract text content from XML node by element name (libxml2 version)
 */
static int xml_get_element_text(xmlNodePtr parent, const char *element_name, 
                                 char *output, size_t output_size) {
    for (xmlNodePtr cur = parent->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && 
            strcmp((const char *)cur->name, element_name) == 0) {
            xmlChar *content = xmlNodeGetContent(cur);
            if (content) {
                size_t len = strlen((const char *)content);
                if (len >= output_size) len = output_size - 1;
                memcpy(output, content, len);
                output[len] = '\0';
                xmlFree(content);
                return 1;
            }
        }
    }
    return 0;
}

/**
 * @brief Load configuration using libxml2
 */
static int load_config_libxml2(const char *filename, device_config_t *config) {
    xmlDocPtr doc = xmlReadFile(filename, NULL, XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        return 0;
    }
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root || strcmp((const char *)root->name, "config") != 0) {
        xmlFreeDoc(doc);
        return 0;
    }
    
    char buf[256];
    
    // Read server_port
    if (xml_get_element_text(root, "server_port", buf, sizeof(buf))) {
        config->server_port = atoi(buf);
        if (config->server_port <= 0 || config->server_port > 65535) {
            config->server_port = DEFAULT_CAMERA_HTTP_PORT;
        }
    }
    
    // Find device element
    for (xmlNodePtr cur = root->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && 
            strcmp((const char *)cur->name, "device") == 0) {
            xml_get_element_text(cur, "manufacturer", config->manufacturer, 
                                sizeof(config->manufacturer));
            xml_get_element_text(cur, "model", config->model, 
                                sizeof(config->model));
            xml_get_element_text(cur, "firmware_version", config->firmware_version, 
                                sizeof(config->firmware_version));
            xml_get_element_text(cur, "serial_number", config->serial_number, 
                                sizeof(config->serial_number));
            xml_get_element_text(cur, "hardware_id", config->hardware_id, 
                                sizeof(config->hardware_id));
            break;
        }
    }
    
    xmlFreeDoc(doc);
    printf("[CONFIG] Loaded config using libxml2 from %s\n", filename);
    return 1;
}
#endif

/**
 * @brief Load configuration using simple string parsing (fallback)
 * 
 * This is a simple parser that works without libxml2 dependency.
 * It handles basic XML but is not as robust as libxml2.
 */
static int load_config_simple(const char *filename, device_config_t *config) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return 0;
    }
    
    char line[512];
    char *content_start, *content_end;
    
    while (fgets(line, sizeof(line), fp)) {
        // Parse server_port
        if ((content_start = strstr(line, "<server_port>")) != NULL) {
            content_start += strlen("<server_port>");
            if ((content_end = strstr(content_start, "</server_port>")) != NULL) {
                *content_end = '\0';
                config->server_port = atoi(content_start);
                if (config->server_port <= 0 || config->server_port > 65535) {
                    config->server_port = DEFAULT_CAMERA_HTTP_PORT;
                }
            }
        }
        
        // Parse manufacturer
        if ((content_start = strstr(line, "<manufacturer>")) != NULL) {
            content_start += strlen("<manufacturer>");
            if ((content_end = strstr(content_start, "</manufacturer>")) != NULL) {
                size_t len = content_end - content_start;
                if (len >= sizeof(config->manufacturer)) len = sizeof(config->manufacturer) - 1;
                memcpy(config->manufacturer, content_start, len);
                config->manufacturer[len] = '\0';
            }
        }
        
        // Parse model
        if ((content_start = strstr(line, "<model>")) != NULL) {
            content_start += strlen("<model>");
            if ((content_end = strstr(content_start, "</model>")) != NULL) {
                size_t len = content_end - content_start;
                if (len >= sizeof(config->model)) len = sizeof(config->model) - 1;
                memcpy(config->model, content_start, len);
                config->model[len] = '\0';
            }
        }
        
        // Parse firmware_version
        if ((content_start = strstr(line, "<firmware_version>")) != NULL) {
            content_start += strlen("<firmware_version>");
            if ((content_end = strstr(content_start, "</firmware_version>")) != NULL) {
                size_t len = content_end - content_start;
                if (len >= sizeof(config->firmware_version)) len = sizeof(config->firmware_version) - 1;
                memcpy(config->firmware_version, content_start, len);
                config->firmware_version[len] = '\0';
            }
        }
        
        // Parse serial_number
        if ((content_start = strstr(line, "<serial_number>")) != NULL) {
            content_start += strlen("<serial_number>");
            if ((content_end = strstr(content_start, "</serial_number>")) != NULL) {
                size_t len = content_end - content_start;
                if (len >= sizeof(config->serial_number)) len = sizeof(config->serial_number) - 1;
                memcpy(config->serial_number, content_start, len);
                config->serial_number[len] = '\0';
            }
        }
        
        // Parse hardware_id
        if ((content_start = strstr(line, "<hardware_id>")) != NULL) {
            content_start += strlen("<hardware_id>");
            if ((content_end = strstr(content_start, "</hardware_id>")) != NULL) {
                size_t len = content_end - content_start;
                if (len >= sizeof(config->hardware_id)) len = sizeof(config->hardware_id) - 1;
                memcpy(config->hardware_id, content_start, len);
                config->hardware_id[len] = '\0';
            }
        }
    }
    
    fclose(fp);
    printf("[CONFIG] Loaded config using simple parser from %s\n", filename);
    return 1;
}

/**
 * @brief Set default configuration values
 */
static void set_default_config(device_config_t *config) {
    config->server_port = DEFAULT_CAMERA_HTTP_PORT;
    strncpy(config->manufacturer, DEFAULT_MANUFACTURER, sizeof(config->manufacturer) - 1);
    strncpy(config->model, DEFAULT_MODEL, sizeof(config->model) - 1);
    strncpy(config->firmware_version, DEFAULT_FIRMWARE_VERSION, sizeof(config->firmware_version) - 1);
    strncpy(config->serial_number, DEFAULT_SERIAL_NUMBER, sizeof(config->serial_number) - 1);
    strncpy(config->hardware_id, DEFAULT_HARDWARE_ID, sizeof(config->hardware_id) - 1);
}

/**
 * @brief Load configuration from config.xml
 * 
 * Tries to load from:
 * 1. ./config.xml
 * 2. ../config.xml
 * 
 * Uses libxml2 if USE_LIBXML2 is defined, otherwise falls back to simple parsing.
 * Sets default values for any missing configuration items.
 */
static void load_config(void) {
    if (g_config_initialized) {
        return;
    }
    
    // Set defaults first
    set_default_config(&g_config);
    
    const char *config_files[] = {"config.xml", "../config.xml", NULL};
    int loaded = 0;
    
    for (int i = 0; config_files[i] && !loaded; i++) {
#ifdef USE_LIBXML2
        loaded = load_config_libxml2(config_files[i], &g_config);
#else
        loaded = load_config_simple(config_files[i], &g_config);
#endif
    }
    
    if (!loaded) {
        printf("[CONFIG] No config.xml found, using defaults\n");
    }
    
    printf("[CONFIG] server_port=%d, manufacturer=%s, model=%s\n",
           g_config.server_port, g_config.manufacturer, g_config.model);
    
    g_config_initialized = 1;
}

/**
 * @brief Get the camera HTTP port from configuration
 */
static int get_camera_http_port(void) {
    if (!g_config_initialized) {
        load_config();
    }
    return g_config.server_port;
}

/**
 * @brief Get the device configuration
 */
static device_config_t* get_device_config(void) {
    if (!g_config_initialized) {
        load_config();
    }
    return &g_config;
}

#endif // CONFIG_H
