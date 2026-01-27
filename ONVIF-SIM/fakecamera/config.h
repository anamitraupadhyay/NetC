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
extern const char *PROBE_MATCH_TEMPLATE;

#endif /* CONFIG_H */