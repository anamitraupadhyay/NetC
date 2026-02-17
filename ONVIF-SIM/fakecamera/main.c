#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include "discovery_server.h"
#include "auth_server.h"

int main(void) {
    printf("[System] Starting ONVIF Camera Simulator...\n");

    // Load application config (server port, device identity, auth mode)
    config cfg = {0};
    if (!load_config("config.xml", &cfg)) {
        fprintf(stderr, "[System] Error: Could not load config.xml. Using defaults.\n");
    }

    // Start servers — both bind to all NICs (INADDR_ANY)
    pthread_t t_disc, tcpserv;

    if (pthread_create(&t_disc, NULL, discovery, NULL) != 0) {
        perror("pthread_create discovery");
        return 1;
    }

    if (pthread_create(&tcpserv, NULL, tcpserver, NULL) != 0) {
        perror("pthread_create tcp");
        pthread_cancel(t_disc);
        return 1;
    }

    printf("[System] Services are running on all network interfaces.\n");
    printf("   > Discovery: UDP %d\n", DISCOVERY_PORT);
    printf("   > SOAP API:  TCP %d\n", cfg.server_port);

    pthread_join(t_disc, NULL);
    pthread_join(tcpserv, NULL);

    printf("[System] Clean exit.\n");
    return 0;
}