#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include "discovery_server.h"
#include "auth_server.h"

// Reconcile Actual (OS) state vs Desired (config.xml) state at startup.
// Rule: If they differ, ActualState overwrites DesiredState to prevent
// the device from being unreachable due to a config typo.
static void reconcile_actual_vs_desired(void) {
    config cfg = {0};
    if (!load_config("config.xml", &cfg)) {
        fprintf(stderr, "[System] Error: Could not load config.xml. Using defaults.\n");
        return;
    }

    // --- IP Reconciliation ---
    char actual_ip[64] = {0};
    getlocalip(actual_ip, sizeof(actual_ip));
    if (actual_ip[0] && strcmp(actual_ip, "127.0.0.1") != 0) {
        if (cfg.ip_addr[0] && strcmp(actual_ip, cfg.ip_addr) != 0) {
            printf("[System] IP Mismatch (Config: %s vs OS: %s). Syncing config to actual.\n",
                   cfg.ip_addr, actual_ip);
            // setdnsinxml is a generic XML tag value setter (not DNS-specific)
            //setdnsinxml(actual_ip, "<addr>", "</addr>");
            strcpy(actual_ip, cfg.ip_addr);
        } else {
            printf("[System] IP consistent: %s\n", actual_ip);
        }
    } else {
        printf("[System] Could not determine actual IP, skipping IP reconciliation\n");
    }

    // --- Hostname Reconciliation ---
    char current_hostname[HOST_NAME_MAX + 1];
    if (gethostname(current_hostname, sizeof(current_hostname)) == 0) {
        if (cfg.hostname[0] && strcmp(cfg.hostname, current_hostname) != 0) {
            printf("[System] Hostname Mismatch (Config: %s vs OS: %s). Syncing config to actual.\n",
                   cfg.hostname, current_hostname);
            sethostnameinxml(current_hostname);
        } else {
            printf("[System] Hostname consistent: %s\n", current_hostname);
        }
    } else {
        printf("[System] Could not determine hostname, skipping hostname reconciliation\n");
    }
}

int main(void) {
    printf("[System] Starting ONVIF Camera Simulator...\n");

    // 1. Reconcile actual OS state vs desired config state before starting servers
    reconcile_actual_vs_desired();

    // 2. Load config for startup info
    config cfg = {0};
    load_config("config.xml", &cfg);

    // 3. Start Servers
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

    printf("[System] Services are running.\n");
    printf("   > Discovery: UDP %d\n", DISCOVERY_PORT);
    printf("   > SOAP API:  TCP %d\n", cfg.server_port);

    pthread_join(t_disc, NULL);
    pthread_join(tcpserv, NULL);

    printf("[System] Clean exit.\n");
    return 0;
}