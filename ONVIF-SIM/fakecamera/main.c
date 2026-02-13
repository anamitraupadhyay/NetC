#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include "discovery_server.h"
#include "auth_server.h"

// Apply config.xml network settings to the OS at boot.
// config.xml is the "Admin State" (source of truth). The OS must match it.
// This prevents split-brain where the OS reverts to defaults on reboot
// while config.xml retains user-configured values.
static void apply_boot_config(config *cfg) {
    printf("[Boot] Enforcing Network Configuration from XML...\n");

    // Resolve interface name from config (fall back to first physical interface)
    char iface[32] = {0};
    if (cfg->interface_token[0] && is_valid_iface_name(cfg->interface_token)) {
        strncpy(iface, cfg->interface_token, sizeof(iface) - 1);
    } else {
        // Auto-detect: use the first non-loopback, non-virtual interface
        Interfacedata scan[3];
        int n = scan_interfaces(scan, 3);
        if (n > 0) {
            strncpy(iface, scan[0].name, sizeof(iface) - 1);
        }
    }

    if (!iface[0]) {
        fprintf(stderr, "[Boot] No valid network interface found. Skipping network enforcement.\n");
        return;
    }

    printf("[Boot] Target interface: %s\n", iface);

    // --- DHCP vs Static ---
    if (cfg->fromdhcp[0] && strcmp(cfg->fromdhcp, "true") == 0) {
        printf("[Boot] DHCP mode: requesting lease on %s\n", iface);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "dhclient -r %s 2>/dev/null; dhclient -nw %s", iface, iface);
        int ret = system(cmd);
        if (ret != 0) {
            fprintf(stderr, "[Boot] dhclient failed (exit %d, requires root)\n", ret);
        }
    } else {
        // Static IP enforcement
        if (cfg->ip_addr[0] && is_valid_ipv4(cfg->ip_addr)) {
            char prefix_str[8];
            snprintf(prefix_str, sizeof(prefix_str), "%d", cfg->prefix_length > 0 ? cfg->prefix_length : 24);

            char actual_ip[64] = {0};
            getlocalip(actual_ip, sizeof(actual_ip));

            if (actual_ip[0] && strcmp(actual_ip, cfg->ip_addr) == 0) {
                printf("[Boot] IP already matches config: %s\n", cfg->ip_addr);
            } else {
                printf("[Boot] IP Mismatch (Config: %s vs OS: %s). Applying config.\n",
                       cfg->ip_addr, actual_ip[0] ? actual_ip : "(none)");
                char cmd[512];
                snprintf(cmd, sizeof(cmd),
                         "ip addr flush dev %s 2>/dev/null && "
                         "ip addr add %s/%s broadcast + dev %s && "
                         "ip link set %s up",
                         iface, cfg->ip_addr, prefix_str, iface, iface);
                int ret = system(cmd);
                if (ret != 0) {
                    fprintf(stderr, "[Boot] Failed to apply IP (exit %d, requires root)\n", ret);
                }
            }
        } else {
            printf("[Boot] No valid IP in config.xml, skipping IP enforcement\n");
        }
    }

    // --- Gateway enforcement ---
    if (cfg->gateway[0] && is_valid_ipv4(cfg->gateway)) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "ip route del default 2>/dev/null; ip route add default via %s dev %s",
                 cfg->gateway, iface);
        int ret = system(cmd);
        if (ret != 0) {
            fprintf(stderr, "[Boot] Failed to apply gateway (exit %d, requires root)\n", ret);
        } else {
            printf("[Boot] Default gateway set to %s\n", cfg->gateway);
        }
    }

    // --- Hostname enforcement ---
    if (cfg->hostname[0]) {
        char current_hostname[HOST_NAME_MAX + 1];
        if (gethostname(current_hostname, sizeof(current_hostname)) == 0 &&
            strcmp(cfg->hostname, current_hostname) != 0) {
            printf("[Boot] Hostname Mismatch (Config: %s vs OS: %s). Applying config.\n",
                   cfg->hostname, current_hostname);
            if (sethostname(cfg->hostname, strlen(cfg->hostname)) != 0) {
                perror("[Boot] Failed to set hostname (requires root)");
            }
        } else {
            printf("[Boot] Hostname consistent: %s\n", cfg->hostname);
        }
    }

    printf("[Boot] Network enforcement complete.\n");
}

int main(void) {
    printf("[System] Starting ONVIF Camera Simulator...\n");

    // 1. Load config and enforce it onto the OS (config.xml is the master)
    config cfg = {0};
    if (!load_config("config.xml", &cfg)) {
        fprintf(stderr, "[System] Error: Could not load config.xml. Using defaults.\n");
    }
    apply_boot_config(&cfg);

    // 2. Start Servers
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