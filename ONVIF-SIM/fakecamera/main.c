#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include "discovery_server.h"
#include "auth_server.h"

// Check if a named interface exists on this machine by scanning OS interfaces.
// Returns 1 if found, 0 if not.
static int iface_exists(const char *name) {
    Interfacedata scan[8];
    int n = scan_interfaces(scan, 8);
    for (int i = 0; i < n; i++) {
        if (strcmp(scan[i].name, name) == 0) return 1;
    }
    return 0;
}

// Apply config.xml network settings to the OS at boot.
// config.xml is the "Admin State" (source of truth). The OS must match it.
// Safety: if config.xml references an interface or IP that doesn't belong to
// this machine (e.g., copied from another device), the function falls back to
// auto-detected OS values and updates config.xml to match reality.
static void apply_boot_config(config *cfg) {
    printf("[Boot] Enforcing Network Configuration from XML...\n");

    // --- Resolve & validate interface name ---
    char iface[32] = {0};
    int iface_from_config = 0;

    if (cfg->interface_token[0] && is_valid_iface_name(cfg->interface_token)) {
        if (iface_exists(cfg->interface_token)) {
            strncpy(iface, cfg->interface_token, sizeof(iface) - 1);
            iface_from_config = 1;
        } else {
            fprintf(stderr, "[Boot] WARNING: Config interface '%s' not found on this machine.\n",
                    cfg->interface_token);
        }
    }

    // Fallback: auto-detect the first physical interface
    if (!iface_from_config) {
        Interfacedata scan[3];
        int n = scan_interfaces(scan, 3);
        if (n > 0) {
            strncpy(iface, scan[0].name, sizeof(iface) - 1);
            printf("[Boot] FALLBACK: Using auto-detected interface '%s'.\n", iface);
            // Update config.xml so it matches this machine
            setdnsinxml(iface, "<interface_token>", "</interface_token>");
        }
    }

    if (!iface[0]) {
        fprintf(stderr, "[Boot] No valid network interface found. Skipping network enforcement.\n");
        return;
    }

    printf("[Boot] Target interface: %s\n", iface);

    // Save current OS IP before any changes (for rollback)
    char saved_ip[64] = {0};
    getlocalip(saved_ip, sizeof(saved_ip));

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

            if (saved_ip[0] && strcmp(saved_ip, cfg->ip_addr) == 0) {
                printf("[Boot] IP already matches config: %s\n", cfg->ip_addr);
            } else {
                printf("[Boot] IP Mismatch (Config: %s vs OS: %s). Applying config.\n",
                       cfg->ip_addr, saved_ip[0] ? saved_ip : "(none)");
                char cmd[512];
                snprintf(cmd, sizeof(cmd),
                         "ip addr flush dev %s 2>/dev/null && "
                         "ip addr add %s/%s broadcast + dev %s && "
                         "ip link set %s up",
                         iface, cfg->ip_addr, prefix_str, iface, iface);
                int ret = system(cmd);

                if (ret != 0) {
                    // Command failed — revert to previous OS IP
                    fprintf(stderr, "[Boot] Failed to apply IP (exit %d). Keeping OS IP.\n", ret);
                    if (saved_ip[0] && is_valid_ipv4(saved_ip)) {
                        setdnsinxml(saved_ip, "<addr>", "</addr>");
                        printf("[Boot] FALLBACK: Updated config.xml addr to OS IP %s\n", saved_ip);
                    }
                } else if (cfg->gateway[0] && is_valid_ipv4(cfg->gateway)) {
                    // IP applied — verify gateway is reachable (quick 1-packet ping, 2s timeout)
                    char ping_cmd[256];
                    snprintf(ping_cmd, sizeof(ping_cmd),
                             "ping -c 1 -W 2 -I %s %s >/dev/null 2>&1", iface, cfg->gateway);
                    int ping_ret = system(ping_cmd);
                    if (ping_ret != 0) {
                        fprintf(stderr,
                                "[Boot] WARNING: Gateway %s unreachable after applying config IP %s.\n",
                                cfg->gateway, cfg->ip_addr);
                        // Rollback: restore previous OS IP and update config.xml
                        if (saved_ip[0] && is_valid_ipv4(saved_ip)) {
                            printf("[Boot] ROLLBACK: Reverting to previous OS IP %s.\n", saved_ip);
                            char revert_cmd[512];
                            snprintf(revert_cmd, sizeof(revert_cmd),
                                     "ip addr flush dev %s 2>/dev/null && "
                                     "ip addr add %s/%s broadcast + dev %s && "
                                     "ip link set %s up",
                                     iface, saved_ip, prefix_str, iface, iface);
                            system(revert_cmd);
                            setdnsinxml(saved_ip, "<addr>", "</addr>");
                            printf("[Boot] FALLBACK: Config.xml updated to OS IP %s\n", saved_ip);
                        }
                    }
                }
            }
        } else {
            // No valid IP in config — adopt OS IP into config.xml
            if (saved_ip[0] && is_valid_ipv4(saved_ip)) {
                printf("[Boot] No valid IP in config.xml. Adopting OS IP %s.\n", saved_ip);
                setdnsinxml(saved_ip, "<addr>", "</addr>");
            } else {
                printf("[Boot] No valid IP in config.xml or OS. Skipping IP enforcement.\n");
            }
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