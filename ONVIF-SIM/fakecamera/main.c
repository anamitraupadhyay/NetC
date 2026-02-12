#include "discovery_server.h"
#include "auth_server.h"
#include <pthread.h>

// Reconcile Actual (OS) IP vs Desired (config.xml) IP at startup.
// If they differ, ActualState overwrites DesiredState to prevent
// the device from being unreachable due to a config typo.
static void reconcile_actual_vs_desired(void) {
    // 1. Get actual IP from OS
    char actual_ip[64] = {0};
    getlocalip(actual_ip, sizeof(actual_ip));
    if (!actual_ip[0] || strcmp(actual_ip, "127.0.0.1") == 0) {
        printf("[Startup] Could not determine actual IP, skipping reconciliation\n");
        return;
    }

    // 2. Get desired IP from config.xml
    config cfg = {0};
    if (!load_config("config.xml", &cfg)) {
        printf("[Startup] Could not load config.xml, skipping reconciliation\n");
        return;
    }

    // 3. Compare and overwrite if different
    if (cfg.ip_addr[0] && strcmp(actual_ip, cfg.ip_addr) != 0) {
        printf("[Startup] IP conflict: Actual=%s, Desired=%s -> overwriting config.xml with actual\n",
               actual_ip, cfg.ip_addr);
        // setdnsinxml is a generic XML tag value setter (not DNS-specific)
        setdnsinxml(actual_ip, "<addr>", "</addr>");
    } else {
        printf("[Startup] IP consistent: %s\n", actual_ip);
    }
}

int main(void) {
  // Reconcile actual OS state vs desired config state before starting servers
  reconcile_actual_vs_desired();

  pthread_t t_disc, tcpserv; // t_auth;
  // t_auth to be later changed as tcp_server *IMPORTANT*

  if (pthread_create(&t_disc, 
    NULL, discovery, NULL) != 0) {
    perror("pthread_create discovery");
    return 1;
  }

  if (pthread_create(&tcpserv, 
    NULL, tcpserver, NULL) != 0) {
    perror("pthread_create auth");
    pthread_cancel(t_disc);
    return 1;
  }

  printf("Both servers running. Press Ctrl+C to stop.\n");

  pthread_join(t_disc, NULL);
  pthread_join(tcpserv, NULL);

  printf("Clean exit.\n");
  return 0;
}