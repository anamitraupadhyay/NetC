#include "discovery_server.h"
#include "auth_server.h"
#include "interface_binding.h"
#include <pthread.h>
#include <getopt.h>
#include <stdlib.h>

void print_usage(const char *prog_name) {
  printf("Usage: %s [OPTIONS]\n", prog_name);
  printf("\nOptions:\n");
  printf("  -i, --interface <name>   Bind to specific network interface (e.g., eth0, wlan0)\n");
  printf("  -a, --address <ip>       Bind to specific IP address (e.g., 192.168.1.100)\n");
  printf("  -h, --help               Show this help message\n");
  printf("\nExamples:\n");
  printf("  %s -i eth0               # Bind to eth0 interface\n", prog_name);
  printf("  %s -a 192.168.1.100      # Bind to specific IP\n", prog_name);
  printf("\nNote: Without -i or -a, the server binds to ALL network interfaces (INADDR_ANY)\n");
}

int main(int argc, char *argv[]) {
  int opt;
  char *interface_spec = NULL;
  
  static struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"address",   required_argument, 0, 'a'},
    {"help",      no_argument,       0, 'h'},
    {0, 0, 0, 0}
  };
  
  // Parse command line arguments
  while ((opt = getopt_long(argc, argv, "i:a:h", long_options, NULL)) != -1) {
    switch (opt) {
      case 'i':
      case 'a':
        interface_spec = optarg;
        break;
      case 'h':
        print_usage(argv[0]);
        return 0;
      default:
        print_usage(argv[0]);
        return 1;
    }
  }
  
  // Set interface binding if specified
  if (interface_spec != NULL) {
    if (set_bind_interface(interface_spec) != 0) {
      fprintf(stderr, "Error: Failed to set interface binding to '%s'\n", interface_spec);
      return 1;
    }
  } else {
    printf("[Warning] No interface specified. Binding to ALL network interfaces.\n");
    printf("          Use -i <interface> or -a <ip> to bind to a specific network.\n\n");
  }
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