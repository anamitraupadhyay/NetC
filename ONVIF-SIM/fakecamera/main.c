#include "discovery_server.h"
#include "auth_server.h"
#include <pthread.h>
#include <signal.h>

static pthread_t t_disc, tcpserv;

static void handle_shutdown(int sig) {
  (void)sig;
  pthread_cancel(t_disc);
  pthread_cancel(tcpserv);
}

int main(void) {
  struct sigaction sa;
  sa.sa_handler = handle_shutdown;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  if (pthread_create(&t_disc, 
    NULL, discovery, NULL) != 0) {
    perror("pthread_create discovery");
    return 1;
  }

  if (pthread_create(&tcpserv, 
    NULL, tcpserver, NULL) != 0) {
    perror("pthread_create tcpserver");
    pthread_cancel(t_disc);
    pthread_join(t_disc, NULL);
    return 1;
  }

  printf("Both servers running. Press Ctrl+C to stop.\n");

  pthread_join(t_disc, NULL);
  pthread_join(tcpserv, NULL);

  printf("Clean exit.\n");
  return 0;
}