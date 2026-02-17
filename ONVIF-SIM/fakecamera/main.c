#include "discovery_server.h"
#include "auth_server.h"
#include <pthread.h>
#include <signal.h>

static volatile sig_atomic_t g_running = 1;
static pthread_t t_disc, tcpserv;

static void handle_shutdown(int sig) {
  (void)sig;
  g_running = 0;
}

int main(void) {
  struct sigaction sa = {0};
  sa.sa_handler = handle_shutdown;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGINT, &sa, NULL) != 0)
    perror("sigaction SIGINT");
  if (sigaction(SIGTERM, &sa, NULL) != 0)
    perror("sigaction SIGTERM");

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

  while (g_running)
    pause();

  pthread_cancel(t_disc);
  pthread_cancel(tcpserv);
  pthread_join(t_disc, NULL);
  pthread_join(tcpserv, NULL);

  printf("Clean exit.\n");
  return 0;
}