#include "discovery_server.h"
#include "auth_server.h"
#include <pthread.h>

int main(void) {
  pthread_t t_disc, t_auth;

  if (pthread_create(&t_disc, NULL, discovery, NULL) != 0) {
    perror("pthread_create discovery");
    return 1;
  }

  if (pthread_create(&t_auth, NULL, authentication, NULL) != 0) {
    perror("pthread_create auth");
    pthread_cancel(t_disc);
    return 1;
  }

  printf("Both servers running. Press Ctrl+C to stop.\n");

  pthread_join(t_disc, NULL);
  pthread_join(t_auth, NULL);

  printf("Clean exit.\n");
  return 0;
}