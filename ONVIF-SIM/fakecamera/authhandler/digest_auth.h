#include <stdlib.h>
#include <time.h>
#include <openssl/md5.h>
#include "../config.h"
#include <stdio.h>
#include <string.h>

inline void generate_nonce(char *nonce, size_t size){
  snprintf(nonce, size, "%ld%d", time(NULL),rand());
}

