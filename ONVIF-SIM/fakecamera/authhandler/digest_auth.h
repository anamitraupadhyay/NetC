#include <stdlib.h>
#include <time.h>
#include <openssl/md5.h>
//#include "../config.h"
#include <stdio.h>
#include <string.h>

inline void generate_nonce(char *nonce, size_t size){
  snprintf(nonce, size, "%ld%d", time(NULL),rand());
}

/*inline int verify_digest(const char *header,
                         const char *method,
                         char *username,
                         char *out,
                         size_t outsize) {// the pass field is not req
                                          // as username needs checking
                                          // then password from separate
  //
}*/
inline int get_check_password_fromcsv(const char *target_user,
                                      char *password,
                                      size_t size) {
  // file
  FILE *fp = fopen("Credential.csv", "r");
  if(!fp) return 0;
  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    // Remove potential newline characters
    line[strcspn(line, "\r\n")] = 0;
    // need coma from username,password
    char *comma = strchr(line, ',');
    if (!comma)
      continue;

    // check user exist
    size_t userlen = comma - line; // both are pointers but comma is later
                                   // and line is first one in the
                                   // representation username,password
    if (strncmp(line, target_user, userlen) == 0 &&
        target_user[userlen] == '\0') {
      // extract password
      char *pass_start = comma + 1;             // include the '\0'
      char *pass_end = strchr(pass_start, ','); // for next comma
      // added by llm
      // Handle case where there is no trailing comma(EOL)
      if (!pass_end)
        pass_end = strchr(pass_start, '\n');
      if (!pass_end)
        pass_end = pass_start + strlen(pass_start);

      size_t passlen = pass_end - pass_start;
      if (passlen > size)
        passlen = size - 1;

      memcpy(password, pass_start, passlen);
      password[passlen] = '\0';

      fclose(fp);
      return 1;
    }
  }
  fclose(fp);
  return 0;
}