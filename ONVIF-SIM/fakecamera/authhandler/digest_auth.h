#include <stdlib.h>
#include <time.h>
#include <openssl/md5.h>
//#include "../config.h"
// below are important headers
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>


#define MIN_USER_LEN 4
#define MAX_USER_LEN 30
#define MIN_PASS_LEN 4
#define MAX_PASS_LEN 30

// Returns 1 if valid, 0 if invalid (and sets reason msg)
int validate_cred_edgecases(const char *user, const char *pass, char *reason_out) {
    size_t u_len = strlen(user);
    size_t p_len = strlen(pass);

    // Window Size Check
    if (u_len < MIN_USER_LEN || u_len > MAX_USER_LEN) {
        sprintf(reason_out, "Username length must be between %d and %d", MIN_USER_LEN, MAX_USER_LEN);
        return 0;
    }
    if (p_len < MIN_PASS_LEN || p_len > MAX_PASS_LEN) {
        sprintf(reason_out, "Password length must be between %d and %d", MIN_PASS_LEN, MAX_PASS_LEN);
        return 0;
    }

    // Username Equal to Password Check
    if (strcmp(user, pass) == 0) {
        strcpy(reason_out, "Password cannot be identical to Username");
        return 0;
    }
    //if(){// load csv and check if username exist or not
    //}

    return 1;
}




inline void generate_nonce(char *nonce, size_t size){
  snprintf(nonce, size, "%ld%d", time(NULL),rand());
}


static void md5_hex(const char *in, char out[33]) {
    unsigned char hash[16];
    unsigned int len;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, in, strlen(in));
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);

    for (int i = 0; i < 16; i++)
        sprintf(out + i*2, "%02x", hash[i]);
    out[32] = '\0';
}

// VERY naive header extractor
static bool get_hdr(const char *req, const char *key,
                    char *out, size_t sz) {
    const char *p = strstr(req, key);
    if (!p) return false;

    p = strchr(p, '=');
    if (!p) return false;
    p++;

    if (*p == '"') p++; // http auth headers have "
    const char *e = strchr(p, '"');
    if (!e) return false;

    size_t n = e - p;
    if (n >= sz) n = sz - 1;
    memcpy(out, p, n);
    out[n] = 0;
    return true;
}


bool verifyhttpdigest(
    const char *http_req,
    const char *stored_user,
    const char *stored_pass
) {
    char user[64], realm[64], nonce[128];
    char uri[128], resp[64], method[8] = "GET";

    if (!get_hdr(http_req, "username", user, sizeof(user))) return false;
    if (!get_hdr(http_req, "realm", realm, sizeof(realm))) return false;
    if (!get_hdr(http_req, "nonce", nonce, sizeof(nonce))) return false;
    if (!get_hdr(http_req, "uri", uri, sizeof(uri))) return false;
    if (!get_hdr(http_req, "response", resp, sizeof(resp))) return false;

    if (strcmp(user, stored_user) != 0)
        return false;

    // HA1 = MD5(user:realm:password)
    char a1[256], ha1[33];
    snprintf(a1, sizeof(a1), "%s:%s:%s",
             user, realm, stored_pass);
    md5_hex(a1, ha1);

    // HA2 = MD5(method:uri)
    char a2[256], ha2[33];
    snprintf(a2, sizeof(a2), "%s:%s", method, uri);
    md5_hex(a2, ha2);

    // response = MD5(HA1:nonce:HA2)
    char final[512], expected[33];
    snprintf(final, sizeof(final), "%s:%s:%s",
             ha1, nonce, ha2);
    md5_hex(final, expected);

    return strcmp(expected, resp) == 0;
}
