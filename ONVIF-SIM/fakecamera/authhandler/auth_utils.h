#ifndef AUTH_UTILS_H
#define AUTH_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "../tcp_config.h"
//#include "getuser.h"

// --- Helper: Trim Whitespace ---
void trim_whitespace(char *str) {
    if (!str) return;

    // Trim trailing
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }

    // Trim leading (by moving memory)
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != str) {
        memmove(str, start, len - (start - str) + 1);
    }
}

// --- Base64 Helpers ---
int base64_decode(char *in, int in_len, unsigned char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(in, in_len);
    bio = BIO_push(b64, bio);
    int out_len = BIO_read(bio, out, in_len);
    BIO_free_all(bio);
    return out_len;
}

void base64_encode(const unsigned char *in, int in_len, char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_write(b64, in, in_len);
    BIO_flush(b64);
    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);
    memcpy(out, bufferPtr->data, bufferPtr->length);
    out[bufferPtr->length] = '\0';
    BIO_free_all(b64);
}

// --- Credential Lookup (FIXED) ---
bool get_password_from_csv(const char *username, char *password_out, size_t size) {
    FILE *fp = fopen("CredsWithLevel.csv", "r");
    if (!fp) {
        printf("[Auth] Error: CredsWithLevel.csv not found\n");
        return false;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // 1. Find the first comma to split User from Password
        char *first_comma = strchr(line, ',');
        if (!first_comma) continue;

        // Terminate username string here
        *first_comma = '\0';

        if (strcmp(line, username) == 0) {
            // 2. Password starts after the first comma
            char *pass_start = first_comma + 1;

            // 3. Find end of password: next comma OR newline OR return char
            // strcspn returns the length of the prefix that does NOT contain any of the chars in the 2nd arg
            size_t pass_len = strcspn(pass_start, ",\r\n");
            pass_start[pass_len] = '\0';

            strncpy(password_out, pass_start, size - 1);
            password_out[size - 1] = '\0';

            // 4. Clean up any accidental spaces
            trim_whitespace(password_out);

            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

// --- Extractors ---

void extract_method(const char *msg, char *out, size_t out_size) {
    size_t i = 0;
    while (msg[i] != ' ' && msg[i] != '\0' && i < out_size - 1) {
        out[i] = msg[i];
        i++;
    }
    out[i] = '\0';
    trim_whitespace(out);
}

void extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size) {
    out[0] = '\0';
    const char *start = strstr(msg, tag);
    if (!start) return;

    start = strchr(start, '>');
    if (!start) return;
    start++;

    const char *end = strstr(start, "</");
    if (!end) return;

    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    trim_whitespace(out);
}

// Add to ONVIF-SIM/fakecamera/authhandler/auth_utils.h

void extract_header_val(const char *msg, const char *key, char *out, size_t out_size) {
    out[0] = '\0';
    
    // 1. Find the Authorization header specifically
    const char *auth = strstr(msg, "Authorization: Digest");
    if (!auth) auth = strstr(msg, "Authorization:Digest"); // Try without space
    if (!auth) return;

    // 2. Search for the key (e.g., "username") starting from the Auth header
    const char *p = auth;
    size_t key_len = strlen(key);
    
    while (1) {
        // Find next occurrence of key
        p = strstr(p, key);
        if (!p) break;

        // 3. Validation: Ensure this is the actual key, not a substring (e.g. "myusername")
        // Check character before match: must be space, comma, newline, or start of auth string
        char prev = (p == auth) ? ' ' : *(p-1);
        if (prev != ' ' && prev != ',' && prev != '\t' && prev != '\n' && prev != '\r' && prev != '"') {
             p += key_len;
             continue;
        }

        // 4. Check for '=' after the key (handling spaces: username = "...")
        const char *check = p + key_len;
        while (*check == ' ') check++; // Skip spaces
        
        if (*check == '=') {
            // FOUND IT! Now extract value
            const char *val_start = check + 1;
            while (*val_start == ' ') val_start++; // Skip spaces after =

            // Handle Quoted Value
            if (*val_start == '"') {
                val_start++; // Skip opening quote
                const char *val_end = strchr(val_start, '"');
                if (val_end) {
                    size_t len = val_end - val_start;
                    if (len >= out_size) len = out_size - 1;
                    memcpy(out, val_start, len);
                    out[len] = '\0';
                }
            } 
            // Handle Unquoted Value
            else {
                size_t i = 0;
                while (val_start[i] != ',' && val_start[i] != '\r' && 
                       val_start[i] != '\n' && val_start[i] != '\0' && 
                       val_start[i] != ' ' && i < out_size - 1) {
                    out[i] = val_start[i];
                    i++;
                }
                out[i] = '\0';
            }
            return; // Done
        }
        
        p += key_len; // Continue searching if this wasn't it
    }
}

void extract_header_val1(const char *msg, const char *key, char *out, size_t out_size) {
    out[0] = '\0';
    const char *auth = strstr(msg, "Authorization: Digest");
    if (!auth) return;

    const char *p = auth;
    size_t key_len = strlen(key);

    while ((p = strstr(p, key)) != NULL) {
        const char *check = p + key_len;
        while (*check == ' ') check++;

        if (*check != '=') { p++; continue; }

        char prev = (p == auth) ? ' ' : *(p-1);
        if (prev == ' ' || prev == ',' || prev == '\t' || prev == '\n' || prev == '\r') {
            const char *val_start = check + 1;
            while (*val_start == ' ') val_start++;

            if (*val_start == '"') {
                val_start++;
                const char *val_end = strchr(val_start, '"');
                if (val_end) {
                    size_t len = val_end - val_start;
                    if (len >= out_size) len = out_size - 1;
                    memcpy(out, val_start, len);
                    out[len] = '\0';
                }
            } else {
                size_t i = 0;
                while (val_start[i] != ',' && val_start[i] != '\r' && val_start[i] != '\n' && val_start[i] != '\0' && i < out_size - 1) {
                    out[i] = val_start[i];
                    i++;
                }
                out[i] = '\0';
            }
            trim_whitespace(out);
            return;
        }
        p++;
    }
}

// --- Helper: EVP Hashing ---
void compute_digest(const EVP_MD *type, const void *d1, size_t l1, const void *d2, size_t l2, const void *d3, size_t l3, unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, type, NULL);
    if(d1) EVP_DigestUpdate(ctx, d1, l1);
    if(d2) EVP_DigestUpdate(ctx, d2, l2);
    if(d3) EVP_DigestUpdate(ctx, d3, l3);
    unsigned int len;
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
}

// --- Verification Logic ---

bool verify_ws_security(const char *request) {
    char user[64]={0}, pass_digest[128]={0}, nonce_b64[128]={0}, created[64]={0}, stored_pass[64]={0};

    extract_tag_value(request, "Username", user, sizeof(user));
    extract_tag_value(request, "Password", pass_digest, sizeof(pass_digest));
    extract_tag_value(request, "Nonce", nonce_b64, sizeof(nonce_b64));
    extract_tag_value(request, "Created", created, sizeof(created));

    if (!user[0]) return false;
    if (!get_password_from_csv(user, stored_pass, sizeof(stored_pass))) return false;

    unsigned char nonce_raw[128];
    int nonce_len = base64_decode(nonce_b64, strlen(nonce_b64), nonce_raw);

    unsigned char sha1_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, nonce_raw, nonce_len);
    EVP_DigestUpdate(ctx, created, strlen(created));
    EVP_DigestUpdate(ctx, stored_pass, strlen(stored_pass));
    unsigned int len;
    EVP_DigestFinal_ex(ctx, sha1_buf, &len);
    EVP_MD_CTX_free(ctx);

    char computed_digest[128];
    base64_encode(sha1_buf, 20, computed_digest);

    return (strcmp(computed_digest, pass_digest) == 0);
}

int is_admin1(const char *buf, const char *user/*, bool *is_admin_user*/){
    FILE *fp = fopen("CredsWithLevel.csv", "r"); //username,password,level
    char line[256];
    char username[64], password[64], level[16];
    while(fgets(line, sizeof(line), fp)){
        sscanf(line, "%[^,],%[^,],%[^,\n]", username, password, level); // took help with these
        // as those upper weird operators "%[^,],%[^,],%[^,\n]" were taken help need more context
        // not even confirmed from my side how it works
        printf("%s,%s,%s\n", username, password, level);
        if(strcmp(username, user) == 0 && strcmp(level, "Administrator") == 0){
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int is_admin(const char *buf, const char *user) {
    FILE *fp = fopen("CredsWithLevel.csv", "r");
    if (!fp) return 0;

    char line[256];
    char username[64], password[64], level[16];
    
    // Skip the header line (username,password,userlevel)
    fgets(line, sizeof(line), fp); 

    while(fgets(line, sizeof(line), fp)) {
        // Corrected sscanf to handle potential spaces and the exact CSV format
        if (sscanf(line, " %[^,],%[^,],%[^,\n\r]", username, password, level) == 3) {
            // Match against "Administrator" as defined in your CSV
            if(strcmp(username, user) == 0 && strcmp(level, "Administrator") == 0) {
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

bool verify_http_digest(const char *request, const char *forced_method) {
    char user[64]={0}, realm[64]={0}, nonce[128]={0}, uri[128]={0}, response[64]={0}, stored_pass[64]={0};
    char qop[16]={0}, nc[16]={0}, cnonce[64]={0}, algo[16]={0}, method[16]={0};

    // Extract Headers
    extract_header_val(request, "username", user, sizeof(user));
    extract_header_val(request, "realm", realm, sizeof(realm));
    extract_header_val(request, "nonce", nonce, sizeof(nonce));
    extract_header_val(request, "uri", uri, sizeof(uri));
    extract_header_val(request, "response", response, sizeof(response));
    extract_header_val(request, "qop", qop, sizeof(qop));
    extract_header_val(request, "cnonce", cnonce, sizeof(cnonce));
    extract_header_val(request, "algorithm", algo, sizeof(algo));
    extract_header_val(request, "nc", nc, sizeof(nc));
    if (!nc[0]) extract_header_val(request, "NC", nc, sizeof(nc));

    extract_method(request, method, sizeof(method));

    if (!user[0] || !response[0]) return false;
    if (!get_password_from_csv(user, stored_pass, sizeof(stored_pass))) return false;

    unsigned char md_buf[EVP_MAX_MD_SIZE];
    char ha1_hex[33], ha2_hex[33], resp_hex[33];
    unsigned int len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    // --- Calculate HA1 = MD5(username:realm:password) ---
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, user, strlen(user));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, realm, strlen(realm));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, stored_pass, strlen(stored_pass));
    EVP_DigestFinal_ex(ctx, md_buf, &len);
    EVP_MD_CTX_reset(ctx);

    // Handle MD5-sess
    if (strcasecmp(algo, "MD5-sess") == 0) {
        EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
        EVP_DigestUpdate(ctx, md_buf, 16);
        EVP_DigestUpdate(ctx, ":", 1);
        EVP_DigestUpdate(ctx, nonce, strlen(nonce));
        EVP_DigestUpdate(ctx, ":", 1);
        EVP_DigestUpdate(ctx, cnonce, strlen(cnonce));
        EVP_DigestFinal_ex(ctx, md_buf, &len);
        EVP_MD_CTX_reset(ctx);
    }

    for(int i=0;i<16;i++) sprintf(&ha1_hex[i*2], "%02x", md_buf[i]);

    // --- Calculate HA2 = MD5(method:digestURI) ---
    const char *final_method = (method[0]) ? method : forced_method;
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, final_method, strlen(final_method));
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, uri, strlen(uri));
    EVP_DigestFinal_ex(ctx, md_buf, &len);
    EVP_MD_CTX_reset(ctx);

    for(int i=0;i<16;i++) sprintf(&ha2_hex[i*2], "%02x", md_buf[i]);

    // --- Calculate Response = MD5(HA1:nonce:nc:cnonce:qop:HA2) ---
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, ha1_hex, 32);
    EVP_DigestUpdate(ctx, ":", 1);
    EVP_DigestUpdate(ctx, nonce, strlen(nonce));
    EVP_DigestUpdate(ctx, ":", 1);

    if (qop[0]) {
        EVP_DigestUpdate(ctx, nc, strlen(nc));
        EVP_DigestUpdate(ctx, ":", 1);
        EVP_DigestUpdate(ctx, cnonce, strlen(cnonce));
        EVP_DigestUpdate(ctx, ":", 1);
        EVP_DigestUpdate(ctx, qop, strlen(qop));
        EVP_DigestUpdate(ctx, ":", 1);
    }

    EVP_DigestUpdate(ctx, ha2_hex, 32);
    EVP_DigestFinal_ex(ctx, md_buf, &len);
    EVP_MD_CTX_free(ctx);

    for(int i=0;i<16;i++) sprintf(&resp_hex[i*2], "%02x", md_buf[i]);

    if (strcmp(resp_hex, response) == 0) return true;

    // DEBUG LOGGING
    printf("[Auth] Digest Mismatch!\n");
    printf("  User: '%s', Pass: '%s', Realm: '%s'\n", user, stored_pass, realm);
    printf("  Method: '%s', URI: '%s'\n", final_method, uri);
    printf("  Nonce: '%s'\n", nonce);
    printf("  NC: '%s'\n", nc);
    printf("  CNonce: '%s'\n", cnonce);
    printf("  QoP: '%s'\n", qop);
    printf("  HA1: %s\n", ha1_hex);
    printf("  HA2: %s\n", ha2_hex);
    printf("  Computed: %s\n", resp_hex);
    printf("  Received: %s\n", response);

    return false;
}

static inline bool is_get_device_information(const char *msg) {
    return (strstr(msg, "GetDeviceInformation") != NULL);
}

void getmessageid1(const char *msg, char *out, size_t out_size) {
    extract_tag_value(msg, "MessageID", out, out_size);
}

#endif /* AUTH_UTILS_H */
