#include "auth.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

/**
 * Base64 encode a buffer
 */
static int base64_encode(const unsigned char *input, int length, 
                        char *output, size_t output_size) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    /* Account for null terminator */
    if (buffer_ptr->length >= output_size - 1) {
        BIO_free_all(bio);
        return -1;
    }
    
    memcpy(output, buffer_ptr->data, buffer_ptr->length);
    output[buffer_ptr->length] = '\0';
    
    BIO_free_all(bio);
    return 0;
}

/**
 * Generate random nonce using OpenSSL (cross-platform)
 */
static void generate_nonce(unsigned char *nonce, size_t size) {
    /* Use OpenSSL's RAND_bytes for cross-platform cryptographically secure random */
    if (RAND_bytes(nonce, (int)size) != 1) {
        /* Fallback to time-based pseudo-random if OpenSSL fails */
        for (size_t i = 0; i < size; i++) {
            nonce[i] = (unsigned char)(time(NULL) + i);
        }
    }
}

/**
 * Get current UTC timestamp in ISO 8601 format
 */
static void get_utc_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(buffer, size, "%Y-%m-%dT%H:%M:%SZ", tm_info);
}

int generate_auth_header(const char *username, const char *password,
                        char *buffer, size_t buffer_size) {
    if (!username || !password || !buffer) {
        return -1;
    }
    
    /* Generate nonce (16 bytes) */
    unsigned char nonce[16];
    generate_nonce(nonce, sizeof(nonce));
    
    /* Base64 encode nonce */
    char nonce_b64[64];
    if (base64_encode(nonce, sizeof(nonce), nonce_b64, sizeof(nonce_b64)) != 0) {
        return -1;
    }
    
    /* Get timestamp */
    char created[32];
    get_utc_timestamp(created, sizeof(created));
    
    /* Calculate password digest: Base64(SHA1(nonce + created + password)) */
    unsigned char digest_input[256];
    int digest_len = 0;
    
    memcpy(digest_input + digest_len, nonce, sizeof(nonce));
    digest_len += sizeof(nonce);
    
    int created_len = strlen(created);
    memcpy(digest_input + digest_len, created, created_len);
    digest_len += created_len;
    
    int password_len = strlen(password);
    memcpy(digest_input + digest_len, password, password_len);
    digest_len += password_len;
    
    /* SHA1 hash */
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(digest_input, digest_len, hash);
    
    /* Base64 encode hash */
    char digest_b64[64];
    if (base64_encode(hash, SHA_DIGEST_LENGTH, digest_b64, sizeof(digest_b64)) != 0) {
        return -1;
    }
    
    /* Build WS-Security header */
    int written = snprintf(buffer, buffer_size,
        "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
        "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
        "<wsse:UsernameToken>"
        "<wsse:Username>%s</wsse:Username>"
        "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password>"
        "<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</wsse:Nonce>"
        "<wsu:Created>%s</wsu:Created>"
        "</wsse:UsernameToken>"
        "</wsse:Security>",
        username, digest_b64, nonce_b64, created);
    
    if (written >= (int)buffer_size) {
        return -1;
    }
    
    return 0;
}

int build_authenticated_request(const char *username, const char *password,
                               const char *soap_body, char *buffer,
                               size_t buffer_size) {
    if (!username || !password || !soap_body || !buffer) {
        return -1;
    }
    
    /* Generate authentication header */
    char auth_header[1024];
    if (generate_auth_header(username, password, auth_header, sizeof(auth_header)) != 0) {
        return -1;
    }
    
    /* Build complete SOAP envelope */
    int written = snprintf(buffer, buffer_size,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
        "<s:Header>%s</s:Header>"
        "<s:Body>%s</s:Body>"
        "</s:Envelope>",
        auth_header, soap_body);
    
    if (written >= (int)buffer_size) {
        return -1;
    }
    
    return 0;
}
