# Authentication Guide for ONVIF-SIM

This guide explains how ONVIF authentication is implemented in the simulator, focusing on `auth_utils.h`. It covers:

- Where authentication fits in ONVIF services
- HTTP Digest vs. WS-Security UsernameToken
- How OpenSSL is used (hashing, Base64)
- How to extend and integrate the helpers
- Reference for HTTP headers, XML structures, and message flow

The goal is to give newcomers a practical, modular understanding of the code and protocols.

## Directory and key files

- `auth_utils.h`: Core helpers for parsing requests and verifying credentials (HTTP Digest and WS-Security UsernameToken).
- `../tcp_config.h`: Shared config for TCP handling used by the auth helpers.
- `Credentials.csv`: Flat file credential store used by the simulator (format: `username,password`).

## Protocols at a glance

### HTTP Digest (RFC 7616)
- Protection at the HTTP header level; credentials never sent in plaintext.
- Client receives `WWW-Authenticate: Digest ...` challenge, then responds with an `Authorization: Digest ...` header containing a computed response hash.
- Integrity is provided for method + URI + nonce + counters; body is not signed.
- Typical for ONVIF HTTP/SOAP endpoints without WS-Security.

### WS-Security UsernameToken (OASIS WSS 1.1)
- Protection inside the SOAP envelope; carries `<wsse:UsernameToken>` in the SOAP Header.
- Credentials may be sent as:
  - `PasswordText` (plaintext) — not recommended unless TLS protects the transport.
  - `PasswordDigest` — safer; uses nonce + created timestamp + password.
- Common for ONVIF Device/Media services over SOAP.

## How the simulator verifies credentials

### Credential lookup
- `get_password_from_csv(username, password_out, size)` reads `Credentials.csv` to retrieve the shared secret.
- Keep the CSV lines as `username,password` with no extra whitespace.

### WS-Security UsernameToken flow

Relevant helpers:
- `extract_tag_value(msg, tag, out, out_size)`: Pulls XML element contents (e.g., `Username`, `Password`, `Nonce`, `Created`).
- `base64_decode` / `base64_encode`: For nonce and digest handling.
- `verify_ws_security(request)`: Implements PasswordDigest verification.

Verification steps (PasswordDigest):
1. Parse `Username`, `Password` (digest), `Nonce` (Base64), and `Created` from the SOAP header.
2. Lookup plaintext password from `Credentials.csv`.
3. Decode `Nonce` from Base64.
4. Compute SHA-1 over `Nonce || Created || Password` using OpenSSL EVP:
   ```c
   EVP_MD_CTX *ctx = EVP_MD_CTX_new();
   EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
   EVP_DigestUpdate(ctx, nonce_raw, nonce_len);
+   EVP_DigestUpdate(ctx, created, strlen(created));
   EVP_DigestUpdate(ctx, stored_pass, strlen(stored_pass));
   EVP_DigestFinal_ex(ctx, sha1_buf, &len);
   EVP_MD_CTX_free(ctx);
   ```
5. Base64-encode the SHA-1 result and compare to the incoming `Password` value.

Notes:
- If the incoming `<wsse:Password>` is `PasswordText`, the digest check will fail; you would need to compare plaintext instead.
- Ensure transport security (TLS) if you ever accept `PasswordText`.
- Timestamps (`Created`) can be checked for freshness to prevent replay (not implemented here).

### HTTP Digest flow

Relevant helpers:
- `extract_header_val(request, key, out, out_size)`: Pulls parameter values from the `Authorization: Digest ...` header.
- `extract_method(request, out, out_size)`: Reads the HTTP method from the request line if not forced.
- `verify_http_digest(request, forced_method)`: Verifies the response hash.

Verification steps:
1. Parse `username`, `realm`, `nonce`, `uri`, `response`, optional `qop`, `cnonce`, `nc`, `algorithm`, and method.
2. Lookup plaintext password from `Credentials.csv`.
3. Compute:
   - `HA1 = MD5(username:realm:password)` (or `MD5(MD5(...):nonce:cnonce)` for `MD5-sess`).
   - `HA2 = MD5(method:uri)`.
   - `response = MD5(HA1:nonce:nc:cnonce:qop:HA2)` (omit `nc/cnonce/qop` if qop absent).
4. Compare computed `response` with the header value.

Notes:
- `forced_method` lets you override the method if the request line is missing/rewritten.
- `nc` (nonce count) and `cnonce` should be validated for replay protection in production.
- Real deployments should store nonces server-side and expire them; the simulator trusts what it sees.

## OpenSSL usage in `auth_utils.h`

Primitives used:
- **EVP_md5 / EVP_sha1**: Hash implementations used via the high-level EVP API.
- `EVP_MD_CTX_new`, `EVP_DigestInit_ex`, `EVP_DigestUpdate`, `EVP_DigestFinal_ex`, `EVP_MD_CTX_free`: Digest lifecycle.
- `BIO_f_base64`, `BIO_new_mem_buf`, `BIO_push`, `BIO_read`, `BIO_flush`, `BIO_get_mem_ptr`: Base64 encode/decode pipelines.

Why EVP:
- Algorithm-agnostic: swapping hashes (e.g., SHA-256) would only change `EVP_md5()`/`EVP_sha1()` calls.
- Consistent memory management and security-hardening from OpenSSL.

Memory and safety tips:
- Always free BIOs and EVP contexts (`BIO_free_all`, `EVP_MD_CTX_free`).
- Zero buffers that hold secrets if you extend the code for production.
- Check return values for partial reads/writes in real deployments.

## HTTP headers and SOAP/XML structures

### HTTP Digest header example
```
Authorization: Digest username="alice", realm="onvif", nonce="abc123", uri="/onvif/device_service", response="d41d8cd98f00b204e9800998ecf8427e", qop=auth, nc=00000001, cnonce="xyz", algorithm=MD5
```

Server challenge (not implemented here, but typical):
```
WWW-Authenticate: Digest realm="onvif", nonce="serverNonceValue", qop="auth", algorithm=MD5
```

### WS-Security UsernameToken (PasswordDigest) example
```xml
<soap:Header>
  <wsse:Security>
    <wsse:UsernameToken>
      <wsse:Username>alice</wsse:Username>
      <wsse:Password Type="...#PasswordDigest">base64digest==</wsse:Password>
      <wsse:Nonce>base64nonce==</wsse:Nonce>
      <wsu:Created>2025-01-01T12:00:00Z</wsu:Created>
    </wsse:UsernameToken>
  </wsse:Security>
</soap:Header>
```

## Integration guidance (modular usage)

### Parsing and validation
- Use `extract_tag_value` to fetch XML header fields for WS-Security.
- Use `extract_header_val` to fetch key/value pairs from the HTTP Digest header.
- Normalize whitespace with `trim_whitespace` to avoid subtle parsing issues.

### Wiring into ONVIF services
- Authenticate requests before dispatching to service handlers (Device, Media, PTZ).
- Use `verify_ws_security` for SOAP requests carrying UsernameTokens.
- Use `verify_http_digest` for HTTP Digest headers on REST/HTTP verbs.
- Consider caching the results per connection/session if performance is a concern.

### Extending safely
- **Replay protection**: track nonces + `Created` timestamps for UsernameToken; track `(nonce, nc, cnonce)` for Digest.
- **Algorithm agility**: wrap hash selection; allow SHA-256 for HA1/HA2 if clients support it.
- **Transport security**: run over TLS; terminate at the camera or an upstream proxy.
- **Credential store**: replace `Credentials.csv` with a secure store (e.g., OS keyring, HSM, or encrypted file).

### XML handling best practices
- Use a proper XML parser for production; the simulator uses string search for simplicity.
- Validate namespaces if multiple security headers exist.
- Enforce time skew limits on `Created`.

## Quick reference to helper functions

- `trim_whitespace(char *str)`: In-place whitespace trimming.
- `base64_decode(char *in, int in_len, unsigned char *out)`: Base64 decode using OpenSSL BIO.
- `base64_encode(const unsigned char *in, int in_len, char *out)`: Base64 encode.
- `get_password_from_csv(const char *username, char *password_out, size_t size)`: Credential lookup.
- `extract_method(const char *msg, char *out, size_t out_size)`: HTTP method parsing.
- `extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size)`: XML tag content extraction.
- `extract_header_val(const char *msg, const char *key, char *out, size_t out_size)`: Authorization header value extraction.
- `compute_digest(...)`: Generalized EVP hash helper (used for composed hashing).
- `verify_ws_security(const char *request)`: UsernameToken PasswordDigest verification.
- `verify_http_digest(const char *request, const char *forced_method)`: HTTP Digest verification.
- `generate_messageid1(char *buf, size_t size)`: UUID-like message ID generator (useful for SOAP headers).
- `getmessageid1(const char *msg, char *out, size_t out_size)`: Extracts `<MessageID>` from SOAP.
- `is_get_device_information(const char *msg)`: Checks for the GetDeviceInformation request.

## Packet and flow notes

- HTTP Digest:
  - Challenge/response happens at HTTP header level; body is opaque to authentication.
  - Nonces and counters mitigate replay; integrity tied to method+URI.
- WS-Security UsernameToken:
  - Authentication data lives in SOAP Header; body can still be tampered with unless signatures are used.
  - PasswordDigest binds nonce + timestamp + secret; rely on TLS for confidentiality.

## Learning resources

- RFC 7616: HTTP Digest Access Authentication
- OASIS WSS UsernameToken Profile 1.1
- ONVIF Core Spec (Device Service authentication sections)
- OpenSSL man pages for EVP and BIO (e.g., `man EVP_DigestInit`, `man BIO_f_base64`)
