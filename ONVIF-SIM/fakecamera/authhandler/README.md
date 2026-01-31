# ONVIF Authentication Guide (authhandler)

This guide explains how `auth_utils.h` verifies ONVIF authentication in the fake camera server and provides a beginner-friendly tour of OpenSSL usage, HTTP digest, and WS-UsernameToken XML handling.

## Contents

1. [Where auth_utils.h is used](#where-auth_utilsh-is-used)
2. [HTTP and SOAP request layout](#http-and-soap-request-layout)
3. [HTTP Digest Authentication walkthrough](#http-digest-authentication-walkthrough)
4. [WS-UsernameToken walkthrough](#ws-usernametoken-walkthrough)
5. [OpenSSL usage in auth_utils.h](#openssl-usage-in-auth_utilsh)
6. [XML parsing considerations](#xml-parsing-considerations)
7. [Packet flow from client to camera](#packet-flow-from-client-to-camera)
8. [Modular extension ideas](#modular-extension-ideas)
9. [Quick reference: auth_utils.h helpers](#quick-reference-auth_utilsh-helpers)

## Where auth_utils.h is used

- `fakecamera/auth_server.h` includes `authhandler/auth_utils.h` and calls:
  - `verify_ws_security(request)` for SOAP WS-UsernameToken validation.
  - `verify_http_digest(request, "POST")` for HTTP Digest validation.
  - `getmessageid1()` to extract SOAP `MessageID` values.

The fake camera flow checks for authentication on protected ONVIF services such as `GetDeviceInformation`.

## HTTP and SOAP request layout

The simulator receives a full HTTP request over TCP. The request contains:

```
POST /onvif/device_service HTTP/1.1
Host: 192.168.1.10
Content-Type: application/soap+xml; charset=utf-8
Authorization: Digest username="admin", realm="ONVIF_Device", ...
Content-Length: 1234

<soap:Envelope>
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="...#PasswordDigest">Base64Digest</wsse:Password>
        <wsse:Nonce>Base64Nonce</wsse:Nonce>
        <wsu:Created>2025-01-01T12:00:00Z</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <tds:GetDeviceInformation />
  </soap:Body>
</soap:Envelope>
```

- HTTP headers (like `Authorization`) are parsed by `extract_header_val()`.
- XML tags (`Username`, `Password`, `Nonce`, `Created`) are parsed by `extract_tag_value()`.

## HTTP Digest Authentication walkthrough

HTTP Digest authenticates the HTTP **headers** (not the XML body). The server challenges the client with:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="ONVIF_Device", qop="auth", nonce="<server_nonce>", algorithm=MD5
```

The client replies with an `Authorization: Digest ...` header. `verify_http_digest()` validates it using MD5 hashes:

1. **Extract header attributes**
   - Username, realm, nonce, URI, response, qop, nc, cnonce, algorithm.
2. **Look up the stored password**
   - `get_password_from_csv()` reads `Credentials.csv` (format: `username,password`).
3. **Compute HA1**
   - `HA1 = MD5(username:realm:password)`
   - For `MD5-sess`, HA1 becomes `MD5(HA1:nonce:cnonce)`.
4. **Compute HA2**
   - `HA2 = MD5(method:uri)` (method defaults to the request line or a forced method like `POST`).
5. **Compute response**
   - `response = MD5(HA1:nonce:nc:cnonce:qop:HA2)` (or `MD5(HA1:nonce:HA2)` if qop is missing).
6. **Compare computed response to header**
   - If they match, HTTP Digest is valid.

### HTTP Digest vs WS-UsernameToken

| Area | HTTP Digest | WS-UsernameToken |
| --- | --- | --- |
| Transport | HTTP headers | SOAP XML headers |
| Hashing | MD5 over `username:realm:password` + request data | SHA1 over `nonce + created + password` |
| Nonce scope | Server-provided HTTP nonce | Client-provided XML nonce |
| Typical ONVIF use | HTTP-level challenge/response | SOAP-level security header |

## WS-UsernameToken walkthrough

WS-UsernameToken secures the SOAP **XML header**. `verify_ws_security()` checks:

1. Extract `<Username>`, `<Password>`, `<Nonce>`, `<Created>` from the SOAP header.
2. Look up the stored password via `get_password_from_csv()`.
3. Decode the XML `Nonce` from Base64 (OpenSSL BIO helper in `base64_decode()`).
4. Compute SHA1:

```
SHA1( nonce_raw + created + stored_password )
```

5. Base64-encode the SHA1 result.
6. Compare to the `<Password>` value in the XML.

If they match, the WS-UsernameToken is valid.

## OpenSSL usage in auth_utils.h

OpenSSL is used strictly for hashing and Base64 in this module:

- **Base64 decoding** (`base64_decode`)
  - Uses `BIO_f_base64()` with `BIO_FLAGS_BASE64_NO_NL` to decode without line breaks.
- **Base64 encoding** (`base64_encode`)
  - Uses a memory BIO + base64 BIO to create the encoded string.
- **SHA1 hashing** (`verify_ws_security`)
  - Uses `EVP_MD_CTX` and `EVP_sha1()`.
- **MD5 hashing** (`verify_http_digest`)
  - Uses `EVP_MD_CTX` and `EVP_md5()`.

### OpenSSL flow (high-level)

1. Create a digest context: `EVP_MD_CTX_new()`.
2. Initialize hash: `EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)`.
3. Update with bytes: `EVP_DigestUpdate(ctx, data, length)`.
4. Finalize: `EVP_DigestFinal_ex(ctx, out, &len)`.
5. Clean up: `EVP_MD_CTX_free(ctx)`.

These same steps work for any digest algorithm OpenSSL supports.

## XML parsing considerations

The parsing in `auth_utils.h` is string-based and intentionally minimal:

- `extract_tag_value()` finds an opening tag, then copies until the next `</`.
- It assumes that tags do not span unexpected nested structures.
- It is case-sensitive.

For production-grade ONVIF servers, use a real XML parser (LibXML2, Expat, etc.) to avoid edge cases and XML injection.

## Packet flow from client to camera

1. **Client** sends HTTP + SOAP XML over TCP.
2. **Camera server** reads the raw TCP bytes.
3. `auth_server.h` checks for authentication:
   - `Authorization: Digest` header -> HTTP Digest flow.
   - `wsse:Security` XML header -> WS-UsernameToken flow.
4. **Server response**:
   - `200 OK` + SOAP response if authenticated.
   - `401 Unauthorized` + `WWW-Authenticate` if not authenticated.

## Modular extension ideas

To make authentication more modular, consider the following structure:

```
/authhandler
  auth_utils.h          # shared helpers (hashing, parsing, CSV lookup)
  http_digest.c/h       # HTTP digest validation
  ws_username_token.c/h # SOAP token validation
  auth_router.c/h       # chooses which strategy to execute
```

You can keep the current API (`verify_http_digest`, `verify_ws_security`) but implement each in separate translation units for readability.

## Quick reference: auth_utils.h helpers

| Function | Purpose |
| --- | --- |
| `trim_whitespace` | Removes leading/trailing whitespace for parsed fields. |
| `base64_decode` | Decode Base64 XML nonce values. |
| `base64_encode` | Encode digests for comparison. |
| `get_password_from_csv` | Reads `Credentials.csv` and returns the password for a username. |
| `extract_method` | Reads the HTTP method from the request line. |
| `extract_tag_value` | Reads XML tag contents (e.g., Username/Nonce). |
| `extract_header_val` | Reads key/value pairs from `Authorization: Digest` header. |
| `verify_ws_security` | Validates WS-UsernameToken SOAP headers. |
| `verify_http_digest` | Validates HTTP Digest headers. |
| `getmessageid1` | Extracts SOAP `MessageID` for responses. |
