# Fake Camera (ONVIF-SIM)

This directory holds the ONVIF camera simulator, including the HTTP/SOAP server and authentication flow.

## Directory map

- `auth_server.h`: request routing, authentication checks, and response templates.
- `authhandler/`: utilities for HTTP Digest and WS-UsernameToken validation.
- `config.xml`: default device metadata used in responses.
- `Credentials.csv`: username/password pairs for authentication.

## Authentication flow summary

1. The TCP server in `auth_server.h` receives an HTTP request that contains SOAP XML in the body.
2. Requests like `GetSystemDateAndTime` are allowed without authentication.
3. Protected requests (example: `GetDeviceInformation`) are checked with `has_any_authentication()`:
   - If a WS-UsernameToken header is present in the SOAP XML, `verify_ws_security()` validates it.
   - If an HTTP `Authorization: Digest` header is present, `verify_http_digest()` validates it.
4. On failure, the server responds with `HTTP/1.1 401 Unauthorized` and a `WWW-Authenticate: Digest` challenge.

Continue with the detailed authentication guide in `authhandler/README.md`.
