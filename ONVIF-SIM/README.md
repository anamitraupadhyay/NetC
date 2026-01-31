# ONVIF-SIM Overview

This directory contains the ONVIF camera simulator. The authentication utilities that secure the simulated endpoints live under `fakecamera/authhandler/`. For a deep dive into how HTTP Digest and WS-Security UsernameToken authentication are implemented with OpenSSL and how to integrate them with ONVIF services, see:

- [`fakecamera/authhandler/README.md`](fakecamera/authhandler/README.md) — end-to-end guide to `auth_utils.h`, OpenSSL usage, HTTP/XML flows, and integration tips.
