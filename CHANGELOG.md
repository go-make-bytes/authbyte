# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.0 — 2026-09-01

Initial code.

The authbyte authorization server as first released: OAuth2/OIDC with PKCE and DPoP,
Web eID card login, upstream OIDC providers (a generic discovery-driven connector plus the
eParaksts profile), RFC 8693 token exchange issuing delegated service tokens, and structured
audit events. Two supported modes: standalone and register-backed. AGPL-3.0-only.
