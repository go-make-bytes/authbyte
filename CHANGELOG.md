# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.1

**Token exchange can act for one registered service — in development only.** A service client's
registry row may carry `exchange_as_subject: true`; the token exchange then admits that client's
own tokens as the subject, so another client can act on its behalf (the case: an integration API
acting toward the platform services as the document system that called it). The default is
unchanged — a service-shaped subject is refused with `403` — and the field is a development
concession with a hard fence: a registry document carrying it **stops the service at start** in
any environment other than `development`, naming the client and the field, so it cannot reach a
staging or production posture by configuration. Every admitted exchange is logged. The field is
retired the day tenant service accounts land and a membership decides instead.

```yaml
service_clients:
  - client_id: svc:acme-dms
    secret_ref: env:AUTHBYTE_CLIENT_SECRET_SVC_ACME_DMS
    enabled: true
    exchange_as_subject: true      # development only — refused at start elsewhere
    grants:
      - audience: svc:signbyte-integration-api
        scopes: [signing-requests:read, signing-requests:write]
```

## v0.1.0 — 2026-09-01

Initial code.

The authbyte authorization server as first released: OAuth2/OIDC with PKCE and DPoP,
Web eID card login, upstream OIDC providers (a generic discovery-driven connector plus the
eParaksts profile), RFC 8693 token exchange issuing delegated service tokens, and structured
audit events. Two supported modes: standalone and register-backed. AGPL-3.0-only.
