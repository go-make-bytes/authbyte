# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.1

### Added — tenant service accounts: a machine that is a member of an organisation

A registered service client can now act **for an organisation** rather than only as itself. At
`POST /token` with `grant_type=client_credentials`, a client that adds `tenant=<id>` is treated as a
**service account**: its membership in that organisation is checked in the membership register (the
register key is the client id itself, e.g. `svc:acme-dms`), the organisation is minted into the token
as `tenant`, and the scopes are what the client's registry grant allows **and** its membership grants.
Not a member of that organisation → `403 err:membership:notMember`; a member with no role toward the
requested audience → `403`; no register configured → `403 err:membership:notMember`; register
unreachable → `502 err:upstream:unavailable`. A client that names no tenant is unchanged: the registry
alone decides, no register is consulted, no tenant is minted. The issue event records the tenant.

```http
POST /token
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIs…

grant_type=client_credentials&client_id=svc:acme-dms&client_secret=…&audience=svc:signbyte-integration-api&scope=signing-requests:write&tenant=01TENANTACME
```

```http
HTTP/1.1 200 OK
{ "access_token": "eyJ…", "token_type": "DPoP", "expires_in": 300 }
```

The token's claims: `sub` and `client_id` `svc:acme-dms`, `tenant` `01TENANTACME`, `scope`
`signing-requests:write`, `cnf.jkt`.

### Changed — token exchange acts for a service account, never for a platform service

RFC 8693 token exchange admits a **service** subject when its token carries a `tenant` — the token of a
service account, which nothing but a verified membership mints — and carries that tenant into the delegated
token together with the actor chain. A service token without a tenant (a platform service acting as itself)
is refused as before, `403`, and the refusal is now recorded as an authorization-denied security event
naming the requesting client and the subject it asked for. People are exchanged exactly as before.

### Changed — who is asked about membership is decided per browser client

Until now one knob, `ROLEBYTE_URL`, decided that **every** person needs a membership. Each browser client's
registry row can now say it for its own people: `membership_required: false` keeps a client's people on the
baseline scope set with no tenant, and **the register is never asked about them**; `true`, or unset with a
register wired, keeps today's behaviour (no membership → `403 err:membership:notMember`). One deployment can
therefore serve a public portal and a members-only product from one issuer. A row that requires a membership
in a deployment with no register refuses to start. Existing deployments change nothing: the default with a
register wired is "required", without one "baseline".

```yaml
public_clients:
  - client_id: portal-spa
    enabled: true
    membership_required: false
    allowed_redirect_uris: [https://portal.example/api/portal/v1/login/callback]
```

### Changed — several memberships are the person's choice, not a refusal

A person who belongs to several organisations was refused with `409 err:membership:ambiguous`. Their token
is now issued with **no tenant and no scopes** — never the union — and the token response lists the
organisations to choose from in a new `tenants` member. The client shows the choice and repeats the login
with `GET /authorize?tenant=<id>`; the choice rides the login into the token issue, is checked against the
person's memberships (an organisation they do not belong to → `403 err:membership:notMember`) and the chosen
organisation's scopes and `tenant` are minted. The session remembers the choice, so a refresh re-resolves the
same organisation. The `409` is no longer produced.

```http
HTTP/1.1 200 OK
{ "access_token": "eyJ…", "token_type": "DPoP", "expires_in": 900, "refresh_token": "…",
  "tenants": ["01TENANTA", "01TENANTB"] }
```

Sessions established before this release carry no client id; at their next refresh they are treated as a
client that requires a membership. In a deployment whose people are on the baseline, such a session is
refused once and the person signs in again.

## v0.1.0 — 2026-09-01

Initial code.

The authbyte authorization server as first released: OAuth2/OIDC with PKCE and DPoP,
Web eID card login, upstream OIDC providers (a generic discovery-driven connector plus the
eParaksts profile), RFC 8693 token exchange issuing delegated service tokens, and structured
audit events. Two supported modes: standalone and register-backed. AGPL-3.0-only.
