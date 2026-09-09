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

### Fixed — a version tag points at the signed image digest again

Publishing a release re-pointed the version tag by rewrapping the image manifest into a new
manifest list, which gave the tag a **different digest from the one the signature covers** — so
verifying the signature on a version tag failed. The retag is now a plain pull, tag and push, which
keeps the digest and therefore keeps the signature valid. Separately, a release published right
after a merge could race the branch build; the job now waits for the image to be published before
tagging.

**A version tag published before this needs one release re-publish** to be re-pointed at the signed
digest. Verifying the rolling `:develop` or `:latest` tag was never affected.

### Changed — the metrics endpoint no longer offers OpenMetrics

A scraper that asked for the OpenMetrics format by sending `Accept: application/openmetrics-text`
used to be answered in it, with the `# EOF` terminator that format requires. This service now
answers in the Prometheus text format whatever the scraper asks for, and writes no `# EOF`:

```http
GET /metrics
Accept: application/openmetrics-text

200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
```

**The metric names, labels and values are unchanged**, so Prometheus — and anything else that
accepts the plain-text exposition format — needs nothing done. Two setups need a look: a scrape
configuration that *requires* the OpenMetrics content type, and a check that reads a missing
`# EOF` as a truncated scrape. Both need their expectation relaxed.

The endpoint itself is unchanged otherwise: still `/metrics` (or `METRICS_PATH`), still enabled by
default, and still answered only for trusted addresses (`METRICS_TRUSTED_IPS`, `127.0.0.1` by
default) — so if nothing scrapes this service, there is nothing to do. The change arrives from the
web framework this service is built on rather than from a change of its own, carried in with the
shared libraries below.

### Notes

- The shared libraries moved to their current releases — the auth client at v0.21.0 and the
  platform kit at v1.11.2 — which carried the web framework, the HTTP stack and the JOSE library up
  with them. No endpoint, field, error or setting of this service changed, and no configuration
  needs touching. The move also clears two published advisories in the cryptography library this
  service depends on; a third has no fix available yet and was already present before the move, and
  the vulnerability scanner reports nothing this service's own code can reach.

## v0.1.0 — 2026-09-01

Initial code.

The authbyte authorization server as first released: OAuth2/OIDC with PKCE and DPoP,
Web eID card login, upstream OIDC providers (a generic discovery-driven connector plus the
eParaksts profile), RFC 8693 token exchange issuing delegated service tokens, and structured
audit events. Two supported modes: standalone and register-backed. AGPL-3.0-only.
