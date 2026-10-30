# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.3.0

### Fixed — a sign-in completes only with a method the request asked for

A request's `acr_values` used to be passed to the provider and then forgotten, so a provider that answered with
another method (its own session still live for it, say) produced a session the client never asked for.
- **At `/authorize`**, each value in `acr_values` must name a method the provider offers, read with the provider's own
  vocabulary. A request naming any other value is answered at the client's registered address with
  `error=unmet_authentication_requirements` and the client's `state`, before a flow is stored or the browser is sent
  on.
- **At completion**, at the provider callback and at the card door alike, the method achieved must be one of those
  asked for. Otherwise no code is issued, nothing is written to the identity store, the failure is recorded with the
  method achieved, and the provider callback sends the browser to the client with
  `error=unmet_authentication_requirements` and its `state` (the card door answers `401`).
- A request that names no method accepts any method the provider allows, as before.

### Fixed — a step-up must be completed by the person the session belongs to

A step-up used to check only the login method, so another person's card, or another person's sign-in at the
provider, could raise a session's assurance level. Now the step-up is refused, at the provider callback and at the
card door alike, unless:
- for a session whose login carried an identity code, the step-up's login carries the same code;
- for a session without one (a directory sign-in), the step-up's login is the same credential at the same provider.

A login with a code never raises a session without one, or the other way round, because nothing links the two yet.
The refusal answers `401` like the other step-up refusals and is recorded as a step-up failure with its own reason.
The session is left as it was. Sessions now keep the login's provider handle and provider, so a directory session
signed in before this version cannot be stepped up; signing in again fixes it.

### Changed — a token exchange checks where the subject token came from

**Breaking for every deployment whose edges exchange a person's token.** Add `act_from` to each such client in the
client registry before taking this version, or its exchanges are refused.
- **A client exchanges only a subject token issued for itself or for an audience it lists under `act_from`.** A
  product's edge lists the product's user audience (`AUTH_USER_AUDIENCE`), for example `act_from: [portal-api]`. A
  token addressed to the client itself needs no entry, so a service passing on what was delegated to it keeps working
  unchanged. A subject token with no audience is refused.
- **The refusal** answers `403`, as a refused delegation already does, and is recorded as a delegation refusal with
  its own reason.
- **The registry refuses unknown keys.** A misspelled key used to load as if it were absent; now the service refuses
  to start and names the line. Check a registry before deploying: one that carried keys this service never read will
  stop the start.

### Changed — PKCE is S256 only, and discovery advertises no ID token

**Breaking for a client that sends `code_challenge_method=plain` or no method at all.** Such a client gets a refusal
where it used to be let through with the weaker form.
- **`/authorize`** takes PKCE only with `code_challenge_method=S256`. An absent method means `plain` (RFC 7636 §4.3),
  so it is refused too, as is a missing `code_challenge`. The refusal is an authorization error response: the browser
  goes back to the client's registered `redirect_uri` with `error=invalid_request` and the client's `state`, before
  any login flow is stored. The `redirect_uri` is checked first, so the refusal never goes anywhere else. A missing
  `code_challenge` used to be answered with a `400` page.
- **`/webeid/challenge`** refuses the same requests with a `422`.
- **The token endpoint** verifies a code only against an S256 challenge.
- **The discovery document** no longer lists `id_token_signing_alg_values_supported`, because no ID token is issued.
  It now lists `none` beside `client_secret_post` in `token_endpoint_auth_methods_supported`, because a browser
  client proves PKCE at `/token` instead of presenting a secret.

### Added — the store's address can come from a file

`REDIS_URL_FILE`: the address of the store that holds flows, sessions and replay guards carries the store's password,
so it can now be read from a file (for example one a secrets agent writes). `REDIS_URL`, when set, still wins, so an
existing deployment changes nothing. A missing or empty file leaves the address unset, and the service refuses to
start because the address is required.

### Changed — the register is asked only about the person being signed in

**Breaking, together with the register.** Release it with the register version that serves the sign-in doors, and in
the same deployment change: point `ROLEBYTE_URL` at the register's sign-in listener (`http://rolebyte:8081` in the
stacks), set the register's `SIGN_IN_CLIENT` to this service's `AUDIT_CLIENT_ID`, and remove every registry grant of
`membership:claim` or `membership:resolve`.

- **Each call to the register carries a token minted for it, naming the person.** At token issue this service mints, in
  its own process, a short-lived token for each sign-in door call: the person (or service account) being signed in as
  `sub`, this service as the acting client (`act`), the door's one scope, bound to the outbound client's DPoP key. It
  sends it to the register's sign-in listener: `POST /api/v1/sign-in/claims`, then `POST /api/v1/sign-in/memberships`,
  and `POST /api/v1/sign-in/directory-admissions` for a directory login. The requests name nobody; the register answers
  for the token's subject alone. No token endpoint and no registry grant are involved any more.
  The token lives one minute and is always bound to the outbound key: a mint without a key thumbprint is refused.
- **An answer about another person is a security event.** It already minted nothing and failed the issue closed
  (`502`); it now also emits `authz.denied` with `kind: sign-in`, which a healthy deployment never produces.
- **Built on go-authbyte's `Client.DoWithToken` and `Client.Thumbprint`** (the release after v0.31.2).

### Changed — built with Go 1.27.3

The service is built with Go 1.27.3 (`go.mod` and the image). Go 1.27.2's `crypto/x509` still trusts
certificates issued by intermediates since found compromised, and the vulnerability checker reports it as
reachable from any call over TLS; under 1.27.3 it reports none. Nothing about the configuration changes.

### Added — a directory sign-in keeps the person's email address

A person who signs in through an organisation's own directory now has the email address the
directory sends kept with their record. The address is read from the verified id_token where it
carries one, otherwise from userinfo, and trimmed. The identity store keeps it only when it is
address-shaped, and keeps none for a person who holds a national identity code. A login is never
refused over it, and a card login sends none. An address carrying a control character, a line or
paragraph separator, or an invisible formatting character (a direction override, a zero-width
character) is dropped and the sign-in goes on. `OIDC_UPSTREAM_CLAIM_EMAIL` names the claim
(default `email`); set it where a provider uses another name.

### Added — two service-only reads of how a person signs in

Both sit beside `POST /identity/persons`, answer `Cache-Control: no-store`, and are for a **service
acting as itself** only: a person's token is refused even when it carries the scope, and so are a
token another service obtained by exchange to act for someone and a service account's token for an
organisation. The two scope levels are
separate, so a grant to read the lines never reaches a code. Neither echoes a value it was sent in
a refusal.

`POST /identity/persons/lines` needs `identity:lines`. It answers, for up to 500 people, whether
each can sign in, the email kept for them (only when there is one) and, for a person holding a
national identity code, its country and the length of the code as a person is shown it. The code
itself is never in the answer. A person the platform does not know is left out.

```
POST /identity/persons/lines      Authorization: DPoP <service token carrying identity:lines>
{"subjects": ["sub:01J8X2K4M9N7P3Q5R6S8T0V1W2", "sub:01J8X2K4M9N7P3Q5R6S8T0V1W3"]}

200 {"lines": [
      {"subject": "sub:01J8X2K4M9N7P3Q5R6S8T0V1W2", "signsIn": true, "country": "LV", "length": 12},
      {"subject": "sub:01J8X2K4M9N7P3Q5R6S8T0V1W3", "signsIn": false, "email": "person@example.org"}]}
422 err:identity:invalid    more than 500, an empty or non-list body, or a subject that is not "sub:" and a 26-character id
403 err:identity:forbidden  not a service acting as itself, or the identity:lines scope is missing
```

`GET /identity/persons/{personSub}/code` needs `identity:code`, takes the bare 26-character person
id and answers the person's national identity code the way a person is shown it, with its country.
Each code answered is recorded with the access audit as a read of that person's identity record by
the calling service (`identity.read`, marked `identityCode`; the code is never in the record). The
record is a routine one: an access audit that is down does not stop the answer, and the caller
records the disclosure it makes onward, which is the record that gates it.

```
GET /identity/persons/01J8X2K4M9N7P3Q5R6S8T0V1W2/code   Authorization: DPoP <service token carrying identity:code>

200 {"code": "XXXXXX-XXXXX", "country": "LV"}
404 err:identity:not_found  the person is not known, or holds no identity code
422 err:identity:invalid    the id is not a 26-character person id
403 err:identity:forbidden  not a service acting as itself, or the identity:code scope is missing
```

## v0.2.2

A security release.

### Fixed — a token refresh no longer admits anyone through a directory

A person who signs in through an organisation's own directory and holds no membership is offered
to the register's admission door, which makes them a member of the organisation that attached that
directory. Until now a token refresh made the same offer. So a session whose person the register no
longer held, after the register was restored or rebuilt, made that person a member again without
anyone signing in. Admission now happens only at a sign-in. A refresh that resolves to no membership
is refused with `403` `err:membership:notMember`, the same as for anyone else without a membership,
and the person is admitted at their next sign-in. A person removed from an organisation was already
refused at the door, and still is. Nothing about the configuration changes.

### Fixed — a refresh while the session store cannot be read is no longer a refusal

A refresh that could not read the session store was answered `401`, the same as a refresh token
whose session is gone. A caller that ends its own session on that answer ended it for a brief store
outage. Such a refresh now answers `503` `err:upstream:unavailable`, and `401` again means the
session is no longer held.

```http
POST /token   grant_type=refresh_token   (the session store unreachable)
503 {"code": "err:upstream:unavailable", …}
```

## v0.2.1

A security release. **The service now builds with Go 1.27.2**, and its libraries move to their Go
1.27.2 releases. Nothing about the API, the configuration or the database changes.

### Changed

- **Go 1.27.2** (was 1.27.0), both in `go.mod` and as the image's default build toolchain
  (`ARG GO_VERSION` in the `Dockerfile`). Go 1.27.2 and `golang.org/x/net` v0.60.0 fix
  vulnerabilities that this service's code reaches under 1.27.0: `govulncheck` found nine it calls,
  GO-2026-6603, -6605, -6607, -6608, -6610, -6611, -6612, -6613 and -6617, in `net/http`,
  `crypto/tls`, `net/textproto` and `golang.org/x/net`. Under the new set it finds none. **Rebuild
  the image to pick the fixes up**; an image built before this change still carries them.
- **Libraries:** `go-authbyte` → v0.29.1 (from v0.23.1), `go-platform-kit` → v1.11.4,
  `go-sec-events` → v1.2.2, `go-gdpr-audit` → v1.1.6, azugo → v0.40.0, `go-redis` → v9.23.0,
  `fasthttp` → v1.75.0, plus 39 indirect modules with them. The go-authbyte releases in between add
  features this service does not use, with one visible change: when the authorization server refuses
  a token request, the error no longer repeats the server's answer, so a log line built from that
  error stops carrying it (the message is now `the token call responded <status>`). None of azugo
  v0.40.0's behaviour changes reaches this service: it sets no cookies, its redirects (on to the
  identity provider, back to the application, and on logout) all answer GET requests, so the new
  `303` after a non-GET request does not apply to them, it makes no outbound calls through azugo's
  HTTP client and it implements no azugo cache.

### Notes

- CI's linter moved to golangci-lint v2.14.0. The earlier release cannot read Go 1.27.2's compiled
  standard library and stops before linting anything.
- The gate is green on Go 1.27.2: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`,
  golangci-lint v2.14.0, `go test -race` with **0 races**; `govulncheck` reports **no
  vulnerabilities found**.

## v0.2.0

### Changed — each card login also permits the CSC flow that reads the card its way

A Web eID login (the card in a reader) now permits `cscEidPlugin` besides `webEid`; an eID Scan login (the card
read by a phone) permits `cscEidScan` besides `eidScan`. Neither login reaches the other card route. The
session's `permitted_flows`:

```json
{ "login_method": "webEid",  "permitted_flows": ["webEid", "cscEidPlugin"] }
{ "login_method": "eidScan", "permitted_flows": ["eidScan", "cscEidScan"] }
```

### Changed — an eParaksts Mobile login no longer permits the CSC signing flow

The CSC remote-signing flow authenticates with the eID card only (read by a phone, or in a card reader), so
it is no longer among the flows an eParaksts Mobile login may drive. The single `csc` flow name is also
retired in favour of two, `cscEidScan` and `cscEidPlugin`, named for how the card is read. The session's
`permitted_flows` for an eParaksts Mobile login:

```json
{ "login_method": "eparakstsMobile", "permitted_flows": ["eparakstsMobile", "eparakstsMobileEseal"] }
```

A Web eID or eID Scan login permits the CSC flow that reads its card the same way (above).

## v0.1.2

### Changed — a token is minted only from a register answer about the person who signed in

With a membership register wired, the register's resolve answer now has to name the subject it is
about (`subjectKey`), and it has to be the subject asked about. An answer about anyone else, or one
that names nobody, refuses the token instead of minting its memberships:

```
POST /token   (a user token, register wired)
→ 502 { "code": "err:upstream:unavailable" }   when the register's answer is not about this person
```

Every resolve also writes one info line, `membership resolved`, with the key asked, the key
answered for, and each membership's tenant and scopes. **Upgrade the register first:** a register
that does not yet name its subject makes every login that needs a membership fail this way.


### Changed — signing out no longer ends a directory provider's session

Signing out through `GET /logout` used to send every upstream login on through the provider's
end-session endpoint, ending the session the provider keeps in the browser. That is right for a
provider whose short-lived SSO session on a shared device would otherwise sign the next person in
as the previous one — the eParaksts profile keeps doing it — and wrong for a directory provider,
whose session is the person's whole estate: signing out of this application signed them out of
their mail and documents too, after a page asking which account to sign out of. The generic
connector now signs out **locally by default**: this service's session ends and the browser
returns to `redirect_uri`; the provider's session is left alone. A deployment that wants the
front-channel hop for a generic provider lists the methods:

```
OIDC_UPSTREAM_METHODS_FEDERATED=upstream
```

The logout audit event's `federated` attribute says which of the two happened. Nothing changes for
the eParaksts profile.

### Added — the generic connector verifies the provider's id_token

When the upstream provider publishes a key set — its discovery document names a `jwks_uri`, as
every mainstream provider's does, or `OIDC_UPSTREAM_JWKS_URL` and `OIDC_UPSTREAM_ISSUER` are set
for a provider configured by explicit endpoints — every login must now carry an id_token that
verifies: signed with one of the published keys (RS256 · PS256 · ES256 only), `iss` equal to the
issuer, `aud` containing this client, `exp` and `iat` within `TOKEN_CLOCK_SKEW_LEEWAY`, the `nonce`
this service sent with the authorize request, and a subject equal to userinfo's. A missing or
failing id_token refuses the login — `401`, the reason in the login-failure audit event, no claim
value in it. The id_token's claims win over userinfo's where both carry one, and its `acrs` join
the `amr` list for the `LOA_POLICY` vocabulary. **Without a key set nothing changes**: the eParaksts
profile and any provider with fixed paths and no `jwks_uri` stay userinfo-only.

Two claim maps for an organisation whose people sign in through its own directory:
`OIDC_UPSTREAM_CLAIM_DIRECTORY_ID` (default `sub`; `oid` for Microsoft Entra ID) names the durable
identifier the person's credential is stored under, and `OIDC_UPSTREAM_CLAIM_ACCOUNT_STATUS`
(`acct` for Entra) with `OIDC_UPSTREAM_ACCOUNT_STATUS_GUEST` (default `1`) tells a member of the
directory from a guest in it.

```
OIDC_UPSTREAM_AUTHORITY_URL=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_UPSTREAM_SCOPES=openid profile email
OIDC_UPSTREAM_CLAIM_SERIAL=            # empty: a directory carries no identity code
OIDC_UPSTREAM_CLAIM_DIRECTORY_ID=oid
OIDC_UPSTREAM_CLAIM_ACCOUNT_STATUS=acct
OIDC_UPSTREAM_METHOD_DEFAULT=upstream
OIDC_UPSTREAM_METHODS_ALLOWED=upstream
OIDC_UPSTREAM_LOA_DEFAULT=low
```

**A login without an identity code is no longer refused.** The identity store creates the person
without one, resolved by their credential on every later login; such a person stays separate from
the same human's card login until linked by a deliberate act (a later release). Requires the
platform database at `identity/V3` — against an older one the login is refused as before.

### Added — a login through an organisation's directory is admitted into the tenant that attached it

At token issue, a person who came through the upstream provider and holds no membership is offered
to the membership register's admission door (`POST /api/v1/directory-admissions`, on the
`membership:claim` scope this service already holds toward the register — **no registry change**):
the tenant that attached that issuer as its directory admits them as an active member with **no
grants**, and the token is minted for that tenant with an empty scope set — a member who holds
nothing until an administrator assigns a role. A guest in the provider's directory is not offered
and is refused as before (`403 err:membership:notMember`); so is everyone whose issuer no tenant
attached. A person already holding a membership is never offered, so a refresh costs no extra
call. **Requires a register release that exposes the door**: an older register answers `404`, and
the issue fails closed (`502 err:upstream:unavailable`) for exactly the people who would have been
admitted — deploy the register first.

### Changed — two configured upstream families refuse to start

Setting both `OIDC_UPSTREAM_*` and `EPARAKSTS_*` used to select the generic connector silently.
The service now refuses to start: *two upstream identity providers are configured (OIDC_UPSTREAM_*
and EPARAKSTS_*): this service runs exactly one — unset one family*. A deployment that carried
eParaksts placeholders beside a generic connector removes them.

### Changed — the membership register is asked by the person's platform subject, never their identity code

At token issue this service asks the membership register which organisations a person belongs to. It
asked by the person's national identity code, typed `pno:<code>`; it now asks by their **platform
subject** — the stable id the identity store keys the person on, which is the token's own `sub` —
typed **`sub:<person id>`**. A service account is still asked for by its client id (`svc:<client id>`).
No token changes shape: the key is a function of `sub`, and every consumer derives it the same way, so
nothing new is minted and the identity code (`serial_number`) stays on the token for the signing side.

```
register lookup, before:  claim + resolve by "pno:PNOLV-XXXXXXXXXXX"
register lookup, after:   claim + resolve by "sub:01J8X2K4M9N7P3Q5R6S8T0V1W2"   (= "sub:" + the token's sub)
```

**Removed with it:** the refusal *"the login carries no identity code"* (a 502 at token issue). A
session always has a subject, so a login method that supplies no identity code can be issued a token
and resolved against the register like any other.

**Deploy order.** The register's database migration that retires the `pno:` kind comes first, then the
register service and this service together. Against an older register this service's `sub:` keys are
refused by the register's constraint; an older authorization server's `pno:` keys are refused by the
new register at every write door and resolve to nobody. Neither combination runs; migrate, then redeploy.

### Added — `POST /identity/persons`: a person gets a platform subject before their first login

An administrator registering or inviting somebody — or recording a person who will never log in —
needs that person's platform subject to register them under, and until now a subject existed only
once the person had logged in. The new door creates the person row in the identity store with the
canonical identity code and whatever name is known, and **no credential**: a record, not an account.
Nothing can log in as them until a login attaches a credential, and that login lands on this row
because the same canonical code is matched there.

```
POST /identity/persons            Authorization: DPoP <token carrying identity:admin>
{"identityCode": "PNOLV-XXXXXX-XXXXX", "name": "…", "givenName": "…", "familyName": "…"}

201 {"personSub": "01J8X2K4M9N7P3Q5R6S8T0V1W2", "created": true}     the person is new
200 {"personSub": "01J8X2K4M9N7P3Q5R6S8T0V1W2", "created": false}    already known (registered, or logged in before);
                                                                      names are filled only where the row has none
422 err:identity:invalid    the code names no country, or an identity type this platform does not know — never echoed
403 err:identity:forbidden  the token does not carry identity:admin
```

The scope is minted like every other: a role in the membership register grants it to an
administrator; for bring-up a registry client may hold it as a service-token grant. Each registration
is recorded as a GDPR-audit identity write (the administrator as actor, the person as subject), routine
and fail-open like the login path's own record. **Nothing to configure.**

## v0.1.1

### Removed — `OIDC_UPSTREAM_COUNTRY`

The setting is gone. It supplied a country for an identity-code claim that carried none, so that a
bare national code could be stored in the canonical `PNO<CC>-<code>` form. Two things were wrong with
it: the variable was never bound to the configuration in the first place, so setting it had no effect
and produced no warning; and the design was unsound even had it worked, because one value applies to
every person who logs in through the provider. A deployment whose users hold codes from more than one
national register would have filed some of them under another register's country — a perfectly valid
key belonging to the wrong person, with nothing to notice it by.

**If you set it:** nothing changes, because nothing was reading it. No deployment behaviour differs.

**What the service does now:** the claim named by `OIDC_UPSTREAM_CLAIM_SERIAL` must carry an identity
code that states its own country (`PNOLV-XXXXXXXXXXX`). A bare code refuses the login, as it already
did. The remedy is a claim mapping at your identity provider, where the identity **type** can be
stated alongside the country rather than assumed. Card login is unaffected: it takes the country from
the card certificate's own subject attribute, which is a fact about the person holding the card.

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

### Changed — one identity code per person, whichever way the card or the provider writes it

A person's identity code now reaches every store and every token in **one spelling**: the identity
type, the country, a hyphen, and the national code with its separators removed —
`PNOLV-XXXXXXXXXXX`. The same person's card certificate may write `PNOLV-XXXXXX-XXXXX` and a
provider may send `XXXXXX-XXXXX`; compared as text those were three different people, and documents
signed under one spelling were unreachable from another.

What an integrator sees: the `serial_number` claim in an issued token, and the identity code the
signer-slot match compares against, are now that one spelling.

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=…&client_id=portal-spa&code_verifier=…
```

```json
{ "sub": "01J…", "serial_number": "PNOLV-XXXXXXXXXXX", "scope": "…", "tenant": "…" }
```

Nothing is guessed. A code that already names its country keeps it — a Lithuanian person
authenticating through a Latvian provider stays Lithuanian. A code that names none is keyed under
the country of the **card certificate** it was read from, or the country configured for the
**provider** it came from. A code with no country available anywhere, or with an identity type this
platform does not recognise, **refuses the login** (`401`) and records why, rather than filing the
person under a guess: a wrong identity key is the wrong person's documents.

### Added — `OIDC_UPSTREAM_COUNTRY`, for a provider that sends a bare national code

| Variable | Default | Purpose |
| --- | --- | --- |
| `OIDC_UPSTREAM_COUNTRY` | — | Two-letter country whose register issues this provider's identity codes; used only when the claim carries no country of its own |

Set it for a generic OIDC provider whose identity-code claim is a bare national code — without it,
those logins are refused. A provider whose claim carries `PNO<CC>-` needs nothing: the value wins
either way. The eParaksts profile already carries `LV`, so eParaksts deployments need no change.

### Notes

- The shared libraries moved to their current releases — the auth client at v0.21.0 and the
  platform kit at v1.11.2 — which carried the web framework, the HTTP stack and the JOSE library up
  with them. No endpoint, field, error or setting of this service changed, and no configuration
  needs touching. The move also clears two published advisories in the cryptography library this
  service depends on; a third has no fix available yet and was already present before the move, and
  the vulnerability scanner reports nothing this service's own code can reach.

### Changed — the shared libraries move to their current releases

`go-platform-kit` v1.11.3, `go-authbyte` v0.23.1, `go-gdpr-audit` v1.1.5 and `go-sec-events`
v1.2.1. No endpoint, field, error or setting changes with them, nothing in your configuration needs
touching, and this service's own behaviour is unchanged. Two of those cross a release worth naming:
`go-authbyte` v0.23.0 added a way to tell a natural person's identity code from an organisation's,
and `go-sec-events` v1.2.0 allows a security event to be emitted from work with no request behind
it — both additions to the libraries, neither a change here. The Postgres driver `pgx/v5` moves to
v5.11.0 in the same pass.

## v0.1.0 — 2026-09-01

Initial code.

The authbyte authorization server as first released: OAuth2/OIDC with PKCE and DPoP,
Web eID card login, upstream OIDC providers (a generic discovery-driven connector plus the
eParaksts profile), RFC 8693 token exchange issuing delegated service tokens, and structured
audit events. Two supported modes: standalone and register-backed. AGPL-3.0-only.
