# Changelog

Notable changes to this service, newest first. Dated rather than versioned: the image is
published per branch and commit, so what matters is what landed on a given day. This file is
written for whoever runs the service or integrates against it.

## 2026-08-31

### Changed

- **A refused request now says which check it failed — in this service's log, never in the answer**
  (`go-authbyte` v0.20.2). Until now the inbound gate refused with `401` and one undifferentiated
  line: the error naming an expired token, a wrong audience or issuer, a bad signature or an unknown
  key id was discarded, and four separate DPoP failures — proof did not verify, proof key is not the
  token's key, replayed proof, and a token that is not sender-constrained at all — collapsed into a
  single code. An expired service token and a forged one produced identical evidence.

  **What changes for you:** refusals now carry a `refused a request at the auth gate` line at `warn`
  with a `reason` field and the underlying error. **The response is byte-identical** — same status,
  same body, same `WWW-Authenticate` — because telling a caller which check it failed hands an
  attacker half the answer. Nothing to configure, and a request that was going to be accepted is
  unaffected.

  A `DPoP-Nonce` challenge is not a refusal and is unchanged: it is the protocol's own first-request
  handshake, answered `401` with a fresh nonce and retried by the client.

## 2026-08-30

### Notes

- **Dependency maintenance only — nothing observable changed.** The framework moved to
  `azugo.io/azugo` and `azugo.io/core` v0.38.0, and the shared libraries to `go-authbyte` v0.20.1, `go-gdpr-audit` v1.1.4, `go-platform-kit` v1.10.0, `go-sec-events` v1.1.4. No route,
  payload, error, environment variable, default or log field is affected, and the image behaves
  exactly as the previous one.

  The platform-kit release is additive on its own side (a size cap for a JetStream stream), and this
  service does not configure one. Recorded here because a deployment that pins image digests will
  see a new build with no accompanying behaviour note otherwise.

## 2026-08-23

### Added

- **The upstream identity provider is now generic: any standard OIDC provider is configuration,
  not code.** Set `OIDC_UPSTREAM_AUTHORITY_URL` (+ client id/secret) and the service resolves the
  provider's endpoints from its discovery document — startup fails closed if it cannot. What was
  provider-specific is now per-deployment configuration: requested scopes
  (`OIDC_UPSTREAM_SCOPES`), the userinfo claim carrying the identity code
  (`OIDC_UPSTREAM_CLAIM_SERIAL`, default `serial_number`), the `acr`/`amr` → login-method
  vocabulary and its fallback (`OIDC_UPSTREAM_METHOD_POLICY` / `_METHOD_DEFAULT`), the allowed
  method set (`OIDC_UPSTREAM_METHODS_ALLOWED`, refused-closed at the callback), the assurance
  fallback (`OIDC_UPSTREAM_LOA_DEFAULT`), and explicit endpoint overrides for providers with
  fixed paths. RP-initiated logout uses the discovered `end_session_endpoint`.
- **Nothing changes for existing deployments.** The `EPARAKSTS_*` variables keep working exactly
  as before — they now select the eParaksts *profile* of the same connector (same fixed
  endpoints, bespoke logout, scope and vocabularies, byte-identical wire behaviour, pinned by
  tests). Configuring both selects the generic provider.

## 2026-08-22

### Documentation

- **The two supported modes are now named: standalone and register-backed.** No behaviour
  changed. The service has always run with or without the membership register, but the
  register-less configuration was described as "the historical behaviour", which under-sold
  it: it is the default, a first-class supported mode, and the one a single-product
  deployment normally runs. The README gains a "Two supported modes" section stating the
  access-control difference (standalone: authentication is access, everyone minted the
  baseline scope set; register-backed: a person with no membership is refused at token
  issue), and the register seam is written down as a contract — the question, the answer,
  both refusals, fail-closed unreachability, and the compatibility promise between the two
  sides. Every case is pinned by an existing test.

## 2026-08-21

### Fixed

- **`service.version` in the logs now reports the build that is running.** Every log line
  carries that field, and until now it was the compiled-in development default. The pipeline
  had always computed a `<branch>-<short-sha>` version and passed it to the image build, but
  the Dockerfile never handed it to the linker, so the value was computed and then discarded —
  which meant no log line could tell you which build produced it. Both halves are wired now.
  Expect a real version where the development default used to appear.
- Nothing else about the image changed: same entrypoint, same ports, same healthcheck, same
  configuration, same behaviour.

### Notes

- Line endings for Go, module, script and Docker files are pinned to LF. Nothing in the
  repository changes — those files were already stored that way — but a Windows working copy
  now holds the same bytes the pipeline builds from, so a local formatting or lint run stops
  reporting differences that do not exist in CI.
