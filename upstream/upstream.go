// Package upstream is the generic upstream-OIDC connector: the one component
// that talks to the external identity provider this deployment authenticates
// against. A provider is CONFIGURATION, not code — endpoints (discovered or
// explicit), client credentials, scopes, claim names, and the vocabularies that
// map the provider's acr/amr claims onto login methods and assurance levels.
//
// The connector supports exactly one configured upstream per deployment. It is
// constructed from a Config VALUE and handed to the routes as a value, so a
// composing layer can supply a differently-configured provider without touching
// this package.
package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/identitycode"
	"github.com/gmb-lib/go-authbyte/jwks"
	"github.com/gmb-lib/go-platform-kit/observability"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/golang-jwt/jwt/v5"

	"go.uber.org/zap"
)

// ErrIDToken is returned when the provider is known to issue id_tokens (its key
// set is known) and the login's id_token is missing or does not verify: the
// signature against the provider's published keys, the issuer, the audience,
// the times, the flow's nonce, or a subject that differs from userinfo's. A
// login that produced it is refused — the provider's own assertion of who
// logged in is the one thing the connector must not take on trust.
//
// It wraps the reason; the reason never carries a claim value.
var ErrIDToken = errors.New("oidc: the provider's id_token did not verify")

// idTokenAlgorithms is the allow-list of signature algorithms an id_token may
// carry: asymmetric only. `none` and the HMAC family are refused — with HMAC the
// key would be the client secret, and a token anyone holding it can mint proves
// nothing about who logged in.
var idTokenAlgorithms = []string{"RS256", "PS256", "ES256"}

// ErrIdentityCode is returned when the provider's identity-code claim cannot be
// reduced to the platform's canonical spelling — an identity type this platform
// does not recognise, or a bare national code from a provider with no Country
// configured. A login that produced it is refused: an identity code that cannot
// be keyed the one way would key the person a second way instead, and the
// documents they signed under the first would be unreachable from the second.
//
// It wraps the reason, which never carries the offending value: an identity code
// is personal data and this error is written to service logs.
var ErrIdentityCode = errors.New("oidc: the identity code from the provider cannot be canonicalised")

// Config describes one upstream OIDC provider completely. Zero-value fields
// fall back to standard OIDC behaviour; the eParaksts profile pre-fills the
// fields that provider needs (see EParakstsProfile).
type Config struct {
	// AuthorityURL is the provider's base URL (issuer). With no explicit
	// endpoint URLs below, endpoints are resolved from
	// {AuthorityURL}/.well-known/openid-configuration at construction.
	AuthorityURL string
	ClientID     string
	ClientSecret string
	// Scopes requested at authorization (default: "openid profile").
	Scopes []string

	// Explicit endpoint URLs (absolute). When ALL required ones are set
	// (authorize + token + userinfo), discovery is skipped — for providers
	// with fixed, non-discoverable paths.
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	// EndSessionURL is the RP-initiated-logout endpoint. Empty and not
	// discovered means the provider gets no logout redirect (LogoutURL
	// returns "").
	EndSessionURL string
	// LogoutTemplate overrides standard RP-initiated logout entirely: a full
	// URL with a %s placeholder for the url-encoded post-logout redirect.
	// Used by providers with a bespoke session-termination endpoint.
	LogoutTemplate string

	// ClaimSerial names the userinfo claim carrying the person's identity
	// code (default "serial_number").
	ClaimSerial string

	// Issuer is the value the provider's id_token `iss` claim must carry, and
	// the identity the platform records a login as having come through.
	// Discovered (the document's `issuer`) unless set explicitly.
	Issuer string
	// JWKSURL is where the provider publishes the keys its id_tokens are signed
	// with. Discovered (`jwks_uri`) unless set explicitly. When it is known the
	// id_token path is ON: every login must carry an id_token that verifies, or
	// it is refused. Empty — the eParaksts profile, a provider with fixed paths
	// and no key set — means userinfo only, exactly as before the path existed.
	JWKSURL string
	// ClaimDirectoryID names the claim carrying the person's durable identifier
	// at the provider — the handle their credential is stored under. Read from
	// the id_token first, then userinfo. Default "sub"; Microsoft Entra ID's is
	// `oid`, because its `sub` is pairwise per application registration and
	// would change if the application were ever registered again.
	ClaimDirectoryID string
	// ClaimAccountStatus names the claim saying whether the person is a member
	// of the provider's own directory or a guest in it (Entra: `acct`), and
	// AccountStatusGuest is the value that marks a guest (default "1"). With no
	// claim named, nobody is a guest. A guest is logged in like anyone else; it
	// is only the admission into a tenant by its attached directory that the
	// flag withholds — a tenant attached its own people, not its visitors.
	ClaimAccountStatus string
	AccountStatusGuest string
	// ClockSkewLeeway is tolerated when checking an id_token's times (default
	// 30s) — the same allowance this service grants its own tokens.
	ClockSkewLeeway time.Duration

	// Country is the two-letter country whose register issues the identity
	// codes this provider authenticates people from — the country of the
	// people it serves, not the country the deployment runs in.
	//
	// It is consulted ONLY when the claim carries no country of its own: a
	// value that states one ("PNOLT-...") keeps it, even here. A provider that
	// sends a bare national code and has no country set delivers a login this
	// service refuses, which is the intended outcome — the alternative is
	// filing a person under a guessed nationality, and a wrong identity key is
	// the wrong person's documents.
	//
	// A PROVIDER PROFILE sets this, never a deployment: it is a statement
	// about one provider's own claim format, which the people configuring a
	// deployment cannot know better than the profile does. It is deliberately
	// not exposed as a setting — one value covers every person who logs in
	// through the provider, so a deployment whose users hold codes from more
	// than one register would file some of them under the wrong one,
	// canonically and with no error to notice. The remedy for a provider that
	// sends bare codes is a claim mapping at that provider, where the identity
	// type can be stated too.
	Country string

	// SignIdentityURL is the base URL (trailing slash included) of the
	// provider's per-identity certificate endpoint: GET {SignIdentityURL}{id}
	// answers the sign identity's certificate. Set only for providers whose
	// userinfo carries a sign-identity catalog; empty disables login-time
	// capability capture.
	SignIdentityURL string

	// MethodPolicy maps acr/amr tokens (lower-cased substrings, longest
	// match wins) to login methods; MethodDefault is the method when nothing
	// matches (default: the legacy "eid" sentinel, which is never allowed —
	// fail closed). LoAPolicy/LoADefault do the same for assurance levels.
	MethodPolicy  map[string]string
	MethodDefault string
	LoAPolicy     map[string]string
	LoADefault    string

	// MethodsAllowed is the set of login methods this provider may deliver;
	// a callback resolving to anything else is refused. Empty means: exactly
	// {MethodDefault}, when MethodDefault is set.
	MethodsAllowed []string
	// MethodsFederated is the set of methods whose sign-out must also travel
	// front-channel through the provider, clearing the session cookie it keeps
	// in the browser. Empty means none: signing out ends this service's session
	// and returns the browser to the application, and the provider's own
	// session is left alone — for a directory provider that session is the
	// person's whole estate (mail, documents, every other application), which
	// an application's sign-out has no business ending. A profile whose
	// provider keeps a short-lived SSO session on shared devices lists its
	// methods here (the eParaksts profile does); a deployment adds methods
	// with OIDC_UPSTREAM_METHODS_FEDERATED.
	MethodsFederated []string
}

// Provider talks to the configured upstream identity provider.
type Provider struct {
	cfg    Config
	httpc  *http.Client
	log    *zap.Logger
	fedSet map[string]bool
	okSet  map[string]bool
	// keys is the provider's published key set, cached and refreshed by kid;
	// nil when no key set is known, in which case no id_token is read.
	keys *jwks.Client
}

// New constructs the provider from its Config value. When endpoints are not
// explicit it resolves them via OIDC discovery (one HTTP call, fail closed).
// log may be nil (a no-op logger is used).
func New(ctx context.Context, cfg Config, log *zap.Logger) (*Provider, error) {
	if log == nil {
		log = zap.NewNop()
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile"}
	}
	if cfg.ClaimSerial == "" {
		cfg.ClaimSerial = "serial_number"
	}
	if cfg.ClaimDirectoryID == "" {
		cfg.ClaimDirectoryID = "sub"
	}
	if cfg.AccountStatusGuest == "" {
		cfg.AccountStatusGuest = "1"
	}
	if cfg.ClockSkewLeeway <= 0 {
		cfg.ClockSkewLeeway = 30 * time.Second
	}
	cfg.AuthorityURL = strings.TrimSuffix(cfg.AuthorityURL, "/")

	// External authority: otel-instrumented so the token-exchange + userinfo
	// calls show as client spans (no-op when tracing is inert). The correlation
	// id is intentionally NOT propagated — a foreign authority ignores it — so
	// this stays a bespoke client rather than the context-bound one our own
	// service-to-service calls use.
	httpc := observability.InstrumentHTTPClient(&http.Client{Timeout: 15 * time.Second})

	if cfg.AuthorizeURL == "" || cfg.TokenURL == "" || cfg.UserInfoURL == "" {
		if err := discover(ctx, httpc, &cfg); err != nil {
			return nil, err
		}
	}

	if len(cfg.MethodsAllowed) == 0 && cfg.MethodDefault != "" {
		cfg.MethodsAllowed = []string{cfg.MethodDefault}
	}
	p := &Provider{cfg: cfg, httpc: httpc, log: log, okSet: map[string]bool{}, fedSet: map[string]bool{}}
	for _, m := range cfg.MethodsAllowed {
		p.okSet[m] = true
	}
	for _, m := range cfg.MethodsFederated {
		p.fedSet[m] = true
	}

	// The id_token path switches on with the provider's key set. A key set
	// without an issuer to check the token against would verify a signature and
	// nothing else — refused at startup rather than trusted at login.
	if cfg.JWKSURL != "" {
		if cfg.Issuer == "" {
			return nil, fmt.Errorf("oidc: the provider publishes a key set (%s) but no issuer is known — set the issuer explicitly or let discovery supply it", cfg.JWKSURL)
		}
		p.keys = jwks.New(cfg.JWKSURL, time.Hour, jwks.WithHTTPClient(httpc))
	}

	return p, nil
}

// IDTokenVerified reports whether logins through this provider carry a verified
// id_token: true when the provider's key set is known.
func (p *Provider) IDTokenVerified() bool { return p.keys != nil }

// Issuer is the identity provider's issuer as discovered or configured.
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// Resolver builds the identity resolver carrying this provider's acr/amr
// vocabularies and defaults.
func (p *Provider) Resolver() *identity.Resolver {
	return identity.NewResolverPolicies(p.cfg.LoAPolicy, p.cfg.MethodPolicy, p.cfg.MethodDefault, p.cfg.LoADefault)
}

// MethodAllowed reports whether a login method resolved from this provider's
// callback is permitted. Anything outside the configured set is rejected, so
// the upstream login path fails closed.
func (p *Provider) MethodAllowed(method string) bool { return p.okSet[method] }

// FederatedMethod reports whether a sign-out after this method must also
// travel through the provider, clearing the session cookie it keeps in the
// browser. The set is the profile's or the deployment's choice
// (Config.MethodsFederated); a method outside it signs out locally.
func (p *Provider) FederatedMethod(method string) bool { return p.fedSet[method] }

// AuthorizeParams configures the authorization redirect.
type AuthorizeParams struct {
	State       string
	RedirectURI string
	// ACRValues optionally requests a specific assurance/method (used for
	// step-up, e.g. to force a particular method).
	ACRValues string
	UILocales string
	Prompt    string
	// Nonce binds the id_token the provider issues to this very flow: the
	// value is kept with the flow and must come back inside the token.
	Nonce string
}

// AuthorizeURL builds the URL to redirect the user to for authentication.
func (p *Provider) AuthorizeURL(params AuthorizeParams) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("state", params.State)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	if params.Nonce != "" {
		q.Set("nonce", params.Nonce)
	}
	if params.ACRValues != "" {
		q.Set("acr_values", params.ACRValues)
	}
	if params.UILocales != "" {
		q.Set("ui_locales", params.UILocales)
	}
	if params.Prompt != "" {
		q.Set("prompt", params.Prompt)
	}

	return p.cfg.AuthorizeURL + "?" + q.Encode()
}

// LogoutURL builds the provider's session-termination URL. The browser MUST be
// navigated here (front-channel) — the IdP's SSO cookie lives in the user's
// browser on the provider's domain, so a server-to-server call cannot clear it.
// The provider redirects the browser to redirectURI when done.
//
// redirectURI must be acceptable to the provider (HTTPS, registered) and SHOULD
// be validated against the client redirect allowlist by the caller
// (open-redirect protection). Returns "" when the provider has no logout
// endpoint — the caller then redirects locally.
func (p *Provider) LogoutURL(redirectURI string) string {
	if p.cfg.LogoutTemplate != "" {
		return fmt.Sprintf(p.cfg.LogoutTemplate, url.QueryEscape(redirectURI))
	}
	if p.cfg.EndSessionURL == "" {
		return ""
	}
	q := url.Values{}
	q.Set("post_logout_redirect_uri", redirectURI)
	q.Set("client_id", p.cfg.ClientID)

	return p.cfg.EndSessionURL + "?" + q.Encode()
}

// tokenResponse is the provider token-endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

// Tokens is what the provider's token endpoint answered: the access token the
// userinfo call rides, and the id_token when the provider issues one.
type Tokens struct {
	AccessToken string
	IDToken     string
}

// Exchange swaps an authorization code for the provider's tokens using HTTP
// Basic client authentication (confidential client).
func (p *Provider) Exchange(ctx context.Context, code, redirectURI string) (Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Set("Authorization", p.basicAuth())

	body, status, err := p.do(req)
	if err != nil {
		return Tokens{}, err
	}
	if status/100 != 2 {
		return Tokens{}, fmt.Errorf("oidc: token exchange returned %d: %s", status, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return Tokens{}, fmt.Errorf("oidc: invalid token response: %w", err)
	}

	return Tokens{AccessToken: tr.AccessToken, IDToken: tr.IDToken}, nil
}

// Claims turns the token endpoint's answer into the platform's identity claims.
//
// The userinfo call is always made — it is where the eParaksts profile's claims
// live, and the standard home of the profile. When the provider's key set is
// known (IDTokenVerified), the id_token is verified first and its claims win
// where present: the signature against the published keys (asymmetric
// algorithms only), the issuer, the audience (this client), the times with the
// configured leeway, the flow's nonce, and its subject must equal userinfo's —
// a userinfo answer about somebody else is not this login's. A missing or
// failing id_token refuses the login (ErrIDToken). Without a known key set the
// id_token is not read and the login behaves exactly as it did before this path
// existed.
//
// Two further claims are read, id_token first: the person's durable identifier
// at the provider (ClaimDirectoryID — the handle their credential is stored
// under) and, when configured, the account status that tells a member of the
// provider's directory from a guest in it. The id_token's `acrs` — the
// authentication contexts the login satisfied, where a provider issues them —
// are appended to the amr list, so the assurance vocabulary can map a context to
// a level the same way it maps any other token.
func (p *Provider) Claims(ctx context.Context, tokens Tokens, nonce string) (identity.UserInfo, error) {
	body, err := p.userInfoBody(ctx, tokens.AccessToken)
	if err != nil {
		return identity.UserInfo{}, err
	}
	info, err := p.mapUserInfo(body)
	if err != nil {
		return info, err
	}
	info.Issuer = p.cfg.Issuer

	var idClaims jwt.MapClaims
	if p.keys != nil {
		if tokens.IDToken == "" {
			return info, fmt.Errorf("%w: the token response carried no id_token", ErrIDToken)
		}
		idClaims, err = p.verifyIDToken(ctx, tokens.IDToken, nonce)
		if err != nil {
			return info, err
		}
		if sub, _ := idClaims["sub"].(string); sub == "" || sub != info.Subject {
			return info, fmt.Errorf("%w: the id_token subject differs from the userinfo subject", ErrIDToken)
		}

		if s := claimText(idClaims["given_name"]); s != "" {
			info.GivenName = s
		}
		if s := claimText(idClaims["family_name"]); s != "" {
			info.FamilyName = s
		}
		if s := claimText(idClaims["name"]); s != "" {
			info.Name = s
		}
		if s := claimText(idClaims["acr"]); s != "" {
			info.ACR = s
		}
		if amr := claimTexts(idClaims["amr"]); len(amr) > 0 {
			info.AMR = amr
		}
		info.AMR = append(info.AMR, claimTexts(idClaims["acrs"])...)
	}

	info.DirectoryID = firstNonEmpty(
		claimText(idClaims[p.cfg.ClaimDirectoryID]),
		anyClaimText(body, p.cfg.ClaimDirectoryID),
		info.Subject)
	if p.cfg.ClaimAccountStatus != "" {
		status := firstNonEmpty(
			claimText(idClaims[p.cfg.ClaimAccountStatus]),
			anyClaimText(body, p.cfg.ClaimAccountStatus))
		info.DirectoryGuest = status != "" && status == p.cfg.AccountStatusGuest
	}

	return info, nil
}

// verifyIDToken checks the id_token the way the OpenID Connect Core rules for a
// relying party require of a code flow: an allow-listed asymmetric algorithm,
// the signature against the provider's published key for the token's kid, `iss`
// equal to the provider's issuer, `aud` containing this client, `exp` present and
// in the future and `iat` not in the future (both with the leeway), and the
// `nonce` equal to the one this flow sent. The error never carries a claim value.
func (p *Provider) verifyIDToken(ctx context.Context, raw, nonce string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(idTokenAlgorithms),
		jwt.WithIssuer(p.cfg.Issuer),
		jwt.WithAudience(p.cfg.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(p.cfg.ClockSkewLeeway),
	)

	claims := jwt.MapClaims{}
	if _, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)

		return p.keys.Key(ctx, kid)
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDToken, err)
	}

	if nonce != "" {
		got, _ := claims["nonce"].(string)
		if got != nonce {
			return nil, fmt.Errorf("%w: the nonce does not match this login", ErrIDToken)
		}
	}

	return claims, nil
}

// UserInfo fetches the authenticated user's claims and maps them onto the
// platform's identity claims. Standard OIDC claims map by their registered
// names; the identity-code claim name is configurable (ClaimSerial), and acr
// may arrive as a string or — from some providers — an array (first value wins).
// The id_token path builds on it: see Claims.
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (identity.UserInfo, error) {
	body, err := p.userInfoBody(ctx, accessToken)
	if err != nil {
		return identity.UserInfo{}, err
	}

	return p.mapUserInfo(body)
}

// userInfoBody fetches the raw userinfo document with the login's access token.
func (p *Provider) userInfoBody(ctx context.Context, accessToken string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	body, status, err := p.do(req)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("oidc: userinfo returned %d: %s", status, body)
	}

	// Debug aid: the full raw identity payload from the provider's userinfo.
	// WARNING: this contains PERSONAL DATA (name, serial number, etc.). It is
	// emitted only at LOG_LEVEL=debug and MUST NOT be enabled in production.
	if ce := p.log.Check(zap.DebugLevel, "upstream userinfo response"); ce != nil {
		ce.Write(zap.Int("status", status), zap.ByteString("body", body))
	}

	return body, nil
}

// mapUserInfo maps a raw userinfo document onto the platform's identity claims.
func (p *Provider) mapUserInfo(body []byte) (identity.UserInfo, error) {
	var info identity.UserInfo

	var raw struct {
		Subject        string          `json:"sub"`
		Domain         string          `json:"domain"`
		ACR            json.RawMessage `json:"acr"`
		AMR            []string        `json:"amr"`
		GivenName      string          `json:"given_name"`
		FamilyName     string          `json:"family_name"`
		Name           string          `json:"name"`
		EIPS           string          `json:"eips"`
		SignIdentities []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Status      struct {
				Value string `json:"value"`
			} `json:"status"`
			Labels []string `json:"labels"`
			Access []struct {
				UserID      string   `json:"user_id"`
				Permissions []string `json:"permissions"`
			} `json:"access"`
		} `json:"sign_identities"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return info, fmt.Errorf("oidc: invalid userinfo response: %w", err)
	}

	info.Subject = raw.Subject
	info.Domain = raw.Domain
	info.ACR = acrString(raw.ACR)
	info.AMR = raw.AMR
	info.GivenName = raw.GivenName
	info.FamilyName = raw.FamilyName
	info.Name = raw.Name
	info.EIPS = raw.EIPS
	// The identity code, reduced to the one spelling the platform stores and
	// compares. A provider writes it its own way — with the identity type and
	// country ("PNOLV-XXXXXX-XXXXX"), with the separator dropped, or as a bare
	// national code — and compared as text those are different people. The
	// country in the value wins; Config.Country answers for a provider that
	// sends none.
	//
	// An empty claim is left empty rather than refused here: a login carrying
	// no identity code at all is a wiring fault the identity store and the
	// token issue each name in their own terms, and moving that refusal here
	// would only rename it.
	info.SerialNumber = stringClaim(body, p.cfg.ClaimSerial)
	if info.SerialNumber != "" {
		canonical, cerr := identitycode.Canonical(info.SerialNumber, p.cfg.Country)
		if cerr != nil {
			return info, fmt.Errorf("%w: %w", ErrIdentityCode, cerr)
		}
		info.SerialNumber = canonical
	}

	// The sign-identity catalog rides the same userinfo response when the
	// profile scope was granted. nil stays nil (no catalog in the response);
	// an empty array stays empty non-nil (catalog read, no identities) — the
	// distinction is what lets a caller treat "none" and "unknown" differently.
	if raw.SignIdentities != nil {
		info.SignIdentities = make([]identity.SignIdentity, 0, len(raw.SignIdentities))
		for _, si := range raw.SignIdentities {
			var perms []string
			for _, a := range si.Access {
				perms = append(perms, a.Permissions...)
			}
			info.SignIdentities = append(info.SignIdentities, identity.SignIdentity{
				ID:          si.ID,
				Description: si.Description,
				Status:      si.Status.Value,
				Labels:      si.Labels,
				Permissions: perms,
			})
		}
	}

	return info, nil
}

// ScopeSignIdentityProfile is the provider scope that lets a login read the
// person's sign-identity catalog (and fetch identity certificates) with the
// login's own access token.
const ScopeSignIdentityProfile = "urn:safelayer:eidas:sign:identity:profile"

// IdentityCatalogEnabled reports whether login-time capability capture is on
// for this provider: the sign-identity profile scope is requested and the
// certificate endpoint is known.
func (p *Provider) IdentityCatalogEnabled() bool {
	if p.cfg.SignIdentityURL == "" {
		return false
	}
	for _, s := range p.cfg.Scopes {
		if s == ScopeSignIdentityProfile {
			return true
		}
	}

	return false
}

// SignIdentityCert fetches one sign identity's certificate (base64 DER) with
// the login's access token. No retry: login latency is bounded, and a
// certificate that is not ready yet simply leaves the capability out — the
// signing-time fallback covers it.
func (p *Provider) SignIdentityCert(ctx context.Context, accessToken, id string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		p.cfg.SignIdentityURL+url.PathEscape(id), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	body, status, err := p.do(req)
	if err != nil {
		return "", err
	}
	if status/100 != 2 {
		return "", fmt.Errorf("oidc: sign identity fetch returned %d", status)
	}

	var d struct {
		Identity struct {
			Details struct {
				Certificate string `json:"certificate"`
			} `json:"details"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return "", fmt.Errorf("oidc: invalid sign identity response: %w", err)
	}
	if d.Identity.Details.Certificate == "" {
		return "", fmt.Errorf("oidc: sign identity %q has no certificate", id)
	}

	return d.Identity.Details.Certificate, nil
}

// stringClaim extracts one top-level string claim by name from the raw
// userinfo document.
func stringClaim(body []byte, name string) string {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(doc[name], &s); err != nil {
		return ""
	}

	return s
}

// anyClaimText extracts one top-level claim by name from the raw userinfo
// document as text, whatever JSON scalar it is — a provider writes an account
// status as the number 0 or 1, and a claim map has to be able to name it.
func anyClaimText(body []byte, name string) string {
	if name == "" {
		return ""
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}

	return claimText(doc[name])
}

// claimText renders a JSON scalar claim as text: a string as it is, a number
// without a fraction where it has none, a boolean as true/false. Anything else
// — an object, an array, nothing — is "".
func claimText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

// claimTexts renders a claim that is an array of scalars (amr, acrs) as texts;
// a lone scalar is one entry. Nothing else contributes.
func claimTexts(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s := claimText(e); s != "" {
				out = append(out, s)
			}
		}

		return out
	case nil:
		return nil
	default:
		if s := claimText(x); s != "" {
			return []string{s}
		}

		return nil
	}
}

// firstNonEmpty answers the first of its arguments that is not "".
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}

	return ""
}

// acrString accepts acr as a JSON string or an array of strings (first wins).
func acrString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return arr[0]
	}

	return ""
}

func (p *Provider) do(req *http.Request) ([]byte, int, error) {
	resp, err := p.httpc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("oidc: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}

func (p *Provider) basicAuth() string {
	creds := p.cfg.ClientID + ":" + p.cfg.ClientSecret

	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}
