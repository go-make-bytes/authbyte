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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gmb-lib/go-platform-kit/observability"
	"github.com/go-make-bytes/authbyte/identity"

	"go.uber.org/zap"
)

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
	// MethodsFederated is the set of methods whose IdP session cookie a
	// logout must clear front-channel. Empty means MethodsAllowed.
	MethodsFederated []string
}

// Provider talks to the configured upstream identity provider.
type Provider struct {
	cfg    Config
	httpc  *http.Client
	log    *zap.Logger
	fedSet map[string]bool
	okSet  map[string]bool
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
	if len(cfg.MethodsFederated) == 0 {
		cfg.MethodsFederated = cfg.MethodsAllowed
	}

	p := &Provider{cfg: cfg, httpc: httpc, log: log, okSet: map[string]bool{}, fedSet: map[string]bool{}}
	for _, m := range cfg.MethodsAllowed {
		p.okSet[m] = true
	}
	for _, m := range cfg.MethodsFederated {
		p.fedSet[m] = true
	}

	return p, nil
}

// Resolver builds the identity resolver carrying this provider's acr/amr
// vocabularies and defaults.
func (p *Provider) Resolver() *identity.Resolver {
	return identity.NewResolverPolicies(p.cfg.LoAPolicy, p.cfg.MethodPolicy, p.cfg.MethodDefault, p.cfg.LoADefault)
}

// MethodAllowed reports whether a login method resolved from this provider's
// callback is permitted. Anything outside the configured set is rejected, so
// the upstream login path fails closed.
func (p *Provider) MethodAllowed(method string) bool { return p.okSet[method] }

// FederatedMethod reports whether the method authenticated through the
// upstream IdP (and therefore set an IdP SSO cookie that a logout must clear
// front-channel).
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
}

// AuthorizeURL builds the URL to redirect the user to for authentication.
func (p *Provider) AuthorizeURL(params AuthorizeParams) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("state", params.State)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
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
}

// Exchange swaps an authorization code for an upstream access token using HTTP
// Basic client authentication (confidential client).
func (p *Provider) Exchange(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Set("Authorization", p.basicAuth())

	body, status, err := p.do(req)
	if err != nil {
		return "", err
	}
	if status/100 != 2 {
		return "", fmt.Errorf("oidc: token exchange returned %d: %s", status, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("oidc: invalid token response: %w", err)
	}

	return tr.AccessToken, nil
}

// UserInfo fetches the authenticated user's claims and maps them onto the
// platform's identity claims. Standard OIDC claims map by their registered
// names; the identity-code claim name is configurable (ClaimSerial), and acr
// may arrive as a string or — from some providers — an array (first value wins).
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (identity.UserInfo, error) {
	var info identity.UserInfo

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserInfoURL, nil)
	if err != nil {
		return info, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	body, status, err := p.do(req)
	if err != nil {
		return info, err
	}
	if status/100 != 2 {
		return info, fmt.Errorf("oidc: userinfo returned %d: %s", status, body)
	}

	// Debug aid: the full raw identity payload from the provider's userinfo.
	// WARNING: this contains PERSONAL DATA (name, serial number, etc.). It is
	// emitted only at LOG_LEVEL=debug and MUST NOT be enabled in production.
	if ce := p.log.Check(zap.DebugLevel, "upstream userinfo response"); ce != nil {
		ce.Write(zap.Int("status", status), zap.ByteString("body", body))
	}

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
	info.SerialNumber = stringClaim(body, p.cfg.ClaimSerial)

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
