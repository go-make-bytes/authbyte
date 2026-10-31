// Package registry holds the service client registry — the authoritative
// client ↔ audience ↔ scope matrix. It is a declarative YAML
// document held in Vault, materialized to a file by the Vault agent and loaded
// + validated at startup, then cached in memory. It carries only secret_refs,
// never the secrets themselves.
package registry

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Errors returned by registry operations.
var (
	ErrUnknownClient         = errors.New("registry: unknown or disabled service client")
	ErrBadSecret             = errors.New("registry: client secret mismatch")
	ErrGrantDenied           = errors.New("registry: requested audience/scope not granted")
	ErrUnknownSignInClient   = errors.New("registry: unknown or disabled sign-in client")
	ErrRedirectURINotAllowed = errors.New("registry: redirect_uri not in allowed list")
)

// The two client types [RFC 6749 §2.1]: a confidential client holds a secret and
// proves itself with it; a public client holds none and is protected by PKCE.
const (
	ClientConfidential = "confidential"
	ClientPublic       = "public"
)

// The personal claims a sign-in client's tokens may carry, each only when its row
// lists it.
const (
	ClaimName         = "name"
	ClaimGivenName    = "given_name"
	ClaimFamilyName   = "family_name"
	ClaimSerialNumber = "serial_number"
)

var knownClaims = []string{ClaimName, ClaimGivenName, ClaimFamilyName, ClaimSerialNumber}

// Grant is a single audience the client may target and the scopes it may
// request toward it.
type Grant struct {
	Audience string   `yaml:"audience"`
	Scopes   []string `yaml:"scopes"`
}

// Client is one registered service client.
type Client struct {
	ClientID  string  `yaml:"client_id"`
	SecretRef string  `yaml:"secret_ref"`
	Enabled   bool    `yaml:"enabled"`
	Grants    []Grant `yaml:"grants"`
	// ActFrom names the audiences whose user tokens the client may exchange to
	// act for their person (RFC 8693): a product's edge lists its product's user
	// audience. A token addressed to the client itself is always accepted, so a
	// service passing on what was delegated to it needs no entry.
	ActFrom []string `yaml:"act_from"`
}

// SignInClient is a registered client that signs people in. Each one carries what
// its product needs, so one deployment can serve several products: its own user
// audience, the scopes and personal claims its tokens carry, the sign-in methods it
// allows, and the addresses it may be sent back to. The setting names follow the
// client metadata the standards define where one exists [RFC 7591 §2].
type SignInClient struct {
	ClientID string `yaml:"client_id"`
	Enabled  bool   `yaml:"enabled"`
	// Type is confidential (an edge that holds SecretRef's secret and proves
	// itself with it) or public (no secret; PKCE protects the flow).
	Type      string `yaml:"type"`
	SecretRef string `yaml:"secret_ref"`
	// Audience is the audience of this client's user tokens.
	Audience string `yaml:"audience"`
	// MembershipRequired says whether the people who log in through this client
	// must hold a membership in the register: true for a product whose
	// organisations decide who belongs (a person without a membership is refused
	// a token), false for a public portal that admits whoever can authenticate
	// (its people are minted BaselineScopes and never consulted in the register).
	// Unset means "required whenever a register is wired" — the safe default.
	MembershipRequired *bool `yaml:"membership_required"`
	// BaselineScopes are what a person signing in through this client is minted
	// when no membership is consulted.
	BaselineScopes []string `yaml:"baseline_scopes"`
	// Claims are the personal claims its tokens carry, from the known four; the
	// identity code (serial_number) only where it is listed.
	Claims []string `yaml:"claims"`
	// Methods are the sign-in methods it allows, by this service's method names;
	// those the deployment does not offer are never offered to it.
	Methods []string `yaml:"methods"`
	// StepUpMethods are the methods a session of this client may step up to; a
	// subset of Methods, and none means no step-up.
	StepUpMethods []string `yaml:"step_up_methods"`
	// Signing says the client signs: its identity answer carries the signing flows
	// a login method permits, and a sign-in through it captures the person's
	// signing identities.
	Signing bool `yaml:"signing"`
	// ClientName and LogoURI name the client to the person on the sign-in page.
	ClientName string `yaml:"client_name"`
	LogoURI    string `yaml:"logo_uri"`
	// RedirectURIs are where a sign-in may return; PostLogoutRedirectURIs where a
	// sign-out may land; BackchannelLogoutURI where a sign-out is told to the edge.
	RedirectURIs           []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
	BackchannelLogoutURI   string   `yaml:"backchannel_logout_uri"`
}

// Document is the parsed registry document.
type Document struct {
	ServiceClients []Client       `yaml:"service_clients"`
	SignInClients  []SignInClient `yaml:"sign_in_clients"`
}

// Registry is the in-memory, validated registry.
type Registry struct {
	clients       map[string]Client
	signInClients map[string]SignInClient
	// secrets maps client_id → resolved secret, for service clients and
	// confidential sign-in clients alike (an id is in one section only).
	// Resolution is provided by the caller (it reads each secret_ref from Vault);
	// the registry itself never stores secrets in the document.
	secrets map[string]string
}

// SecretResolver resolves a client's secret_ref to the actual secret value.
type SecretResolver func(clientID, secretRef string) (string, error)

// Load parses, validates and caches a registry document. resolve is called per
// enabled client to fetch its secret from the secret store; pass nil to skip
// secret resolution (e.g. in tests that supply secrets directly).
func Load(doc []byte, resolve SecretResolver) (*Registry, error) {
	// An unknown key is refused rather than ignored, so a misspelled setting
	// stops the start instead of loading as its absence.
	var d Document
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("registry: parse: %w", err)
	}

	r := &Registry{
		clients:       make(map[string]Client, len(d.ServiceClients)),
		signInClients: make(map[string]SignInClient, len(d.SignInClients)),
		secrets:       make(map[string]string),
	}

	for _, c := range d.ServiceClients {
		if err := validateClient(c); err != nil {
			return nil, err
		}

		if _, dup := r.clients[c.ClientID]; dup {
			return nil, fmt.Errorf("registry: duplicate client_id %q", c.ClientID)
		}

		r.clients[c.ClientID] = c

		if c.Enabled && resolve != nil {
			secret, err := resolve(c.ClientID, c.SecretRef)
			if err != nil {
				return nil, fmt.Errorf("registry: resolve secret for %q: %w", c.ClientID, err)
			}

			r.secrets[c.ClientID] = secret
		}
	}

	for _, sc := range d.SignInClients {
		if err := validateSignInClient(sc); err != nil {
			return nil, err
		}

		if _, dup := r.signInClients[sc.ClientID]; dup {
			return nil, fmt.Errorf("registry: duplicate sign-in client_id %q", sc.ClientID)
		}
		// One id in both sections would have two secrets and two meanings at the
		// token endpoint.
		if _, dup := r.clients[sc.ClientID]; dup {
			return nil, fmt.Errorf("registry: client_id %q is both a service client and a sign-in client", sc.ClientID)
		}

		r.signInClients[sc.ClientID] = sc

		if sc.Enabled && sc.Type == ClientConfidential && resolve != nil {
			secret, err := resolve(sc.ClientID, sc.SecretRef)
			if err != nil {
				return nil, fmt.Errorf("registry: resolve secret for %q: %w", sc.ClientID, err)
			}

			r.secrets[sc.ClientID] = secret
		}
	}

	return r, nil
}

func validateClient(c Client) error {
	if c.ClientID == "" {
		return errors.New("registry: client with empty client_id")
	}
	if c.Enabled && c.SecretRef == "" {
		return fmt.Errorf("registry: client %q has no secret_ref", c.ClientID)
	}

	for _, g := range c.Grants {
		if g.Audience == "" {
			return fmt.Errorf("registry: client %q has a grant with empty audience", c.ClientID)
		}
	}

	if slices.Contains(c.ActFrom, "") {
		return fmt.Errorf("registry: client %q has an empty act_from audience", c.ClientID)
	}

	return nil
}

func validateSignInClient(c SignInClient) error {
	if c.ClientID == "" {
		return errors.New("registry: sign-in client with empty client_id")
	}
	bad := func(format string, args ...any) error {
		return fmt.Errorf("registry: sign-in client %q "+format, append([]any{c.ClientID}, args...)...)
	}

	switch c.Type {
	case ClientConfidential:
		if c.Enabled && c.SecretRef == "" {
			return bad("is confidential and has no secret_ref")
		}
	case ClientPublic:
		if c.SecretRef != "" {
			return bad("is public and must not have a secret_ref")
		}
	default:
		return bad("has type %q; want %s or %s", c.Type, ClientConfidential, ClientPublic)
	}

	if c.Audience == "" {
		return bad("has no audience")
	}
	if c.Enabled && len(c.RedirectURIs) == 0 {
		return bad("has no redirect_uris")
	}
	// The baseline is minted only to people no membership is asked about.
	if len(c.BaselineScopes) > 0 && c.MembershipRequired != nil && *c.MembershipRequired {
		return bad("requires a membership, so its baseline_scopes could never apply")
	}
	for _, m := range c.StepUpMethods {
		if !slices.Contains(c.Methods, m) {
			return bad("lists step_up_methods %q, which is not among its methods", m)
		}
	}
	for _, claim := range c.Claims {
		if !slices.Contains(knownClaims, claim) {
			return bad("lists claim %q; the known claims are %s", claim, strings.Join(knownClaims, ", "))
		}
	}

	confidential := c.Type == ClientConfidential
	for _, u := range c.RedirectURIs {
		if err := checkAddress(u, true); err != nil {
			return bad("redirect_uris %q: %w", u, err)
		}
	}
	for _, u := range c.PostLogoutRedirectURIs {
		if err := checkAddress(u, confidential); err != nil {
			return bad("post_logout_redirect_uris %q: %w", u, err)
		}
	}
	if c.BackchannelLogoutURI != "" {
		if err := checkAddress(c.BackchannelLogoutURI, confidential); err != nil {
			return bad("backchannel_logout_uri %q: %w", c.BackchannelLogoutURI, err)
		}
	}
	if c.LogoURI != "" {
		if err := checkAddress(c.LogoURI, false); err != nil {
			return bad("logo_uri %q: %w", c.LogoURI, err)
		}
	}

	return nil
}

// checkAddress accepts an absolute address with no fragment [RFC 6749 §3.1.2],
// on https, or on http where httpAllowed: a sign-out or back-channel address may
// use http only for a confidential client [OIDC RP-Initiated Logout §3.1]
// [OIDC Back-Channel Logout §2.2]. A sign-in return keeps the http it has always
// been allowed (an edge reached inside its own network).
func checkAddress(raw string, httpAllowed bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if !u.IsAbs() || u.Host == "" {
		return errors.New("not an absolute address")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("carries a fragment")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !httpAllowed) {
		return fmt.Errorf("scheme %q not allowed here", u.Scheme)
	}

	return nil
}

// SetSecret overrides a client's resolved secret (used by tests).
func (r *Registry) SetSecret(clientID, secret string) {
	r.secrets[clientID] = secret
}

// Authenticate verifies the client id + secret and returns the client.
func (r *Registry) Authenticate(clientID, secret string) (Client, error) {
	c, ok := r.clients[clientID]
	if !ok || !c.Enabled {
		return Client{}, ErrUnknownClient
	}

	expected, ok := r.secrets[clientID]
	if !ok || expected == "" || subtleMismatch(expected, secret) {
		return Client{}, ErrBadSecret
	}

	return c, nil
}

// AllowedScopes returns the scopes a client may receive toward an audience,
// intersected with the requested scopes. It errors if the audience is not
// granted or any requested scope is outside the grant.
func (r *Registry) AllowedScopes(clientID, audience string, requested []string) ([]string, error) {
	c, ok := r.clients[clientID]
	if !ok || !c.Enabled {
		return nil, ErrUnknownClient
	}

	var grant *Grant
	for i := range c.Grants {
		if c.Grants[i].Audience == audience {
			grant = &c.Grants[i]

			break
		}
	}
	if grant == nil {
		return nil, fmt.Errorf("%w: audience %q", ErrGrantDenied, audience)
	}

	allowed := make(map[string]struct{}, len(grant.Scopes))
	for _, s := range grant.Scopes {
		allowed[s] = struct{}{}
	}

	// No explicit request → grant the full set for the audience.
	if len(requested) == 0 {
		return append([]string(nil), grant.Scopes...), nil
	}

	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := allowed[s]; !ok {
			return nil, fmt.Errorf("%w: scope %q", ErrGrantDenied, s)
		}

		out = append(out, s)
	}

	return out, nil
}

// MayActFrom reports whether clientID may exchange a subject token issued for
// audiences: the client must be known and enabled, and one of the audiences
// must be the client itself or a value it lists under act_from (each principal
// a JWT is meant for names itself in its audience, [RFC 7519 §4.1.3]).
func (r *Registry) MayActFrom(clientID string, audiences []string) bool {
	c, ok := r.clients[clientID]
	if !ok || !c.Enabled {
		return false
	}

	for _, aud := range audiences {
		if aud != "" && (aud == c.ClientID || slices.Contains(c.ActFrom, aud)) {
			return true
		}
	}

	return false
}

// MembershipRequired reports whether the people who log in through the public
// client clientID need a membership in the register. A client that leaves it
// unset — and an unknown client — follows registerWired: required whenever a
// register is configured, never when there is none (fail closed toward the
// register, not toward the baseline).
func (r *Registry) MembershipRequired(clientID string, registerWired bool) bool {
	if c, ok := r.signInClients[clientID]; ok && c.MembershipRequired != nil {
		return *c.MembershipRequired
	}

	return registerWired
}

// RequiresMembershipSomewhere reports whether any enabled sign-in client
// explicitly requires a membership. A deployment with no register configured
// refuses to start with such a client rather than silently minting it the
// baseline.
func (r *Registry) RequiresMembershipSomewhere() bool {
	for _, c := range r.signInClients {
		if c.Enabled && c.MembershipRequired != nil && *c.MembershipRequired {
			return true
		}
	}

	return false
}

// BaselinesNeverMinted names the enabled sign-in clients whose baseline_scopes
// could never be minted: their people need a membership, so the register's
// answer is minted instead. The load refuses a row that says so itself; this
// names the rows that need one because a register is wired and they leave it
// unset.
func (r *Registry) BaselinesNeverMinted(registerWired bool) []string {
	var out []string
	for _, c := range r.SignInClients() {
		if len(c.BaselineScopes) > 0 && r.MembershipRequired(c.ClientID, registerWired) {
			out = append(out, c.ClientID)
		}
	}

	return out
}

// SignInClient returns the enabled sign-in client clientID.
func (r *Registry) SignInClient(clientID string) (SignInClient, bool) {
	c, ok := r.signInClients[clientID]
	if !ok || !c.Enabled {
		return SignInClient{}, false
	}

	return c, true
}

// SignInClients returns every enabled sign-in client, ordered by id.
func (r *Registry) SignInClients() []SignInClient {
	out := make([]SignInClient, 0, len(r.signInClients))
	for _, c := range r.signInClients {
		if c.Enabled {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b SignInClient) int { return strings.Compare(a.ClientID, b.ClientID) })

	return out
}

// AuthenticateSignIn checks how a sign-in client proved itself: a confidential
// client must present its own secret, and a public client must present none,
// since it has none [RFC 7591 §2]. presented says whether the request carried a
// secret at all, so an empty one is still a secret presented.
func (r *Registry) AuthenticateSignIn(clientID, secret string, presented bool) (SignInClient, error) {
	c, ok := r.SignInClient(clientID)
	if !ok {
		return SignInClient{}, ErrUnknownSignInClient
	}

	if c.Type == ClientPublic {
		if presented {
			return SignInClient{}, ErrBadSecret
		}

		return c, nil
	}

	expected, ok := r.secrets[clientID]
	if !presented || !ok || expected == "" || subtleMismatch(expected, secret) {
		return SignInClient{}, ErrBadSecret
	}

	return c, nil
}

// Audiences returns the user audiences of the enabled sign-in clients, each once
// and ordered: every audience this service's own identity answer accepts.
func (r *Registry) Audiences() []string {
	var out []string
	for _, c := range r.signInClients {
		if c.Enabled && !slices.Contains(out, c.Audience) {
			out = append(out, c.Audience)
		}
	}
	slices.Sort(out)

	return out
}

// ValidateRedirectURI confirms that clientID is a known, enabled sign-in client
// and that redirectURI is one of its sign-in returns. Both conditions must hold;
// an error is returned if either fails so callers can reject the request without
// redirecting (open-redirect protection per [RFC 6749 §10.6]).
func (r *Registry) ValidateRedirectURI(clientID, redirectURI string) error {
	c, ok := r.SignInClient(clientID)
	if !ok {
		return ErrUnknownSignInClient
	}
	if !slices.Contains(c.RedirectURIs, redirectURI) {
		return fmt.Errorf("%w: %q", ErrRedirectURINotAllowed, redirectURI)
	}

	return nil
}

// ValidatePostLogoutURI confirms that clientID is a known, enabled sign-in
// client and that redirectURI is one of its sign-out landings, a list of its own
// [OIDC RP-Initiated Logout §3.1]: a login return is not a sign-out landing.
func (r *Registry) ValidatePostLogoutURI(clientID, redirectURI string) error {
	c, ok := r.SignInClient(clientID)
	if !ok {
		return ErrUnknownSignInClient
	}
	if !slices.Contains(c.PostLogoutRedirectURIs, redirectURI) {
		return fmt.Errorf("%w: %q", ErrRedirectURINotAllowed, redirectURI)
	}

	return nil
}

// subtleMismatch compares two secrets in constant time, returning true when
// they differ.
func subtleMismatch(a, b string) bool {
	if len(a) != len(b) {
		return true
	}

	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}

	return diff != 0
}

// ParseScopeString splits a space-delimited scope string into a slice.
func ParseScopeString(s string) []string {
	return strings.Fields(s)
}
