// Package registry holds the service client registry — the authoritative
// client ↔ audience ↔ scope matrix. It is a declarative YAML
// document held in Vault, materialized to a file by the Vault agent and loaded
// + validated at startup, then cached in memory. It carries only secret_refs,
// never the secrets themselves.
package registry

import (
	"errors"
	"fmt"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Errors returned by registry operations.
var (
	ErrUnknownClient         = errors.New("registry: unknown or disabled service client")
	ErrBadSecret             = errors.New("registry: client secret mismatch")
	ErrGrantDenied           = errors.New("registry: requested audience/scope not granted")
	ErrUnknownPublicClient   = errors.New("registry: unknown or disabled public client")
	ErrRedirectURINotAllowed = errors.New("registry: redirect_uri not in allowed list")
)

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
}

// PublicClient is a registered browser/native client (no secret; protected by
// PKCE). The only enforcement is the redirect_uri allowlist.
type PublicClient struct {
	ClientID            string   `yaml:"client_id"`
	Enabled             bool     `yaml:"enabled"`
	AllowedRedirectURIs []string `yaml:"allowed_redirect_uris"`
}

// Document is the parsed registry document.
type Document struct {
	ServiceClients []Client       `yaml:"service_clients"`
	PublicClients  []PublicClient `yaml:"public_clients"`
}

// Registry is the in-memory, validated registry.
type Registry struct {
	clients    map[string]Client
	pubClients map[string]PublicClient
	// secrets maps client_id → resolved secret. Resolution is provided by the
	// caller (it reads each secret_ref from Vault); the registry itself never
	// stores secrets in the document.
	secrets map[string]string
}

// SecretResolver resolves a client's secret_ref to the actual secret value.
type SecretResolver func(clientID, secretRef string) (string, error)

// Load parses, validates and caches a registry document. resolve is called per
// enabled client to fetch its secret from the secret store; pass nil to skip
// secret resolution (e.g. in tests that supply secrets directly).
func Load(doc []byte, resolve SecretResolver) (*Registry, error) {
	var d Document
	if err := yaml.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("registry: parse: %w", err)
	}

	r := &Registry{
		clients:    make(map[string]Client, len(d.ServiceClients)),
		pubClients: make(map[string]PublicClient, len(d.PublicClients)),
		secrets:    make(map[string]string),
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

	for _, pc := range d.PublicClients {
		if err := validatePublicClient(pc); err != nil {
			return nil, err
		}

		if _, dup := r.pubClients[pc.ClientID]; dup {
			return nil, fmt.Errorf("registry: duplicate public client_id %q", pc.ClientID)
		}

		r.pubClients[pc.ClientID] = pc
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

	return nil
}

func validatePublicClient(c PublicClient) error {
	if c.ClientID == "" {
		return errors.New("registry: public client with empty client_id")
	}
	if c.Enabled && len(c.AllowedRedirectURIs) == 0 {
		return fmt.Errorf("registry: public client %q has no allowed_redirect_uris", c.ClientID)
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

// ValidateRedirectURI confirms that clientID is a known, enabled public client
// and that redirectURI appears in its allowlist. Both conditions must hold; an
// error is returned if either fails so callers can reject the request without
// redirecting (open-redirect protection per [RFC 6749 §10.6]).
func (r *Registry) ValidateRedirectURI(clientID, redirectURI string) error {
	c, ok := r.pubClients[clientID]
	if !ok || !c.Enabled {
		return ErrUnknownPublicClient
	}

	for _, u := range c.AllowedRedirectURIs {
		if u == redirectURI {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrRedirectURINotAllowed, redirectURI)
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
