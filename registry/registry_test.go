package registry

import (
	"errors"
	"testing"
)

const doc = `
service_clients:
  - client_id: svc:signflow
    secret_ref: env:ORCH
    enabled: true
    grants:
      - audience: svc:document
        scopes: [documents:read]
      - audience: svc:envelope
        scopes: [envelopes:read, envelopes:transition]
  - client_id: svc:notification
    secret_ref: env:NOTIF
    enabled: true
    grants:
      - audience: svc:envelope
        scopes: [envelopes:read]
  - client_id: svc:disabled
    secret_ref: env:X
    enabled: false
    grants: []
`

func load(t *testing.T) *Registry {
	t.Helper()

	secrets := map[string]string{
		"svc:signflow":     "orch-secret",
		"svc:notification": "notif-secret",
	}

	r, err := Load([]byte(doc), func(clientID, _ string) (string, error) {
		return secrets[clientID], nil
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	return r
}

func TestAuthenticate(t *testing.T) {
	r := load(t)

	if _, err := r.Authenticate("svc:signflow", "orch-secret"); err != nil {
		t.Fatalf("valid credentials rejected: %v", err)
	}

	if _, err := r.Authenticate("svc:signflow", "wrong"); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("expected ErrBadSecret, got %v", err)
	}

	if _, err := r.Authenticate("svc:unknown", "x"); !errors.Is(err, ErrUnknownClient) {
		t.Fatalf("expected ErrUnknownClient, got %v", err)
	}

	if _, err := r.Authenticate("svc:disabled", "x"); !errors.Is(err, ErrUnknownClient) {
		t.Fatalf("disabled client must be rejected, got %v", err)
	}
}

func TestAllowedScopesWithinGrant(t *testing.T) {
	r := load(t)

	scopes, err := r.AllowedScopes("svc:signflow", "svc:envelope", []string{"envelopes:read"})
	if err != nil {
		t.Fatalf("AllowedScopes: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != "envelopes:read" {
		t.Fatalf("unexpected scopes: %v", scopes)
	}
}

func TestAllowedScopesDefaultsToFullGrant(t *testing.T) {
	r := load(t)

	scopes, err := r.AllowedScopes("svc:signflow", "svc:envelope", nil)
	if err != nil {
		t.Fatalf("AllowedScopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected full grant of 2 scopes, got %v", scopes)
	}
}

func TestAllowedScopesDeniesUngrantedAudience(t *testing.T) {
	r := load(t)

	if _, err := r.AllowedScopes("svc:notification", "svc:document", []string{"documents:read"}); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("expected ErrGrantDenied for ungranted audience, got %v", err)
	}
}

func TestAllowedScopesDeniesUngrantedScope(t *testing.T) {
	r := load(t)

	// notification may only read envelopes, not transition them.
	if _, err := r.AllowedScopes("svc:notification", "svc:envelope", []string{"envelopes:transition"}); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("expected ErrGrantDenied for ungranted scope, got %v", err)
	}
}

const docPublic = `
service_clients: []
public_clients:
  - client_id: portal-spa
    enabled: true
    allowed_redirect_uris:
      - https://app.example.com/callback
      - https://app.example.com/other
  - client_id: portal-disabled
    enabled: false
    allowed_redirect_uris:
      - https://app.example.com/callback
`

func loadPublic(t *testing.T) *Registry {
	t.Helper()

	r, err := Load([]byte(docPublic), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	return r
}

func TestValidateRedirectURIValid(t *testing.T) {
	r := loadPublic(t)

	if err := r.ValidateRedirectURI("portal-spa", "https://app.example.com/callback"); err != nil {
		t.Fatalf("valid redirect_uri rejected: %v", err)
	}

	if err := r.ValidateRedirectURI("portal-spa", "https://app.example.com/other"); err != nil {
		t.Fatalf("second valid redirect_uri rejected: %v", err)
	}
}

func TestValidateRedirectURIUnknownClient(t *testing.T) {
	r := loadPublic(t)

	if err := r.ValidateRedirectURI("portal-unknown", "https://app.example.com/callback"); !errors.Is(err, ErrUnknownPublicClient) {
		t.Fatalf("expected ErrUnknownPublicClient, got %v", err)
	}
}

func TestValidateRedirectURIDisabledClient(t *testing.T) {
	r := loadPublic(t)

	if err := r.ValidateRedirectURI("portal-disabled", "https://app.example.com/callback"); !errors.Is(err, ErrUnknownPublicClient) {
		t.Fatalf("disabled public client must be rejected, got %v", err)
	}
}

func TestValidateRedirectURINotAllowed(t *testing.T) {
	r := loadPublic(t)

	if err := r.ValidateRedirectURI("portal-spa", "https://evil.example.com/steal"); !errors.Is(err, ErrRedirectURINotAllowed) {
		t.Fatalf("expected ErrRedirectURINotAllowed, got %v", err)
	}
}

func TestLoadEmpty(t *testing.T) {
	r, err := Load(nil, nil)
	if err != nil {
		t.Fatalf("empty registry should load: %v", err)
	}
	if _, err := r.Authenticate("svc:any", "x"); !errors.Is(err, ErrUnknownClient) {
		t.Fatalf("expected ErrUnknownClient, got %v", err)
	}
}

// publicDoc registers two browser clients: a public portal that admits whoever
// can authenticate, and a product portal that leaves the requirement unset.
const publicDoc = `
service_clients: []
public_clients:
  - client_id: portal-spa
    enabled: true
    membership_required: false
    allowed_redirect_uris: [https://portal.example/callback]
  - client_id: product-spa
    enabled: true
    allowed_redirect_uris: [https://product.example/callback]
  - client_id: strict-spa
    enabled: true
    membership_required: true
    allowed_redirect_uris: [https://strict.example/callback]
`

func loadMembershipDoc(t *testing.T) *Registry {
	t.Helper()

	r, err := Load([]byte(publicDoc), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	return r
}

// An explicit false keeps a client's people on the baseline even with a
// register wired; an unset requirement follows the register; an unknown client
// follows the register too (fail closed toward the register).
func TestMembershipRequiredFollowsTheClientThenTheRegister(t *testing.T) {
	r := loadMembershipDoc(t)

	if r.MembershipRequired("portal-spa", true) {
		t.Fatal("portal-spa opted out of the membership requirement but was reported as requiring one")
	}
	if !r.MembershipRequired("product-spa", true) {
		t.Fatal("product-spa left the requirement unset with a register wired — it must be required")
	}
	if r.MembershipRequired("product-spa", false) {
		t.Fatal("product-spa left the requirement unset with no register — it cannot be required")
	}
	if !r.MembershipRequired("strict-spa", false) {
		t.Fatal("strict-spa requires a membership explicitly — the register's absence does not lift it")
	}
	if !r.MembershipRequired("nobody-spa", true) {
		t.Fatal("an unknown client must follow the register, not fall open to the baseline")
	}
}

// Only an explicit, enabled requirement makes a deployment without a register
// refuse to start.
func TestRequiresMembershipSomewhere(t *testing.T) {
	if !loadMembershipDoc(t).RequiresMembershipSomewhere() {
		t.Fatal("strict-spa requires a membership explicitly — the registry must say so")
	}

	r, err := Load([]byte(`
public_clients:
  - client_id: portal-spa
    enabled: true
    membership_required: false
    allowed_redirect_uris: [https://portal.example/callback]
  - client_id: product-spa
    enabled: true
    allowed_redirect_uris: [https://product.example/callback]
`), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.RequiresMembershipSomewhere() {
		t.Fatal("no client requires a membership explicitly — an unset requirement must not block a register-less start")
	}
}
