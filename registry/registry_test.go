package registry

import (
	"errors"
	"fmt"
	"slices"
	"strings"
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
sign_in_clients:
  - client_id: portal-spa
    type: public
    audience: portal-api
    enabled: true
    redirect_uris:
      - https://app.example.com/callback
      - https://app.example.com/other
  - client_id: portal-disabled
    type: public
    audience: portal-api
    enabled: false
    redirect_uris:
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

	if err := r.ValidateRedirectURI("portal-unknown", "https://app.example.com/callback"); !errors.Is(err, ErrUnknownSignInClient) {
		t.Fatalf("expected ErrUnknownSignInClient, got %v", err)
	}
}

func TestValidateRedirectURIDisabledClient(t *testing.T) {
	r := loadPublic(t)

	if err := r.ValidateRedirectURI("portal-disabled", "https://app.example.com/callback"); !errors.Is(err, ErrUnknownSignInClient) {
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
sign_in_clients:
  - client_id: portal-spa
    type: public
    audience: portal-api
    enabled: true
    membership_required: false
    redirect_uris: [https://portal.example/callback]
  - client_id: product-spa
    type: public
    audience: portal-api
    enabled: true
    redirect_uris: [https://product.example/callback]
  - client_id: strict-spa
    type: public
    audience: portal-api
    enabled: true
    membership_required: true
    redirect_uris: [https://strict.example/callback]
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
sign_in_clients:
  - client_id: portal-spa
    type: public
    audience: portal-api
    enabled: true
    membership_required: false
    redirect_uris: [https://portal.example/callback]
  - client_id: product-spa
    type: public
    audience: portal-api
    enabled: true
    redirect_uris: [https://product.example/callback]
`), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.RequiresMembershipSomewhere() {
		t.Fatal("no client requires a membership explicitly — an unset requirement must not block a register-less start")
	}
}

// A misspelled key must stop the start: read leniently, "act_form" would load as
// a client that acts from nothing, and every exchange it makes would be refused
// with no hint of why.
func TestLoadRefusesAnUnknownKey(t *testing.T) {
	_, err := Load([]byte(`
service_clients:
  - client_id: svc:portal-api
    secret_ref: env:PORTAL
    enabled: true
    act_form: [portal-api]
`), nil)
	if err == nil {
		t.Fatal("a registry with an unknown key must not load")
	}
}

const actDoc = `
service_clients:
  - client_id: svc:portal-api
    secret_ref: env:PORTAL
    enabled: true
    act_from: [portal-api]
  - client_id: svc:signflow
    secret_ref: env:ORCH
    enabled: true
  - client_id: svc:disabled
    secret_ref: env:X
    enabled: false
    act_from: [portal-api]
`

// A client exchanges a token only when it was issued for the client itself (a
// hop in a chain) or for an audience the client lists under act_from.
func TestMayActFrom(t *testing.T) {
	r, err := Load([]byte(actDoc), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		name      string
		client    string
		audiences []string
		want      bool
	}{
		{"a listed audience", "svc:portal-api", []string{"portal-api"}, true},
		{"an audience the client does not list", "svc:portal-api", []string{"flowbyte-portal"}, false},
		{"another service's delegated token", "svc:portal-api", []string{"svc:document"}, false},
		{"a client listing nothing, given a product token", "svc:signflow", []string{"portal-api"}, false},
		{"a client listing nothing, given a token addressed to itself", "svc:signflow", []string{"svc:signflow"}, true},
		{"a token with no audience", "svc:portal-api", nil, false},
		{"an empty audience value", "svc:portal-api", []string{""}, false},
		{"two audiences, one listed", "svc:portal-api", []string{"svc:document", "portal-api"}, true},
		{"two audiences, one the client itself", "svc:signflow", []string{"portal-api", "svc:signflow"}, true},
		{"a disabled client", "svc:disabled", []string{"portal-api"}, false},
		{"an unknown client", "svc:nobody", []string{"svc:nobody"}, false},
	}
	for _, c := range cases {
		if got := r.MayActFrom(c.client, c.audiences); got != c.want {
			t.Errorf("%s: MayActFrom(%q, %q) = %v, want %v", c.name, c.client, c.audiences, got, c.want)
		}
	}
}

// grantDoc is one client with one grant, its scopes and, when named is not
// empty, the levels it names for an assistant's chain.
func grantDoc(scopes, named string) string {
	doc := `
service_clients:
  - client_id: svc:product-api
    secret_ref: env:API
    enabled: true
    grants:
      - audience: svc:register
        scopes: ` + scopes + "\n"
	if named != "" {
		doc += "        assistant_levels: " + named + "\n"
	}

	return doc
}

// A grant names the levels that may ride a token made through an assistant;
// with the field left out it names none.
func TestAGrantNamesTheLevelsThatRideAnAssistantsChain(t *testing.T) {
	r, err := Load([]byte(`
service_clients:
  - client_id: svc:product-api
    secret_ref: env:API
    enabled: true
    grants:
      - audience: svc:register
        scopes: [membership:people, membership:admin]
        assistant_levels: [membership:people]
      - audience: svc:engine
        scopes: [projects:read, projects/task:view]
`), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		name, client, audience string
		want                   []string
	}{
		{"the grant naming one", "svc:product-api", "svc:register", []string{"membership:people"}},
		{"a grant naming none", "svc:product-api", "svc:engine", nil},
		{"an audience not granted", "svc:product-api", "svc:other", nil},
		{"an unknown client", "svc:nobody", "svc:register", nil},
	}
	for _, c := range cases {
		if got := r.AssistantLevels(c.client, c.audience); !slices.Equal(got, c.want) {
			t.Errorf("%s: AssistantLevels(%q, %q) = %q, want %q", c.name, c.client, c.audience, got, c.want)
		}
	}
}

// Each level a grant names must be a level the grant holds: a box, anything of
// no level's shape, and a level the grant lacks (a misspelling) stop the start,
// named, rather than loading as a name that matches nothing.
func TestLoadRefusesANamedLevelThatIsNoLevelOfTheGrant(t *testing.T) {
	const scopes = "[membership:people, projects/task:view]"
	if _, err := Load([]byte(grantDoc(scopes, "[membership:people]")), nil); err != nil {
		t.Fatalf("a held level must load: %v", err)
	}

	for name, entry := range map[string]string{
		"a box the grant holds": "projects/task:view",
		"no colon":              "membership",
		"no level":              "membership:",
		"no group":              ":people",
		"two in one string":     "membership:people projects:read",
		"an empty entry":        "",
		"a level not held":      "membership:peopel",
	} {
		_, err := Load([]byte(grantDoc(scopes, fmt.Sprintf("[%q]", entry))), nil)
		if err == nil {
			t.Errorf("%s: assistant_levels [%q] loaded", name, entry)

			continue
		}
		for _, want := range []string{`"svc:product-api"`, `"svc:register"`, fmt.Sprintf("%q", entry)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the error %q does not name %s", name, err, want)
			}
		}
	}
}

// Two grants toward one audience stop the start: only the first would ever be
// read, so the second's scopes and named levels would be ignored unseen.
func TestLoadRefusesTwoGrantsTowardOneAudience(t *testing.T) {
	_, err := Load([]byte(`
service_clients:
  - client_id: svc:product-api
    secret_ref: env:API
    enabled: true
    grants:
      - audience: svc:register
        scopes: [membership:people]
      - audience: svc:register
        scopes: [membership:people]
        assistant_levels: [membership:people]
`), nil)
	if err == nil {
		t.Fatal("two grants toward one audience loaded")
	}
	for _, want := range []string{`"svc:product-api"`, `"svc:register"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not name %s", err, want)
		}
	}
}

// A grant scope is a box (service/feature:act) or a level (group:level); any
// other entry stops the start, named, rather than loading as written.
func TestLoadRefusesAGrantScopeOfNoShape(t *testing.T) {
	if _, err := Load([]byte(grantDoc("[membership:people, projects/task:view]", "")), nil); err != nil {
		t.Fatalf("a box and a level must load: %v", err)
	}

	for _, scope := range []string{
		"admin", "*", "openid", ":read", "projects:", "a:b c:d", "projects:read write", "a:b:c", "projects/task", "projects/task:",
		"projects/task:view\nmembership:admin", "projects/task:view membership:admin",
	} {
		_, err := Load([]byte(grantDoc(fmt.Sprintf("[membership:people, %q]", scope), "")), nil)
		if err == nil {
			t.Errorf("the grant scope %q loaded", scope)

			continue
		}
		for _, want := range []string{`"svc:product-api"`, fmt.Sprintf("%q", scope)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: the error %q does not name %s", scope, err, want)
			}
		}
	}
}
