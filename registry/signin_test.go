package registry

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// signInDoc registers one client of each type, with every setting a sign-in
// client can carry on the confidential one.
const signInDoc = `
sign_in_clients:
  - client_id: edge-app
    enabled: true
    type: confidential
    secret_ref: env:EDGE
    audience: app-portal
    membership_required: false
    baseline_scopes: [records:read, records:write]
    claims: [name, given_name, family_name, serial_number]
    methods: [cardLogin, mobileLogin]
    step_up_methods: [cardLogin]
    signing: true
    client_name: The App
    logo_uri: https://app.example/logo.svg
    redirect_uris: [https://app.example/callback]
    post_logout_redirect_uris: [https://app.example/, http://edge.internal/signed-out]
    backchannel_logout_uri: http://edge.internal/backchannel-logout
  - client_id: browser-app
    enabled: true
    type: public
    audience: other-portal
    methods: [cardLogin]
    redirect_uris: [https://other.example/callback]
    post_logout_redirect_uris: [https://other.example/]
  - client_id: off-app
    enabled: false
    type: public
    audience: off-portal
    redirect_uris: [https://off.example/callback]
`

func loadSignIn(t *testing.T) *Registry {
	t.Helper()

	r, err := Load([]byte(signInDoc), func(clientID, _ string) (string, error) {
		if clientID == "edge-app" {
			return "edge-secret", nil
		}

		return "", errors.New("no secret for " + clientID)
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	return r
}

// mustNotLoad asserts the document is refused, and that the refusal names want.
func mustNotLoad(t *testing.T, name, doc, want string) {
	t.Helper()

	_, err := Load([]byte(doc), func(string, string) (string, error) { return "s", nil })
	if err == nil {
		t.Errorf("%s: loaded, want a refusal naming %q", name, want)

		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: refused with %q, want it to name %q", name, err, want)
	}
}

// signInRow wraps one sign-in client row (its lines indented four spaces under
// the list dash) in a document.
func signInRow(lines string) string {
	return "sign_in_clients:\n  - client_id: row\n    enabled: true\n" + lines
}

func TestLoadKeepsEverySignInSetting(t *testing.T) {
	r := loadSignIn(t)

	c, ok := r.SignInClient("edge-app")
	if !ok {
		t.Fatal("edge-app not found")
	}
	if c.Type != ClientConfidential || c.Audience != "app-portal" || !c.Signing {
		t.Errorf("type, audience or signing lost: %+v", c)
	}
	if !slices.Equal(c.BaselineScopes, []string{"records:read", "records:write"}) ||
		!slices.Equal(c.Claims, []string{"name", "given_name", "family_name", "serial_number"}) ||
		!slices.Equal(c.Methods, []string{"cardLogin", "mobileLogin"}) ||
		!slices.Equal(c.StepUpMethods, []string{"cardLogin"}) {
		t.Errorf("a list setting was lost: %+v", c)
	}
	// Kept for the code that will use them: the hosted page and the sign-out
	// that reaches every product.
	if c.ClientName != "The App" || c.LogoURI != "https://app.example/logo.svg" ||
		c.BackchannelLogoutURI != "http://edge.internal/backchannel-logout" {
		t.Errorf("name, logo or back-channel address lost: %+v", c)
	}

	if _, ok := r.SignInClient("off-app"); ok {
		t.Error("a disabled client must not be found")
	}
	if _, ok := r.SignInClient("nobody"); ok {
		t.Error("an unknown client must not be found")
	}
}

// The registry's earlier shape is refused, naming the key, rather than loading as
// a registry with no sign-in clients.
func TestLoadRefusesTheEarlierShape(t *testing.T) {
	mustNotLoad(t, "public_clients", `
public_clients:
  - client_id: portal-spa
    enabled: true
    allowed_redirect_uris: [https://app.example/callback]
`, "public_clients")
}

func TestLoadRefusesABadSignInRow(t *testing.T) {
	const base = "    audience: a\n    redirect_uris: [https://app.example/cb]\n"

	for _, tc := range []struct{ name, row, want string }{
		{"no audience", "    type: public\n    redirect_uris: [https://app.example/cb]\n", "audience"},
		{"no type", base, "type"},
		{"another type", "    type: private\n" + base, "type"},
		{"confidential without a secret", "    type: confidential\n" + base, "secret_ref"},
		{"public with a secret", "    type: public\n    secret_ref: env:X\n" + base, "secret_ref"},
		{"baseline with a membership", "    type: public\n    membership_required: true\n    baseline_scopes: [a:b]\n" + base, "baseline_scopes"},
		{"step-up outside the methods", "    type: public\n    methods: [cardLogin]\n    step_up_methods: [mobileLogin]\n" + base, "step_up_methods"},
		{"an unknown claim", "    type: public\n    claims: [serialNumber]\n" + base, "serialNumber"},
		{"a relative login address", "    type: public\n    audience: a\n    redirect_uris: [/cb]\n", "redirect_uris"},
		{"a login address with a fragment", "    type: public\n    audience: a\n    redirect_uris: [https://app.example/cb#x]\n", "redirect_uris"},
		{"a sign-out address with a fragment", "    type: public\n    post_logout_redirect_uris: [https://app.example/#x]\n" + base, "post_logout_redirect_uris"},
		{"an http sign-out address on a public client", "    type: public\n    post_logout_redirect_uris: [http://app.example/]\n" + base, "post_logout_redirect_uris"},
		{"an http back-channel address on a public client", "    type: public\n    backchannel_logout_uri: http://app.example/bc\n" + base, "backchannel_logout_uri"},
		{"a relative back-channel address", "    type: confidential\n    secret_ref: env:X\n    backchannel_logout_uri: /bc\n" + base, "backchannel_logout_uri"},
		{"an http logo", "    type: public\n    logo_uri: http://app.example/logo.svg\n" + base, "logo_uri"},
	} {
		mustNotLoad(t, tc.name, signInRow(tc.row), tc.want)
	}
}

// One id in both sections would have two secrets and two meanings at the token
// endpoint.
func TestLoadRefusesAnIDInBothSections(t *testing.T) {
	mustNotLoad(t, "both sections", `
service_clients:
  - client_id: edge
    secret_ref: env:EDGE
    enabled: true
sign_in_clients:
  - client_id: edge
    enabled: true
    type: public
    audience: a
    redirect_uris: [https://app.example/cb]
`, "edge")
}

func TestAuthenticateSignIn(t *testing.T) {
	r := loadSignIn(t)

	for _, tc := range []struct {
		name      string
		client    string
		secret    string
		presented bool
		ok        bool
	}{
		{"confidential, its secret", "edge-app", "edge-secret", true, true},
		{"confidential, no secret", "edge-app", "", false, false},
		{"confidential, a wrong secret", "edge-app", "other", true, false},
		{"confidential, an empty secret", "edge-app", "", true, false},
		{"public, no secret", "browser-app", "", false, true},
		{"public, a secret", "browser-app", "anything", true, false},
		{"disabled", "off-app", "", false, false},
		{"unknown", "nobody", "", false, false},
	} {
		_, err := r.AuthenticateSignIn(tc.client, tc.secret, tc.presented)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok = %v", tc.name, err, tc.ok)
		}
	}
}

// A sign-out lands only on the client's sign-out list, never on its login
// callback, and the login callback only on its login list.
func TestSignInAndSignOutAddressesAreSeparateLists(t *testing.T) {
	r := loadSignIn(t)

	if err := r.ValidateRedirectURI("edge-app", "https://app.example/callback"); err != nil {
		t.Errorf("login callback refused: %v", err)
	}
	if err := r.ValidateRedirectURI("edge-app", "https://app.example/"); err == nil {
		t.Error("a sign-out landing accepted as a login callback")
	}
	if err := r.ValidatePostLogoutURI("edge-app", "https://app.example/"); err != nil {
		t.Errorf("sign-out landing refused: %v", err)
	}
	if err := r.ValidatePostLogoutURI("edge-app", "https://app.example/callback"); err == nil {
		t.Error("a login callback accepted as a sign-out landing")
	}
	if err := r.ValidatePostLogoutURI("off-app", "https://off.example/callback"); !errors.Is(err, ErrUnknownSignInClient) {
		t.Errorf("disabled client: err = %v, want ErrUnknownSignInClient", err)
	}
}

func TestAudiencesAreTheEnabledSignInClients(t *testing.T) {
	r := loadSignIn(t)

	if got := r.Audiences(); !slices.Equal(got, []string{"app-portal", "other-portal"}) {
		t.Errorf("Audiences() = %v, want the two enabled clients' audiences", got)
	}
}

// Case 4: a baseline is minted only to people no membership is asked about. With
// a register wired, a row that leaves membership_required unset asks for one, so
// its baseline could never be minted and is named for the start to refuse.
// Without a register the same row mints it, and nothing is named.
func TestBaselinesNeverMintedAreNamed(t *testing.T) {
	r, err := Load([]byte(`
sign_in_clients:
  - client_id: unset-with-baseline
    enabled: true
    type: public
    audience: a-portal
    baseline_scopes: [a:read]
    redirect_uris: [https://a.example/callback]
  - client_id: open-with-baseline
    enabled: true
    type: public
    audience: b-portal
    membership_required: false
    baseline_scopes: [b:read]
    redirect_uris: [https://b.example/callback]
  - client_id: unset-without-baseline
    enabled: true
    type: public
    audience: c-portal
    redirect_uris: [https://c.example/callback]
  - client_id: off-with-baseline
    enabled: false
    type: public
    audience: d-portal
    baseline_scopes: [d:read]
    redirect_uris: [https://d.example/callback]
`), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := r.BaselinesNeverMinted(true); !slices.Equal(got, []string{"unset-with-baseline"}) {
		t.Errorf("with a register: %v, want the row whose people need a membership", got)
	}
	if got := r.BaselinesNeverMinted(false); len(got) != 0 {
		t.Errorf("without a register: %v, want none", got)
	}
}
