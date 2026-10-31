package authbytecore

import (
	"slices"
	"testing"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/go-make-bytes/authbyte/registry"
)

// accepted is every audience an inbound check takes, its own first.
func accepted(c *authclient.Configuration) []string {
	return append([]string{c.ServiceAudience}, c.AlsoAcceptedAudiences...)
}

// The identity door answers for every product's people, so its inbound check
// accepts each enabled sign-in client's audience, and a disabled client's not.
func TestTheIdentityDoorAcceptsEverySignInClientsAudience(t *testing.T) {
	reg, err := registry.Load([]byte(`
sign_in_clients:
  - client_id: one-app
    enabled: true
    type: public
    audience: one-api
    redirect_uris: [https://one.example/cb]
  - client_id: two-app
    enabled: true
    type: public
    audience: two-api
    redirect_uris: [https://two.example/cb]
  - client_id: off-app
    enabled: false
    type: public
    audience: off-api
    redirect_uris: [https://off.example/cb]
`), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := inboundAuthConfig(&Configuration{IssuerURL: "http://auth.example"}, reg)
	if a := accepted(got); !slices.Equal(a, []string{"one-api", "two-api"}) {
		t.Errorf("accepted %q, want every enabled sign-in client's audience and nothing else", a)
	}
}

// Each client carries its own audience, so no deployment-wide one is read: the
// setting that named it opens nothing, beside the registry or without one.
func TestADeploymentWideUserAudienceOpensNothing(t *testing.T) {
	t.Setenv("AUTH_USER_AUDIENCE", "stray-api")

	t.Setenv("SERVICE_CLIENT_REGISTRY", `
sign_in_clients:
  - client_id: one-app
    enabled: true
    type: public
    audience: one-api
    redirect_uris: [https://one.example/cb]
`)
	app := TestApp(t)
	if a := accepted(inboundAuthConfig(app.Config(), app.Registry())); !slices.Equal(a, []string{"one-api"}) {
		t.Errorf("with one client: accepted %q, want only its audience", a)
	}

	// With no sign-in client nobody signs in, and the door's audience is empty:
	// every token this service mints names one audience, never an empty one, so
	// none is accepted.
	t.Setenv("SERVICE_CLIENT_REGISTRY", "")
	app = TestApp(t)
	if a := accepted(inboundAuthConfig(app.Config(), app.Registry())); !slices.Equal(a, []string{""}) {
		t.Errorf("with no client: accepted %q, want none", a)
	}
}
