package authbytecore

import (
	"slices"
	"strings"
	"testing"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/registry"
)

// Case 4, at the start: with a register wired, a row that leaves its membership
// need unset asks for one, so a baseline written on it could never be minted.
// The start is refused, naming the row.
func TestTheStartRefusesABaselineThatCouldNeverBeMinted(t *testing.T) {
	t.Setenv("ROLEBYTE_URL", "http://rolebyte.example:8081")
	t.Setenv("SERVICE_CLIENT_REGISTRY", `
sign_in_clients:
  - client_id: needs-members
    enabled: true
    type: public
    audience: a-portal
    baseline_scopes: [a:read]
    redirect_uris: [https://a.example/callback]
`)

	_, err := startTestApp(t)
	if err == nil || !strings.Contains(err.Error(), "needs-members") {
		t.Errorf("start: err = %v, want a refusal naming needs-members", err)
	}
}

// Case 10: a row none of whose methods this deployment offers is named for a
// warning, not refused. One registry file serves every mode of a stack, whose
// modes offer different methods, so a row can be right in one and empty in
// another; such a row's sign-in is refused where it is asked for.
func TestClientsOfferedNothingAreNamed(t *testing.T) {
	reg, err := registry.Load([]byte(`
sign_in_clients:
  - client_id: card-only
    enabled: true
    type: public
    audience: a-api
    methods: [webEid]
    redirect_uris: [https://a.example/cb]
  - client_id: mobile-and-card
    enabled: true
    type: public
    audience: a-api
    methods: [eparakstsMobile, webEid]
    redirect_uris: [https://a.example/cb]
  - client_id: no-methods
    enabled: true
    type: public
    audience: a-api
    redirect_uris: [https://a.example/cb]
  - client_id: off
    enabled: false
    type: public
    audience: a-api
    methods: [webEid]
    redirect_uris: [https://a.example/cb]
`), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	offered := func(m string) bool { return m == identity.LoginEParakstsMobile }
	if got := clientsOfferedNothing(reg, offered); !slices.Equal(got, []string{"card-only", "no-methods"}) {
		t.Errorf("named %v, want the two enabled rows this deployment offers nothing to", got)
	}
}

// The deployment offers what its provider allows, and the card only where the
// card engine is named.
func TestTheDeploymentOffersItsProvidersMethodsAndTheCardWithAnEngine(t *testing.T) {
	app := TestApp(t)
	for m, want := range map[string]bool{
		identity.LoginEParakstsMobile: true,
		identity.LoginEIDScan:         true,
		identity.LoginWebEID:          false,
		"upstream":                    false,
	} {
		if got := app.offersMethod(m); got != want {
			t.Errorf("without an engine, offers %s = %v, want %v", m, got, want)
		}
	}

	t.Setenv("WEBEID_ENGINE_URL", "http://localhost:9998")
	app = TestApp(t)
	if !app.offersMethod(identity.LoginWebEID) {
		t.Error("with an engine, the card is not offered")
	}
}
