package authbytecore

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/upstream"
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

// twoUpstreams is a set an embedding program passes: eParaksts beside a
// directory provider, each with fixed endpoints, so nothing is fetched.
func twoUpstreams(t *testing.T) Option {
	t.Helper()

	eparaksts := upstream.EParakstsProfile("https://eparaksts.example", "")
	eparaksts.ClientID = "e-cid"
	ep, err := upstream.New(context.Background(), eparaksts, nil)
	if err != nil {
		t.Fatalf("eparaksts: %v", err)
	}
	dir, err := upstream.New(context.Background(), upstream.Config{
		AuthorizeURL: "https://dir.example/a", TokenURL: "https://dir.example/t", UserInfoURL: "https://dir.example/u",
		ClientID: "d-cid", Issuer: "https://dir.example", MethodDefault: "upstream",
	}, nil)
	if err != nil {
		t.Fatalf("directory: %v", err)
	}

	return WithUpstreams(
		upstream.Entry{Name: "eparaksts", Provider: ep, ReturnPath: "/auth/eparaksts/callback"},
		upstream.Entry{Name: "entra", Provider: dir, ReturnPath: "/Auth/Complete", HoldsStored: true},
	)
}

// Case 8 (call 1): a set passed through the option replaces the upstream
// settings. They are neither required nor read, so both families set at once —
// which the open build refuses — is no refusal, and the deployment offers what
// the set's entries allow.
func TestAPassedSetReplacesTheUpstreamSettings(t *testing.T) {
	t.Setenv("EPARAKSTS_AUTHORITY_URL", "http://localhost:9999")
	t.Setenv("EPARAKSTS_CLIENT_ID", "test-client")
	t.Setenv("OIDC_UPSTREAM_AUTHORITY_URL", "http://unreachable.invalid")

	app, err := startTestApp(t, twoUpstreams(t))
	if err != nil {
		t.Fatalf("start with a passed set: %v", err)
	}
	if n := len(app.Upstreams().Entries()); n != 2 {
		t.Errorf("the deployment runs %d upstreams, want the set's 2", n)
	}
	for m, want := range map[string]bool{
		identity.LoginEParakstsMobile: true,
		identity.LoginEIDScan:         true,
		"upstream":                    true,
		identity.LoginWebEID:          false,
	} {
		if got := app.offersMethod(m); got != want {
			t.Errorf("offers %s = %v, want %v", m, got, want)
		}
	}
}

// Case 7: the open build keeps its one upstream, from its settings, and its
// one-family rule.
func TestTheOpenBuildRunsOneUpstreamFromItsSettings(t *testing.T) {
	app := TestApp(t)
	entries := app.Upstreams().Entries()
	if len(entries) != 1 {
		t.Fatalf("the open build runs %d upstreams, want 1", len(entries))
	}
	e := entries[0]
	if e.ReturnPath != "/callback" || !e.HoldsStored || e.CredentialProvider() != "" {
		t.Errorf("the open build's upstream: path %q, holds the stored sign-ins %v, keys by %q; want /callback, true, \"\"",
			e.ReturnPath, e.HoldsStored, e.CredentialProvider())
	}

	t.Setenv("OIDC_UPSTREAM_AUTHORITY_URL", "http://unreachable.invalid")
	if _, err := startTestApp(t); err == nil || !strings.Contains(err.Error(), "two upstream identity providers") {
		t.Errorf("both families in the open build: err = %v, want the one-family refusal", err)
	}
}

// A passed set the seam refuses stops the start, naming what is wrong.
func TestAPassedSetTheSeamRefusesStopsTheStart(t *testing.T) {
	ep, err := upstream.New(context.Background(), upstream.EParakstsProfile("https://eparaksts.example", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = startTestApp(t, WithUpstreams(
		upstream.Entry{Name: "a", Provider: ep, ReturnPath: "/a", HoldsStored: true},
		upstream.Entry{Name: "b", Provider: ep, ReturnPath: "/b"},
	))
	if err == nil || !strings.Contains(err.Error(), identity.LoginEIDScan) {
		t.Errorf("two entries claiming one method: err = %v, want a refusal naming it", err)
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
