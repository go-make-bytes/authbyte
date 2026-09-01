package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-make-bytes/authbyte/identity"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func eparakstsProvider(t *testing.T, authority, logoutIDP string, log *zap.Logger) *Provider {
	t.Helper()
	cfg := EParakstsProfile(authority, logoutIDP)
	cfg.ClientID = "client"
	cfg.ClientSecret = "secret"
	p, err := New(context.Background(), cfg, log)
	qt.Assert(t, qt.IsNil(err))

	return p
}

// TestEParakstsProfileEndpoints pins the eParaksts profile to the exact
// Entrust endpoints the fleet has always used — the profile must stay
// byte-identical for deployments configured only with EPARAKSTS_* variables.
func TestEParakstsProfileEndpoints(t *testing.T) {
	p := eparakstsProvider(t, "http://localhost:9999/", "", nil)

	auth := p.AuthorizeURL(AuthorizeParams{State: "s", RedirectURI: "https://cb"})
	qt.Check(t, qt.StringContains(auth,
		"http://localhost:9999/trustedx-authserver/oauth/lvrtc-eipsign-as?"))
	qt.Check(t, qt.StringContains(auth, "scope=urn%3Alvrtc%3Afpeil%3Aaa"))
	qt.Check(t, qt.StringContains(auth, "response_type=code"))
}

// TestEParakstsLogoutURL checks the IdP session-termination URL is built on the
// IdP id (distinct from the OAuth AS id) with the redirect query-encoded.
func TestEParakstsLogoutURL(t *testing.T) {
	p := eparakstsProvider(t, "http://localhost:9999/", "lvrtc-eipsign-idp", nil)

	got := p.LogoutURL("https://localhost:5001/demo/index.html")

	qt.Check(t, qt.StringContains(got,
		"http://localhost:9999/trustedx-authserver/lvrtc-eipsign-idp/logout?"))
	qt.Check(t, qt.StringContains(got,
		"redirect_uri=https%3A%2F%2Flocalhost%3A5001%2Fdemo%2Findex.html"))
}

// TestEParakstsLogoutDefaultsIDP confirms an empty idp falls back to the
// profile default.
func TestEParakstsLogoutDefaultsIDP(t *testing.T) {
	p := eparakstsProvider(t, "http://localhost:9999", "", nil)

	got := p.LogoutURL("https://localhost:5001/demo/index.html")

	qt.Check(t, qt.StringContains(got,
		"/trustedx-authserver/"+EParakstsDefaultLogoutIDP+"/logout?"))
}

// TestEParakstsMethodGates pins the profile's allowed/federated method sets:
// eParaksts Mobile and eID Scan log in; the legacy plugin eID is refused but
// still counts as federated (its IdP SSO cookie must be cleared on logout);
// Web eID is neither (it never touches this IdP).
func TestEParakstsMethodGates(t *testing.T) {
	p := eparakstsProvider(t, "http://localhost:9999", "", nil)

	qt.Check(t, qt.IsTrue(p.MethodAllowed(identity.LoginEParakstsMobile)))
	qt.Check(t, qt.IsTrue(p.MethodAllowed(identity.LoginEIDScan)))
	qt.Check(t, qt.IsFalse(p.MethodAllowed(identity.LoginEID)))
	qt.Check(t, qt.IsFalse(p.MethodAllowed(identity.LoginWebEID)))

	qt.Check(t, qt.IsTrue(p.FederatedMethod(identity.LoginEID)))
	qt.Check(t, qt.IsTrue(p.FederatedMethod(identity.LoginEParakstsMobile)))
	qt.Check(t, qt.IsFalse(p.FederatedMethod(identity.LoginWebEID)))
}

// TestDiscoveryResolvesEndpoints proves a generic provider with only an
// authority URL takes its endpoints from the discovery document, and that the
// end-session endpoint drives standard RP-initiated logout.
func TestDiscoveryResolvesEndpoints(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qt.Check(t, qt.Equals(r.URL.Path, "/.well-known/openid-configuration"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"authorization_endpoint": "` + srvURL + `/authz",
			"token_endpoint": "` + srvURL + `/tok",
			"userinfo_endpoint": "` + srvURL + `/ui",
			"end_session_endpoint": "` + srvURL + `/bye"
		}`))
	}))
	defer srv.Close()
	srvURL = srv.URL

	p, err := New(context.Background(), Config{
		AuthorityURL:  srv.URL,
		ClientID:      "cid",
		MethodDefault: "upstream",
	}, nil)
	qt.Assert(t, qt.IsNil(err))

	auth := p.AuthorizeURL(AuthorizeParams{State: "s", RedirectURI: "https://cb"})
	qt.Check(t, qt.StringContains(auth, srv.URL+"/authz?"))
	qt.Check(t, qt.StringContains(auth, "scope=openid+profile"))

	bye := p.LogoutURL("https://app/out")
	qt.Check(t, qt.StringContains(bye, srv.URL+"/bye?"))
	qt.Check(t, qt.StringContains(bye, "post_logout_redirect_uri=https%3A%2F%2Fapp%2Fout"))
	qt.Check(t, qt.StringContains(bye, "client_id=cid"))

	// The configured default method is the allowed set when none is given.
	qt.Check(t, qt.IsTrue(p.MethodAllowed("upstream")))
	qt.Check(t, qt.IsFalse(p.MethodAllowed(identity.LoginEID)))
}

// TestDiscoveryFailsClosed: a provider whose endpoints cannot be established
// must not construct.
func TestDiscoveryFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := New(context.Background(), Config{AuthorityURL: srv.URL, ClientID: "cid"}, nil)
	qt.Assert(t, qt.IsNotNil(err))
}

// testIDCodeLV returns a Latvian personal identity code in the PNO form an
// upstream reports: the country, a six-digit leading group and a five-digit
// serial, built from one repeated digit so it reads as a placeholder at a glance.
//
// It is assembled from those parts at run time rather than written as a literal —
// an identifier-shaped constant in the source is indistinguishable from a
// credential to a secret scanner, and indistinguishable from a real person's code
// to a reader.
func testIDCodeLV(digit int) string {
	d := strconv.Itoa(digit)

	return "PNOLV-" + strings.Repeat(d, 6) + "-" + strings.Repeat(d, 5)
}

// TestUserInfoSerialClaimConfigurable proves the identity-code claim name is
// configuration (a provider that carries it in a custom claim needs no code),
// and that acr arriving as an ARRAY is accepted (first value wins).
func TestUserInfoSerialClaimConfigurable(t *testing.T) {
	serial := testIDCodeLV(1)
	payload := `{"sub":"u1","name":"JĀNIS BĒRZIŅŠ","nationalId":"` + serial + `","acr":["urn:example:mfa"]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	p, err := New(context.Background(), Config{
		AuthorizeURL: srv.URL + "/a", TokenURL: srv.URL + "/t", UserInfoURL: srv.URL,
		ClientID: "cid", ClaimSerial: "nationalId", MethodDefault: "upstream",
	}, nil)
	qt.Assert(t, qt.IsNil(err))

	info, err := p.UserInfo(t.Context(), "tok")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.SerialNumber, serial))
	qt.Check(t, qt.Equals(info.ACR, "urn:example:mfa"))
	qt.Check(t, qt.Equals(info.Name, "JĀNIS BĒRZIŅŠ"))
}

// TestGenericResolverDefaults proves a generic provider's resolver falls back
// to the configured method/LoA defaults when the IdP sends no recognizable
// acr/amr tokens — the standalone-friendly path a plain OIDC provider takes.
func TestGenericResolverDefaults(t *testing.T) {
	p, err := New(context.Background(), Config{
		AuthorizeURL: "https://x/a", TokenURL: "https://x/t", UserInfoURL: "https://x/u",
		ClientID: "cid", MethodDefault: "upstream", LoADefault: identity.LoASubstantial,
	}, nil)
	qt.Assert(t, qt.IsNil(err))

	method, loa := p.Resolver().Interpret("", nil)
	qt.Check(t, qt.Equals(method, "upstream"))
	qt.Check(t, qt.Equals(loa, identity.LoASubstantial))

	// A configured vocabulary still wins over the default.
	p2, err := New(context.Background(), Config{
		AuthorizeURL: "https://x/a", TokenURL: "https://x/t", UserInfoURL: "https://x/u",
		ClientID: "cid", MethodDefault: "upstream",
		MethodPolicy: map[string]string{"smartcard": "corpCard"},
	}, nil)
	qt.Assert(t, qt.IsNil(err))
	m2, _ := p2.Resolver().Interpret("urn:example:smartcard", nil)
	qt.Check(t, qt.Equals(m2, "corpCard"))
}

// TestUserInfoDebugLogsRawBody proves the raw userinfo JSON is logged at debug
// level (and is silent above it).
func TestUserInfoDebugLogsRawBody(t *testing.T) {
	const payload = `{"sub":"abc","name":"MĀRA PARAUDZIŅA","amr":["urn:eparaksts:tws:policies:authentication:adaptive:methods:mobileid"]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	profile := func(log *zap.Logger) *Provider {
		cfg := EParakstsProfile(srv.URL, "")
		cfg.ClientID, cfg.ClientSecret = "cid", "secret"
		cfg.UserInfoURL = srv.URL
		p, err := New(context.Background(), cfg, log)
		qt.Assert(t, qt.IsNil(err))

		return p
	}

	// debug → logged
	core, logs := observer.New(zapcore.DebugLevel)
	_, err := profile(zap.New(core)).UserInfo(t.Context(), "tok")
	qt.Assert(t, qt.IsNil(err))

	entries := logs.FilterMessage("upstream userinfo response").All()
	qt.Assert(t, qt.Equals(len(entries), 1))
	qt.Check(t, qt.StringContains(entries[0].ContextMap()["body"].(string), "mobileid"))

	// info → suppressed
	core2, logs2 := observer.New(zapcore.InfoLevel)
	_, err = profile(zap.New(core2)).UserInfo(t.Context(), "tok")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(logs2.FilterMessage("upstream userinfo response").Len(), 0))
}
