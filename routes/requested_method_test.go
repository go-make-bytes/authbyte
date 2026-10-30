package routes

import (
	"net/url"
	"testing"

	"github.com/go-make-bytes/authbyte/identity"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

const (
	acrMobile = "urn:eparaksts:authentication:flow:mobileid"
	acrScan   = "urn:eparaksts:authentication:flow:mobile-eid"
)

// The methods a request asks for are read from its acr_values, a space-separated
// list in order of preference (OIDC Core §3.1.2.1). A value no method answers
// to, or a method this provider does not offer, makes the request one that can
// never be met.
func TestRequestedMethods(t *testing.T) {
	res := identity.NewResolverPolicies(nil, nil, identity.LoginEParakstsMobile, "")
	offered := func(m string) bool { return m == identity.LoginEParakstsMobile || m == identity.LoginEIDScan }

	cases := []struct {
		name    string
		acr     string
		methods []string
		ok      bool
	}{
		{"none asked", "", nil, true},
		{"one asked", acrMobile, []string{identity.LoginEParakstsMobile}, true},
		{"two asked, in order", acrScan + " " + acrMobile, []string{identity.LoginEIDScan, identity.LoginEParakstsMobile}, true},
		{"the same asked twice", acrMobile + "  " + acrMobile, []string{identity.LoginEParakstsMobile}, true},
		{"a value no method answers to", "urn:nobody:flow:fingerprint", nil, false},
		{"a method this provider does not offer", "sc_plugin", nil, false},
		{"one good, one unknown", acrMobile + " urn:nobody:flow:fingerprint", nil, false},
	}
	for _, c := range cases {
		methods, ok := requestedMethods(res, offered, c.acr)
		qt.Check(t, qt.DeepEquals(methods, c.methods), qt.Commentf("%s", c.name))
		qt.Check(t, qt.Equals(ok, c.ok), qt.Commentf("%s", c.name))
	}
}

// A sign-in completes only with a method the request asked for (cases 7-11 of
// the C0 task). Nothing asked means any method the provider allows.
func TestMethodRequested(t *testing.T) {
	both := []string{identity.LoginEIDScan, identity.LoginEParakstsMobile}

	cases := []struct {
		name      string
		requested []string
		achieved  string
		want      bool
	}{
		{"7: asked A, answered A", []string{identity.LoginEParakstsMobile}, identity.LoginEParakstsMobile, true},
		{"8: asked A, answered B", []string{identity.LoginEParakstsMobile}, identity.LoginEIDScan, false},
		{"9: nothing asked", nil, identity.LoginEIDScan, true},
		{"10: asked A B, answered B", both, identity.LoginEParakstsMobile, true},
		{"10: asked A B, answered C", both, identity.LoginWebEID, false},
		{"11: asked a provider method, completed with the card", []string{identity.LoginEIDScan}, identity.LoginWebEID, false},
	}
	for _, c := range cases {
		qt.Check(t, qt.Equals(methodRequested(c.requested, c.achieved), c.want), qt.Commentf("%s", c.name))
	}
}

// Case 12: a request for a method this deployment never offers is refused at
// /authorize, at the client's own address, before a flow is stored or the
// browser is sent to the provider.
func TestAuthorizeRefusesAMethodTheDeploymentDoesNotOffer(t *testing.T) {
	app := pkceApp(t)

	for _, acr := range []string{"urn:nobody:flow:fingerprint", "sc_plugin"} {
		q, err := url.ParseQuery(authorizeQuery("challenge-of-forty-three-characters-long-aaaa", ptr("S256"))[len("/authorize?"):])
		qt.Assert(t, qt.IsNil(err))
		q.Set("acr_values", acr)

		resp, err := app.TestClient().Get("/authorize?" + q.Encode())
		qt.Assert(t, qt.IsNil(err))

		qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound), qt.Commentf("%s", acr))
		loc, err := url.Parse(string(resp.Header.Peek("Location")))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(loc.Host, "app.example"), qt.Commentf("%s", acr))
		qt.Check(t, qt.Equals(loc.Query().Get("error"), "unmet_authentication_requirements"), qt.Commentf("%s", acr))
		qt.Check(t, qt.Equals(loc.Query().Get("state"), "spa-state"), qt.Commentf("%s", acr))
		fasthttp.ReleaseResponse(resp)
	}
}
