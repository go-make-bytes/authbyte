package routes

import (
	"net/url"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// pkceApp registers one browser client so /authorize gets past its redirect
// check and reaches the PKCE parameters.
func pkceApp(t *testing.T) *azugo.TestApp {
	t.Helper()

	t.Setenv("SERVICE_CLIENT_REGISTRY", `
sign_in_clients:
  - client_id: app
    type: public
    audience: portal-api
    enabled: true
    methods: [eparakstsMobile, eidScan, webEid]
    redirect_uris: [https://app.example/cb]
`)
	// The card routes exist only with an engine named; nothing calls it here.
	t.Setenv("WEBEID_ENGINE_URL", "http://localhost:9998")

	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	return app
}

// authorizeQuery is a valid /authorize request with the PKCE parameters left
// to the caller: method nil sends no code_challenge_method, challenge "" sends
// no code_challenge.
func authorizeQuery(challenge string, method *string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "app")
	q.Set("redirect_uri", "https://app.example/cb")
	q.Set("state", "spa-state")
	if challenge != "" {
		q.Set("code_challenge", challenge)
	}
	if method != nil {
		q.Set("code_challenge_method", *method)
	}

	return "/authorize?" + q.Encode()
}

// assertPKCERefused checks that /authorize answered the client's own address
// with invalid_request and its state, and did not send the browser on to the
// identity provider.
func assertPKCERefused(t *testing.T, app *azugo.TestApp, path string) {
	t.Helper()

	resp, err := app.TestClient().Get(path)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))

	loc, err := url.Parse(string(resp.Header.Peek("Location")))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(loc.Host, "app.example"))
	qt.Check(t, qt.Equals(loc.Query().Get("error"), "invalid_request"))
	qt.Check(t, qt.Equals(loc.Query().Get("state"), "spa-state"))
	qt.Check(t, qt.Equals(loc.Query().Get("code"), ""))
}

func ptr(s string) *string { return &s }

func TestAuthorizeRefusesThePlainChallengeMethod(t *testing.T) {
	app := pkceApp(t)
	assertPKCERefused(t, app, authorizeQuery("the-verifier-itself", ptr("plain")))
}

// An absent method means plain, so it is refused like plain.
func TestAuthorizeRefusesAChallengeWithNoMethod(t *testing.T) {
	app := pkceApp(t)
	assertPKCERefused(t, app, authorizeQuery("the-verifier-itself", nil))
}

func TestAuthorizeRefusesAMethodSpelledInLowerCase(t *testing.T) {
	app := pkceApp(t)
	assertPKCERefused(t, app, authorizeQuery("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", ptr("s256")))
}

func TestAuthorizeRefusesARequestWithNoChallenge(t *testing.T) {
	app := pkceApp(t)
	assertPKCERefused(t, app, authorizeQuery("", ptr("S256")))
}

// The card door's challenge is a call from the client's server, so it refuses
// with an error answer instead of a redirect, and stores no flow.
func TestWebEIDChallengeRefusesThePlainChallengeMethod(t *testing.T) {
	app := pkceApp(t)

	for _, method := range []*string{ptr("plain"), nil, ptr("s256")} {
		q := url.Values{}
		q.Set("client_id", "app")
		q.Set("redirect_uri", "https://app.example/cb")
		q.Set("code_challenge", "the-verifier-itself")
		if method != nil {
			q.Set("code_challenge_method", *method)
		}

		resp, err := app.TestClient().Get("/webeid/challenge?" + q.Encode())
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity), qt.Commentf("method %v", method))
		fasthttp.ReleaseResponse(resp)
	}
}

// The plain form, a verifier equal to the stored challenge, never verifies.
func TestAVerifierEqualToTheChallengeNeverVerifies(t *testing.T) {
	for _, method := range []string{"plain", "", "S256"} {
		qt.Check(t, qt.IsFalse(verifyPKCE("the-verifier-itself", "the-verifier-itself", method)), qt.Commentf("method %q", method))
	}
}

// The S256 form still verifies (the RFC 7636 appendix B example).
func TestAnS256VerifierVerifies(t *testing.T) {
	qt.Check(t, qt.IsTrue(verifyPKCE("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256")))
}
