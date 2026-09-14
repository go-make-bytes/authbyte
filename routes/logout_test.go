package routes

import (
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// TestLogoutRequiresClientID confirms the route is registered and rejects a call
// without the required client_id (so the redirect_uri can't be validated). This
// exercises the front-channel /logout entrypoint without needing Redis or a
// populated client registry (the happy path needs a registered client + session).
func TestLogoutRequiresClientID(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/logout")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
}

// TestLogoutRejectsUnregisteredRedirect confirms a redirect_uri that is not on
// the client's allowlist is refused (open-redirect guard) rather than reflected.
// With the test registry empty, portal-spa is unknown, so validation fails.
func TestLogoutRejectsUnregisteredRedirect(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/logout?client_id=portal-spa&redirect_uri=https%3A%2F%2Fevil.example%2Fx")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
}

// genericUpstreamApp wires the service to a generic provider with fixed endpoints
// (no discovery, no network) and one registered browser client, so the logout
// route's decision — local, or through the provider — can be read off the
// redirect it answers. federated is the OIDC_UPSTREAM_METHODS_FEDERATED value.
func genericUpstreamApp(t *testing.T, federated string) *azugo.TestApp {
	t.Helper()

	t.Setenv("OIDC_UPSTREAM_AUTHORIZE_URL", "https://idp.example/authorize")
	t.Setenv("OIDC_UPSTREAM_TOKEN_URL", "https://idp.example/token")
	t.Setenv("OIDC_UPSTREAM_USERINFO_URL", "https://idp.example/userinfo")
	t.Setenv("OIDC_UPSTREAM_END_SESSION_URL", "https://idp.example/logout")
	t.Setenv("OIDC_UPSTREAM_CLIENT_ID", "cid")
	t.Setenv("OIDC_UPSTREAM_METHODS_FEDERATED", federated)
	t.Setenv("SERVICE_CLIENT_REGISTRY", `
public_clients:
  - client_id: app
    enabled: true
    allowed_redirect_uris: [https://app.example/]
`)

	app := authbytecore.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	return azugo.NewTestApp(app.App)
}

// signOutLocation runs a sign-out after an upstream login (the login_method hint
// stands in for a session, so no Redis is needed) and returns where the browser
// is sent.
func signOutLocation(t *testing.T, app *azugo.TestApp) string {
	t.Helper()

	resp, err := app.TestClient().Get("/logout?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2F&login_method=upstream")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	status := resp.StatusCode()
	qt.Assert(t, qt.IsTrue(status == fasthttp.StatusFound || status == fasthttp.StatusSeeOther),
		qt.Commentf("a sign-out answers a redirect, got %d: %s", status, resp.Body()))

	return string(resp.Header.Peek("Location"))
}

// TestLogoutAfterGenericUpstreamLoginIsLocal pins the default for a generic
// provider: signing out ends this service's session and returns the browser to
// the application — the provider is not visited, so the session it keeps in the
// browser (for a directory provider, the person's whole estate) is left alone.
func TestLogoutAfterGenericUpstreamLoginIsLocal(t *testing.T) {
	app := genericUpstreamApp(t, "")
	app.Start(t)
	defer app.Stop()

	qt.Check(t, qt.Equals(signOutLocation(t, app), "https://app.example/"))
}

// TestLogoutAfterGenericUpstreamLoginFederatesWhenListed is the opt-in: a
// deployment that lists the method sends the browser through the provider's
// end-session endpoint first, with the application as the post-logout return.
func TestLogoutAfterGenericUpstreamLoginFederatesWhenListed(t *testing.T) {
	app := genericUpstreamApp(t, "upstream")
	app.Start(t)
	defer app.Stop()

	loc := signOutLocation(t, app)
	qt.Check(t, qt.StringContains(loc, "https://idp.example/logout?"))
	qt.Check(t, qt.StringContains(loc, "post_logout_redirect_uri=https%3A%2F%2Fapp.example%2F"))
	qt.Check(t, qt.StringContains(loc, "client_id=cid"))
}
