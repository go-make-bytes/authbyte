package routes

import (
	"encoding/json"
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
	"azugo.io/azugo/user"
	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// signingApp runs the shared registry, where portal-spa signs and product-spa
// does not, with scratch routes that reach the handlers as a validated token or
// a completed login would; extra adds a test's own before the start.
func signingApp(t *testing.T, extra ...func(*authbytecore.App, *router)) (*azugo.TestApp, *router) {
	t.Helper()

	t.Setenv("SERVICE_CLIENT_REGISTRY", testRegistry)
	app := authbytecore.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	r := &router{App: app}
	app.Get("/testonly/identity", func(ctx *azugo.Context) {
		c := &claims.Claims{LoginMethod: identity.LoginWebEID, LoA: "high", ClientID: ctx.Header.Get("X-Test-Client")}
		c.Subject = testPersonSub(5)
		ctx.SetUser(user.New(c.ToUserClaims()))
		r.identity(ctx)
	})
	for _, add := range extra {
		add(app, r)
	}

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return ta, r
}

// Case 39: after the same card sign-in, the identity answer names the signing
// flows the method permits only to a signing client's token.
func TestOnlyASigningClientIsToldItsSigningFlows(t *testing.T) {
	app, _ := signingApp(t)

	flows := func(clientID string) []string {
		tc := app.TestClient()
		resp, err := tc.Get("/testonly/identity", tc.WithHeader("X-Test-Client", clientID))
		qt.Assert(t, qt.IsNil(err))
		defer fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK), qt.Commentf("%s", resp.Body()))

		var out struct {
			LoginMethod    string   `json:"login_method"`
			PermittedFlows []string `json:"permitted_flows"`
		}
		qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
		qt.Check(t, qt.Equals(out.LoginMethod, identity.LoginWebEID))

		return out.PermittedFlows
	}

	qt.Check(t, qt.DeepEquals(flows("portal-spa"), identity.BindingResolver{}.PermittedFlows(identity.LoginWebEID)))
	qt.Check(t, qt.HasLen(flows("portal-spa"), 2))
	qt.Check(t, qt.IsNil(flows("product-spa")))
	qt.Check(t, qt.IsNil(flows("")), qt.Commentf("a token naming no client"))
}

// Case 40: a sign-in through a non-signing client reads nothing of the person's
// signing identities: the capture answers nothing before it would fetch the seal
// this catalog lists. A signing client's capture runs (here over a catalog with
// nothing to fetch).
func TestOnlyASigningClientsSignInCapturesSigningIdentities(t *testing.T) {
	seal := []identity.SignIdentity{{
		ID: "seal-1", Status: "ENABLED", Labels: []string{"QSealC", "CN=Example Org"}, Permissions: []string{"sign"},
	}}

	var signing, plain *session.Capabilities
	app, _ := signingApp(t, func(a *authbytecore.App, r *router) {
		a.Get("/testonly/capture", func(ctx *azugo.Context) {
			portal, _ := r.Registry().SignInClient("portal-spa")
			product, _ := r.Registry().SignInClient("product-spa")
			signing = r.captureCapabilities(ctx, portal, "idp-token", identity.UserInfo{SignIdentities: []identity.SignIdentity{}}, identity.LoginEParakstsMobile)
			plain = r.captureCapabilities(ctx, product, "idp-token", identity.UserInfo{SignIdentities: seal}, identity.LoginEParakstsMobile)
		})
	})

	resp, err := app.TestClient().Get("/testonly/capture")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.IsNotNil(signing))
	qt.Check(t, qt.IsNil(plain))
}

// Case 41: a card sign-in through a non-signing client keeps no authentication
// certificate; through a signing client it keeps the card's.
func TestOnlyASigningClientsCardSignInKeepsTheCertificate(t *testing.T) {
	_, r := signingApp(t)

	token := json.RawMessage(`{"unverifiedCertificate":"MIIB-the-card"}`)
	portal, _ := r.Registry().SignInClient("portal-spa")
	product, _ := r.Registry().SignInClient("product-spa")

	got := cardCapabilities(portal, token)
	qt.Assert(t, qt.IsNotNil(got))
	qt.Check(t, qt.Equals(got.AuthCertificate, "MIIB-the-card"))

	qt.Check(t, qt.IsNil(cardCapabilities(product, token)))
}
