package routes

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

const edgeRedirect = "https://edge.example/callback"

// basicAuth builds HTTP Basic client credentials, each part form-encoded first
// [RFC 6749 §2.3.1].
func basicAuth(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

func (e *edge) exchangeWith(in signIn, clientID, redirectURI string, extra url.Values) (int, map[string]any) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {in.code},
		"code_verifier": {in.verifier},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
	}
	for k, v := range extra {
		form[k] = v
	}

	return e.post("/token", form)
}

// A confidential client exchanges its code only with its secret. A request
// without it, or with a wrong one, gets nothing, and the code is not spent: the
// client is checked before the code is, so the code still works for its client.
func TestAConfidentialClientExchangesItsCodeOnlyWithItsSecret(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)
	in := seedSignIn(t, mem, "edge-app", edgeRedirect)

	status, body := e.exchangeWith(in, "edge-app", edgeRedirect, nil)
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("no secret: %s", body["_raw"]))
	qt.Check(t, qt.IsNil(body["access_token"]))

	status, body = e.exchangeWith(in, "edge-app", edgeRedirect, url.Values{"client_secret": {"wrong"}})
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("wrong secret: %s", body["_raw"]))
	qt.Check(t, qt.IsNil(body["access_token"]))

	status, body = e.exchangeWith(in, "edge-app", edgeRedirect, url.Values{"client_secret": {"edge-secret"}})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("its secret: %s", body["_raw"]))
	qt.Check(t, qt.Not(qt.Equals(body["access_token"], any(nil))))
}

// HTTP Basic is accepted at every grant [RFC 6749 §2.3.1], and the form secret
// sent beside it is refused: one method per request [RFC 6749 §2.3].
func TestTheSecretByBasicIsAcceptedAtEveryGrant(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)
	e.basic = []string{"edge-app", "edge-secret"}

	in := seedSignIn(t, mem, "edge-app", edgeRedirect)
	status, body := e.exchangeWith(in, "edge-app", edgeRedirect, nil)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("code by Basic: %s", body["_raw"]))
	refresh, _ := body["refresh_token"].(string)

	status, body = e.refresh(refresh, "edge-app")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("refresh by Basic: %s", body["_raw"]))

	svc := newEdge(t, app)
	svc.basic = []string{"svc:caller", "caller-secret"}
	status, body = svc.post("/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc:caller"}, "audience": {"svc:target"}})
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("client credentials by Basic: %s", body["_raw"]))
}

func TestBasicAndAFormSecretTogetherAreRefused(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)
	e.basic = []string{"edge-app", "edge-secret"}
	in := seedSignIn(t, mem, "edge-app", edgeRedirect)

	status, body := e.exchangeWith(in, "edge-app", edgeRedirect, url.Values{"client_secret": {"edge-secret"}})
	qt.Check(t, qt.Not(qt.Equals(status, fasthttp.StatusOK)), qt.Commentf("%s", body["_raw"]))
	qt.Check(t, qt.IsNil(body["access_token"]))
}

// A public client has no secret: it signs in with PKCE alone, and one that
// sends a secret is refused [RFC 7591 §2].
func TestAPublicClientSendsNoSecret(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	in := seedSignIn(t, mem, "portal-spa", portalRedirect)
	status, body := e.exchangeWith(in, "portal-spa", portalRedirect, url.Values{"client_secret": {"anything"}})
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%s", body["_raw"]))

	status, body = e.exchangeWith(in, "portal-spa", portalRedirect, nil)
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
}

// A confidential client's refresh and revocation need its secret too
// [RFC 7009 §2.1]; without it nothing changes, and the session goes on
// refreshing.
func TestAConfidentialClientRefreshesAndRevokesOnlyWithItsSecret(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)
	e.basic = []string{"edge-app", "edge-secret"}

	in := seedSignIn(t, mem, "edge-app", edgeRedirect)
	status, body := e.exchangeWith(in, "edge-app", edgeRedirect, nil)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	refresh, _ := body["refresh_token"].(string)

	e.basic = nil
	status, body = e.refresh(refresh, "edge-app")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("refresh without a secret: %s", body["_raw"]))

	e.basic = []string{"edge-app", "wrong"}
	status, body = e.revoke(refresh, "edge-app")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("revoke with a wrong secret: %s", body["_raw"]))

	e.basic = []string{"edge-app", "edge-secret"}
	status, body = e.refresh(refresh, "edge-app")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("the session goes on: %s", body["_raw"]))
}
