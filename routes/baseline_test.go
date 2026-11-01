package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// A client whose people need no membership mints each person its own row's
// baseline, and a row with none mints no scopes: the scopes are no longer one
// signing product's, written into the code.
func TestEachClientMintsItsOwnBaseline(t *testing.T) {
	app, mem := signInApp(t)

	for _, tc := range []struct {
		client, redirect string
		basic            []string
		scope            any
	}{
		{"portal-spa", portalRedirect, nil, "envelopes:read envelopes:write documents:read"},
		{"edge-app", edgeRedirect, []string{"edge-app", "edge-secret"}, "records:read"},
		{"product-spa", productRedirect, nil, nil},
	} {
		e := newEdge(t, app)
		e.basic = tc.basic
		in := seedSignIn(t, mem, tc.client, tc.redirect)

		status, body := e.exchange(in, tc.client, tc.redirect)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", tc.client, body["_raw"]))
		qt.Check(t, qt.Equals(tokenClaims(t, body["access_token"].(string))["scope"], tc.scope), qt.Commentf("%s at the exchange", tc.client))

		status, body = e.refresh(body["refresh_token"].(string), tc.client)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", tc.client, body["_raw"]))
		qt.Check(t, qt.Equals(tokenClaims(t, body["access_token"].(string))["scope"], tc.scope), qt.Commentf("%s at refresh", tc.client))
	}
}
