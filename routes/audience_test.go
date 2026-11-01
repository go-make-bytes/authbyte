package routes

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-authbyte/replay"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// tokenClaims reads a token's payload without checking it: the test only asks
// what the token says.
func tokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	qt.Assert(t, qt.Equals(len(parts), 3))
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	qt.Assert(t, qt.IsNil(err))

	var out map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &out)))

	return out
}

// audienceOf answers a token's audience as a list, however the issuer wrote it.
func audienceOf(c map[string]any) []any {
	switch aud := c["aud"].(type) {
	case []any:
		return aud
	case string:
		return []any{aud}
	default:
		return nil
	}
}

// A session whose client is disabled after the sign-in (the registry changed and
// the service restarted) refreshes nothing more.
func TestARefreshAfterTheClientIsDisabledIsRefused(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)
	in := seedSignIn(t, mem, "product-spa", productRedirect)
	status, body := e.exchange(in, "product-spa", productRedirect)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	refresh := body["refresh_token"].(string)

	disabled := strings.Replace(testRegistry,
		"  - client_id: product-spa\n    type: public\n    audience: product-api\n    enabled: true\n",
		"  - client_id: product-spa\n    type: public\n    audience: product-api\n    enabled: false\n", 1)
	qt.Assert(t, qt.Not(qt.Equals(disabled, testRegistry)))
	t.Setenv("SERVICE_CLIENT_REGISTRY", disabled)
	restarted := authbytecore.TestApp(t)
	restarted.SetSessionStore(mem)
	restarted.SetReplay(replay.NewMemory())
	qt.Assert(t, qt.IsNil(Init(restarted)))
	ta := azugo.NewTestApp(restarted.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	e.app = ta
	status, body = e.refresh(refresh, "product-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%s", body["_raw"]))
	qt.Check(t, qt.IsNil(body["access_token"]))
}

// Two clients on one deployment, each with its own audience: each token carries
// its client's audience and names the client it was issued to [RFC 9068 §2.2],
// at the code exchange and at refresh, and the audit's line names the same.
func TestEachClientsTokenCarriesItsOwnAudience(t *testing.T) {
	events := &eventLog{}
	app, mem := signInApp(t, recordingAudit(events))

	for _, tc := range []struct{ client, redirect, audience string }{
		{"portal-spa", portalRedirect, "portal-api"},
		{"product-spa", productRedirect, "product-api"},
	} {
		e := newEdge(t, app)
		in := seedSignIn(t, mem, tc.client, tc.redirect)

		status, body := e.exchange(in, tc.client, tc.redirect)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", tc.client, body["_raw"]))
		c := tokenClaims(t, body["access_token"].(string))
		qt.Check(t, qt.DeepEquals(audienceOf(c), []any{tc.audience}), qt.Commentf("%s at the exchange", tc.client))
		qt.Check(t, qt.Equals(c["client_id"], any(tc.client)))

		status, body = e.refresh(body["refresh_token"].(string), tc.client)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", tc.client, body["_raw"]))
		c = tokenClaims(t, body["access_token"].(string))
		qt.Check(t, qt.DeepEquals(audienceOf(c), []any{tc.audience}), qt.Commentf("%s at refresh", tc.client))
		qt.Check(t, qt.Equals(c["client_id"], any(tc.client)))
	}

	events.mu.Lock()
	defer events.mu.Unlock()
	var audiences []any
	for _, ev := range events.events {
		if aud, ok := ev.Attributes["audience"]; ok {
			audiences = append(audiences, aud)
		}
	}
	qt.Check(t, qt.DeepEquals(audiences, []any{"portal-api", "portal-api", "product-api", "product-api"}))
}
