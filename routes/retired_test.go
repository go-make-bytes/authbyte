package routes

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-make-bytes/authbyte/session"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The step-up's two doors are gone: neither answers, and nothing is parked for a
// later completion. Served with the card read on, so the card's door would exist
// if anything still registered it.
func TestTheStepUpDoorsAreGone(t *testing.T) {
	app, mem, card := cardApp(t)
	tc := app.TestClient()

	for path, body := range map[string]any{
		"/step-up": map[string]any{
			"refresh_token": "a-refresh-token", "client_id": "every-way", "method": "webEid",
			"code_challenge": "c", "redirect_uri": everyReturn,
		},
		"/webeid/login": map[string]any{"state": "a-state", "authToken": json.RawMessage(cardToken("n", selfOriginInTests))},
	} {
		before := flowCount(mem)
		resp, err := tc.PostJSON(path, body, tc.WithHost(testHost))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound), qt.Commentf("%s", path))
		fasthttp.ReleaseResponse(resp)
		qt.Check(t, qt.Equals(flowCount(mem), before), qt.Commentf("%s parked a flow", path))
	}
	qt.Check(t, qt.Equals(card.calls, 0))
}

// A step-up flow saved before the upgrade is read back without the fields that
// made it one, and with no browser binding, since a client's server started it.
// Presented where a sign-in completes, it completes nothing: the card's answer
// shows the page again, and the provider's return is refused.
func TestAStepUpSavedBeforeTheUpgradeCompletesNothing(t *testing.T) {
	app, mem, card := cardApp(t)
	tc := app.TestClient()

	// The card's: the page is shown, so this browser holds a binding and the
	// page's token; the flow it presents is the old step-up's.
	p := showCardPage(t, tc, pageQuery("every-way", everyReturn))
	qt.Assert(t, qt.IsNil(mem.SaveFlow(context.Background(), "an-old-card-step-up", &session.Flow{
		ClientID: "every-way", AppRedirectURI: everyReturn, SPAState: "s",
		CodeChallenge: "c", CodeChallengeMethod: "S256", WebEIDNonce: "n",
	}, flowTTL)))
	a := postCard(t, tc, p, "an-old-card-step-up", cardToken("n", selfOriginInTests), p.token, selfOriginInTests)
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK), qt.Commentf("%s", a.location))
	qt.Check(t, qt.StringContains(a.body, "That sign-in took too long and has expired."))
	qt.Check(t, qt.Equals(a.location, ""))
	qt.Check(t, qt.Equals(card.calls, 0))

	// The provider's: a return to the old step-up's state, in a browser with a
	// binding of its own, is the cannot-start page, and the flow is spent.
	qt.Assert(t, qt.IsNil(mem.SaveFlow(context.Background(), "an-old-step-up", &session.Flow{
		ClientID: "every-way", AppRedirectURI: everyReturn, SPAState: "s",
		CodeChallenge: "c", CodeChallengeMethod: "S256",
		EntrustRedirectURI: "http://localhost:8080/callback", Nonce: "provider-nonce",
	}, flowTTL)))
	a = got(t)(tc.Get("/callback?code=the-providers-code&state=an-old-step-up", asBrowser(tc)))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized), qt.Commentf("%s", a.location))
	qt.Check(t, qt.IsTrue(isCannotStart(a)))
	_, err := mem.ConsumeFlow(context.Background(), "an-old-step-up")
	qt.Check(t, qt.IsNotNil(err), qt.Commentf("the flow is spent"))

	qt.Check(t, qt.HasLen(mem.Keys("code:"), 0), qt.Commentf("an application code was minted"))
	qt.Check(t, qt.HasLen(mem.Keys("sess:"), 0), qt.Commentf("a session was created"))
}
