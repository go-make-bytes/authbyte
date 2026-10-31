package routes

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// methodsRegistry holds three clients of one deployment that allow different
// sign-in methods. The deployment offers eParaksts Mobile and eID Scan through
// its provider, and the card through its own door.
const methodsRegistry = `
sign_in_clients:
  - client_id: mobile-only
    type: public
    audience: mobile-api
    enabled: true
    redirect_uris: [https://mobile.example/cb]
    methods: [eparakstsMobile]
    step_up_methods: [eparakstsMobile]
  - client_id: card-only
    type: public
    audience: card-api
    enabled: true
    redirect_uris: [https://card.example/cb]
    methods: [webEid]
  - client_id: every-way
    type: public
    audience: every-api
    enabled: true
    redirect_uris: [https://every.example/cb]
    methods: [eparakstsMobile, eidScan, webEid]
    step_up_methods: [webEid]
`

const (
	mobileReturn = "https://mobile.example/cb"
	cardReturn   = "https://card.example/cb"
	everyReturn  = "https://every.example/cb"
)

func methodsApp(t *testing.T) (*azugo.TestApp, *sessiontest.Memory) {
	t.Helper()

	// The card door exists only with an engine named; nothing calls it here.
	t.Setenv("WEBEID_ENGINE_URL", "http://localhost:9998")

	return registryApp(t, methodsRegistry)
}

// authorizeAs sends a browser to /authorize for clientID, asking for the methods
// in acr ("" asks for none), and answers where it was sent.
func authorizeAs(t *testing.T, app *azugo.TestApp, clientID, redirectURI, acr string) *url.URL {
	t.Helper()

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", "spa-state")
	q.Set("code_challenge", "challenge-of-forty-three-characters-long-aaaa")
	q.Set("code_challenge_method", "S256")
	if acr != "" {
		q.Set("acr_values", acr)
	}

	resp, err := app.TestClient().Get("/authorize?" + q.Encode())
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound), qt.Commentf("%s", resp.Body()))
	loc, err := url.Parse(string(resp.Header.Peek("Location")))
	qt.Assert(t, qt.IsNil(err))

	return loc
}

// checkUnmet checks that a sign-in was answered at the client's own address with
// unmet_authentication_requirements and its state.
func checkUnmet(t *testing.T, loc *url.URL, host string) {
	t.Helper()

	qt.Check(t, qt.Equals(loc.Host, host))
	qt.Check(t, qt.Equals(loc.Query().Get("error"), "unmet_authentication_requirements"))
	qt.Check(t, qt.Equals(loc.Query().Get("state"), "spa-state"))
}

func flowCount(mem *sessiontest.Memory) int { return len(mem.Keys("flow:")) }

// Case 33: a method the deployment offers but the client is not allowed is
// refused like one nobody offers, at the client's address and before a flow is
// stored. The method it is allowed goes on to the provider.
func TestAuthorizeRefusesAMethodTheClientIsNotAllowed(t *testing.T) {
	app, mem := methodsApp(t)

	checkUnmet(t, authorizeAs(t, app, "mobile-only", mobileReturn, acrScan), "mobile.example")
	qt.Check(t, qt.Equals(flowCount(mem), 0))

	loc := authorizeAs(t, app, "mobile-only", mobileReturn, acrMobile)
	qt.Check(t, qt.Equals(loc.Query().Get("error"), ""))
	qt.Check(t, qt.Equals(loc.Host, "localhost:9999"))
	qt.Check(t, qt.Equals(flowCount(mem), 1))
}

// Case 34: a request that names no method may complete only with one its client
// allows that the provider offers. Those become the flow's requested methods, so
// the completion's one check (TestMethodRequested, case 8 of the C0 task) refuses
// any other method the provider answers with. The card has a door of its own.
func TestAnUnnamedMethodMeansTheClientsOwn(t *testing.T) {
	app, mem := methodsApp(t)

	for _, tc := range []struct {
		client, redirect string
		want             []string
	}{
		{"mobile-only", mobileReturn, []string{identity.LoginEParakstsMobile}},
		{"every-way", everyReturn, []string{identity.LoginEParakstsMobile, identity.LoginEIDScan}},
	} {
		loc := authorizeAs(t, app, tc.client, tc.redirect, "")
		qt.Assert(t, qt.Equals(loc.Host, "localhost:9999"), qt.Commentf("%s", tc.client))

		flow, err := mem.ConsumeFlow(context.Background(), loc.Query().Get("state"))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(flow.RequestedMethods, tc.want), qt.Commentf("%s", tc.client))
	}

	qt.Check(t, qt.IsFalse(methodRequested([]string{identity.LoginEParakstsMobile}, identity.LoginEIDScan)))
}

// Case 36: a client none of whose methods the provider offers can never sign in
// through it; /authorize says so at its address and stores nothing.
func TestAuthorizeRefusesAClientAllowedNothingTheProviderOffers(t *testing.T) {
	app, mem := methodsApp(t)

	checkUnmet(t, authorizeAs(t, app, "card-only", cardReturn, ""), "card.example")
	qt.Check(t, qt.Equals(flowCount(mem), 0))
}

// cardChallenge asks the card door to begin a sign-in for clientID and answers
// its status.
func cardChallenge(t *testing.T, app *azugo.TestApp, clientID, redirectURI string) int {
	t.Helper()

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", "challenge-of-forty-three-characters-long-aaaa")
	q.Set("code_challenge_method", "S256")

	resp, err := app.TestClient().Get("/webeid/challenge?" + q.Encode())
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	return resp.StatusCode()
}

// Case 35: the card door opens only for a client allowed the card; for another
// it is refused before a flow is stored.
func TestTheCardDoorOpensOnlyForAClientAllowedTheCard(t *testing.T) {
	app, mem := methodsApp(t)

	qt.Check(t, qt.Equals(cardChallenge(t, app, "mobile-only", mobileReturn), fasthttp.StatusForbidden))
	qt.Check(t, qt.Equals(flowCount(mem), 0))

	qt.Check(t, qt.Equals(cardChallenge(t, app, "card-only", cardReturn), fasthttp.StatusOK))
	qt.Check(t, qt.Equals(flowCount(mem), 1))
}

// stepUpAs exchanges a sign-in for clientID and asks to step its session up to
// method, answering the step-up's status.
func stepUpAs(t *testing.T, app *azugo.TestApp, mem *sessiontest.Memory, clientID, redirectURI string, methods ...string) []int {
	t.Helper()

	e := newEdge(t, app)
	in := seedSignIn(t, mem, clientID, redirectURI)
	status, body := e.exchange(in, clientID, redirectURI)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	refresh, _ := body["refresh_token"].(string)

	statuses := make([]int, 0, len(methods))
	for _, m := range methods {
		raw, err := json.Marshal(map[string]string{
			"refresh_token":  refresh,
			"client_id":      clientID,
			"method":         m,
			"code_challenge": "a-challenge",
			"redirect_uri":   redirectURI,
		})
		qt.Assert(t, qt.IsNil(err))

		tc := app.TestClient()
		resp, err := tc.Post("/step-up", raw, tc.WithHost(testHost), tc.WithHeader("Content-Type", "application/json"))
		qt.Assert(t, qt.IsNil(err))
		statuses = append(statuses, resp.StatusCode())
		fasthttp.ReleaseResponse(resp)
	}

	return statuses
}

// Case 37: a step-up goes only to a method on its client's step-up list. The card
// and eID Scan are offered here but are not on mobile-only's list; each is refused
// as a method outside the fixed list always was, 422, and so are the legacy plugin
// "eid" and a wrong-case spelling.
func TestAStepUpGoesOnlyToAMethodOnTheClientsList(t *testing.T) {
	app, mem := methodsApp(t)

	got := stepUpAs(t, app, mem, "mobile-only", mobileReturn, identity.LoginWebEID, identity.LoginEIDScan, identity.LoginEID, "EPARAKSTSMOBILE")
	refused := fasthttp.StatusUnprocessableEntity
	qt.Check(t, qt.DeepEquals(got, []int{refused, refused, refused, refused}))
	qt.Check(t, qt.Equals(flowCount(mem), 0))

	got = stepUpAs(t, app, mem, "mobile-only", mobileReturn, identity.LoginEParakstsMobile)
	qt.Check(t, qt.DeepEquals(got, []int{fasthttp.StatusOK}))
	qt.Check(t, qt.Equals(flowCount(mem), 1))
}

// Case 38: a client with no step-up list cannot step up at all.
func TestAClientWithNoStepUpListCannotStepUp(t *testing.T) {
	app, mem := methodsApp(t)

	got := stepUpAs(t, app, mem, "card-only", cardReturn, identity.LoginWebEID)
	qt.Check(t, qt.DeepEquals(got, []int{fasthttp.StatusUnprocessableEntity}))
	qt.Check(t, qt.Equals(flowCount(mem), 0))
}
