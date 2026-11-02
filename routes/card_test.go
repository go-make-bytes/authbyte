package routes

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session/sessiontest"
	"github.com/go-make-bytes/authbyte/store"
	"github.com/go-make-bytes/authbyte/webeid"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// standInCard is the web-eid engine in these tests: a token is good when it
// answers the challenge it is checked against and was signed for this service's
// own origin, as the engine's origin list will say once it names authbyte only.
type standInCard struct {
	calls int
}

func (c *standInCard) Validate(_ *azugo.Context, authToken json.RawMessage, nonce string) (*webeid.Subject, error) {
	c.calls++
	var tok struct{ Nonce, Origin string }
	if err := json.Unmarshal(authToken, &tok); err != nil {
		return nil, err
	}
	if tok.Nonce != nonce || tok.Origin != selfOriginInTests {
		return nil, errors.New("the engine refuses the token")
	}

	return &webeid.Subject{IDCode: "PNOLV-555555-55555", CountryCode: "LV", GivenName: "JĀNIS", Surname: "BĒRZIŅŠ"}, nil
}

// oneIdentity stands in for the identity store: every person is one known
// internal subject.
type oneIdentity struct{}

func (oneIdentity) EnsureMapping(context.Context, string, store.Profile) (string, bool, error) {
	return "internal-subject", false, nil
}

// cardToken is what the card signs on the page, as the stand-in reads it.
func cardToken(nonce, origin string) string {
	b, _ := json.Marshal(map[string]string{"nonce": nonce, "origin": origin})

	return string(b)
}

// cardApp is the methods deployment with the card read on the page.
func cardApp(t *testing.T) (*azugo.TestApp, *sessiontest.Memory, *standInCard) {
	t.Helper()

	t.Setenv("WEBEID_ENGINE_URL", "http://localhost:9998")
	card := &standInCard{}
	app, mem := registryApp(t, methodsRegistry, func(a *authbytecore.App) {
		a.SetWebEID(card)
		a.SetIdentities(oneIdentity{})
	})

	return app, mem, card
}

var (
	cardActionRe = regexp.MustCompile(`<form id="card"[^>]*? action="([^"]+)"`)
	cardNonceRe  = regexp.MustCompile(`<form id="card"[^>]*data-nonce="([^"]+)"`)
	cardStateRe  = regexp.MustCompile(`name="state" value="([^"]+)"`)
)

// cardPage is a page that offers the card: its card form's address, state and
// nonce, and its token.
type cardPage struct {
	shown
	cardAction, state, nonce string
}

func showCardPage(t *testing.T, tc *azugo.TestClient, q url.Values, opts ...azugo.TestClientOption) cardPage {
	t.Helper()

	p := cardPage{shown: showPage(t, tc, q, opts...)}
	if m := cardActionRe.FindStringSubmatch(p.body); m != nil {
		p.cardAction = html.UnescapeString(m[1])
	}
	if m := cardNonceRe.FindStringSubmatch(p.body); m != nil {
		p.nonce = html.UnescapeString(m[1])
	}
	if m := cardStateRe.FindStringSubmatch(p.body); m != nil {
		p.state = m[1]
	}

	return p
}

// postCard posts what the page's script posts once the card has signed.
func postCard(t *testing.T, tc *azugo.TestClient, p cardPage, state, token, csrf, origin string, extra ...azugo.TestClientOption) answer {
	t.Helper()

	opts := append([]azugo.TestClientOption{asBrowser(tc)}, extra...)
	if origin != "" {
		opts = append(opts, tc.WithHeader("Origin", origin))
	}
	form := map[string]any{"state": state, "token": token}
	if csrf != "" {
		form["csrf"] = csrf
	}

	return got(t)(tc.PostForm(p.cardAction, form, opts...))
}

// Cases 1, 4, 14, 15, 17: the page offers the card in the row's order where the
// deployment reads cards, with its hint; the challenge is made as the page is
// shown, tied to the browser, and the page loads its script from this host only.
func TestThePageOffersTheCard(t *testing.T) {
	app, mem, _ := cardApp(t)
	tc := app.TestClient()

	p := showCardPage(t, tc, pageQuery("every-way", everyReturn))
	qt.Assert(t, qt.Equals(p.status, fasthttp.StatusOK), qt.Commentf("%s", p.body))
	qt.Check(t, qt.DeepEquals(ways(p.body), []string{identity.LoginEParakstsMobile, identity.LoginEIDScan, identity.LoginWebEID}))
	qt.Check(t, qt.StringContains(p.body, ">eID</button>"))
	qt.Check(t, qt.StringContains(p.body, "eID is your ID card, read by the card software on this computer; it asks for your PIN."))
	qt.Check(t, qt.StringContains(p.body, `<script type="module" src="/signin/card.js"></script>`))
	qt.Check(t, qt.StringContains(p.body, `data-waiting="Waiting for the card…"`))
	qt.Check(t, qt.Not(qt.Equals(p.nonce, "")))
	qt.Check(t, qt.StringContains(p.cardAction, "/authorize/card?"))

	flow, err := mem.ConsumeFlow(context.Background(), p.state)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(flow.WebEIDNonce, p.nonce))
	qt.Check(t, qt.Equals(flow.Binding, bindingHash(tc.Cookies()[signInCookie])))
	qt.Check(t, qt.DeepEquals(flow.RequestedMethods, []string{identity.LoginWebEID}))
	qt.Check(t, qt.IsTrue(flow.Picker))

	csp := p.header["Content-Security-Policy"]
	qt.Check(t, qt.StringContains(csp, "script-src 'self'"))
	for _, never := range []string{"unsafe-inline", "unsafe-eval", "connect-src"} {
		qt.Check(t, qt.Not(qt.StringContains(csp, never)))
	}
	// The card's answer is a form post answered with a redirect to the client, and
	// browsers that apply form-action to a post's redirects (Chromium, WebKit)
	// refuse a target the policy does not name [CSP3 §6.4.1].
	qt.Check(t, qt.StringContains(csp, "form-action 'self' http://localhost:9999 https://every.example;"))

	only := showCardPage(t, app.TestClient(), pageQuery("card-only", cardReturn))
	qt.Check(t, qt.DeepEquals(ways(only.body), []string{identity.LoginWebEID}))
	qt.Check(t, qt.Not(qt.StringContains(only.body, "No way to sign in is set up here.")))
	qt.Check(t, qt.StringContains(only.header["Content-Security-Policy"], "form-action 'self' http://localhost:9999 https://card.example;"))
}

// Case 2: where the deployment reads no card, the card is never offered.
func TestNoCardWhereTheDeploymentReadsNone(t *testing.T) {
	app, mem := registryApp(t, methodsRegistry)

	p := showCardPage(t, app.TestClient(), pageQuery("every-way", everyReturn))
	qt.Check(t, qt.DeepEquals(ways(p.body), []string{identity.LoginEParakstsMobile, identity.LoginEIDScan}))
	qt.Check(t, qt.Not(qt.StringContains(p.body, `id="card"`)))
	qt.Check(t, qt.Not(qt.StringContains(p.body, "card.js")))
	qt.Check(t, qt.Equals(flowCount(mem), 0))
}

// Cases 5-7: a request naming the card is shown the page with the ways it names,
// the card among them; one naming provider ways only goes straight on.
func TestARequestNamingTheCardIsShownIt(t *testing.T) {
	app, _, _ := cardApp(t)

	for _, c := range []struct {
		acr  string
		want []string
	}{
		{identity.LoginWebEID, []string{identity.LoginWebEID}},
		{identity.LoginWebEID + " " + identity.LoginEParakstsMobile, []string{identity.LoginWebEID, identity.LoginEParakstsMobile}},
	} {
		q := pageQuery("every-way", everyReturn)
		q.Set("acr_values", c.acr)
		p := showCardPage(t, app.TestClient(), q)
		qt.Check(t, qt.Equals(p.status, fasthttp.StatusOK), qt.Commentf("%s: %s", c.acr, p.location))
		qt.Check(t, qt.DeepEquals(ways(p.body), c.want), qt.Commentf("%s", c.acr))
	}

	q := pageQuery("every-way", everyReturn)
	q.Set("acr_values", identity.LoginEParakstsMobile)
	direct := showPage(t, app.TestClient(), q)
	qt.Check(t, qt.Equals(direct.status, fasthttp.StatusFound))
	qt.Check(t, qt.StringContains(direct.location, "http://localhost:9999/"))
}

// Cases 10, 19: the card's answer from the browser the page was shown in signs
// the person in and sends the browser back to the application with a code.
func TestTheCardSignsInOnThePage(t *testing.T) {
	app, mem, card := cardApp(t)
	tc := app.TestClient()

	p := showCardPage(t, tc, pageQuery("every-way", everyReturn))
	a := postCard(t, tc, p, p.state, cardToken(p.nonce, selfOriginInTests), p.token, selfOriginInTests)
	qt.Assert(t, qt.Equals(a.status, fasthttp.StatusSeeOther), qt.Commentf("%s", a.body))
	loc, err := url.Parse(a.location)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(loc.Scheme+"://"+loc.Host+loc.Path, everyReturn))
	qt.Check(t, qt.Equals(loc.Query().Get("state"), "spa-state"))
	qt.Check(t, qt.Not(qt.Equals(loc.Query().Get("code"), "")))
	qt.Check(t, qt.Not(qt.Equals(loc.Query().Get("iss"), "")))
	qt.Check(t, qt.Equals(card.calls, 1))

	code, err := mem.ConsumeAppCode(context.Background(), loc.Query().Get("code"))
	qt.Assert(t, qt.IsNil(err))
	sess, err := mem.LoadSession(context.Background(), code.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.LoginMethod, identity.LoginWebEID))
	qt.Check(t, qt.Not(qt.Equals(sess.AuthTime, int64(0))))
}

// Cases 20-22: a card answer the page did not send is refused before the engine
// sees it, and nothing is signed in.
func TestAForgedCardAnswerIsRefused(t *testing.T) {
	app, _, card := cardApp(t)

	for _, c := range []struct {
		name   string
		send   func(tc *azugo.TestClient, p cardPage) answer
		status int
	}{
		{"20: another browser", func(_ *azugo.TestClient, p cardPage) answer {
			other := app.TestClient()
			showPage(t, other, pageQuery("every-way", everyReturn))

			return postCard(t, other, p, p.state, cardToken(p.nonce, selfOriginInTests), cardPageToken(t, other), selfOriginInTests)
		}, fasthttp.StatusUnauthorized},
		{"21: a wrong token", func(tc *azugo.TestClient, p cardPage) answer {
			return postCard(t, tc, p, p.state, cardToken(p.nonce, selfOriginInTests), "AAAA"+p.token[4:], selfOriginInTests)
		}, fasthttp.StatusForbidden},
		{"21: no token", func(tc *azugo.TestClient, p cardPage) answer {
			return postCard(t, tc, p, p.state, cardToken(p.nonce, selfOriginInTests), "", selfOriginInTests)
		}, fasthttp.StatusForbidden},
		{"22: another origin", func(tc *azugo.TestClient, p cardPage) answer {
			return postCard(t, tc, p, p.state, cardToken(p.nonce, selfOriginInTests), p.token, "https://evil.example")
		}, fasthttp.StatusForbidden},
		{"22: a null origin", func(tc *azugo.TestClient, p cardPage) answer {
			return postCard(t, tc, p, p.state, cardToken(p.nonce, selfOriginInTests), p.token, "null")
		}, fasthttp.StatusForbidden},
		{"22: no origin", func(tc *azugo.TestClient, p cardPage) answer {
			return postCard(t, tc, p, p.state, cardToken(p.nonce, selfOriginInTests), p.token, "")
		}, fasthttp.StatusForbidden},
	} {
		tc := app.TestClient()
		p := showCardPage(t, tc, pageQuery("every-way", everyReturn))
		a := c.send(tc, p)
		qt.Check(t, qt.Equals(a.status, c.status), qt.Commentf("%s: %s", c.name, a.body))
		qt.Check(t, qt.IsTrue(isCannotStart(a)), qt.Commentf("%s", c.name))
	}
	qt.Check(t, qt.Equals(card.calls, 0))
}

// cardPageToken is the page token the browser behind tc holds.
func cardPageToken(t *testing.T, tc *azugo.TestClient) string {
	t.Helper()

	return choiceToken(tc.Cookies()[signInCookie])
}

// Cases 23, 24: an unknown or used challenge shows the page again, saying the
// sign-in took too long, with a fresh challenge; a second post of one answer
// signs in no one twice.
func TestAnUsedOrUnknownChallengeShowsThePageAgain(t *testing.T) {
	app, mem, card := cardApp(t)
	tc := app.TestClient()

	p := showCardPage(t, tc, pageQuery("every-way", everyReturn))
	first := postCard(t, tc, p, p.state, cardToken(p.nonce, selfOriginInTests), p.token, selfOriginInTests)
	qt.Assert(t, qt.Equals(first.status, fasthttp.StatusSeeOther))

	again := postCard(t, tc, p, p.state, cardToken(p.nonce, selfOriginInTests), p.token, selfOriginInTests)
	qt.Check(t, qt.Equals(again.status, fasthttp.StatusOK))
	qt.Check(t, qt.StringContains(again.body, "That sign-in took too long and has expired."))
	qt.Check(t, qt.Equals(card.calls, 1))

	unknown := postCard(t, tc, p, "no-such-state", cardToken(p.nonce, selfOriginInTests), p.token, selfOriginInTests)
	qt.Check(t, qt.StringContains(unknown.body, "That sign-in took too long and has expired."))
	fresh := cardStateRe.FindStringSubmatch(unknown.body)
	qt.Assert(t, qt.HasLen(fresh, 2))
	qt.Check(t, qt.Not(qt.Equals(fresh[1], p.state)))
	_, err := mem.ConsumeFlow(context.Background(), fresh[1])
	qt.Check(t, qt.IsNil(err))
}

// Cases 25, 26: a token the engine refuses (signed for another origin) signs no
// one in; the page says the card did not complete.
func TestATokenTheEngineRefusesSignsNoOneIn(t *testing.T) {
	app, _, card := cardApp(t)
	tc := app.TestClient()

	p := showCardPage(t, tc, pageQuery("every-way", everyReturn))
	a := postCard(t, tc, p, p.state, cardToken(p.nonce, "https://localhost:5011"), p.token, selfOriginInTests)
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized))
	qt.Check(t, qt.Equals(a.location, ""))
	qt.Check(t, qt.StringContains(a.body, "That did not complete. Check the card is in the reader and try again."))
	qt.Check(t, qt.StringContains(a.body, `role="alert"`))
	qt.Check(t, qt.Equals(card.calls, 1))
}

// Case 13: with script off the card's button posts the page's choice, and the
// page says why the card cannot be read.
func TestTheCardWithoutScriptSaysWhy(t *testing.T) {
	app, mem, _ := cardApp(t)
	tc := app.TestClient()

	p := showCardPage(t, tc, pageQuery("every-way", everyReturn))
	before := flowCount(mem)
	a := choose(t, tc, p.shown, identity.LoginWebEID, p.token, selfOriginInTests)
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK), qt.Commentf("%s", a.location))
	qt.Check(t, qt.StringContains(a.body, "Signing in with a card needs JavaScript turned on in this browser."))
	qt.Check(t, qt.Equals(a.location, ""))
	qt.Check(t, qt.Equals(flowCount(mem), before+1))
}

// The page's own files: the card's script and the Web eID library, the
// library byte for byte the copy the applications ship (cases 15, 16).
func TestThePageServesTheCardsScripts(t *testing.T) {
	app, _, _ := cardApp(t)
	tc := app.TestClient()

	for _, name := range []string{"card.js", "web-eid.js"} {
		a := got(t)(tc.Get("/signin/" + name))
		qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(a.header["Content-Type"], "text/javascript; charset=utf-8"), qt.Commentf("%s", name))
		qt.Check(t, qt.Not(qt.StringContains(a.body, "http://")), qt.Commentf("%s", name))
	}
	lib := got(t)(tc.Get("/signin/web-eid.js"))
	qt.Check(t, qt.StringContains(lib.body, "Copyright (c) 2020-2025 Estonian Information System Authority"))
	qt.Check(t, qt.IsTrue(strings.Contains(lib.body, "VERSION: \"2.1.0\"") || strings.Contains(lib.body, "VERSION:\"2.1.0\"")))
}
