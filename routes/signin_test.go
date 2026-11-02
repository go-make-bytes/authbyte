package routes

import (
	"context"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// selfOriginInTests is BASE_URL's origin in the test app.
const selfOriginInTests = "http://localhost:8080"

// answer is what one request was answered, read before the response is released.
type answer struct {
	status   int
	body     string
	location string
	header   map[string]string
	cookies  []string
}

// got reads what one request was answered: got(t)(client.Get(...)).
func got(t *testing.T) func(*fasthttp.Response, error) answer {
	return func(resp *fasthttp.Response, err error) answer {
		t.Helper()

		return readAnswer(t, resp, err)
	}
}

func readAnswer(t *testing.T, resp *fasthttp.Response, err error) answer {
	t.Helper()
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	a := answer{
		status:   resp.StatusCode(),
		body:     string(resp.Body()),
		location: string(resp.Header.Peek("Location")),
		header:   map[string]string{},
	}
	for k, v := range resp.Header.All() {
		if strings.EqualFold(string(k), "Set-Cookie") {
			a.cookies = append(a.cookies, string(v))

			continue
		}
		a.header[string(k)] = string(v)
	}

	return a
}

// pageQuery is a valid authorization request for clientID that names no way.
func pageQuery(clientID, redirectURI string) url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", "spa-state")
	q.Set("code_challenge", "challenge-of-forty-three-characters-long-aaaa")
	q.Set("code_challenge_method", "S256")

	return q
}

// html asks for a page, as a browser does.
func asBrowser(tc *azugo.TestClient) azugo.TestClientOption {
	return tc.WithHeader("Accept", "text/html,application/xhtml+xml")
}

var (
	tokenRe  = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	actionRe = regexp.MustCompile(`action="([^"]+)"`)
	wayRe    = regexp.MustCompile(`name="way" value="([^"]+)"`)
	hrefRe   = regexp.MustCompile(`href="[^"]*"`)
)

// shown is a sign-in page as the browser holds it: its form's address and token.
type shown struct {
	answer
	action, token string
}

func showPage(t *testing.T, tc *azugo.TestClient, q url.Values, opts ...azugo.TestClientOption) shown {
	t.Helper()

	a := got(t)(tc.Get("/authorize?"+q.Encode(), append([]azugo.TestClientOption{asBrowser(tc)}, opts...)...))
	s := shown{answer: a}
	if m := actionRe.FindStringSubmatch(a.body); m != nil {
		s.action = html.UnescapeString(m[1])
	}
	if m := tokenRe.FindStringSubmatch(a.body); m != nil {
		s.token = m[1]
	}

	return s
}

func ways(body string) []string {
	var out []string
	for _, m := range wayRe.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}

	return out
}

// choose posts the person's pick from the page, as the page's own form does.
func choose(t *testing.T, tc *azugo.TestClient, s shown, way, token, origin string, extra ...azugo.TestClientOption) answer {
	t.Helper()

	opts := append([]azugo.TestClientOption{asBrowser(tc)}, extra...)
	if origin != "" {
		opts = append(opts, tc.WithHeader("Origin", origin))
	}
	form := map[string]any{"way": way}
	if token != "" {
		form["csrf"] = token
	}

	return got(t)(tc.PostForm(s.action, form, opts...))
}

// providerState is the state authbyte sent the provider.
func providerState(t *testing.T, a answer) string {
	t.Helper()

	loc, err := url.Parse(a.location)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(loc.Host, "localhost:9999"), qt.Commentf("sent to %q", a.location))

	return loc.Query().Get("state")
}

func isCannotStart(a answer) bool {
	return strings.Contains(a.body, "This sign-in cannot start") && a.location == ""
}

// Cases 1, 2, 4, 39, 51, 53: the page lists the ways the client's row allows that
// the provider can start, in the row's order; the card waits for its own phase;
// nothing is stored and nothing sent on; every answer carries the page's headers.
func TestThePageListsTheWaysTheClientMayUse(t *testing.T) {
	app, mem := pageApp(t)

	every := showPage(t, app.TestClient(), pageQuery("every-way", everyReturn))
	qt.Assert(t, qt.Equals(every.status, fasthttp.StatusOK), qt.Commentf("%s", every.body))
	qt.Check(t, qt.DeepEquals(ways(every.body), []string{identity.LoginEParakstsMobile, identity.LoginEIDScan}))
	qt.Check(t, qt.StringContains(every.body, `class="btn pri" type="submit" name="way" value="eparakstsMobile">eParaksts Mobile</button>`))
	qt.Check(t, qt.StringContains(every.body, `>eID Scan</button>`))
	qt.Check(t, qt.Not(qt.StringContains(every.body, `value="webEid"`)))
	// No registered name: the title names the client's id.
	qt.Check(t, qt.StringContains(every.body, "<title>Sign in to every-way</title>"))
	qt.Check(t, qt.StringContains(every.body, `<html lang="en">`))
	qt.Check(t, qt.Equals(strings.Count(every.body, "<h1>"), 1))

	mobile := showPage(t, app.TestClient(), pageQuery("mobile-only", mobileReturn))
	qt.Check(t, qt.DeepEquals(ways(mobile.body), []string{identity.LoginEParakstsMobile}))
	qt.Check(t, qt.Not(qt.StringContains(mobile.body, `value="eidScan"`)))

	card := showPage(t, app.TestClient(), pageQuery("card-only", cardReturn))
	qt.Check(t, qt.Equals(card.status, fasthttp.StatusOK))
	qt.Check(t, qt.Equals(card.location, ""))
	qt.Check(t, qt.StringContains(card.body, "No way to sign in is set up here."))
	qt.Check(t, qt.StringContains(card.body, `role="alert"`))
	qt.Check(t, qt.Not(qt.StringContains(card.body, "<form")))

	qt.Check(t, qt.Equals(flowCount(mem), 0))

	for _, a := range []answer{every.answer, card.answer} {
		csp := a.header["Content-Security-Policy"]
		for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self' http://localhost:9999"} {
			qt.Check(t, qt.StringContains(csp, want))
		}
		qt.Check(t, qt.StringContains(csp, "script-src 'self';"))
		qt.Check(t, qt.Equals(a.header["X-Frame-Options"], "DENY"))
		// A window that opened the page cannot post into it (measured 2026-11-02).
		qt.Check(t, qt.Equals(a.header["Cross-Origin-Opener-Policy"], "same-origin"))
		qt.Check(t, qt.Equals(a.header["Cache-Control"], "no-store"))
		// Not no-referrer: under it browsers send Origin: null on the page's own
		// form post, and the choice is refused (measured in Chrome and Firefox).
		qt.Check(t, qt.Equals(a.header["Referrer-Policy"], "same-origin"))
		qt.Check(t, qt.Equals(a.header["X-Content-Type-Options"], "nosniff"))
	}
}

// Case 3: the generic provider's way is named as the deployment names it, else
// as the person's organisation's sign-in; one way still shows the page.
func TestTheGenericProvidersWayIsNamedByTheDeployment(t *testing.T) {
	const registry = `
sign_in_clients:
  - client_id: directory-app
    type: public
    audience: directory-api
    enabled: true
    redirect_uris: [https://directory.example/cb]
    methods: [upstream, webEid]
`
	for _, tc := range []struct{ name, want string }{
		{"Microsoft Entra", ">Microsoft Entra</button>"},
		{"", ">Your organisation’s sign-in</button>"},
	} {
		t.Setenv("OIDC_UPSTREAM_AUTHORIZE_URL", "https://idp.example/authorize")
		t.Setenv("OIDC_UPSTREAM_TOKEN_URL", "https://idp.example/token")
		t.Setenv("OIDC_UPSTREAM_USERINFO_URL", "https://idp.example/userinfo")
		t.Setenv("OIDC_UPSTREAM_CLIENT_ID", "cid")
		t.Setenv("OIDC_UPSTREAM_DISPLAY_NAME", tc.name)
		app, _ := registryApp(t, registry)

		p := showPage(t, app.TestClient(), pageQuery("directory-app", "https://directory.example/cb"))
		qt.Check(t, qt.Equals(p.status, fasthttp.StatusOK))
		qt.Check(t, qt.DeepEquals(ways(p.body), []string{"upstream"}))
		qt.Check(t, qt.StringContains(p.body, tc.want))
		qt.Check(t, qt.StringContains(p.header["Content-Security-Policy"], "form-action 'self' https://idp.example;"))
	}
}

// Cases 5, 8: a request naming its way skips the page; prompt=none never shows one.
func TestThePageIsShownOnlyForARequestThatNamesNoWay(t *testing.T) {
	app, _ := pageApp(t)

	q := pageQuery("every-way", everyReturn)
	q.Set("acr_values", identity.LoginEIDScan)
	direct := got(t)(app.TestClient().Get("/authorize?" + q.Encode()))
	qt.Check(t, qt.Equals(direct.status, fasthttp.StatusFound))
	qt.Check(t, qt.StringContains(direct.location, "http://localhost:9999/"))

	q = pageQuery("every-way", everyReturn)
	q.Set("prompt", "none")
	none := got(t)(app.TestClient().Get("/authorize?" + q.Encode()))
	loc, err := url.Parse(none.location)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(loc.Host, "every.example"))
	qt.Check(t, qt.Equals(loc.Query().Get("error"), "login_required"))
}

// formOf is a request's query as a form body.
func formOf(q url.Values) map[string]any {
	form := map[string]any{}
	for k, v := range q {
		form[k] = v[0]
	}

	return form
}

// Case 11: the same request as a form POST to /authorize is answered alike, from
// a browser that sends its binding with it.
func TestAuthorizeTakesAFormPost(t *testing.T) {
	app, _ := pageApp(t)

	form := formOf(pageQuery("every-way", everyReturn))
	tc := app.TestClient()
	showPage(t, tc, pageQuery("every-way", everyReturn))
	page := got(t)(tc.PostForm("/authorize", form, asBrowser(tc)))
	qt.Check(t, qt.Equals(page.status, fasthttp.StatusOK))
	qt.Check(t, qt.DeepEquals(ways(page.body), []string{identity.LoginEParakstsMobile, identity.LoginEIDScan}))

	form["acr_values"] = identity.LoginEIDScan
	direct := got(t)(tc.PostForm("/authorize", form))
	qt.Check(t, qt.Equals(direct.status, fasthttp.StatusSeeOther))
	qt.Check(t, qt.StringContains(direct.location, "http://localhost:9999/"))
}

// Case 11: a form POST from another site arrives without the browser's Lax
// binding, though the browser holds one and keeps whatever the answer sets. A new
// binding would replace it and fail its sign-ins under way in other tabs, so the
// post sets none; it sends the browser to the same request as a GET, which
// carries the binding, and that keeps it.
func TestAPostWithoutTheBindingSetsNone(t *testing.T) {
	app, mem := pageApp(t)
	tc := app.TestClient()

	q := pageQuery("every-way", everyReturn)
	p := showPage(t, tc, q)
	value := tc.Cookies()[signInCookie]
	qt.Assert(t, qt.Not(qt.Equals(value, "")))
	// The same browser, posting from another site: its jar keeps the binding, the
	// post goes without it.
	crossSite := tc.WithCookie(signInCookie, "")

	post := got(t)(tc.PostForm("/authorize", formOf(q), asBrowser(tc), crossSite))
	qt.Check(t, qt.Equals(post.status, fasthttp.StatusSeeOther), qt.Commentf("%s", post.body))
	qt.Check(t, qt.Equals(post.location, "/authorize?"+q.Encode()))
	qt.Check(t, qt.HasLen(post.cookies, 0), qt.Commentf("%v", post.cookies))
	qt.Check(t, qt.Equals(tc.Cookies()[signInCookie], value))
	followed := got(t)(tc.Get(post.location, asBrowser(tc)))
	qt.Check(t, qt.StringContains(followed.body, `name="csrf" value="`+p.token+`"`))

	named := pageQuery("every-way", everyReturn)
	named.Set("acr_values", identity.LoginEIDScan)
	post = got(t)(tc.PostForm("/authorize", formOf(named), asBrowser(tc), crossSite))
	qt.Check(t, qt.Equals(post.status, fasthttp.StatusSeeOther))
	qt.Check(t, qt.Equals(post.location, "/authorize?"+named.Encode()))
	qt.Check(t, qt.Equals(tc.Cookies()[signInCookie], value))
	flow, err := mem.ConsumeFlow(context.Background(), providerState(t, got(t)(tc.Get(post.location, asBrowser(tc)))))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(flow.Binding, bindingHash(value)))

	// A request that fails its checks is answered at once, as a GET is.
	bad := pageQuery("every-way", everyReturn)
	bad.Set("code_challenge_method", "plain")
	refused := got(t)(tc.PostForm("/authorize", formOf(bad), asBrowser(tc), crossSite))
	qt.Check(t, qt.StringContains(refused.location, "error=invalid_request"))
	qt.Check(t, qt.HasLen(refused.cookies, 0))
	qt.Check(t, qt.Equals(tc.Cookies()[signInCookie], value))
}

// Case 16: browsers leave a scheme's default port out of Origin, so this
// service's own origin does too, whatever BASE_URL spells.
func TestTheOwnOriginLeavesTheDefaultPortOut(t *testing.T) {
	for base, want := range map[string]string{
		"https://auth.example:443":      "https://auth.example",
		"http://auth.example:80":        "http://auth.example",
		"https://auth.example":          "https://auth.example",
		"https://auth.example:8443/":    "https://auth.example:8443",
		"http://auth.example:443":       "http://auth.example:443",
		"HTTPS://Auth.Example:443/base": "https://auth.example",
		"https://[::1]:443":             "https://[::1]",
	} {
		qt.Check(t, qt.Equals(originOf(base), want), qt.Commentf("BASE_URL %s", base))
	}
}

// Case 47: the language link's next is rebuilt from its parsed query, so the
// answer's Location carries no byte of the request as it came.
func TestTheLanguageLinkRebuildsItsAddress(t *testing.T) {
	app, _ := pageApp(t)
	tc := app.TestClient()

	sent := "/authorize?client_id=a\tb&x=<y>&z=%41&a=1\r\nSet-Cookie:%20planted=1"
	a := got(t)(tc.Get("/signin/language?" + url.Values{"lang": {"lv"}, "next": {sent}}.Encode()))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusSeeOther))
	qt.Check(t, qt.Equals(a.location, "/authorize?"+url.Values{
		"client_id": {"a\tb"}, "x": {"<y>"}, "z": {"A"}, "a": {"1\r\nSet-Cookie: planted=1"},
	}.Encode()))
	for _, c := range a.cookies {
		qt.Check(t, qt.Not(qt.StringContains(c, "planted")), qt.Commentf("%s", c))
	}

	unparsed := got(t)(tc.Get("/signin/language?" + url.Values{"next": {"/authorize?%zz"}}.Encode()))
	qt.Check(t, qt.Equals(unparsed.location, "/authorize"))
}

// Cases 9, 12, 48: the person's pick sends the browser to the provider with that
// way's own code; the flow keeps the browser's binding and the client's request,
// and everything a direct request carries.
func TestTheChoiceStartsThatWayAtTheProvider(t *testing.T) {
	app, mem := pageApp(t)
	tc := app.TestClient()

	q := pageQuery("every-way", everyReturn)
	q.Set("prompt", "login")
	q.Set("nonce", "the client's nonce")
	q.Set("tenant", "org-1")
	p := showPage(t, tc, q, tc.WithHeader("Accept-Language", "lv"))
	qt.Assert(t, qt.Not(qt.Equals(p.token, "")))

	a := choose(t, tc, p, identity.LoginEIDScan, p.token, selfOriginInTests, tc.WithHeader("Accept-Language", "lv"))
	qt.Assert(t, qt.Equals(a.status, fasthttp.StatusSeeOther), qt.Commentf("%s", a.body))
	loc, err := url.Parse(a.location)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(loc.Host, "localhost:9999"))
	qt.Check(t, qt.Equals(loc.Query().Get("acr_values"), "urn:eparaksts:authentication:flow:mobile-eid"))
	qt.Check(t, qt.Equals(loc.Query().Get("prompt"), "login"))
	qt.Check(t, qt.Equals(loc.Query().Get("ui_locales"), "lv"))

	flow, err := mem.ConsumeFlow(context.Background(), loc.Query().Get("state"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(flow.RequestedMethods, []string{identity.LoginEIDScan}))
	qt.Check(t, qt.IsTrue(flow.Picker))
	qt.Check(t, qt.Not(qt.Equals(flow.Binding, "")))
	qt.Check(t, qt.StringContains(flow.Request, "client_id=every-way"))
	qt.Check(t, qt.Equals(flow.SPAState, "spa-state"))
	qt.Check(t, qt.Equals(flow.ClientNonce, "the client's nonce"))
	qt.Check(t, qt.Equals(flow.Tenant, "org-1"))
	qt.Check(t, qt.IsTrue(flow.ForcedLogin))
}

// Cases 13-17: a choice the page did not make is refused, and nothing is stored.
func TestAForgedChoiceIsRefused(t *testing.T) {
	app, mem := pageApp(t)
	tc := app.TestClient()
	p := showPage(t, tc, pageQuery("every-way", everyReturn))

	for _, c := range []struct {
		name, way, token, origin string
	}{
		{"13: the card, not on the page", identity.LoginWebEID, p.token, selfOriginInTests},
		{"13: the generic provider, not offered here", "upstream", p.token, selfOriginInTests},
		{"13: no way at all", "fingerprint", p.token, selfOriginInTests},
		{"15: a wrong token", identity.LoginEIDScan, "AAAA" + p.token[4:], selfOriginInTests},
		{"15: no token", identity.LoginEIDScan, "", selfOriginInTests},
		{"16: another site", identity.LoginEIDScan, p.token, "https://evil.example"},
		{"16: null", identity.LoginEIDScan, p.token, "null"},
		{"16: no Origin", identity.LoginEIDScan, p.token, ""},
	} {
		a := choose(t, tc, p, c.way, c.token, c.origin)
		qt.Check(t, qt.Equals(a.status, fasthttp.StatusForbidden), qt.Commentf("%s", c.name))
		qt.Check(t, qt.IsTrue(isCannotStart(a)), qt.Commentf("%s", c.name))
	}

	// 17: the request on the form's address is checked again.
	forged := p
	forged.action = strings.Replace(p.action, url.QueryEscape(everyReturn), url.QueryEscape("https://evil.example/cb"), 1)
	qt.Assert(t, qt.Not(qt.Equals(forged.action, p.action)))
	a := choose(t, tc, forged, identity.LoginEIDScan, p.token, selfOriginInTests)
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusBadRequest))
	qt.Check(t, qt.IsTrue(isCannotStart(a)))

	// 14: another browser, or the binding run out: the page again, to start afresh.
	other := app.TestClient()
	expired := choose(t, other, p, identity.LoginEIDScan, p.token, selfOriginInTests)
	qt.Check(t, qt.Equals(expired.status, fasthttp.StatusOK))
	qt.Check(t, qt.StringContains(expired.body, "That sign-in took too long and has expired."))
	qt.Check(t, qt.Not(qt.Equals(len(expired.cookies), 0)))

	qt.Check(t, qt.Equals(flowCount(mem), 0))
}

// Cases 18-20: a double click starts two flows and a second tab its own; one
// browser's binding serves every sign-in it starts.
func TestOneBrowserMayStartSeveralSignIns(t *testing.T) {
	app, mem := pageApp(t)
	tc := app.TestClient()

	first := showPage(t, tc, pageQuery("every-way", everyReturn))
	second := showPage(t, tc, pageQuery("mobile-only", mobileReturn))
	qt.Check(t, qt.Equals(first.token, second.token))

	a := choose(t, tc, first, identity.LoginEIDScan, first.token, selfOriginInTests)
	b := choose(t, tc, first, identity.LoginEIDScan, first.token, selfOriginInTests)
	c := choose(t, tc, second, identity.LoginEParakstsMobile, second.token, selfOriginInTests)
	qt.Check(t, qt.Equals(flowCount(mem), 3))

	var bindings []string
	for _, x := range []answer{a, b, c} {
		f, err := mem.ConsumeFlow(context.Background(), providerState(t, x))
		qt.Assert(t, qt.IsNil(err))
		bindings = append(bindings, f.Binding)
	}
	qt.Check(t, qt.Equals(bindings[0], bindings[1]))
	qt.Check(t, qt.Equals(bindings[0], bindings[2]))
}

// Cases 21-24, 28: the provider's answer completes a sign-in only in the browser
// that started it, page or direct; elsewhere it is refused before the code is
// exchanged, and the flow is spent.
func TestTheProvidersAnswerCountsOnlyInTheBrowserThatStartedIt(t *testing.T) {
	app, mem := pageApp(t)
	person := app.TestClient()
	p := showPage(t, person, pageQuery("every-way", everyReturn))

	for _, c := range []struct {
		name string
		by   func() *azugo.TestClient
	}{
		{"22: a browser with no binding", app.TestClient},
		{"23: a browser with a binding of its own", func() *azugo.TestClient {
			other := app.TestClient()
			showPage(t, other, pageQuery("every-way", everyReturn))

			return other
		}},
	} {
		state := providerState(t, choose(t, person, p, identity.LoginEIDScan, p.token, selfOriginInTests))
		by := c.by()
		a := got(t)(by.Get("/callback?code=the-providers-code&state="+state, asBrowser(by)))
		qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized), qt.Commentf("%s", c.name))
		qt.Check(t, qt.IsTrue(isCannotStart(a)), qt.Commentf("%s", c.name))
		_, err := mem.ConsumeFlow(context.Background(), state)
		qt.Check(t, qt.IsNotNil(err), qt.Commentf("%s: the flow is spent", c.name))
	}

	// 24: direct mode is bound the same way.
	q := pageQuery("every-way", everyReturn)
	q.Set("acr_values", identity.LoginEIDScan)
	state := providerState(t, got(t)(person.Get("/authorize?"+q.Encode())))
	stranger := app.TestClient()
	a := got(t)(stranger.Get("/callback?code=x&state="+state, asBrowser(stranger)))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized))

	// 28: an error answer in another browser goes nowhere.
	state = providerState(t, choose(t, person, p, identity.LoginEIDScan, p.token, selfOriginInTests))
	a = got(t)(stranger.Get("/callback?error=access_denied&state="+state, asBrowser(stranger)))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized))
	qt.Check(t, qt.IsTrue(isCannotStart(a)))

	// 21: in the person's own browser the binding holds, and the provider's code
	// is taken on to the exchange (which fails here: no provider runs).
	state = providerState(t, choose(t, person, p, identity.LoginEIDScan, p.token, selfOriginInTests))
	a = got(t)(person.Get("/callback?code=x&state="+state, asBrowser(person)))
	qt.Check(t, qt.IsFalse(isCannotStart(a)), qt.Commentf("%d %s", a.status, a.body))
}

// Cases 25-27, 30: a cancel or a provider failure brings a page-started sign-in
// back to the page with what happened, once; a direct one is told to its client.
func TestACancelComesBackToThePage(t *testing.T) {
	app, _ := pageApp(t)
	tc := app.TestClient()
	p := showPage(t, tc, pageQuery("every-way", everyReturn))

	for _, c := range []struct{ code, want string }{
		{"access_denied", "The sign-in was cancelled."},
		{"server_error", "The identity provider could not complete the sign-in."},
		{"temporarily_unavailable", "The identity provider could not complete the sign-in."},
	} {
		state := providerState(t, choose(t, tc, p, identity.LoginEIDScan, p.token, selfOriginInTests))
		back := got(t)(tc.Get("/callback?error="+c.code+"&state="+state, asBrowser(tc)))
		qt.Assert(t, qt.Equals(back.status, fasthttp.StatusFound), qt.Commentf("%s", c.code))
		// Back to this service's own page, not to the client.
		qt.Check(t, qt.IsTrue(strings.HasPrefix(back.location, "/authorize?")), qt.Commentf("%s: %s", c.code, back.location))

		again := got(t)(tc.Get(back.location, asBrowser(tc)))
		qt.Check(t, qt.StringContains(again.body, c.want), qt.Commentf("%s", c.code))
		once := got(t)(tc.Get(back.location, asBrowser(tc)))
		qt.Check(t, qt.Not(qt.StringContains(once.body, c.want)), qt.Commentf("%s: shown once", c.code))
	}

	q := pageQuery("every-way", everyReturn)
	q.Set("acr_values", identity.LoginEIDScan)
	state := providerState(t, got(t)(tc.Get("/authorize?"+q.Encode())))
	direct := got(t)(tc.Get("/callback?error=access_denied&state=" + state))
	loc, err := url.Parse(direct.location)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(loc.Host, "every.example"))
	qt.Check(t, qt.Equals(loc.Query().Get("error"), "access_denied"))
	qt.Check(t, qt.Equals(loc.Query().Get("state"), "spa-state"))
	qt.Check(t, qt.Not(qt.Equals(loc.Query().Get("iss"), "")))
}

// Cases 29, 31-33: what this service cannot place gets the cannot-start page in a
// browser and the problem answer elsewhere, never a redirect.
func TestARequestThisServiceCannotPlace(t *testing.T) {
	app, _ := pageApp(t)
	tc := app.TestClient()

	unknown := pageQuery("an-unknown-app", everyReturn)
	unregistered := pageQuery("every-way", "https://evil.example/cb")
	for _, q := range []url.Values{unknown, unregistered} {
		a := got(t)(tc.Get("/authorize?"+q.Encode(), asBrowser(tc)))
		qt.Check(t, qt.Equals(a.status, fasthttp.StatusBadRequest))
		qt.Check(t, qt.IsTrue(isCannotStart(a)))
		// No client is named in what the page says; its language links repeat the
		// request as it came, to show it again.
		qt.Check(t, qt.Not(qt.StringContains(hrefRe.ReplaceAllString(a.body, ""), "an-unknown-app")))

		api := got(t)(tc.Get("/authorize?" + q.Encode()))
		// As before this page existed: the invalid parameter, 422.
		qt.Check(t, qt.Equals(api.status, fasthttp.StatusUnprocessableEntity))
		qt.Check(t, qt.Equals(api.location, ""))
		qt.Check(t, qt.Not(qt.StringContains(api.body, "<html")))
	}

	a := got(t)(tc.Get("/callback?code=x&state=nobody-knows-it", asBrowser(tc)))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized))
	qt.Check(t, qt.IsTrue(isCannotStart(a)))
}

// Cases 35, 37, 38: on a development server over plain HTTP the binding has its
// plain name, is read by that name only, and keeps its value while it lives.
func TestTheBrowsersBindingCookie(t *testing.T) {
	app, _ := pageApp(t)
	tc := app.TestClient()

	p := showPage(t, tc, pageQuery("every-way", everyReturn))
	qt.Assert(t, qt.Equals(len(p.cookies), 1))
	set := p.cookies[0]
	qt.Check(t, qt.IsTrue(strings.HasPrefix(set, signInCookie+"=")), qt.Commentf("%s", set))
	for _, want := range []string{"HttpOnly", "SameSite=Lax", "path=/", "max-age=600"} {
		qt.Check(t, qt.StringContains(strings.ToLower(set), strings.ToLower(want)), qt.Commentf("%s", set))
	}
	qt.Check(t, qt.Not(qt.StringContains(strings.ToLower(set), "secure")))
	value := tc.Cookies()[signInCookie]

	again := showPage(t, tc, pageQuery("every-way", everyReturn))
	qt.Check(t, qt.Equals(tc.Cookies()[signInCookie], value))
	qt.Check(t, qt.Equals(again.token, p.token))

	// A planted prefixed copy is not this service's cookie on this lane.
	planted := app.TestClient()
	b := got(t)(planted.PostForm(p.action, map[string]any{"way": identity.LoginEIDScan, "csrf": p.token},
		asBrowser(planted), planted.WithHeader("Origin", selfOriginInTests), planted.WithCookie(hostPrefix+signInCookie, value)))
	qt.Check(t, qt.StringContains(b.body, "That sign-in took too long and has expired."))
}

// Cases 43-47 in the routes: the page speaks the browser's language, the
// client's word before it, the person's own choice before both; diacritics stay.
func TestThePageSpeaksThePersonsLanguage(t *testing.T) {
	app, _ := pageApp(t)

	tc := app.TestClient()
	lv := showPage(t, tc, pageQuery("every-way", everyReturn), tc.WithHeader("Accept-Language", "lv-LV,lv;q=0.9,en;q=0.5"))
	qt.Check(t, qt.StringContains(lv.body, `<html lang="lv">`))
	qt.Check(t, qt.StringContains(lv.body, "<title>Pieslēgšanās lietotnei every-way</title>"))

	q := pageQuery("every-way", everyReturn)
	q.Set("ui_locales", "lv")
	asked := showPage(t, tc, q, tc.WithHeader("Accept-Language", "en"))
	qt.Check(t, qt.StringContains(asked.body, `<html lang="lv">`))

	// The person picks English; it is kept over the client's lv.
	pick := got(t)(tc.Get("/signin/language?" + url.Values{"lang": {"en"}, "next": {"/authorize?" + q.Encode()}}.Encode()))
	qt.Check(t, qt.Equals(pick.status, fasthttp.StatusSeeOther))
	qt.Check(t, qt.Equals(pick.location, "/authorize?"+q.Encode()))
	kept := showPage(t, tc, q, tc.WithHeader("Accept-Language", "lv"))
	qt.Check(t, qt.StringContains(kept.body, `<html lang="en">`))

	// The menu goes nowhere but this service's own sign-in.
	away := got(t)(tc.Get("/signin/language?lang=lv&next=https://evil.example/"))
	qt.Check(t, qt.Equals(away.location, "/authorize"))
}

// Cases 50, 56: an application's name is text, never markup; the foot names who
// runs the sign-in when the deployment says so, with its mark served as an image
// that runs nothing.
func TestTheNamesOnThePage(t *testing.T) {
	const registry = `
sign_in_clients:
  - client_id: acme
    type: public
    audience: acme-api
    enabled: true
    client_name: "<b>Acme & Co</b>"
    redirect_uris: [https://acme.example/cb]
    methods: [eparakstsMobile]
`
	mark := filepath.Join(t.TempDir(), "mark.svg")
	qt.Assert(t, qt.IsNil(os.WriteFile(mark, []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 0o600)))
	t.Setenv("SIGN_IN_OPERATOR_NAME", "Go Make Bytes")
	t.Setenv("SIGN_IN_OPERATOR_MARK_FILE", mark)
	app, _ := registryApp(t, registry)
	tc := app.TestClient()

	p := showPage(t, tc, pageQuery("acme", "https://acme.example/cb"))
	qt.Check(t, qt.StringContains(p.body, "Sign in to &lt;b&gt;Acme &amp; Co&lt;/b&gt;"))
	qt.Check(t, qt.Not(qt.StringContains(p.body, "<b>Acme")))
	qt.Check(t, qt.StringContains(p.body, "Sign-in run by Go Make Bytes for &lt;b&gt;Acme &amp; Co&lt;/b&gt;"))
	qt.Check(t, qt.StringContains(p.body, `<img src="/signin/operator.svg" alt="">`))

	svg := got(t)(tc.Get("/signin/operator.svg"))
	qt.Check(t, qt.Equals(svg.status, fasthttp.StatusOK))
	qt.Check(t, qt.StringContains(svg.header["Content-Type"], "image/svg+xml"))
	qt.Check(t, qt.StringContains(svg.header["Content-Security-Policy"], "sandbox"))

	css := got(t)(tc.Get("/signin/style.css"))
	qt.Check(t, qt.Equals(css.status, fasthttp.StatusOK))
	qt.Check(t, qt.StringContains(css.header["Content-Type"], "text/css"))
	qt.Check(t, qt.Equals(got(t)(tc.Get("/signin/nothing.js")).status, fasthttp.StatusNotFound))
}

// Case 56: a mark file named but missing stops the start.
func TestAMissingOperatorMarkStopsTheStart(t *testing.T) {
	t.Setenv("SERVICE_CLIENT_REGISTRY", methodsRegistry)
	t.Setenv("SIGN_IN_OPERATOR_MARK_FILE", filepath.Join(t.TempDir(), "absent.svg"))
	app := authbytecore.TestApp(t)
	app.SetSessionStore(sessiontest.NewMemory())

	qt.Check(t, qt.ErrorMatches(Init(app), "sign-in operator mark: .*"))
}

// Case 52: discovery names the page's languages.
func TestDiscoveryNamesThePagesLanguages(t *testing.T) {
	app, _ := pageApp(t)

	a := got(t)(app.TestClient().Get("/.well-known/openid-configuration"))
	qt.Check(t, qt.StringContains(a.body, `"ui_locales_supported":["en","lv"]`))
}

// Cases 34, 36: behind a proxy that reports TLS, the binding is host-prefixed and
// Secure, and read by that name only.
func TestTheBindingIsHostPrefixedOverTLS(t *testing.T) {
	t.Setenv("REVERSE_PROXY_TRUSTED_IPS", "*")
	app, _ := pageApp(t)
	tc := app.TestClient()
	tls := tc.WithHeader("X-Forwarded-Proto", "https")

	p := showPage(t, tc, pageQuery("every-way", everyReturn), tls)
	qt.Assert(t, qt.Equals(len(p.cookies), 1))
	set := strings.ToLower(p.cookies[0])
	qt.Check(t, qt.IsTrue(strings.HasPrefix(p.cookies[0], hostPrefix+signInCookie+"=")), qt.Commentf("%s", p.cookies[0]))
	qt.Check(t, qt.StringContains(set, "secure"))
	qt.Check(t, qt.StringContains(set, "path=/"))
	qt.Check(t, qt.Not(qt.StringContains(set, "domain=")))

	// The plain name, planted, is no binding on this lane.
	value := tc.Cookies()[hostPrefix+signInCookie]
	other := app.TestClient()
	a := got(t)(other.PostForm(p.action, map[string]any{"way": identity.LoginEIDScan, "csrf": p.token},
		asBrowser(other), other.WithHeader("Origin", selfOriginInTests), other.WithHeader("X-Forwarded-Proto", "https"),
		other.WithCookie(signInCookie, value)))
	qt.Check(t, qt.StringContains(a.body, "That sign-in took too long and has expired."))
}

// Cases 57-59: one address may make SIGN_IN_RATE_LIMIT sign-in requests in a
// window; the next is refused 429 with Retry-After and kept by no cache, and
// nothing is stored. Another address, and the provider's return, are not
// counted. The counts live in the application's cache: this needs a live Valkey
// (VALKEY_TEST_URL).
func TestSignInIsLimitedPerAddress(t *testing.T) {
	valkey := os.Getenv("VALKEY_TEST_URL")
	if valkey == "" {
		t.Skip("VALKEY_TEST_URL is not set")
	}
	t.Setenv("CACHE_CONNECTION", valkey)
	t.Setenv("CACHE_KEY_PREFIX", "authbyte-limit-test-"+randomToken(6))
	t.Setenv("SIGN_IN_RATE_LIMIT", "3")
	t.Setenv("REVERSE_PROXY_TRUSTED_IPS", "*")
	app, mem := pageApp(t)
	tc := app.TestClient()
	from := func(ip string) azugo.TestClientOption { return tc.WithHeader("X-Forwarded-For", ip) }
	page := "/authorize?" + pageQuery("every-way", everyReturn).Encode()

	for i := 1; i <= 3; i++ {
		a := got(t)(tc.Get(page, asBrowser(tc), from("203.0.113.1")))
		qt.Assert(t, qt.Equals(a.status, fasthttp.StatusOK), qt.Commentf("request %d", i))
	}
	over := got(t)(tc.Get(page, asBrowser(tc), from("203.0.113.1")))
	qt.Check(t, qt.Equals(over.status, fasthttp.StatusTooManyRequests))
	qt.Check(t, qt.Not(qt.Equals(over.header["Retry-After"], "")))
	// azugo's refusal carries its own headers only; [RFC 6585 §4] puts the
	// no-store duty on caches.
	qt.Check(t, qt.Not(qt.StringContains(over.body, "<form")))

	qt.Check(t, qt.Equals(got(t)(tc.Get(page, asBrowser(tc), from("203.0.113.2"))).status, fasthttp.StatusOK))
	ret := got(t)(tc.Get("/callback?code=x&state=unknown", asBrowser(tc), from("203.0.113.1")))
	qt.Check(t, qt.Equals(ret.status, fasthttp.StatusUnauthorized))
	qt.Check(t, qt.Equals(flowCount(mem), 0))
}

// pageApp is the methods deployment reading no card: the page's provider ways
// alone. The card on the page is card_test.go's.
func pageApp(t *testing.T) (*azugo.TestApp, *sessiontest.Memory) {
	t.Helper()

	return registryApp(t, methodsRegistry)
}
