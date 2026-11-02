package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"
	"github.com/go-make-bytes/authbyte/store"
	"github.com/go-make-bytes/authbyte/webeid"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The deployment of these tests: three single sign-on apps (one that allows only
// the card, one that allows the card and eParaksts Mobile, one whose tokens carry
// the identity code), and one app that is not single sign-on.
const sharedRegistry = `
sign_in_clients:
  - client_id: plain-card
    type: public
    audience: plain-api
    enabled: true
    redirect_uris: [https://plain.example/cb]
    post_logout_redirect_uris: [https://plain.example/]
    methods: [webEid]
    claims: [name]
    single_sign_on: true
  - client_id: second-app
    type: public
    audience: second-api
    enabled: true
    redirect_uris: [https://second.example/cb]
    methods: [eparakstsMobile, webEid]
    single_sign_on: true
  - client_id: needs-code
    type: public
    audience: code-api
    enabled: true
    redirect_uris: [https://code.example/cb]
    methods: [webEid]
    claims: [name, serial_number]
    single_sign_on: true
  - client_id: sso-off
    type: public
    audience: off-api
    enabled: true
    redirect_uris: [https://off.example/cb]
    methods: [webEid]
`

const (
	plainReturn  = "https://plain.example/cb"
	secondReturn = "https://second.example/cb"
	codeReturn   = "https://code.example/cb"
	offReturn    = "https://off.example/cb"

	annasCard  = "PNOLV-555555-55555"
	janissCard = "PNOLV-333333-33333"

	// The codes as stored: one canonical spelling.
	annasCode  = "PNOLV-55555555555"
	janissCode = "PNOLV-33333333333"
)

// whoseCard is the card engine in these tests: the token names whose card signed.
type whoseCard struct{}

func (whoseCard) Validate(_ *azugo.Context, authToken json.RawMessage, nonce string) (*webeid.Subject, error) {
	var tok struct{ Nonce, Origin, Code string }
	if err := json.Unmarshal(authToken, &tok); err != nil {
		return nil, err
	}
	if tok.Nonce != nonce || tok.Origin != selfOriginInTests {
		return nil, errors.New("the engine refuses the token")
	}

	return &webeid.Subject{IDCode: tok.Code, CountryCode: "LV", GivenName: "ANNA", Surname: "BĒRZIŅA"}, nil
}

// byCode is the identity store in these tests: every code is its own person.
type byCode struct{}

func (byCode) EnsureMapping(_ context.Context, _ string, p store.Profile) (string, bool, error) {
	return "sub-" + p.SerialNumber, false, nil
}

// sharedApp is the deployment above, with the card read on the page, its
// security events recorded, the given register and any further setup.
func sharedApp(t *testing.T, resolver authbytecore.ScopeResolver, setup ...func(*authbytecore.App)) (*azugo.TestApp, *sessiontest.Memory, *eventLog) {
	t.Helper()

	t.Setenv("WEBEID_ENGINE_URL", "http://localhost:9998")
	events := &eventLog{}
	app, mem := registryApp(t, sharedRegistry, append([]func(*authbytecore.App){func(a *authbytecore.App) {
		a.SetWebEID(whoseCard{})
		a.SetIdentities(byCode{})
		if resolver != nil {
			a.SetScopeResolver(resolver)
		}
	}, recordingAudit(events)}, setup...)...)
	t.Cleanup(func() { clock = time.Now })

	return app, mem, events
}

// pkce is a verifier and its S256 challenge.
func pkce() (verifier, challenge string) {
	verifier = randomToken(32)
	sum := sha256.Sum256([]byte(verifier))

	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// requestFor is an authorization request for clientID with a challenge of its own.
func requestFor(clientID, redirectURI, challenge string) url.Values {
	q := pageQuery(clientID, redirectURI)
	q.Set("code_challenge", challenge)

	return q
}

// signInByCard signs code's card in through clientID's page in tc's browser and
// answers where the browser was sent, and the verifier of its code.
func signInByCard(t *testing.T, tc *azugo.TestClient, clientID, redirectURI, code string, opts ...azugo.TestClientOption) (answer, string) {
	t.Helper()

	verifier, challenge := pkce()
	p := showCardPage(t, tc, requestFor(clientID, redirectURI, challenge), opts...)
	qt.Assert(t, qt.Equals(p.status, fasthttp.StatusOK), qt.Commentf("%s", p.body))
	b, _ := json.Marshal(map[string]string{"nonce": p.nonce, "origin": selfOriginInTests, "code": code})

	return postCard(t, tc, p, p.state, string(b), p.token, selfOriginInTests, opts...), verifier
}

// codeAt is the code an answer sends back to redirectURI, or "".
func codeAt(t *testing.T, a answer, redirectURI string) string {
	t.Helper()

	if !strings.HasPrefix(a.location, redirectURI+"?") {
		return ""
	}
	loc, err := url.Parse(a.location)
	qt.Assert(t, qt.IsNil(err))

	return loc.Query().Get("code")
}

// authorizeIn sends tc's browser to /authorize for clientID with extra.
func authorizeIn(t *testing.T, tc *azugo.TestClient, clientID, redirectURI string, extra url.Values, opts ...azugo.TestClientOption) answer {
	t.Helper()

	q := pageQuery(clientID, redirectURI)
	for k, v := range extra {
		q[k] = v
	}

	return got(t)(tc.Get("/authorize?"+q.Encode(), append([]azugo.TestClientOption{asBrowser(tc)}, opts...)...))
}

// sessionOf is the app session a code was minted for.
func sessionOf(t *testing.T, mem *sessiontest.Memory, code string) (string, *session.Session) {
	t.Helper()

	var c session.AppCode
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(mem.Entries()["code:"+code]), &c)))
	sess, err := mem.LoadSession(context.Background(), c.SessionID)
	qt.Assert(t, qt.IsNil(err))

	return c.SessionID, sess
}

// sharedOf is the shared session a browser's cookie names, and its id.
func sharedOf(t *testing.T, mem *sessiontest.Memory, tc *azugo.TestClient) (string, *session.Shared) {
	t.Helper()

	v := tc.Cookies()[sharedCookie]
	id, _, ok := strings.Cut(v, ".")
	qt.Assert(t, qt.IsTrue(ok), qt.Commentf("cookie %q", v))
	sh, err := mem.LoadShared(context.Background(), id)
	qt.Assert(t, qt.IsNil(err))

	return id, sh
}

// seedShared stores a shared session holding ways for subject and answers the
// cookie that names it.
func seedShared(t *testing.T, mem *sessiontest.Memory, subject, code string, ways ...session.Way) string {
	t.Helper()

	id, secret := randomToken(sharedIDBytes), randomToken(sharedSecretBytes)
	sh := &session.Shared{SecretHash: sharedSecretHash(secret), Subject: subject, SerialNumber: code}
	for _, w := range ways {
		sh.Keep(w)
	}
	qt.Assert(t, qt.IsNil(mem.CreateShared(context.Background(), id, sh)))

	return id + "." + secret
}

func aWay(method string) session.Way {
	now := time.Now()

	return session.Way{Method: method, LoA: "high", AuthTime: now.Unix(), AMR: []string{"sc"}, SignedIn: now, Ends: now.Add(time.Hour)}
}

// sharedEvents are the recorded shared-session events of kind.
func (l *eventLog) sharedEvents(kind string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []map[string]any
	for _, ev := range l.events {
		if ev.Attributes["kind"] == kind {
			out = append(out, ev.Attributes)
		}
	}

	return out
}

// Cases 1, 4: a card sign-in through the page makes the browser's shared
// session: a host-prefixed, Secure, http-only, Lax cookie for the session's whole
// life, naming a record that holds the person and the way, never the cookie's
// secret, and no tenant.
func TestASignInMakesTheSharedSession(t *testing.T) {
	t.Setenv("REVERSE_PROXY_TRUSTED_IPS", "*")
	app, mem, events := sharedApp(t, nil)
	tc := app.TestClient()
	tls := tc.WithHeader("X-Forwarded-Proto", "https")

	_, challenge := pkce()
	q := requestFor("plain-card", plainReturn, challenge)
	q.Set("tenant", "01TENANTACME")
	p := showCardPage(t, tc, q, tls)
	b, _ := json.Marshal(map[string]string{"nonce": p.nonce, "origin": selfOriginInTests, "code": annasCard})
	a := postCard(t, tc, p, p.state, string(b), p.token, selfOriginInTests, tls)
	qt.Assert(t, qt.Not(qt.Equals(codeAt(t, a, plainReturn), "")), qt.Commentf("%d %s", a.status, a.location))

	var set string
	for _, c := range a.cookies {
		if strings.HasPrefix(c, hostPrefix+sharedCookie+"=") {
			set = strings.ToLower(c)
		}
	}
	qt.Assert(t, qt.Not(qt.Equals(set, "")), qt.Commentf("%v", a.cookies))
	for _, want := range []string{"secure", "httponly", "samesite=lax", "path=/", "max-age=43200"} {
		qt.Check(t, qt.StringContains(set, want))
	}
	qt.Check(t, qt.Not(qt.StringContains(set, "domain=")))

	value := tc.Cookies()[hostPrefix+sharedCookie]
	id, secret, _ := strings.Cut(value, ".")
	sh, err := mem.LoadShared(context.Background(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sh.Subject, "sub-"+annasCode))
	qt.Check(t, qt.Equals(sh.SerialNumber, annasCode))
	qt.Assert(t, qt.HasLen(sh.Ways, 1))
	qt.Check(t, qt.Equals(sh.Ways[0].Method, identity.LoginWebEID))
	qt.Check(t, qt.Not(qt.Equals(sh.Ways[0].AuthTime, int64(0))))
	qt.Check(t, qt.Not(qt.HasLen(sh.Ways[0].AMR, 0)))

	for k, v := range mem.Entries() {
		qt.Check(t, qt.Not(qt.StringContains(v, secret)), qt.Commentf("%s holds the cookie's secret", k))
		if strings.HasPrefix(k, "shared:") {
			qt.Check(t, qt.Not(qt.StringContains(v, "tenant")), qt.Commentf("%s", v))
			qt.Check(t, qt.Not(qt.StringContains(v, "01TENANTACME")), qt.Commentf("%s", v))
		}
	}
	qt.Check(t, qt.HasLen(events.sharedEvents("shared_session_created"), 1))
}

// Case 6: in development over plain HTTP the cookie carries the plain name.
func TestTheSharedCookieIsPlainInDevelopment(t *testing.T) {
	app, _, _ := sharedApp(t, nil)
	tc := app.TestClient()

	a, _ := signInByCard(t, tc, "plain-card", plainReturn, annasCard)
	qt.Assert(t, qt.Not(qt.Equals(codeAt(t, a, plainReturn), "")))
	qt.Check(t, qt.Not(qt.Equals(tc.Cookies()[sharedCookie], "")))
	qt.Check(t, qt.Equals(tc.Cookies()[hostPrefix+sharedCookie], ""))
}

// Case 3: an app that is not single sign-on still makes the shared session.
func TestEverySignInJoinsTheSharedSession(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)
	tc := app.TestClient()

	a, _ := signInByCard(t, tc, "sso-off", offReturn, annasCard)
	qt.Assert(t, qt.Not(qt.Equals(codeAt(t, a, offReturn), "")))
	_, sh := sharedOf(t, mem, tc)
	qt.Check(t, qt.Equals(sh.Subject, "sub-"+annasCode))
}

// Case 5: a refused card makes no shared session, and leaves the one the browser
// holds as it was.
func TestARefusedSignInLeavesTheSharedSession(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)
	tc := app.TestClient()

	p := showCardPage(t, tc, pageQuery("plain-card", plainReturn))
	refused := postCard(t, tc, p, p.state, `{"nonce":"another"}`, p.token, selfOriginInTests)
	qt.Check(t, qt.Equals(refused.status, fasthttp.StatusUnauthorized))
	qt.Check(t, qt.Equals(tc.Cookies()[sharedCookie], ""))
	qt.Check(t, qt.HasLen(mem.Keys("shared:"), 0))

	signInByCard(t, tc, "plain-card", plainReturn, annasCard)
	before, cookie := mem.Entries(), tc.Cookies()[sharedCookie]
	p = showCardPage(t, tc, pageQuery("plain-card", plainReturn))
	postCard(t, tc, p, p.state, `{"nonce":"another"}`, p.token, selfOriginInTests)
	qt.Check(t, qt.Equals(tc.Cookies()[sharedCookie], cookie))
	id, _, _ := strings.Cut(cookie, ".")
	qt.Check(t, qt.Equals(mem.Entries()["shared:"+id], before["shared:"+id]))
}

// Cases 7, 8, 9: a second single sign-on app is answered with no page, with or
// without naming the way, for the same person and the first sign-in's moment; its
// code is exchanged and refreshed as any other, for its own audience, and the
// first app's session is untouched.
func TestASecondAppSignsInWithNoPage(t *testing.T) {
	app, mem, events := sharedApp(t, nil)
	tc := app.TestClient()

	first, _ := signInByCard(t, tc, "plain-card", plainReturn, annasCard)
	firstSID, firstSess := sessionOf(t, mem, codeAt(t, first, plainReturn))
	sharedID, _ := sharedOf(t, mem, tc)

	for _, acr := range []string{identity.LoginWebEID, ""} {
		verifier, challenge := pkce()
		extra := url.Values{"code_challenge": {challenge}, "scope": {"openid"}, "nonce": {"n-1"}}
		if acr != "" {
			extra.Set("acr_values", acr)
		}
		a := authorizeIn(t, tc, "second-app", secondReturn, extra)
		code := codeAt(t, a, secondReturn)
		qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("acr %q: %d %s %s", acr, a.status, a.location, a.body))
		loc, _ := url.Parse(a.location)
		qt.Check(t, qt.Equals(loc.Query().Get("state"), "spa-state"))
		qt.Check(t, qt.Equals(loc.Query().Get("iss"), "http://localhost:8080"))

		_, sess := sessionOf(t, mem, code)
		qt.Check(t, qt.Equals(sess.Subject, firstSess.Subject))
		qt.Check(t, qt.Equals(sess.LoginMethod, identity.LoginWebEID))
		qt.Check(t, qt.Equals(sess.AuthTime, firstSess.AuthTime))
		qt.Check(t, qt.Equals(sess.Shared, sharedID))
		qt.Check(t, qt.Not(qt.Equals(sess.SID, firstSess.SID)))

		e := newEdge(t, app)
		status, body := e.exchange(signIn{code: code, verifier: verifier}, "second-app", secondReturn)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
		qt.Check(t, qt.DeepEquals(audienceOf(tokenClaims(t, body["access_token"].(string))), []any{"second-api"}))
		id := tokenClaims(t, body["id_token"].(string))
		qt.Check(t, qt.Equals(id["acr"], identity.LoginWebEID))
		qt.Check(t, qt.Equals(int64(id["auth_time"].(float64)), firstSess.AuthTime))
		status, body = e.refresh(body["refresh_token"].(string), "second-app")
		qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	}

	_, err := mem.LoadSession(context.Background(), firstSID)
	qt.Check(t, qt.IsNil(err))
	reused := events.sharedEvents("shared_session_reused")
	qt.Assert(t, qt.HasLen(reused, 2))
	qt.Check(t, qt.Equals(reused[0]["client"], "second-app"))
}

// Cases 10, 11: prompt=none is answered from a shared session that fits, and is
// login_required at the client when there is none or it does not fit, with
// nothing stored.
func TestPromptNoneIsAnsweredFromTheSharedSession(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)
	tc := app.TestClient()

	none := url.Values{"prompt": {"none"}}
	a := authorizeIn(t, tc, "second-app", secondReturn, none)
	qt.Check(t, qt.Equals(errorAt(t, a.location), "login_required"))

	signInByCard(t, tc, "plain-card", plainReturn, annasCard)
	a = authorizeIn(t, tc, "second-app", secondReturn, none)
	qt.Check(t, qt.Not(qt.Equals(codeAt(t, a, secondReturn), "")), qt.Commentf("%s", a.location))

	flows := len(mem.Keys("flow:"))
	notThisWay := url.Values{"prompt": {"none"}, "acr_values": {identity.LoginEParakstsMobile}}
	a = authorizeIn(t, tc, "second-app", secondReturn, notThisWay)
	qt.Check(t, qt.Equals(errorAt(t, a.location), "login_required"))
	qt.Check(t, qt.Equals(len(mem.Keys("flow:")), flows))
}

func errorAt(t *testing.T, location string) string {
	t.Helper()

	loc, err := url.Parse(location)
	qt.Assert(t, qt.IsNil(err))

	return loc.Query().Get("error")
}

// Cases 12, 13, 15, 16, 48: prompt=login, max_age=0 and select_account sign the
// person in again, and an app that is not single sign-on is never answered; none
// of them is a refusal.
func TestAFreshSignInIsNeverAnsweredFromTheSharedSession(t *testing.T) {
	app, _, events := sharedApp(t, nil)
	tc := app.TestClient()
	signInByCard(t, tc, "plain-card", plainReturn, annasCard)

	for _, c := range []struct {
		name, client, back string
		extra              url.Values
	}{
		{"prompt=login", "second-app", secondReturn, url.Values{"prompt": {"login"}}},
		{"max_age=0", "second-app", secondReturn, url.Values{"max_age": {"0"}}},
		{"select_account", "second-app", secondReturn, url.Values{"prompt": {"select_account"}}},
		{"not single sign-on", "sso-off", offReturn, nil},
	} {
		a := authorizeIn(t, tc, c.client, c.back, c.extra)
		qt.Check(t, qt.Equals(codeAt(t, a, c.back), ""), qt.Commentf("%s: %s", c.name, a.location))
		qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK), qt.Commentf("%s: the page", c.name))
	}
	qt.Check(t, qt.HasLen(events.sharedEvents("shared_session_refused"), 0))
}

// Case 14: max_age=N answers a way that authenticated exactly N seconds ago, and
// signs the person in again at N+1.
func TestMaxAgeIsHeldAgainstTheWaysMoment(t *testing.T) {
	app, mem, events := sharedApp(t, nil)
	tc := app.TestClient()
	first, _ := signInByCard(t, tc, "plain-card", plainReturn, annasCard)
	_, sess := sessionOf(t, mem, codeAt(t, first, plainReturn))

	const n = 300
	clock = func() time.Time { return time.Unix(sess.AuthTime+n, 0) }
	a := authorizeIn(t, tc, "second-app", secondReturn, url.Values{"max_age": {"300"}})
	qt.Check(t, qt.Not(qt.Equals(codeAt(t, a, secondReturn), "")), qt.Commentf("%s", a.location))

	clock = func() time.Time { return time.Unix(sess.AuthTime+n+1, 0) }
	a = authorizeIn(t, tc, "second-app", secondReturn, url.Values{"max_age": {"300"}})
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""))
	refused := events.sharedEvents("shared_session_refused")
	qt.Assert(t, qt.HasLen(refused, 1))
	qt.Check(t, qt.Equals(refused[0]["reason"], refusedAge))
}

// Cases 17, 18, 19: a way the app does not allow, a way the request does not
// name, and an identity code the app needs and the person's way has not, each
// send the person to sign in, as without a shared session.
func TestASharedSessionThatDoesNotFitIsNotAnswered(t *testing.T) {
	app, mem, events := sharedApp(t, nil)

	// 17: a directory sign-in (no code) and the card-only app.
	tc := app.TestClient()
	cookie := seedShared(t, mem, "sub-directory", "", aWay("upstream"))
	a := authorizeIn(t, tc, "plain-card", plainReturn, nil, tc.WithCookie(sharedCookie, cookie))
	qt.Check(t, qt.Equals(codeAt(t, a, plainReturn), ""))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK))

	// 18: the card held, eParaksts Mobile asked for: to the provider.
	tc = app.TestClient()
	cookie = seedShared(t, mem, "sub-anna", annasCard, aWay(identity.LoginWebEID))
	a = authorizeIn(t, tc, "second-app", secondReturn, url.Values{"acr_values": {identity.LoginEParakstsMobile}},
		tc.WithCookie(sharedCookie, cookie))
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""))
	qt.Check(t, qt.StringContains(a.location, "localhost:9999"), qt.Commentf("%s", a.location))

	// 19: the card's way, but no code, and an app that carries the code: only the
	// identity guard refuses.
	tc = app.TestClient()
	cookie = seedShared(t, mem, "sub-codeless", "", aWay(identity.LoginWebEID))
	a = authorizeIn(t, tc, "needs-code", codeReturn, nil, tc.WithCookie(sharedCookie, cookie))
	qt.Check(t, qt.Equals(codeAt(t, a, codeReturn), ""))

	var reasons []any
	for _, ev := range events.sharedEvents("shared_session_refused") {
		reasons = append(reasons, ev["reason"])
	}
	qt.Check(t, qt.DeepEquals(reasons, []any{refusedWay, refusedWay, refusedIdentity}))
}

// Cases 21, 22, 23: an app that requires a membership is answered only when the
// register holds one for the person; nothing is admitted, and a register that
// cannot answer means no answer.
func TestAMembershipAppIsAnsweredOnlyForAMember(t *testing.T) {
	for _, c := range []struct {
		name     string
		resolver *fakeResolver
		answered bool
		reason   string
	}{
		{"no membership", &fakeResolver{admit: true}, false, refusedMembership},
		{"a member", &fakeResolver{memberships: memberships("01TENANTACME")}, true, ""},
		{"register down", &fakeResolver{err: errors.New("down")}, false, refusedRegister},
	} {
		app, mem, events := sharedApp(t, c.resolver)
		tc := app.TestClient()
		cookie := seedShared(t, mem, "sub-anna", annasCard, aWay(identity.LoginWebEID))

		a := authorizeIn(t, tc, "second-app", secondReturn, nil, tc.WithCookie(sharedCookie, cookie))
		qt.Check(t, qt.Equals(codeAt(t, a, secondReturn) != "", c.answered), qt.Commentf("%s", c.name))
		qt.Check(t, qt.Equals(c.resolver.asked, rolebyte.PersonKey("sub-anna")), qt.Commentf("%s", c.name))
		qt.Check(t, qt.Equals(c.resolver.admittedKey, ""), qt.Commentf("%s: nothing admitted", c.name))
		if c.reason != "" {
			refused := events.sharedEvents("shared_session_refused")
			qt.Assert(t, qt.HasLen(refused, 1), qt.Commentf("%s", c.name))
			qt.Check(t, qt.Equals(refused[0]["reason"], any(c.reason)), qt.Commentf("%s", c.name))
		}
	}
}

// Cases 24, 25: a cookie that names no live shared session is not answered and
// is cleared.
func TestACookieThatNamesNothingIsCleared(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)
	good := seedShared(t, mem, "sub-anna", annasCard, aWay(identity.LoginWebEID))
	id, _, _ := strings.Cut(good, ".")

	for name, value := range map[string]string{
		"no dot":         strings.ReplaceAll(good, ".", ""),
		"short":          good[:20],
		"unknown id":     randomToken(sharedIDBytes) + "." + randomToken(sharedSecretBytes),
		"another secret": id + "." + randomToken(sharedSecretBytes),
	} {
		tc := app.TestClient()
		a := authorizeIn(t, tc, "second-app", secondReturn, nil, tc.WithCookie(sharedCookie, value))
		qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""), qt.Commentf("%s", name))
		qt.Check(t, qt.IsTrue(clears(a.cookies, sharedCookie)), qt.Commentf("%s: %v", name, a.cookies))
	}

	// 25: past its end.
	clock = func() time.Time { return time.Now().Add(2 * time.Hour) }
	mem.SetClock(clock)
	tc := app.TestClient()
	a := authorizeIn(t, tc, "second-app", secondReturn, nil, tc.WithCookie(sharedCookie, good))
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""))
	qt.Check(t, qt.IsTrue(clears(a.cookies, sharedCookie)))
}

func clears(cookies []string, name string) bool {
	for _, c := range cookies {
		if strings.HasPrefix(c, name+"=;") || strings.HasPrefix(c, name+"=deleted") ||
			(strings.HasPrefix(c, name+"=") && strings.Contains(strings.ToLower(c), "max-age=0")) ||
			(strings.HasPrefix(c, name+"=") && strings.Contains(c, "1970")) {
			return true
		}
	}

	return false
}

// Cases 26, 27: an answer a second before the way ends gives an app session that
// ends with it, never later; a tenant asked for is the code's, never the shared
// session's.
func TestAnAnswerEndsWithItsWay(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)
	w := aWay(identity.LoginWebEID)
	cookie := seedShared(t, mem, "sub-anna", annasCard, w)

	clock = func() time.Time { return w.Ends.Add(-time.Second) }
	mem.SetClock(clock)
	tc := app.TestClient()
	a := authorizeIn(t, tc, "second-app", secondReturn, url.Values{"tenant": {"01TENANTACME"}}, tc.WithCookie(sharedCookie, cookie))
	code := codeAt(t, a, secondReturn)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%s", a.location))
	_, sess := sessionOf(t, mem, code)
	qt.Check(t, qt.IsTrue(sess.ExpiresAt.Equal(w.Ends)), qt.Commentf("%v, want %v", sess.ExpiresAt, w.Ends))

	var c session.AppCode
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(mem.Entries()["code:"+code]), &c)))
	qt.Check(t, qt.Equals(c.Tenant, "01TENANTACME"))
	for k, v := range mem.Entries() {
		if strings.HasPrefix(k, "shared:") {
			qt.Check(t, qt.Not(qt.StringContains(v, "01TENANTACME")))
		}
	}
}

// Case 25: a way that has ended answers nothing, though another way of the same
// shared session still lives.
func TestAnEndedWayAnswersNothing(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)
	ended := aWay(identity.LoginWebEID)
	ended.Ends = time.Now().Add(-time.Minute)
	cookie := seedShared(t, mem, "sub-anna", annasCode, ended, aWay(identity.LoginEParakstsMobile))

	tc := app.TestClient()
	a := authorizeIn(t, tc, "second-app", secondReturn, url.Values{"acr_values": {identity.LoginWebEID}},
		tc.WithCookie(sharedCookie, cookie))
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""), qt.Commentf("%s", a.location))
	a = authorizeIn(t, tc, "second-app", secondReturn, url.Values{"acr_values": {identity.LoginEParakstsMobile}},
		tc.WithCookie(sharedCookie, cookie))
	qt.Check(t, qt.Not(qt.Equals(codeAt(t, a, secondReturn), "")), qt.Commentf("%s", a.location))
}

// Cases 31, 32: the same person signing in again by another way keeps the shared
// session and its apps, gains the way, and gets a new secret: the cookie from
// before names nothing.
func TestTheSamePersonsSignInRenewsTheSharedSession(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)
	tc := app.TestClient()
	old := seedShared(t, mem, "sub-"+annasCode, annasCard, aWay(identity.LoginEParakstsMobile))
	id, _, _ := strings.Cut(old, ".")
	_, err := mem.PutSharedApp(context.Background(), id, "mobile-app", "mobile-session", time.Now().Add(time.Hour))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(mem.CreateSession(context.Background(), "mobile-session", &session.Session{Subject: "sub-" + annasCode}, time.Hour)))

	a, _ := signInByCard(t, tc, "plain-card", plainReturn, annasCard, tc.WithCookie(sharedCookie, old))
	qt.Assert(t, qt.Not(qt.Equals(codeAt(t, a, plainReturn), "")))
	newID, sh := sharedOf(t, mem, tc)
	qt.Check(t, qt.Equals(newID, id))
	qt.Check(t, qt.Not(qt.Equals(tc.Cookies()[sharedCookie], old)))
	var methods []string
	for _, w := range sh.Ways {
		methods = append(methods, w.Method)
	}
	qt.Check(t, qt.DeepEquals(methods, []string{identity.LoginEParakstsMobile, identity.LoginWebEID}))
	_, err = mem.LoadSession(context.Background(), "mobile-session")
	qt.Check(t, qt.IsNil(err))

	// 32: the cookie from before the sign-in.
	stale := app.TestClient()
	a = authorizeIn(t, stale, "second-app", secondReturn, nil, stale.WithCookie(sharedCookie, old))
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""))
}

// Cases 33, 34, 35: another person's sign-in in the browser ends the shared
// session and the app sessions signed in under it; the same app signing in again
// ends its earlier app session.
func TestAnotherPersonEndsTheFirstPersonsApps(t *testing.T) {
	app, mem, events := sharedApp(t, nil)
	tc := app.TestClient()

	// 35: the same app signs in twice, the same person; an app that is not single
	// sign-on shows the page each time, as a repeat sign-in does.
	first, _ := signInByCard(t, tc, "sso-off", offReturn, annasCard)
	firstSID, _ := sessionOf(t, mem, codeAt(t, first, offReturn))
	again, _ := signInByCard(t, tc, "sso-off", offReturn, annasCard)
	againSID, _ := sessionOf(t, mem, codeAt(t, again, offReturn))
	_, err := mem.LoadSession(context.Background(), firstSID)
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
	_, err = mem.LoadSession(context.Background(), againSID)
	qt.Check(t, qt.IsNil(err))

	answered := authorizeIn(t, tc, "second-app", secondReturn, nil)
	secondSID, _ := sessionOf(t, mem, codeAt(t, answered, secondReturn))
	annasShared, _ := sharedOf(t, mem, tc)

	// 33: Jānis signs in in the same browser.
	b, _ := signInByCard(t, tc, "sso-off", offReturn, janissCard)
	qt.Assert(t, qt.Not(qt.Equals(codeAt(t, b, offReturn), "")))
	for _, sid := range []string{againSID, secondSID} {
		_, err := mem.LoadSession(context.Background(), sid)
		qt.Check(t, qt.ErrorIs(err, session.ErrNotFound), qt.Commentf("%s", sid))
	}
	_, err = mem.LoadShared(context.Background(), annasShared)
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
	jID, jShared := sharedOf(t, mem, tc)
	qt.Check(t, qt.Not(qt.Equals(jID, annasShared)))
	qt.Check(t, qt.Equals(jShared.Subject, "sub-"+janissCode))

	ended := events.sharedEvents("shared_session_ended")
	qt.Assert(t, qt.HasLen(ended, 1))
	qt.Check(t, qt.Equals(ended[0]["reason"], endedAnotherPerson))
}

// C7 cases 1, 5, 7, 15 (C6's 37, 41, 42): an app's sign-out (its revoke) ends
// the shared session it was signed in under and, at once, every app session
// signed in under it with its refresh grant, so nothing more is answered and no
// app renews; one ended event counts the sessions. A revoke that is refused ends
// nothing. An access token already issued lives to its own end.
func TestASignOutEndsEveryAppOfTheSharedSession(t *testing.T) {
	var core *authbytecore.App
	app, mem, events := sharedApp(t, nil, func(a *authbytecore.App) { core = a })
	tc := app.TestClient()
	ctx := context.Background()

	plain := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)
	second := answeredApp(t, app, mem, tc, "second-app", secondReturn)
	third := answeredApp(t, app, mem, tc, "needs-code", codeReturn)
	all := []appIn{plain, second, third}
	id, _ := sharedOf(t, mem, tc)

	// 5 (41): another client's revoke, and the right client's without the
	// session's key, are refused and end nothing.
	status, _ := second.edge.revoke(plain.refresh, "second-app")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))
	status, _ = newEdge(t, app).revoke(plain.refresh, "plain-card")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))
	_, err := mem.LoadShared(ctx, id)
	qt.Check(t, qt.IsNil(err))
	for _, a := range all {
		qt.Check(t, qt.Equals(a.renews(), fasthttp.StatusOK), qt.Commentf("%s before the sign-out", a.client))
	}

	// 1 (37, 42): the app's own revoke, whatever made it revoke.
	qt.Assert(t, qt.Equals(plain.signsOut(), fasthttp.StatusOK))
	_, err = mem.LoadShared(ctx, id)
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
	for _, a := range all {
		a.ended(t, mem)
	}
	a := authorizeIn(t, tc, "second-app", secondReturn, nil)
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""))

	// 15: one ended event, naming the person, the reason and the count.
	ended := events.sharedEnded()
	qt.Assert(t, qt.HasLen(ended, 1))
	qt.Check(t, qt.Equals(ended[0].Actor.ID, "sub-"+annasCode))
	qt.Check(t, qt.Equals(ended[0].Attributes["reason"], endedSignOut))
	qt.Check(t, qt.Equals(ended[0].Attributes["sessions"], 3))
	qt.Check(t, qt.HasLen(events.sharedEvents("session_ended"), 1))

	// 7: an access token already issued is still accepted where this authority
	// accepts one (the token exchange's subject token), to its own end, at most a
	// user token's lifetime after it was issued.
	_, err = core.Issuer().ParseSubjectToken(second.access)
	qt.Check(t, qt.IsNil(err))
	claims := tokenClaims(t, second.access)
	lifetime := time.Duration(claims["exp"].(float64)-claims["iat"].(float64)) * time.Second
	qt.Check(t, qt.IsTrue(lifetime <= core.Config().UserTokenTTL), qt.Commentf("lifetime %s", lifetime))
}

// C7 case 2 (C6's 39): the browser's sign-out leg ends the shared session it
// names and every app session under it, and clears the cookie.
func TestTheBrowsersSignOutEndsEveryApp(t *testing.T) {
	app, mem, events := sharedApp(t, nil)
	tc := app.TestClient()
	plain := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)
	second := answeredApp(t, app, mem, tc, "second-app", secondReturn)
	id, _ := sharedOf(t, mem, tc)

	a := got(t)(tc.Get("/logout?client_id=plain-card&redirect_uri=" + url.QueryEscape("https://plain.example/")))
	qt.Check(t, qt.Equals(a.location, "https://plain.example/"))
	qt.Check(t, qt.Equals(tc.Cookies()[sharedCookie], ""))
	_, err := mem.LoadShared(context.Background(), id)
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
	for _, a := range []appIn{plain, second} {
		a.ended(t, mem)
	}

	ended := events.sharedEnded()
	qt.Assert(t, qt.HasLen(ended, 1))
	qt.Check(t, qt.Equals(ended[0].Attributes["reason"], endedSignOut))
	qt.Check(t, qt.Equals(ended[0].Attributes["sessions"], 2))
}
