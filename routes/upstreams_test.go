package routes

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmb-lib/go-authbyte/replay"
	"github.com/gmb-lib/go-sec-events/secevents"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"
	"github.com/go-make-bytes/authbyte/store"
	"github.com/go-make-bytes/authbyte/upstream"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The deployment of these tests runs two upstream providers side by side, each on
// its own return path: eParaksts (Mobile and eID Scan, with the identity code and
// the signing catalog) and a work directory (Microsoft Entra in the lab: no code,
// a verified ID token, and the holder of the sign-ins stored before providers
// were told apart). The card is read on the page.
const upstreamsRegistry = `
sign_in_clients:
  - client_id: mobile-and-entra
    type: public
    audience: me-api
    enabled: true
    redirect_uris: [https://me.example/cb]
    post_logout_redirect_uris: [https://me.example/]
    methods: [eparakstsMobile, upstream]
    single_sign_on: true
  - client_id: entra-only
    type: public
    audience: entra-api
    enabled: true
    redirect_uris: [https://entra.example/cb]
    methods: [upstream]
    single_sign_on: true
  - client_id: with-google
    type: public
    audience: google-api
    enabled: true
    redirect_uris: [https://google.example/cb]
    methods: [google, upstream]
  - client_id: signer
    type: public
    audience: sign-api
    enabled: true
    redirect_uris: [https://sign.example/cb]
    methods: [eparakstsMobile, upstream]
    signing: true
  - client_id: needs-code-sso
    type: public
    audience: code-api
    enabled: true
    redirect_uris: [https://codes.example/cb]
    methods: [upstream, eparakstsMobile]
    claims: [name, serial_number]
    single_sign_on: true
  - client_id: card-sso
    type: public
    audience: card-api
    enabled: true
    redirect_uris: [https://cards.example/cb]
    methods: [webEid]
    single_sign_on: true
`

const (
	meReturn    = "https://me.example/cb"
	entraReturn = "https://entra.example/cb"
	googleRet   = "https://google.example/cb"
	signReturn  = "https://sign.example/cb"
	codesReturn = "https://codes.example/cb"
	cardsReturn = "https://cards.example/cb"

	eparakstsPath = "/auth/eparaksts/callback"
	entraPath     = "/Auth/Complete"

	// The eParaksts profile's own addresses below its authority.
	eparakstsTokenPath    = "/trustedx-authserver/oauth/lvrtc-eipsign-as/token"
	eparakstsUserInfoPath = "/trustedx-resources/openid/v1/users/me"
	eparakstsCertPrefix   = "/trustedx-resources/esigp/v1/sign_identities/"
)

// standIn is one upstream provider in these tests. It counts the codes it is
// asked to exchange and the certificates it is asked for, answers userinfo as
// it is told, and, with a key, issues an ID token for the nonce it is told.
type standIn struct {
	srv       *httptest.Server
	url       string
	exchanges atomic.Int32
	certs     atomic.Int32

	mu       sync.Mutex
	userinfo string
	key      *rsa.PrivateKey // nil: no key set, no ID token
	signWith *rsa.PrivateKey // the key the ID token is signed with (the published one unless set)
	nonce    string
	oid      string
}

func newStandIn(t *testing.T, withKeys bool) *standIn {
	t.Helper()

	s := &standIn{}
	if withKeys {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		qt.Assert(t, qt.IsNil(err))
		s.key, s.signWith = key, key
	}
	token := func(w http.ResponseWriter, _ *http.Request) {
		s.exchanges.Add(1)
		resp := map[string]any{"access_token": "the-providers-access-token", "token_type": "Bearer", "expires_in": 600}
		if s.key != nil {
			resp["id_token"] = s.idToken(t)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
	userinfo := func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		body := s.userinfo
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", token)
	mux.HandleFunc(eparakstsTokenPath, token)
	mux.HandleFunc("/userinfo", userinfo)
	mux.HandleFunc(eparakstsUserInfoPath, userinfo)
	mux.HandleFunc(eparakstsCertPrefix, func(w http.ResponseWriter, _ *http.Request) {
		s.certs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"certificate":"MIIB"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	s.srv = httptest.NewServer(mux)
	s.url = s.srv.URL
	t.Cleanup(s.srv.Close)

	return s
}

func (s *standIn) answer(userinfo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userinfo = userinfo
}

// expect tells the provider the nonce of the flow it is about to answer and the
// directory id of the person it signs in.
func (s *standIn) expect(nonce, oid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonce, s.oid = nonce, oid
}

func (s *standIn) idToken(t *testing.T) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": s.url + "/v2.0", "aud": "entra-client", "sub": "pairwise-" + s.oid, "oid": s.oid,
		"exp": jwt.NewNumericDate(now.Add(5 * time.Minute)), "iat": jwt.NewNumericDate(now),
		"nonce": s.nonce, "name": "Directory Person", "acct": 0,
	})
	tok.Header["kid"] = "k1"
	str, err := tok.SignedString(s.signWith)
	qt.Check(t, qt.IsNil(err))

	return str
}

// lanes are the deployment's two providers.
type lanes struct {
	eparaksts, entra *standIn
}

func (l lanes) entries(t *testing.T) []upstream.Entry {
	t.Helper()

	e := upstream.EParakstsProfile(l.eparaksts.url, "")
	e.ClientID = "eparaksts-client"
	ep, err := upstream.New(context.Background(), e, nil)
	qt.Assert(t, qt.IsNil(err))
	dir, err := upstream.New(context.Background(), upstream.Config{
		AuthorizeURL: l.entra.url + "/authorize", TokenURL: l.entra.url + "/token", UserInfoURL: l.entra.url + "/userinfo",
		JWKSURL: l.entra.url + "/jwks", Issuer: l.entra.url + "/v2.0", EndSessionURL: l.entra.url + "/logout",
		ClientID: "entra-client", MethodDefault: "upstream", ClaimDirectoryID: "oid", ClaimAccountStatus: "acct",
	}, nil)
	qt.Assert(t, qt.IsNil(err))

	return []upstream.Entry{
		{
			Name: "eparaksts", Provider: ep, ReturnPath: eparakstsPath,
			ACR: map[string]string{identity.LoginEParakstsMobile: "urn:eparaksts:mobileid", identity.LoginEIDScan: "urn:eparaksts:mobile-eid"},
		},
		{Name: "entra", Provider: dir, ReturnPath: entraPath, DisplayName: "Microsoft Entra", HoldsStored: true},
	}
}

// mapped is one call the identity store was given.
type mapped struct {
	handle  string
	profile store.Profile
}

// byProvider is the identity store in these tests: a person with a code is that
// code's; anyone else is their provider's handle's. Every call is kept.
type byProvider struct {
	mu    sync.Mutex
	calls []mapped
}

func (s *byProvider) EnsureMapping(_ context.Context, handle string, p store.Profile) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, mapped{handle, p})
	if p.SerialNumber != "" {
		return "sub-" + p.SerialNumber, false, nil
	}

	return "sub-" + p.Provider + "|" + handle, false, nil
}

func (s *byProvider) last() mapped {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return mapped{}
	}

	return s.calls[len(s.calls)-1]
}

func (s *byProvider) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.calls)
}

// twoLaneDeployment is the routes over the two-provider set, an in-memory
// session store, the card on the page, the identity store above and recorded
// security events.
type twoLaneDeployment struct {
	app    *azugo.TestApp
	mem    *sessiontest.Memory
	lanes  lanes
	people *byProvider
	events *eventLog
}

func twoLaneApp(t *testing.T) *twoLaneDeployment {
	t.Helper()

	d := &twoLaneDeployment{
		lanes:  lanes{eparaksts: newStandIn(t, false), entra: newStandIn(t, true)},
		people: &byProvider{},
		events: &eventLog{},
		mem:    sessiontest.NewMemory(),
	}
	t.Setenv("WEBEID_ENGINE_URL", "http://localhost:9998")
	t.Setenv("SERVICE_CLIENT_REGISTRY", upstreamsRegistry)
	app := authbytecore.TestApp(t, authbytecore.WithUpstreams(d.lanes.entries(t)...))
	app.SetSessionStore(d.mem)
	app.SetReplay(replay.NewMemory())
	app.SetWebEID(whoseCard{})
	app.SetIdentities(d.people)
	recordingAudit(d.events)(app)
	qt.Assert(t, qt.IsNil(Init(app)))

	d.app = azugo.NewTestApp(app.App)
	d.app.Start(t)
	t.Cleanup(d.app.Stop)

	return d
}

// flowOf is the sign-in flow stored under state, read without spending it.
func (d *twoLaneDeployment) flowOf(t *testing.T, state string) *session.Flow {
	t.Helper()

	raw, ok := d.mem.Entries()["flow:"+state]
	qt.Assert(t, qt.IsTrue(ok), qt.Commentf("no flow under %q", state))
	var f session.Flow
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(raw), &f)))

	return &f
}

// sentTo is where an answer sent the browser on, and the state it carries.
func sentTo(t *testing.T, a answer) (*url.URL, string) {
	t.Helper()

	loc, err := url.Parse(a.location)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("%d %s", a.status, a.body))

	return loc, loc.Query().Get("state")
}

// startDirect starts a sign-in for clientID asking for method by acr_values.
func (d *twoLaneDeployment) startDirect(t *testing.T, tc *azugo.TestClient, clientID, redirectURI, method string, extra url.Values) (*url.URL, string) {
	t.Helper()

	q := url.Values{"acr_values": {method}}
	for k, v := range extra {
		q[k] = v
	}

	return sentTo(t, authorizeIn(t, tc, clientID, redirectURI, q))
}

// complete answers the provider's code on path, in tc's browser.
func complete(t *testing.T, tc *azugo.TestClient, path, state string, extra ...string) answer {
	t.Helper()

	return got(t)(tc.Get(path+"?code=the-providers-code&state="+url.QueryEscape(state)+strings.Join(extra, ""), asBrowser(tc)))
}

// eParakstsPerson is the eParaksts userinfo of a person signing in by method,
// with their code and their signing catalog.
func eParakstsPerson(acr string) string {
	return `{"sub":"opaque-eparaksts-handle","serial_number":"` + annasCard + `","name":"ANNA BĒRZIŅA",` +
		`"given_name":"ANNA","family_name":"BĒRZIŅA","acr":"` + acr + `",` +
		`"sign_identities":[{"id":"id-serverid-sign","description":"eparaksts:serverid:sign","status":{"value":"enabled"},` +
		`"labels":["serverid","x509:keyUsage:contentCommitment"],"access":[{"user_id":"u1","permissions":["sign"]}]}]}`
}

// directoryUserinfo is the directory's userinfo for the person oid: the same subject as its ID token.
func directoryUserinfo(oid string) string {
	return `{"sub":"pairwise-` + oid + `","name":"Directory Person"}`
}

// signInByEntra completes a direct Entra sign-in for clientID in tc's browser as
// the directory person oid, answering where the browser was sent.
func (d *twoLaneDeployment) signInByEntra(t *testing.T, tc *azugo.TestClient, clientID, redirectURI, oid string) answer {
	t.Helper()

	_, state := d.startDirect(t, tc, clientID, redirectURI, "upstream", nil)
	d.lanes.entra.answer(directoryUserinfo(oid))
	d.lanes.entra.expect(d.flowOf(t, state).Nonce, oid)

	return complete(t, tc, entraPath, state)
}

// signInByEParaksts completes a direct eParaksts Mobile sign-in for clientID.
func (d *twoLaneDeployment) signInByEParaksts(t *testing.T, tc *azugo.TestClient, clientID, redirectURI string) answer {
	t.Helper()

	_, state := d.startDirect(t, tc, clientID, redirectURI, identity.LoginEParakstsMobile, nil)
	d.lanes.eparaksts.answer(eParakstsPerson("urn:eparaksts:mobileid"))

	return complete(t, tc, eparakstsPath, state)
}

// failures are the recorded failed sign-ins' reasons.
func (l *eventLog) failures() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []string
	for _, ev := range l.events {
		if ev.EventType == secevents.EventAuthentication && ev.Outcome == broker.OutcomeFailure {
			r, _ := ev.Attributes[secevents.AttrReason].(string)
			out = append(out, r)
		}
	}

	return out
}

// successes are the recorded successful sign-ins' methods.
func (l *eventLog) successes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []string
	for _, ev := range l.events {
		if ev.EventType == secevents.EventAuthentication && ev.Outcome == broker.OutcomeSuccess &&
			ev.Attributes[secevents.AttrKind] == nil {
			m, _ := ev.Attributes[secevents.AttrMethod].(string)
			out = append(out, m)
		}
	}

	return out
}

// Case 9 (and 1's discovery, call 3): the page lists the client's ways across
// both providers, each by its own name, and nothing the client does not allow;
// discovery offers every entry's methods and the card.
func TestThePageListsTheWaysOfEveryProvider(t *testing.T) {
	d := twoLaneApp(t)

	p := showPage(t, d.app.TestClient(), pageQuery("mobile-and-entra", meReturn))
	qt.Assert(t, qt.Equals(p.status, fasthttp.StatusOK), qt.Commentf("%s", p.body))
	qt.Check(t, qt.DeepEquals(ways(p.body), []string{identity.LoginEParakstsMobile, "upstream"}))
	qt.Check(t, qt.StringContains(p.body, "eParaksts Mobile"))
	qt.Check(t, qt.StringContains(p.body, "Microsoft Entra"))
	qt.Check(t, qt.Not(qt.StringContains(p.body, "eID Scan")))
	// The page's form may send the browser on to either provider.
	csp := p.header["Content-Security-Policy"]
	qt.Check(t, qt.StringContains(csp, d.lanes.eparaksts.url), qt.Commentf("%s", csp))
	qt.Check(t, qt.StringContains(csp, d.lanes.entra.url), qt.Commentf("%s", csp))

	resp, err := d.app.TestClient().Get("/.well-known/openid-configuration")
	qt.Assert(t, qt.IsNil(err))
	var doc struct {
		ACR []string `json:"acr_values_supported"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &doc)))
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.DeepEquals(doc.ACR, []string{identity.LoginEIDScan, identity.LoginEParakstsMobile, "upstream", identity.LoginWebEID}))
}

// Cases 10 and 12 (call 2): a named way goes straight to its own provider, with
// that provider's return address, its own words for the method and the
// client's sign-in demands; the flow records the provider.
func TestANamedWayGoesToItsOwnProvider(t *testing.T) {
	d := twoLaneApp(t)
	maxAge := url.Values{"prompt": {"login"}, "max_age": {"300"}}

	loc, state := d.startDirect(t, d.app.TestClient(), "mobile-and-entra", meReturn, "upstream", maxAge)
	qt.Check(t, qt.Equals(loc.Scheme+"://"+loc.Host+loc.Path, d.lanes.entra.url+"/authorize"))
	qt.Check(t, qt.Equals(loc.Query().Get("redirect_uri"), selfOriginInTests+entraPath))
	qt.Check(t, qt.Equals(loc.Query().Get("client_id"), "entra-client"))
	qt.Check(t, qt.Equals(loc.Query().Get("acr_values"), ""))
	qt.Check(t, qt.Equals(loc.Query().Get("prompt"), "login"))
	qt.Check(t, qt.Equals(loc.Query().Get("max_age"), "300"))
	f := d.flowOf(t, state)
	qt.Check(t, qt.Equals(f.Upstream, "entra"))
	qt.Check(t, qt.Equals(f.EntrustRedirectURI, selfOriginInTests+entraPath))

	loc, state = d.startDirect(t, d.app.TestClient(), "mobile-and-entra", meReturn, identity.LoginEParakstsMobile, maxAge)
	qt.Check(t, qt.Equals(loc.Scheme+"://"+loc.Host, d.lanes.eparaksts.url))
	qt.Check(t, qt.Equals(loc.Query().Get("redirect_uri"), selfOriginInTests+eparakstsPath))
	qt.Check(t, qt.Equals(loc.Query().Get("client_id"), "eparaksts-client"))
	qt.Check(t, qt.Equals(loc.Query().Get("acr_values"), "urn:eparaksts:mobileid"))
	qt.Check(t, qt.Equals(loc.Query().Get("prompt"), "login"))
	qt.Check(t, qt.Equals(loc.Query().Get("max_age"), "300"))
	qt.Check(t, qt.Equals(d.flowOf(t, state).Upstream, "eparaksts"))

	// The page's pick goes the same way.
	tc := d.app.TestClient()
	p := showPage(t, tc, pageQuery("mobile-and-entra", meReturn))
	loc, state = sentTo(t, choose(t, tc, p, "upstream", p.token, selfOriginInTests))
	qt.Check(t, qt.Equals(loc.Scheme+"://"+loc.Host+loc.Path, d.lanes.entra.url+"/authorize"))
	qt.Check(t, qt.Equals(d.flowOf(t, state).Upstream, "entra"))
}

// A request naming ways of two providers names no one provider to go to: the
// person picks on the page, among the ways it named.
func TestWaysOfTwoProvidersArePickedOnThePage(t *testing.T) {
	d := twoLaneApp(t)

	q := pageQuery("mobile-and-entra", meReturn)
	q.Set("acr_values", identity.LoginEParakstsMobile+" upstream")
	p := showPage(t, d.app.TestClient(), q)
	qt.Assert(t, qt.Equals(p.status, fasthttp.StatusOK), qt.Commentf("%s", p.location))
	qt.Check(t, qt.DeepEquals(ways(p.body), []string{identity.LoginEParakstsMobile, "upstream"}))
}

// Case 11: a way the client allows that no provider offers is not on the page,
// and asked for directly it is refused, as before.
func TestAWayNoProviderOffersIsNeitherShownNorStarted(t *testing.T) {
	d := twoLaneApp(t)

	p := showPage(t, d.app.TestClient(), pageQuery("with-google", googleRet))
	qt.Check(t, qt.DeepEquals(ways(p.body), []string{"upstream"}))

	loc, _ := sentTo(t, authorizeIn(t, d.app.TestClient(), "with-google", googleRet, url.Values{"acr_values": {"google"}}))
	qt.Check(t, qt.Equals(loc.Query().Get("error"), "unmet_authentication_requirements"))
	qt.Check(t, qt.Equals(len(d.mem.Keys("flow:")), 0))
}

// Cases 13, 18, 20 and 26: each provider's answer on its own path completes the
// sign-in with that provider's method. The directory's ID token is verified
// against its own keys; eParaksts is read from userinfo. The identity store is
// told which provider each handle came from, and the event names the method.
func TestEachProviderCompletesOnItsOwnPath(t *testing.T) {
	d := twoLaneApp(t)

	tc := d.app.TestClient()
	a := d.signInByEntra(t, tc, "entra-only", entraReturn, "oid-1")
	code := codeAt(t, a, entraReturn)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%d %s %s", a.status, a.location, a.body))
	_, sess := sessionOf(t, d.mem, code)
	qt.Check(t, qt.Equals(sess.LoginMethod, "upstream"))
	qt.Check(t, qt.Equals(d.lanes.entra.exchanges.Load(), int32(1)))
	qt.Check(t, qt.Equals(d.lanes.eparaksts.exchanges.Load(), int32(0)))
	m := d.people.last()
	qt.Check(t, qt.Equals(m.handle, "oid-1"))
	qt.Check(t, qt.Equals(m.profile.Provider, ""), qt.Commentf("the holder of the stored sign-ins keys its people as they were stored"))

	tc = d.app.TestClient()
	a = d.signInByEParaksts(t, tc, "mobile-and-entra", meReturn)
	code = codeAt(t, a, meReturn)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%d %s %s", a.status, a.location, a.body))
	_, sess = sessionOf(t, d.mem, code)
	qt.Check(t, qt.Equals(sess.LoginMethod, identity.LoginEParakstsMobile))
	qt.Check(t, qt.Equals(d.lanes.eparaksts.exchanges.Load(), int32(1)))
	m = d.people.last()
	qt.Check(t, qt.Equals(m.handle, "opaque-eparaksts-handle"))
	qt.Check(t, qt.Equals(m.profile.Provider, d.lanes.eparaksts.url))

	qt.Check(t, qt.DeepEquals(d.events.successes(), []string{"upstream", identity.LoginEParakstsMobile}))

	// 18: an ID token signed with a key the directory does not publish is refused.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))
	d.lanes.entra.mu.Lock()
	d.lanes.entra.signWith = other
	d.lanes.entra.mu.Unlock()
	tc = d.app.TestClient()
	a = d.signInByEntra(t, tc, "entra-only", entraReturn, "oid-2")
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized), qt.Commentf("%s %s", a.location, a.body))
	qt.Check(t, qt.Equals(codeAt(t, a, entraReturn), ""))
}

// Cases 14, 15 and 26 (call 2, the mix-up defence): an answer arriving on the
// return path of a provider other than the one the sign-in went to is refused
// before any code is exchanged: neither provider is called, no session is made,
// and the refusal is audited without naming anybody. So is an answer whose iss
// names another issuer than the provider's own.
func TestAnAnswerOnAnotherProvidersPathIsRefusedBeforeAnyExchange(t *testing.T) {
	d := twoLaneApp(t)

	for _, c := range []struct {
		name, method, path string
		extra              string
	}{
		{"begun for Entra, answered on eParaksts' path", "upstream", eparakstsPath, ""},
		{"begun for eParaksts, answered on Entra's path", identity.LoginEParakstsMobile, entraPath, ""},
		{"begun for Entra, answered with another issuer", "upstream", entraPath, "&iss=" + url.QueryEscape("https://attacker.example")},
		{"begun for Entra, an error answered on eParaksts' path", "upstream", eparakstsPath, "&error=access_denied"},
	} {
		tc := d.app.TestClient()
		_, state := d.startDirect(t, tc, "mobile-and-entra", meReturn, c.method, nil)
		before := d.people.count()
		failed := len(d.events.failures())

		a := complete(t, tc, c.path, state, c.extra)
		qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized), qt.Commentf("%s: %s %s", c.name, a.location, a.body))
		qt.Check(t, qt.IsTrue(isCannotStart(a)), qt.Commentf("%s", c.name))
		qt.Check(t, qt.Equals(d.lanes.entra.exchanges.Load()+d.lanes.eparaksts.exchanges.Load(), int32(0)), qt.Commentf("%s", c.name))
		qt.Check(t, qt.Equals(d.people.count(), before), qt.Commentf("%s: nothing written", c.name))
		qt.Check(t, qt.HasLen(d.mem.Keys("code:"), 0), qt.Commentf("%s", c.name))
		_, err := d.mem.ConsumeFlow(context.Background(), state)
		qt.Check(t, qt.IsNotNil(err), qt.Commentf("%s: the flow is spent", c.name))

		// The refusal is the last failure recorded; an error answer was recorded
		// as the provider's error before it, as every error answer is.
		reasons := d.events.failures()[failed:]
		qt.Assert(t, qt.Not(qt.HasLen(reasons, 0)), qt.Commentf("%s", c.name))
		refusal := reasons[len(reasons)-1]
		qt.Check(t, qt.IsTrue(strings.Contains(refusal, "another provider's return path") ||
			strings.Contains(refusal, "another issuer")), qt.Commentf("%s: %v", c.name, reasons))
		for _, r := range reasons {
			qt.Check(t, qt.Not(qt.StringContains(r, state)), qt.Commentf("%s", c.name))
			qt.Check(t, qt.Not(qt.StringContains(r, "the-providers-code")), qt.Commentf("%s", c.name))
		}
	}

	// The provider's own issuer in iss is no refusal.
	tc := d.app.TestClient()
	_, state := d.startDirect(t, tc, "entra-only", entraReturn, "upstream", nil)
	d.lanes.entra.answer(directoryUserinfo("oid-3"))
	d.lanes.entra.expect(d.flowOf(t, state).Nonce, "oid-3")
	a := complete(t, tc, entraPath, state, "&iss="+url.QueryEscape(d.lanes.entra.url+"/v2.0"))
	qt.Check(t, qt.Not(qt.Equals(codeAt(t, a, entraReturn), "")), qt.Commentf("%d %s %s", a.status, a.location, a.body))
}

// unnamed rewrites the flow stored under state as one stored before providers
// were named.
func unnamed(t *testing.T, mem *sessiontest.Memory, state string) {
	t.Helper()

	var f session.Flow
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(mem.Entries()["flow:"+state]), &f)))
	f.Upstream = ""
	qt.Assert(t, qt.IsNil(mem.SaveFlow(context.Background(), state, &f, time.Minute)))
}

// A sign-in begun before the upgrade (its flow names no provider) completes on
// the open build, whose one provider it was sent to; on a set of several the
// provider it went to is unknown, so it is refused before any exchange.
func TestAFlowStoredBeforeProvidersWereNamed(t *testing.T) {
	app, mem := pageApp(t)
	tc := app.TestClient()
	q := pageQuery("every-way", everyReturn)
	q.Set("acr_values", identity.LoginEIDScan)
	state := providerState(t, got(t)(tc.Get("/authorize?"+q.Encode())))
	unnamed(t, mem, state)
	a := got(t)(tc.Get("/callback?code=x&state="+state, asBrowser(tc)))
	qt.Check(t, qt.IsFalse(isCannotStart(a)), qt.Commentf("%d %s", a.status, a.body))

	d := twoLaneApp(t)
	tc = d.app.TestClient()
	_, state = d.startDirect(t, tc, "mobile-and-entra", meReturn, "upstream", nil)
	unnamed(t, d.mem, state)
	a = complete(t, tc, entraPath, state)
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized), qt.Commentf("%s", a.body))
	qt.Check(t, qt.Equals(d.lanes.entra.exchanges.Load(), int32(0)))
}

// Cases 16 and 17: each provider's own rules still hold. eParaksts answering
// with a method it may not deliver is refused; an unknown state on either path,
// and an answer reaching another browser, are refused as before.
func TestEachProvidersOwnRulesHold(t *testing.T) {
	d := twoLaneApp(t)

	tc := d.app.TestClient()
	_, state := d.startDirect(t, tc, "mobile-and-entra", meReturn, identity.LoginEParakstsMobile, nil)
	d.lanes.eparaksts.answer(eParakstsPerson("urn:eparaksts:sc_plugin"))
	a := complete(t, tc, eparakstsPath, state)
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusForbidden), qt.Commentf("%s %s", a.location, a.body))
	qt.Check(t, qt.HasLen(d.mem.Keys("code:"), 0))

	for _, path := range []string{eparakstsPath, entraPath} {
		a = complete(t, d.app.TestClient(), path, "nobody-knows-it")
		qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized), qt.Commentf("%s", path))
		qt.Check(t, qt.IsTrue(isCannotStart(a)), qt.Commentf("%s", path))
	}

	_, state = d.startDirect(t, d.app.TestClient(), "entra-only", entraReturn, "upstream", nil)
	exchanged := d.lanes.entra.exchanges.Load()
	a = complete(t, d.app.TestClient(), entraPath, state)
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusUnauthorized))
	qt.Check(t, qt.Equals(d.lanes.entra.exchanges.Load(), exchanged))
}

// Case 19: a person signed in by the directory (no code), then by eParaksts
// (a code), in one browser, is two people: the second sign-in is another
// person's, so the first person's apps end.
func TestAnotherProviderWithoutACommonCodeIsAnotherPerson(t *testing.T) {
	d := twoLaneApp(t)

	tc := d.app.TestClient()
	first := codeAt(t, d.signInByEntra(t, tc, "mobile-and-entra", meReturn, "oid-4"), meReturn)
	qt.Assert(t, qt.Not(qt.Equals(first, "")))
	firstSid, firstSess := sessionOf(t, d.mem, first)

	second := codeAt(t, d.signInByEParaksts(t, tc, "mobile-and-entra", meReturn), meReturn)
	qt.Assert(t, qt.Not(qt.Equals(second, "")))
	_, secondSess := sessionOf(t, d.mem, second)

	qt.Check(t, qt.Not(qt.Equals(firstSess.Subject, secondSess.Subject)))
	_, err := d.mem.LoadSession(context.Background(), firstSid)
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound), qt.Commentf("the first person's app session ended"))
	_, sh := sharedOf(t, d.mem, tc)
	qt.Check(t, qt.Equals(sh.Subject, secondSess.Subject))
}

// The card's sign-in is keyed as it always was: by the empty provider.
func TestTheCardKeysItsPeopleAsBefore(t *testing.T) {
	d := twoLaneApp(t)

	a, _ := signInByCard(t, d.app.TestClient(), "card-sso", cardsReturn, annasCard)
	qt.Assert(t, qt.Not(qt.Equals(codeAt(t, a, cardsReturn), "")), qt.Commentf("%d %s", a.status, a.body))
	qt.Check(t, qt.Equals(d.people.last().profile.Provider, ""))
}

// Cases 21 and 23 (C6's rules, per way): a single sign-on client is answered from
// a shared session made by eParaksts when it allows that way, and is shown the
// page when it allows only the directory's; a shared session made by the
// directory (no code) never answers a client whose tokens carry the code.
func TestTheSharedSessionAnswersByTheWayItWasMade(t *testing.T) {
	d := twoLaneApp(t)

	tc := d.app.TestClient()
	cookie := seedShared(t, d.mem, "sub-anna", annasCode, aWay(identity.LoginEParakstsMobile))
	a := authorizeIn(t, tc, "mobile-and-entra", meReturn, nil, tc.WithCookie(sharedCookie, cookie))
	qt.Check(t, qt.Not(qt.Equals(codeAt(t, a, meReturn), "")), qt.Commentf("%d %s", a.status, a.location))

	tc = d.app.TestClient()
	cookie = seedShared(t, d.mem, "sub-anna", annasCode, aWay(identity.LoginEParakstsMobile))
	a = authorizeIn(t, tc, "entra-only", entraReturn, nil, tc.WithCookie(sharedCookie, cookie))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK), qt.Commentf("%s", a.location))
	qt.Check(t, qt.DeepEquals(ways(a.body), []string{"upstream"}))

	tc = d.app.TestClient()
	cookie = seedShared(t, d.mem, "sub-directory", "", aWay("upstream"))
	a = authorizeIn(t, tc, "needs-code-sso", codesReturn, nil, tc.WithCookie(sharedCookie, cookie))
	qt.Check(t, qt.Equals(codeAt(t, a, codesReturn), ""))
}

// Case 22: a signing client's sign-in reads the signing identities from the
// provider it signed in through, never from another.
func TestSigningIdentitiesComeFromTheProviderSignedInThrough(t *testing.T) {
	d := twoLaneApp(t)

	a := d.signInByEParaksts(t, d.app.TestClient(), "signer", signReturn)
	code := codeAt(t, a, signReturn)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%d %s %s", a.status, a.location, a.body))
	_, sess := sessionOf(t, d.mem, code)
	qt.Check(t, qt.IsNotNil(sess.Capabilities))
	qt.Check(t, qt.Not(qt.Equals(d.lanes.eparaksts.certs.Load(), int32(0))))
	qt.Check(t, qt.Equals(d.lanes.entra.certs.Load(), int32(0)))

	a = d.signInByEntra(t, d.app.TestClient(), "signer", signReturn, "oid-5")
	code = codeAt(t, a, signReturn)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%d %s %s", a.status, a.location, a.body))
	_, sess = sessionOf(t, d.mem, code)
	qt.Check(t, qt.IsNil(sess.Capabilities))
	qt.Check(t, qt.Equals(d.lanes.entra.certs.Load(), int32(0)))
}

// Case 24: a sign-out after eParaksts also clears eParaksts' own session; one
// after the directory leaves the directory's alone.
func TestSignOutVisitsOnlyTheProviderSignedInThrough(t *testing.T) {
	d := twoLaneApp(t)

	for _, c := range []struct {
		method string
		at     string
	}{
		{identity.LoginEParakstsMobile, d.lanes.eparaksts.url + "/trustedx-authserver/"},
		{identity.LoginEIDScan, d.lanes.eparaksts.url + "/trustedx-authserver/"},
		{"upstream", "https://me.example/"},
		{identity.LoginWebEID, "https://me.example/"},
	} {
		a := got(t)(d.app.TestClient().Get("/logout?client_id=mobile-and-entra&redirect_uri=" +
			url.QueryEscape("https://me.example/") + "&login_method=" + c.method))
		qt.Check(t, qt.IsTrue(strings.HasPrefix(a.location, c.at)), qt.Commentf("%s: %s", c.method, a.location))
	}
}

// Case 25: one person signed in to two apps through two lanes (eParaksts Mobile
// and the card, one code) signs out of both at once.
func TestASignOutEndsAppsOfEveryLane(t *testing.T) {
	d := twoLaneApp(t)

	tc := d.app.TestClient()
	byMobile := codeAt(t, d.signInByEParaksts(t, tc, "mobile-and-entra", meReturn), meReturn)
	qt.Assert(t, qt.Not(qt.Equals(byMobile, "")))
	mobileSid, _ := sessionOf(t, d.mem, byMobile)

	a, _ := signInByCard(t, tc, "card-sso", cardsReturn, annasCard)
	byCard := codeAt(t, a, cardsReturn)
	qt.Assert(t, qt.Not(qt.Equals(byCard, "")), qt.Commentf("%d %s", a.status, a.body))
	cardSid, _ := sessionOf(t, d.mem, byCard)

	out := got(t)(tc.Get("/logout?client_id=mobile-and-entra&redirect_uri=" + url.QueryEscape("https://me.example/") +
		"&login_method=" + identity.LoginEParakstsMobile))
	qt.Check(t, qt.Not(qt.Equals(out.location, "")))
	for _, sid := range []string{mobileSid, cardSid} {
		_, err := d.mem.LoadSession(context.Background(), sid)
		qt.Check(t, qt.IsTrue(errors.Is(err, session.ErrNotFound)), qt.Commentf("app session %s", sid))
	}
}

// Call 3 at the routes: a return path one of the service's own routes uses is
// refused at the start, naming it.
func TestAReturnPathOnACoreRouteIsRefused(t *testing.T) {
	l := lanes{eparaksts: newStandIn(t, false), entra: newStandIn(t, true)}
	for _, path := range []string{"/token", "/authorize", "/authorize/choice", "/signin/web-eid.js", "/logout",
		"/revoke", "/identity", "/identity/persons", "/.well-known/jwks.json", "/healthz", "/readyz"} {
		entries := l.entries(t)
		entries[1].ReturnPath = path
		app := authbytecore.TestApp(t, authbytecore.WithUpstreams(entries...))
		err := Init(app)
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("a return path on %s: err = %v, want a refusal naming it", path, err)
		}
	}
}
