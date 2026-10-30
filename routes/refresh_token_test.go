package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmb-lib/go-authbyte/dpop"
	"github.com/gmb-lib/go-authbyte/replay"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"
	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// testHost is the host the token tests send to; a DPoP proof names it.
const testHost = "authbyte.test"

// sessionLifetime is the lifetime the tests' sign-ins are given.
const sessionLifetime = 12 * time.Hour

// signInApp runs the real routes over an in-memory session store.
func signInApp(t *testing.T, setup ...func(*authbytecore.App)) (*azugo.TestApp, *sessiontest.Memory) {
	t.Helper()

	t.Setenv("SERVICE_CLIENT_REGISTRY", testRegistry)
	app := authbytecore.TestApp(t)
	mem := sessiontest.NewMemory()
	app.SetSessionStore(mem)
	app.SetReplay(replay.NewMemory())
	for _, s := range setup {
		s(app)
	}
	qt.Assert(t, qt.IsNil(Init(app)))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return ta, mem
}

// signIn is a completed sign-in waiting for its code exchange: what the person's
// login left in the store.
type signIn struct {
	sid      string
	code     string
	verifier string
}

// seedSignIn stores a session and an application code for it, as a completed
// login at the card door or the provider's callback does.
func seedSignIn(t *testing.T, mem *sessiontest.Memory, clientID, redirectURI string) signIn {
	t.Helper()

	in := signIn{sid: randomToken(24), code: randomToken(24), verifier: randomToken(32)}
	sum := sha256.Sum256([]byte(in.verifier))

	ctx := context.Background()
	qt.Assert(t, qt.IsNil(mem.CreateSession(ctx, in.sid, &session.Session{
		Subject:     testPersonSub(5),
		LoA:         "high",
		LoginMethod: "webEid",
		Scopes:      defaultUserScopes,
	}, sessionLifetime)))
	qt.Assert(t, qt.IsNil(mem.SaveAppCode(ctx, in.code, &session.AppCode{
		SessionID:           in.sid,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(sum[:]),
		CodeChallengeMethod: "S256",
		ClientID:            clientID,
		RedirectURI:         redirectURI,
	}, time.Minute)))

	return in
}

// edge is a client of the token endpoint holding one DPoP key, the way a
// product's edge holds the key its session is bound to.
type edge struct {
	t     *testing.T
	app   *azugo.TestApp
	key   *ecdsa.PrivateKey
	nonce string
	mu    sync.Mutex
}

func newEdge(t *testing.T, app *azugo.TestApp) *edge {
	t.Helper()

	key, err := dpop.GenerateKey()
	qt.Assert(t, qt.IsNil(err))

	return &edge{t: t, app: app, key: key}
}

// post sends a form with a fresh DPoP proof, answering the server's nonce
// challenge once.
func (e *edge) post(path string, form url.Values) (int, map[string]any) {
	e.t.Helper()

	for attempt := 0; ; attempt++ {
		e.mu.Lock()
		nonce := e.nonce
		e.mu.Unlock()

		proof, err := dpop.GenerateProof(e.key, fasthttp.MethodPost, "http://"+testHost+path, "", nonce)
		qt.Assert(e.t, qt.IsNil(err))

		tc := e.app.TestClient()
		resp, err := tc.Post(path, []byte(form.Encode()),
			tc.WithHost(testHost),
			tc.WithHeader("Content-Type", "application/x-www-form-urlencoded"),
			tc.WithHeader("DPoP", proof))
		qt.Assert(e.t, qt.IsNil(err))

		status := resp.StatusCode()
		fresh := string(resp.Header.Peek("DPoP-Nonce"))
		body := append([]byte(nil), resp.Body()...)
		fasthttp.ReleaseResponse(resp)

		if status == fasthttp.StatusUnauthorized && fresh != "" && attempt == 0 {
			e.mu.Lock()
			e.nonce = fresh
			e.mu.Unlock()

			continue
		}

		var out map[string]any
		if len(body) > 0 {
			_ = json.Unmarshal(body, &out)
		}
		if out == nil {
			out = map[string]any{}
		}
		out["_raw"] = string(body)

		return status, out
	}
}

func (e *edge) exchange(in signIn, clientID, redirectURI string) (int, map[string]any) {
	return e.post("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {in.code},
		"code_verifier": {in.verifier},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
	})
}

func (e *edge) refresh(token, clientID string) (int, map[string]any) {
	return e.post("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
		"client_id":     {clientID},
	})
}

func (e *edge) revoke(token, clientID string) (int, map[string]any) {
	return e.post("/revoke", url.Values{
		"token":           {token},
		"token_type_hint": {"refresh_token"},
		"client_id":       {clientID},
	})
}

const (
	portalRedirect  = "https://portal.example/callback"
	productRedirect = "https://product.example/callback"
)

// signedIn completes a sign-in for portal-spa and answers its refresh token.
func signedIn(t *testing.T, app *azugo.TestApp, mem *sessiontest.Memory, e *edge) (signIn, string) {
	t.Helper()

	in := seedSignIn(t, mem, "portal-spa", portalRedirect)
	status, body := e.exchange(in, "portal-spa", portalRedirect)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	refresh, _ := body["refresh_token"].(string)
	qt.Assert(t, qt.Not(qt.Equals(refresh, "")))

	return in, refresh
}

// The refresh token a code exchange answers is its own value: the session's
// internal id is not it, and appears in no answer.
func TestTheRefreshTokenIsNotTheSessionID(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	in, refresh := signedIn(t, app, mem, e)

	qt.Check(t, qt.Not(qt.Equals(refresh, in.sid)))

	status, body := e.refresh(refresh, "portal-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	qt.Check(t, qt.IsFalse(strings.Contains(body["_raw"].(string), in.sid)))
}

// The store keeps the refresh token only as a hash: no key and no value it
// holds is the token itself.
func TestTheStoreKeepsNoRefreshToken(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	_, refresh := signedIn(t, app, mem, e)

	for k, v := range mem.Entries() {
		qt.Check(t, qt.IsFalse(strings.Contains(k, refresh)), qt.Commentf("key %q", k))
		qt.Check(t, qt.IsFalse(strings.Contains(v, refresh)), qt.Commentf("value under %q", k))
	}
}

// A refresh token is bound to the client it was issued to: another client
// presenting it with the session's own key gets the answer an ended session
// gets, and the session still refreshes for its own client.
func TestARefreshByAnotherClientIsRefused(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	_, refresh := signedIn(t, app, mem, e)

	status, body := e.refresh(refresh, "product-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%s", body["_raw"]))

	status, body = e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
}

// A refresh token is bound to the session's key: presented with another key it
// is refused, and the session still refreshes with its own.
func TestARefreshWithAnotherKeyLeavesTheSession(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	_, refresh := signedIn(t, app, mem, e)

	status, _ := newEdge(t, app).refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))

	status, body := e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
}

// Two refreshes of one session at the same moment both succeed: the token is
// not rotated, so neither signs the other out.
func TestTwoRefreshesAtOnceBothSucceed(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	_, refresh := signedIn(t, app, mem, e)

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], _ = e.refresh(refresh, "portal-spa")
		}()
	}
	wg.Wait()

	qt.Check(t, qt.DeepEquals(statuses, []int{fasthttp.StatusOK, fasthttp.StatusOK}))

	status, _ := e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK))
}

// A session's lifetime runs from the sign-in and is not extended by what is
// saved on it later: the code exchange an hour in leaves the end where it was.
func TestASessionEndsAtItsLifetimeFromTheSignIn(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	start := time.Now()
	now := start
	var mu sync.Mutex
	mem.SetClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()

		return now
	})
	at := func(d time.Duration) {
		mu.Lock()
		now = start.Add(d)
		mu.Unlock()
	}

	in := seedSignIn(t, mem, "portal-spa", portalRedirect)
	at(30 * time.Second)
	status, body := e.exchange(in, "portal-spa", portalRedirect)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	refresh := body["refresh_token"].(string)

	at(sessionLifetime - time.Second)
	status, body = e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("before the end: %s", body["_raw"]))

	at(sessionLifetime)
	status, _ = e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("at the end"))
}

// Sign-out ends the session at the authority, server to server: its refresh
// token is refused afterwards.
func TestARefreshAfterSignOutIsRefused(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	_, refresh := signedIn(t, app, mem, e)

	status, body := e.revoke(refresh, "portal-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	status, _ = e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))
	qt.Check(t, qt.HasLen(mem.Keys("sess:"), 0))
	qt.Check(t, qt.HasLen(mem.Keys("refresh:"), 0))
}

// Only the session's own client, proving the session's key, ends it: another
// client, or the right client with another key, is refused and the session
// still refreshes for its own client.
func TestASignOutByAnotherClientOrKeyIsRefused(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	_, refresh := signedIn(t, app, mem, e)

	status, _ := e.revoke(refresh, "product-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("another client"))

	status, _ = newEdge(t, app).revoke(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("another key"))

	status, body := e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	// The positive control: the session's own client with its key ends it.
	status, body = e.revoke(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	status, _ = e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}

// Ending a session is recorded once, naming the person and the method they signed
// in with; a refused attempt records no ending.
func TestASignOutIsRecordedOnce(t *testing.T) {
	events := &eventLog{}
	app, mem := signInApp(t, recordingAudit(events))
	e := newEdge(t, app)

	_, refresh := signedIn(t, app, mem, e)

	ended := func() []*broker.Envelope {
		events.mu.Lock()
		defer events.mu.Unlock()

		var out []*broker.Envelope
		for _, ev := range events.events {
			if ev.Attributes[secevents.AttrKind] == "session_ended" {
				out = append(out, ev)
			}
		}

		return out
	}

	status, _ := e.revoke(refresh, "product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))
	qt.Check(t, qt.HasLen(ended(), 0))

	status, _ = e.revoke(refresh, "portal-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	got := ended()
	qt.Assert(t, qt.HasLen(got, 1))
	qt.Check(t, qt.Equals(got[0].Actor.ID, testPersonSub(5)))
	qt.Check(t, qt.Equals(got[0].Attributes[secevents.AttrMethod], any("webEid")))
}

// A token the authority does not hold is answered as revoked
// [RFC 7009 §2.2]: there is nothing to end, and the caller can do nothing
// with an error.
func TestASignOutOfAnUnknownTokenSucceeds(t *testing.T) {
	app, _ := signInApp(t)

	status, body := newEdge(t, app).revoke("not-a-token-this-authority-issued", "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
}

// The browser's sign-out address takes no session value: a refresh token put
// there ends nothing, so no client has a reason to put one in a browser
// address.
func TestTheBrowserSignOutTakesNoSessionValue(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	_, refresh := signedIn(t, app, mem, e)

	q := url.Values{"client_id": {"portal-spa"}, "redirect_uri": {portalRedirect}, "sid": {refresh}}
	tc := app.TestClient()
	resp, err := tc.Get("/logout?"+q.Encode(), tc.WithHost(testHost))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))
	fasthttp.ReleaseResponse(resp)

	status, body := e.refresh(refresh, "portal-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
}

// A step-up names the session by its refresh token and its own client; the
// internal session id names nothing outside the authority.
func TestAStepUpNamesTheSessionByItsRefreshToken(t *testing.T) {
	app, mem := signInApp(t)
	e := newEdge(t, app)

	in, refresh := signedIn(t, app, mem, e)

	stepUp := func(token, clientID string) int {
		body, err := json.Marshal(map[string]string{
			"refresh_token":  token,
			"client_id":      clientID,
			"method":         "webEid",
			"code_challenge": "a-challenge",
			"redirect_uri":   portalRedirect,
		})
		qt.Assert(t, qt.IsNil(err))

		tc := app.TestClient()
		resp, err := tc.Post("/step-up", body, tc.WithHost(testHost), tc.WithHeader("Content-Type", "application/json"))
		qt.Assert(t, qt.IsNil(err))
		defer fasthttp.ReleaseResponse(resp)

		return resp.StatusCode()
	}

	flows := func() int { return len(mem.Keys("flow:")) }

	qt.Check(t, qt.Equals(stepUp(in.sid, "portal-spa"), fasthttp.StatusUnauthorized), qt.Commentf("the internal id"))
	qt.Check(t, qt.Equals(stepUp(refresh, "product-spa"), fasthttp.StatusUnauthorized), qt.Commentf("another client"))
	qt.Check(t, qt.Equals(flows(), 0))

	qt.Check(t, qt.Equals(stepUp(refresh, "portal-spa"), fasthttp.StatusOK))
	qt.Check(t, qt.Equals(flows(), 1))
}
