package routes

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// appIn is one app's session in a browser: the edge holding its key, its tokens
// and its session at the authority.
type appIn struct {
	client  string
	edge    *edge
	refresh string
	access  string
	sid     string
}

// cardSignedIn signs code's card in through client's page in tc's browser and redeems
// the code.
func cardSignedIn(t *testing.T, app *azugo.TestApp, mem *sessiontest.Memory, tc *azugo.TestClient, client, redirectURI, code string) appIn {
	t.Helper()

	a, verifier := signInByCard(t, tc, client, redirectURI, code)

	return redeemed(t, app, mem, client, redirectURI, codeAt(t, a, redirectURI), verifier)
}

// answeredApp is client answered from tc's browser's shared session with no page,
// its code redeemed.
func answeredApp(t *testing.T, app *azugo.TestApp, mem *sessiontest.Memory, tc *azugo.TestClient, client, redirectURI string) appIn {
	t.Helper()

	verifier, challenge := pkce()
	a := authorizeIn(t, tc, client, redirectURI, url.Values{"code_challenge": {challenge}})
	code := codeAt(t, a, redirectURI)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%s: %d %s %s", client, a.status, a.location, a.body))

	return redeemed(t, app, mem, client, redirectURI, code, verifier)
}

func redeemed(t *testing.T, app *azugo.TestApp, mem *sessiontest.Memory, client, redirectURI, code, verifier string) appIn {
	t.Helper()

	sid, _ := sessionOf(t, mem, code)
	e := newEdge(t, app)
	status, body := e.exchange(signIn{code: code, verifier: verifier}, client, redirectURI)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", client, body["_raw"]))

	return appIn{client: client, edge: e, refresh: body["refresh_token"].(string), access: body["access_token"].(string), sid: sid}
}

// renews answers the status of the app's refresh, as the app renews.
func (a appIn) renews() int {
	status, _ := a.edge.refresh(a.refresh, a.client)

	return status
}

// signsOut answers the status of the app's revoke, as the app signs out.
func (a appIn) signsOut() int {
	status, _ := a.edge.revoke(a.refresh, a.client)

	return status
}

// ended requires the app's session and its refresh grant gone, and its refresh
// refused as an ended session's is.
func (a appIn) ended(t *testing.T, mem *sessiontest.Memory) {
	t.Helper()

	_, err := mem.LoadSession(context.Background(), a.sid)
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound), qt.Commentf("%s's session", a.client))
	_, err = mem.LoadRefresh(context.Background(), refreshKey(a.refresh))
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound), qt.Commentf("%s's refresh grant", a.client))
	qt.Check(t, qt.Equals(a.renews(), fasthttp.StatusUnauthorized), qt.Commentf("%s renews", a.client))
}

// sharedEnded are the recorded events of a shared session's end.
func (l *eventLog) sharedEnded() []*broker.Envelope {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []*broker.Envelope
	for _, ev := range l.events {
		if ev.Attributes["kind"] == "shared_session_ended" {
			out = append(out, ev)
		}
	}

	return out
}

// C7 case 4: a session signed in before shared sessions existed names none, and
// its sign-out ends only it.
func TestASignOutOfASessionWithNoSharedSessionEndsOnlyIt(t *testing.T) {
	app, mem, events := sharedApp(t, nil)
	tc := app.TestClient()
	plain := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)
	second := answeredApp(t, app, mem, tc, "second-app", secondReturn)
	id, _ := sharedOf(t, mem, tc)

	in := seedSignIn(t, mem, "sso-off", offReturn)
	before := redeemed(t, app, mem, "sso-off", offReturn, in.code, in.verifier)

	qt.Assert(t, qt.Equals(before.signsOut(), fasthttp.StatusOK))
	before.ended(t, mem)
	_, err := mem.LoadShared(context.Background(), id)
	qt.Check(t, qt.IsNil(err))
	for _, a := range []appIn{plain, second} {
		qt.Check(t, qt.Equals(a.renews(), fasthttp.StatusOK), qt.Commentf("%s", a.client))
	}
	qt.Check(t, qt.HasLen(events.sharedEnded(), 0))
}

// C7 case 6: the revoke of a session that has already ended (its grant outlived
// it) removes the grant and ends nothing else: the session no longer says which
// shared session it was signed in under.
func TestASignOutOfAnEndedSessionEndsNothingElse(t *testing.T) {
	app, mem, events := sharedApp(t, nil)
	tc := app.TestClient()
	plain := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)
	second := answeredApp(t, app, mem, tc, "second-app", secondReturn)
	id, _ := sharedOf(t, mem, tc)

	qt.Assert(t, qt.IsNil(mem.DeleteSession(context.Background(), plain.sid)))
	qt.Check(t, qt.Equals(plain.signsOut(), fasthttp.StatusOK))
	plain.ended(t, mem)
	_, err := mem.LoadShared(context.Background(), id)
	qt.Check(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(second.renews(), fasthttp.StatusOK))
	qt.Check(t, qt.HasLen(events.sharedEnded(), 0))
}

// C7 case 10: an app that discards the session it has just opened (go-authbyte
// revokes it when the ID token fails its check) signs every app out: the revoke
// says nothing of why, and ending everything is the reading that fails closed.
func TestAnAnsweredAppsRevokeEndsTheAppThatSignedIn(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)
	tc := app.TestClient()
	plain := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)
	second := answeredApp(t, app, mem, tc, "second-app", secondReturn)

	qt.Assert(t, qt.Equals(second.signsOut(), fasthttp.StatusOK))
	for _, a := range []appIn{plain, second} {
		a.ended(t, mem)
	}
}

// C7 case 11: an app that is not single sign-on still joins the browser's shared
// session, so its sign-out ends the other apps, and another app's sign-out ends
// its session.
func TestAnAppThatIsNotSingleSignOnSignsOutWithTheRest(t *testing.T) {
	app, mem, _ := sharedApp(t, nil)

	tc := app.TestClient()
	off := cardSignedIn(t, app, mem, tc, "sso-off", offReturn, annasCard)
	second := answeredApp(t, app, mem, tc, "second-app", secondReturn)
	qt.Assert(t, qt.Equals(off.signsOut(), fasthttp.StatusOK))
	second.ended(t, mem)

	other := app.TestClient()
	off = cardSignedIn(t, app, mem, other, "sso-off", offReturn, annasCard)
	second = answeredApp(t, app, mem, other, "second-app", secondReturn)
	qt.Assert(t, qt.Equals(second.signsOut(), fasthttp.StatusOK))
	off.ended(t, mem)
}

// C7 case 12: two apps signing out at the same moment are both answered, every
// session ends, and the shared session's end is recorded once.
func TestTwoAppsSigningOutAtOnceEndEverythingOnce(t *testing.T) {
	app, mem, events := sharedApp(t, nil)
	tc := app.TestClient()
	plain := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)
	second := answeredApp(t, app, mem, tc, "second-app", secondReturn)
	third := answeredApp(t, app, mem, tc, "needs-code", codeReturn)

	statuses := make([]int, 2)
	var wg sync.WaitGroup
	for i, a := range []appIn{plain, second} {
		wg.Go(func() { statuses[i] = a.signsOut() })
	}
	wg.Wait()
	qt.Check(t, qt.DeepEquals(statuses, []int{fasthttp.StatusOK, fasthttp.StatusOK}))
	for _, a := range []appIn{plain, second, third} {
		a.ended(t, mem)
	}

	ended := events.sharedEnded()
	qt.Assert(t, qt.HasLen(ended, 1))
	qt.Check(t, qt.Equals(ended[0].Attributes["sessions"], 3))
}

// racingStore is the session store with a sign-out that lands while an answer
// from the shared session is being given: after the answer read the shared
// session and wrote its new app session, just before it records the app under
// the shared one. putFails makes recording the app fail instead.
type racingStore struct {
	*sessiontest.Memory

	mu       sync.Mutex
	signOut  func()
	putFails bool
	recorded []string
}

func (s *racingStore) PutSharedApp(ctx context.Context, id, client, sid string, until time.Time) (string, error) {
	s.mu.Lock()
	s.recorded = append(s.recorded, sid)
	signOut, fails := s.signOut, s.putFails
	s.signOut = nil
	s.mu.Unlock()
	if signOut != nil {
		signOut()
	}
	if fails {
		return "", errors.New("the store could not record the app")
	}

	return s.Memory.PutSharedApp(ctx, id, client, sid, until)
}

// lastRecorded is the app session most recently recorded, or attempted.
func (s *racingStore) lastRecorded() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.recorded[len(s.recorded)-1]
}

// C7 case 13: an answer from the shared session given while a sign-out ends it
// does not outlive the sign-out: it finds the shared session gone once it has
// recorded its app, ends the session it made and shows the page, with no code. An
// answer whose app cannot be recorded under the shared session is not given
// either, since no sign-out would reach it.
func TestAnAnswerDuringASignOutDoesNotOutliveIt(t *testing.T) {
	var racing *racingStore
	app, mem, _ := sharedApp(t, nil, func(a *authbytecore.App) {
		racing = &racingStore{Memory: a.Session().(*sessiontest.Memory)}
		a.SetSessionStore(racing)
	})

	tc := app.TestClient()
	plain := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)
	racing.mu.Lock()
	racing.signOut = func() {
		qt.Check(t, qt.Equals(plain.signsOut(), fasthttp.StatusOK))
	}
	racing.mu.Unlock()

	a := authorizeIn(t, tc, "second-app", secondReturn, nil)
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""), qt.Commentf("%d %s", a.status, a.location))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK))
	_, err := mem.LoadSession(context.Background(), racing.lastRecorded())
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
	plain.ended(t, mem)

	other := app.TestClient()
	cardSignedIn(t, app, mem, other, "plain-card", plainReturn, annasCard)
	racing.mu.Lock()
	racing.putFails = true
	racing.mu.Unlock()
	a = authorizeIn(t, other, "second-app", secondReturn, nil)
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""), qt.Commentf("%d %s", a.status, a.location))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK))
	_, err = mem.LoadSession(context.Background(), racing.lastRecorded())
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
}
