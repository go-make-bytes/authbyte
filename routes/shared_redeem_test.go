package routes

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The app's session is replaced under the browser's shared session when the code
// of its new sign-in is redeemed, never when the code is issued: a sign-in the
// app is refused leaves its earlier session recorded and working.

// listedUnder is the app session recorded for client under tc's browser's shared
// session ("" when none).
func listedUnder(t *testing.T, mem *sessiontest.Memory, tc *azugo.TestClient, client string) string {
	t.Helper()

	id, _ := sharedOf(t, mem, tc)
	apps, err := mem.SharedApps(context.Background(), id)
	qt.Assert(t, qt.IsNil(err))

	return apps[client]
}

// holdsRefreshGrant reports whether the store holds a refresh grant of the app
// session sid.
func holdsRefreshGrant(mem *sessiontest.Memory, sid string) bool {
	for k, v := range mem.Entries() {
		if strings.HasPrefix(k, "refresh:") && strings.Contains(v, sid) {
			return true
		}
	}

	return false
}

// sessionKeys are the keys of the live sessions in the store.
func sessionKeys(mem *sessiontest.Memory) []string { return mem.Keys("sess:") }

// endingStore is the session store with a sign-out that lands between the
// browser's arrival and the answer: the shared session is ended just before the
// next read of it after arm.
type endingStore struct {
	*sessiontest.Memory

	mu    sync.Mutex
	armed bool
	reads int
}

func (s *endingStore) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armed, s.reads = true, 0
}

func (s *endingStore) LoadShared(ctx context.Context, id string) (*session.Shared, error) {
	s.mu.Lock()
	s.reads++
	end := s.armed && s.reads == 2
	s.mu.Unlock()
	if end {
		_, _ = s.EndShared(ctx, id)
	}

	return s.Memory.LoadShared(ctx, id)
}

// pageCodeFor signs the card in again through client's page, asking for tenant,
// and answers the code not yet redeemed and its verifier.
func pageCodeFor(t *testing.T, tc *azugo.TestClient, client, redirectURI, card, tenant string) (code, verifier string) {
	t.Helper()

	verifier, challenge := pkce()
	q := requestFor(client, redirectURI, challenge)
	q.Set("prompt", "login") // the page, not an answer from the shared session
	if tenant != "" {
		q.Set("tenant", tenant)
	}
	p := showCardPage(t, tc, q)
	qt.Assert(t, qt.Equals(p.status, fasthttp.StatusOK), qt.Commentf("%s", p.body))
	b, _ := json.Marshal(map[string]string{"nonce": p.nonce, "origin": selfOriginInTests, "code": card})
	a := postCard(t, tc, p, p.state, string(b), p.token, selfOriginInTests)
	code = codeAt(t, a, redirectURI)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%d %s %s", a.status, a.location, a.body))

	return code, verifier
}

// answeredCodeFor is client answered from the shared session, asking for tenant,
// its code not yet redeemed, and its verifier.
func answeredCodeFor(t *testing.T, tc *azugo.TestClient, client, redirectURI, tenant string) (code, verifier string) {
	t.Helper()

	verifier, challenge := pkce()
	extra := url.Values{"code_challenge": {challenge}}
	if tenant != "" {
		extra.Set("tenant", tenant)
	}
	a := authorizeIn(t, tc, client, redirectURI, extra)
	code = codeAt(t, a, redirectURI)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%s: %d %s %s", client, a.status, a.location, a.body))

	return code, verifier
}

// codeIssuer issues a code for an app that already holds a session.
type codeIssuer func(t *testing.T, tc *azugo.TestClient, tenant string) (code, verifier string)

// issuers are the two places a code is issued from: a reuse of the shared
// session, and the sign-in page.
var issuers = map[string]codeIssuer{
	"answered from the shared session": func(t *testing.T, tc *azugo.TestClient, tenant string) (string, string) {
		return answeredCodeFor(t, tc, "plain-card", plainReturn, tenant)
	},
	"completed at the sign-in page": func(t *testing.T, tc *azugo.TestClient, tenant string) (string, string) {
		return pageCodeFor(t, tc, "plain-card", plainReturn, annasCard, tenant)
	},
}

func memberOfOne() *fakeResolver { return &fakeResolver{memberships: memberships(orgA)} }

func TestAnAppsEarlierSessionEndsWhenTheNewCodeIsRedeemed(t *testing.T) {
	for name, issue := range issuers {
		app, mem, _ := sharedApp(t, memberOfOne())
		tc := app.TestClient()
		earlier := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)

		code, verifier := issue(t, tc, "")
		newSID, _ := sessionOf(t, mem, code)
		qt.Check(t, qt.Equals(earlier.renews(), fasthttp.StatusOK), qt.Commentf("%s: before the redeem", name))
		qt.Check(t, qt.Equals(listedUnder(t, mem, tc, "plain-card"), earlier.sid), qt.Commentf("%s: listed before", name))

		now := redeemed(t, app, mem, "plain-card", plainReturn, code, verifier)
		qt.Check(t, qt.Equals(now.sid, newSID), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(earlier.renews(), fasthttp.StatusUnauthorized), qt.Commentf("%s: earlier after the redeem", name))
		qt.Check(t, qt.Equals(now.renews(), fasthttp.StatusOK), qt.Commentf("%s: new after the redeem", name))
		qt.Check(t, qt.Equals(listedUnder(t, mem, tc, "plain-card"), newSID), qt.Commentf("%s: listed after", name))
	}
}

func TestARefusedRedeemLeavesTheAppsEarlierSessionWorking(t *testing.T) {
	for name, issue := range issuers {
		app, mem, _ := sharedApp(t, memberOfOne())
		tc := app.TestClient()
		earlier := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)

		// The person is in orgA only; the sign-in names orgB.
		code, verifier := issue(t, tc, orgB)
		newSID, _ := sessionOf(t, mem, code)
		status, body := newEdge(t, app).exchange(signIn{code: code, verifier: verifier}, "plain-card", plainReturn)
		qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%s: %s", name, body["_raw"]))
		qt.Check(t, qt.StringContains(body["_raw"].(string), "err:membership:notMember"), qt.Commentf("%s", name))

		qt.Check(t, qt.Equals(earlier.renews(), fasthttp.StatusOK), qt.Commentf("%s: earlier still renews", name))
		qt.Check(t, qt.Equals(listedUnder(t, mem, tc, "plain-card"), earlier.sid), qt.Commentf("%s: earlier still listed", name))
		_, err := mem.LoadSession(context.Background(), newSID)
		qt.Check(t, qt.ErrorIs(err, session.ErrNotFound), qt.Commentf("%s: the new session is gone", name))

		// A sign-out still reaches the earlier session.
		out := got(t)(tc.Get("/logout?client_id=plain-card&redirect_uri=" + url.QueryEscape("https://plain.example/")))
		qt.Check(t, qt.Not(qt.Equals(out.location, "")), qt.Commentf("%s", name))
		earlier.ended(t, mem)
	}
}

func TestACodeNeverRedeemedLeavesTheAppsEarlierSessionWorking(t *testing.T) {
	for name, issue := range issuers {
		app, mem, _ := sharedApp(t, memberOfOne())
		tc := app.TestClient()
		earlier := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)

		code, _ := issue(t, tc, "")
		newSID, newSess := sessionOf(t, mem, code)

		qt.Check(t, qt.Equals(earlier.renews(), fasthttp.StatusOK), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(listedUnder(t, mem, tc, "plain-card"), earlier.sid), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(newSess.RefreshKey, ""), qt.Commentf("%s: the new session holds no refresh grant", name))
		_, err := mem.LoadSession(context.Background(), newSID)
		qt.Check(t, qt.IsNil(err), qt.Commentf("%s: it ends with its own expiry", name))
	}
}

func TestASignOutBetweenTheIssueAndTheRedeemRefusesTheRedeem(t *testing.T) {
	for name, issue := range issuers {
		app, mem, _ := sharedApp(t, memberOfOne())
		tc := app.TestClient()
		earlier := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)

		code, verifier := issue(t, tc, "")
		newSID, _ := sessionOf(t, mem, code)
		qt.Check(t, qt.Equals(earlier.signsOut(), fasthttp.StatusOK), qt.Commentf("%s", name))

		status, body := newEdge(t, app).exchange(signIn{code: code, verifier: verifier}, "plain-card", plainReturn)
		qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%s: %s", name, body["_raw"]))
		qt.Check(t, qt.IsNil(body["access_token"]), qt.Commentf("%s", name))
		earlier.ended(t, mem)
		_, err := mem.LoadSession(context.Background(), newSID)
		qt.Check(t, qt.ErrorIs(err, session.ErrNotFound), qt.Commentf("%s: the new session is gone", name))
		qt.Check(t, qt.IsFalse(holdsRefreshGrant(mem, newSID)), qt.Commentf("%s: its refresh grant is gone", name))
		qt.Check(t, qt.HasLen(mem.Keys("refresh:"), 0), qt.Commentf("%s: no refresh grant of the app is left", name))
	}
}

// A shared session that a sign-out ended between the browser's arrival and the
// answer is not answered from: no code, and the session made for the answer is
// ended, the request going on as without a shared session.
func TestASharedSessionEndedBeforeTheAnswerIsNotAnsweredFrom(t *testing.T) {
	var ending *endingStore
	app, mem, _ := sharedApp(t, memberOfOne(), func(a *authbytecore.App) {
		ending = &endingStore{Memory: a.Session().(*sessiontest.Memory)}
		a.SetSessionStore(ending)
	})
	tc := app.TestClient()
	cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)
	before := sessionKeys(mem)
	refreshBefore := mem.Keys("refresh:")

	ending.arm()
	a := authorizeIn(t, tc, "second-app", secondReturn, nil)
	qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""), qt.Commentf("%d %s", a.status, a.location))
	qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK))
	qt.Check(t, qt.HasLen(mem.Keys("code:"), 0))

	// Only the session made for the answer is gone; the store's own end of the
	// shared session leaves the first app session as it was.
	qt.Check(t, qt.HasLen(sessionKeys(mem), len(before)))
	qt.Check(t, qt.HasLen(mem.Keys("refresh:"), len(refreshBefore)))
}

// A stolen code is refused whatever it is presented with: a wrong verifier, or
// another client. Each refusal ends the session made for the code and leaves the
// app's earlier session working and listed.
func TestAStolenCodeIsRefusedAndLeavesTheAppsEarlierSession(t *testing.T) {
	for name, issue := range issuers {
		for _, c := range []struct {
			what     string
			client   string
			redirect string
			verifier func(string) string
		}{
			{"a wrong verifier", "plain-card", plainReturn, func(string) string { return randomToken(32) }},
			{"another client", "second-app", secondReturn, func(v string) string { return v }},
		} {
			app, mem, _ := sharedApp(t, memberOfOne())
			tc := app.TestClient()
			earlier := cardSignedIn(t, app, mem, tc, "plain-card", plainReturn, annasCard)

			code, verifier := issue(t, tc, "")
			newSID, _ := sessionOf(t, mem, code)
			status, body := newEdge(t, app).exchange(signIn{code: code, verifier: c.verifier(verifier)}, c.client, c.redirect)
			qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%s, %s: %s", name, c.what, body["_raw"]))
			qt.Check(t, qt.IsNil(body["access_token"]), qt.Commentf("%s, %s", name, c.what))

			qt.Check(t, qt.Equals(earlier.renews(), fasthttp.StatusOK), qt.Commentf("%s, %s: earlier still renews", name, c.what))
			qt.Check(t, qt.Equals(listedUnder(t, mem, tc, "plain-card"), earlier.sid), qt.Commentf("%s, %s: earlier still listed", name, c.what))
			_, err := mem.LoadSession(context.Background(), newSID)
			qt.Check(t, qt.ErrorIs(err, session.ErrNotFound), qt.Commentf("%s, %s: the new session is gone", name, c.what))
		}
	}
}

func TestAFirstSignInIsRecordedWhenItsCodeIsRedeemed(t *testing.T) {
	app, mem, _ := sharedApp(t, memberOfOne())
	tc := app.TestClient()

	a, verifier := signInByCard(t, tc, "plain-card", plainReturn, annasCard)
	code := codeAt(t, a, plainReturn)
	qt.Assert(t, qt.Not(qt.Equals(code, "")))
	qt.Check(t, qt.Equals(listedUnder(t, mem, tc, "plain-card"), ""), qt.Commentf("not listed before the redeem"))

	first := redeemed(t, app, mem, "plain-card", plainReturn, code, verifier)
	qt.Check(t, qt.Equals(listedUnder(t, mem, tc, "plain-card"), first.sid))
	qt.Check(t, qt.Equals(first.renews(), fasthttp.StatusOK))

	out := got(t)(tc.Get("/logout?client_id=plain-card&redirect_uri=" + url.QueryEscape("https://plain.example/")))
	qt.Check(t, qt.Not(qt.Equals(out.location, "")))
	first.ended(t, mem)
}
