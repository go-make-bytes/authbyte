package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// named is a membership of an organisation with a name, whose roles grant the
// scopes given.
func named(tenant, name string, scopes ...string) rolebyte.Membership {
	return rolebyte.Membership{TenantID: tenant, TenantName: name, Scopes: scopes}
}

// withRegister is the setup that gives a test app a register answering from f.
func withRegister(f *fakeResolver) func(*authbytecore.App) {
	return func(a *authbytecore.App) { a.SetScopeResolver(f) }
}

// seedSignInNaming is seedSignIn for a sign-in at the given assurance level
// whose request named an organisation (tenant is empty when it named none).
func seedSignInNaming(t *testing.T, mem *sessiontest.Memory, clientID, redirectURI, tenant, loa string) signIn {
	t.Helper()

	in := signIn{sid: randomToken(24), code: randomToken(24), verifier: randomToken(32)}
	sum := sha256.Sum256([]byte(in.verifier))

	ctx := context.Background()
	qt.Assert(t, qt.IsNil(mem.CreateSession(ctx, in.sid, &session.Session{
		Subject:     testPersonSub(5),
		LoA:         loa,
		LoginMethod: "webEid",
	}, sessionLifetime)))
	qt.Assert(t, qt.IsNil(mem.SaveAppCode(ctx, in.code, &session.AppCode{
		SessionID:           in.sid,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(sum[:]),
		CodeChallengeMethod: "S256",
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Tenant:              tenant,
	}, time.Minute)))

	return in
}

// exchanged signs a person in at product-spa, naming tenant (or none), and answers
// the sign-in with the code exchange's status and body.
func exchanged(t *testing.T, mem *sessiontest.Memory, e *edge, tenant string) (signIn, int, map[string]any) {
	t.Helper()

	in := seedSignInNaming(t, mem, "product-spa", productRedirect, tenant, "high")
	status, body := e.exchange(in, "product-spa", productRedirect)

	return in, status, body
}

// listed is the organisations a token answer lists in `memberships`, in the order
// answered, as id then name; each entry has exactly the keys `tenant` and `name`.
func listed(t *testing.T, body map[string]any) [][2]string {
	t.Helper()

	list, ok := body["memberships"].([]any)
	qt.Assert(t, qt.IsTrue(ok), qt.Commentf("%s", body["_raw"]))

	out := make([][2]string, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		qt.Assert(t, qt.IsTrue(ok), qt.Commentf("%s", body["_raw"]))
		qt.Check(t, qt.DeepEquals(keysOf(m), []string{"name", "tenant"}))
		id, _ := m["tenant"].(string)
		name, _ := m["name"].(string)
		out = append(out, [2]string{id, name})
	}

	return out
}

// keysOf is the sorted set of keys of an answer, without the test's own `_raw`.
func keysOf(body map[string]any) []string {
	keys := make([]string, 0, len(body))
	for k := range body {
		if k != "_raw" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	return keys
}

// scopesOf is the scopes of an answer's access token.
func scopesOf(t *testing.T, body map[string]any) []string {
	t.Helper()

	tok, _ := body["access_token"].(string)
	s, _ := tokenClaims(t, tok)["scope"].(string)

	return strings.Fields(s)
}

// tenantOf is the tenant of an answer's access token ("" when it has none).
func tenantOf(t *testing.T, body map[string]any) string {
	t.Helper()

	tok, _ := body["access_token"].(string)
	s, _ := tokenClaims(t, tok)["tenant"].(string)

	return s
}

// refused checks the refusal of a person who is a member nowhere they named: 403
// with the code, and a body that holds no token, no organisation and no list.
func refused(t *testing.T, status int, body map[string]any, what ...string) {
	t.Helper()

	raw, _ := body["_raw"].(string)
	qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%s", raw))
	qt.Check(t, qt.StringContains(raw, "err:membership:notMember"))
	for _, s := range append([]string{"access_token", "memberships", "tenants"}, what...) {
		qt.Check(t, qt.IsFalse(strings.Contains(raw, s)), qt.Commentf("%q in %s", s, raw))
	}
}

const (
	orgA = "01TENANTAAAAAAAAAAAAAAAAAA"
	orgB = "01TENANTBBBBBBBBBBBBBBBBBB"
	orgC = "01TENANTCCCCCCCCCCCCCCCCCC"
)

// the answer of a code exchange that carries a refresh token and nothing more.
var plainAnswerKeys = []string{"access_token", "expires_in", "refresh_token", "token_type"}

// A person in two organisations who names none is answered a token with no
// tenant and no scope, the ids in `tenants` and both organisations with their
// names in `memberships`, in the register's order.
func TestTwoMembershipsNoneNamedListsBothByName(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		named(orgB, "Beta Ltd", "b:b"),
		named(orgA, "Alpha Ltd", "a:a"),
	}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	_, status, body := exchanged(t, mem, e, "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	qt.Check(t, qt.Equals(tenantOf(t, body), ""))
	qt.Check(t, qt.HasLen(scopesOf(t, body), 0))
	qt.Check(t, qt.DeepEquals(body["tenants"], any([]any{orgB, orgA})))
	qt.Check(t, qt.DeepEquals(listed(t, body), [][2]string{{orgB, "Beta Ltd"}, {orgA, "Alpha Ltd"}}))
}

// One of two organisations named on the code: its token and its scopes only,
// both organisations listed, no `tenants`.
func TestTwoMembershipsOneNamedListsBothAndMintsTheNamedOne(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		named(orgA, "Alpha Ltd", "a:a"),
		named(orgB, "Beta Ltd", "b:b"),
	}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	_, status, body := exchanged(t, mem, e, orgB)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	qt.Check(t, qt.Equals(tenantOf(t, body), orgB))
	qt.Check(t, qt.DeepEquals(scopesOf(t, body), []string{"b:b"}))
	qt.Check(t, qt.IsFalse(strings.Contains(strings.Join(scopesOf(t, body), " "), "a:a")))
	qt.Check(t, qt.DeepEquals(listed(t, body), [][2]string{{orgA, "Alpha Ltd"}, {orgB, "Beta Ltd"}}))
	_, has := body["tenants"]
	qt.Check(t, qt.IsFalse(has))
}

// A person in one organisation, naming none or naming it, is answered with the
// keys they always were: neither `memberships` nor `tenants`.
func TestOneMembershipAnswersTheKeysItAlwaysDid(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a")}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	for name, tenant := range map[string]string{"none named": "", "named": orgA} {
		_, status, body := exchanged(t, mem, e, tenant)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", name, body["_raw"]))

		qt.Check(t, qt.DeepEquals(keysOf(body), plainAnswerKeys), qt.Commentf("%s", name))
		raw := body["_raw"].(string)
		qt.Check(t, qt.IsFalse(strings.Contains(raw, "memberships")), qt.Commentf("%s", name))
		qt.Check(t, qt.IsFalse(strings.Contains(raw, "tenants")), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(tenantOf(t, body), orgA))
	}
}

// A third organisation named: refused, and the answer holds no token, no
// organisation's id, no name and no list.
func TestANamedOrganisationTheyAreNotInIsRefusedWithNothingListed(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		named(orgA, "Alpha Ltd", "a:a"),
		named(orgB, "Beta Ltd", "b:b"),
	}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	_, status, body := exchanged(t, mem, e, orgC)

	refused(t, status, body, orgA, orgB, "Alpha Ltd", "Beta Ltd")
}

// A request that names an organisation and is answered from the browser's
// single sign-on session with no page: its code, exchanged, gives the named
// organisation's token, and both organisations are listed.
func TestASingleSignOnAnswerHonoursTheNamedOrganisation(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		named(orgA, "Alpha Ltd", "a:a"),
		named(orgB, "Beta Ltd", "b:b"),
	}}
	app, _, _ := sharedApp(t, fake)
	tc := app.TestClient()
	signInByCard(t, tc, "plain-card", plainReturn, annasCard)

	verifier, challenge := pkce()
	a := authorizeIn(t, tc, "second-app", secondReturn, url.Values{"code_challenge": {challenge}, "tenant": {orgB}})
	code := codeAt(t, a, secondReturn)
	qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%d %s %s", a.status, a.location, a.body))

	status, body := newEdge(t, app).exchange(signIn{code: code, verifier: verifier}, "second-app", secondReturn)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	qt.Check(t, qt.Equals(tenantOf(t, body), orgB))
	qt.Check(t, qt.DeepEquals(scopesOf(t, body), []string{"b:b"}))
	qt.Check(t, qt.DeepEquals(listed(t, body), [][2]string{{orgA, "Alpha Ltd"}, {orgB, "Beta Ltd"}}))
}

// With prompt=login, and with max_age=0, the request is not answered from the
// single sign-on session; after the sign-in on the page the code's organisation is
// the named one and the exchanged token is for it.
func TestAFreshSignInKeepsTheNamedOrganisation(t *testing.T) {
	for name, extra := range map[string]url.Values{
		"prompt=login": {"prompt": {"login"}},
		"max_age=0":    {"max_age": {"0"}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeResolver{memberships: []rolebyte.Membership{
				named(orgA, "Alpha Ltd", "a:a"),
				named(orgB, "Beta Ltd", "b:b"),
			}}
			app, mem, _ := sharedApp(t, fake)
			tc := app.TestClient()
			signInByCard(t, tc, "plain-card", plainReturn, annasCard)

			// Not answered from the single sign-on session: the page is shown.
			verifier, challenge := pkce()
			q := url.Values{"code_challenge": {challenge}, "tenant": {orgB}}
			for k, v := range extra {
				q[k] = v
			}
			a := authorizeIn(t, tc, "second-app", secondReturn, q)
			qt.Check(t, qt.Equals(codeAt(t, a, secondReturn), ""), qt.Commentf("%s", a.location))
			qt.Check(t, qt.Equals(a.status, fasthttp.StatusOK))

			// Signing in on that page carries the same request.
			req := requestFor("second-app", secondReturn, challenge)
			for k, v := range q {
				req[k] = v
			}
			p := showCardPage(t, tc, req)
			qt.Assert(t, qt.Equals(p.status, fasthttp.StatusOK), qt.Commentf("%s", p.body))
			card := `{"nonce":"` + p.nonce + `","origin":"` + selfOriginInTests + `","code":"` + annasCard + `"}`
			done := postCard(t, tc, p, p.state, card, p.token, selfOriginInTests)
			code := codeAt(t, done, secondReturn)
			qt.Assert(t, qt.Not(qt.Equals(code, "")), qt.Commentf("%d %s %s", done.status, done.location, done.body))

			_, sess := sessionOf(t, mem, code)
			qt.Check(t, qt.Not(qt.Equals(sess.Subject, "")))

			status, body := newEdge(t, app).exchange(signIn{code: code, verifier: verifier}, "second-app", secondReturn)
			qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
			qt.Check(t, qt.Equals(tenantOf(t, body), orgB))
			qt.Check(t, qt.DeepEquals(scopesOf(t, body), []string{"b:b"}))
		})
	}
}

// A session issued for the one organisation its person was in keeps minting
// for it when the register later answers that one and another; the refresh lists
// both and carries no `tenants`.
func TestARefreshStaysInItsOrganisationWhenAnotherJoins(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a")}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	_, status, body := exchanged(t, mem, e, "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	qt.Check(t, qt.Equals(tenantOf(t, body), orgA))
	refresh, _ := body["refresh_token"].(string)

	fake.memberships = []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a"), named(orgB, "Beta Ltd", "b:b")}
	status, body = e.refresh(refresh, "product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	qt.Check(t, qt.Equals(tenantOf(t, body), orgA))
	qt.Check(t, qt.DeepEquals(scopesOf(t, body), []string{"a:a"}))
	qt.Check(t, qt.DeepEquals(listed(t, body), [][2]string{{orgA, "Alpha Ltd"}, {orgB, "Beta Ltd"}}))
	_, has := body["tenants"]
	qt.Check(t, qt.IsFalse(has))
}

// A session issued for one of two organisations stays in it when the register
// later answers that one alone, and the refresh lists nothing.
func TestARefreshListsNothingOnceThePersonIsInOneOrganisation(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a"), named(orgB, "Beta Ltd", "b:b")}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	_, status, body := exchanged(t, mem, e, orgA)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	refresh, _ := body["refresh_token"].(string)

	fake.memberships = []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a")}
	status, body = e.refresh(refresh, "product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	qt.Check(t, qt.Equals(tenantOf(t, body), orgA))
	qt.Check(t, qt.IsFalse(strings.Contains(body["_raw"].(string), "memberships")))
}

// A session issued for an organisation the register no longer answers for the
// person is refused at its refresh, with nothing in the body, and the stored
// session still names that organisation.
func TestARefreshForAnOrganisationTheyLeftIsRefused(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a")}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	in, status, body := exchanged(t, mem, e, orgA)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	refresh, _ := body["refresh_token"].(string)

	fake.memberships = []rolebyte.Membership{named(orgB, "Beta Ltd", "b:b")}
	status, body = e.refresh(refresh, "product-spa")
	refused(t, status, body, orgA, orgB, "Alpha Ltd", "Beta Ltd")

	sess, err := mem.LoadSession(context.Background(), in.sid)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.Tenant, orgA))
}

// A session opened with two organisations and none named lists both at every
// refresh, with or without a `tenant` in the form, which a refresh ignores.
func TestARefreshOfASessionWithNoOrganisationListsBoth(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a"), named(orgB, "Beta Ltd", "b:b")}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	_, status, body := exchanged(t, mem, e, "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	refresh, _ := body["refresh_token"].(string)

	for name, extra := range map[string]string{"plain": "", "with tenant": orgA} {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"product-spa"}}
		if extra != "" {
			form.Set("tenant", extra)
		}
		status, body = e.post("/token", form)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", name, body["_raw"]))

		qt.Check(t, qt.Equals(tenantOf(t, body), ""), qt.Commentf("%s", name))
		qt.Check(t, qt.HasLen(scopesOf(t, body), 0), qt.Commentf("%s", name))
		qt.Check(t, qt.DeepEquals(body["tenants"], any([]any{orgA, orgB})), qt.Commentf("%s", name))
		qt.Check(t, qt.DeepEquals(listed(t, body), [][2]string{{orgA, "Alpha Ltd"}, {orgB, "Beta Ltd"}}), qt.Commentf("%s", name))
	}
}

// Scopes that count only on a high sign-in, through the real token endpoint
// on a client set to carry them (extends the seam tests in
// token_highscopes_test.go, which prove the same rule below the endpoint): a high
// sign-in naming the organisation without one gets that organisation's scopes and
// not the other's high-only scope; one naming the organisation with one carries it;
// a sign-in below high naming it does not.
func TestHighOnlyScopesFollowTheNamedOrganisationAtTheEndpoint(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		withHigh(orgA, []string{"a:a"}, []string{highOnly}),
		withHigh(orgB, []string{"b:b"}, nil),
	}}
	fake.memberships[0].TenantName = "Alpha Ltd"
	fake.memberships[1].TenantName = "Beta Ltd"
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)
	const adminRedirect = "https://admin.example/callback"

	for _, c := range []struct {
		name, tenant, loa string
		want              []string
	}{
		{"high naming the organisation without one", orgB, "high", []string{"b:b"}},
		{"high naming the organisation with one", orgA, "high", []string{"a:a", highOnly}},
		{"below high naming the organisation with one", orgA, "substantial", []string{"a:a"}},
	} {
		in := seedSignInNaming(t, mem, "admin-spa", adminRedirect, c.tenant, c.loa)
		status, body := e.exchange(in, "admin-spa", adminRedirect)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", c.name, body["_raw"]))
		qt.Check(t, qt.DeepEquals(scopesOf(t, body), c.want), qt.Commentf("%s", c.name))
		qt.Check(t, qt.Equals(tenantOf(t, body), c.tenant), qt.Commentf("%s", c.name))
		qt.Check(t, qt.HasLen(listed(t, body), 2), qt.Commentf("%s", c.name))
	}
}

// An AI app's sign-in whose request names an organisation: the name is dropped
// as before and the token answer lists nothing, though the person is in two.
func TestAnAIAppsAnswerListsNoOrganisations(t *testing.T) {
	d := aiApp(t)
	d.register.memberships = []rolebyte.Membership{named(orgA, "Alpha Ltd", "plain:read"), named(orgB, "Beta Ltd", "plain:read")}
	tc := d.app.TestClient()
	verifier := randomToken(32)

	page := d.signInAs(t, tc, annasOID, aiAsk(verifier, url.Values{"tenant": {orgB}}))
	qt.Assert(t, qt.Equals(page.status, fasthttp.StatusOK), qt.Commentf("%s", page.body))
	code := codeFrom(t, pick(t, tc, page, assistantWay(annasFirst)))

	status, out := tokenAt(t, d, "/token", codeExchange(code, verifier))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", out))
	raw, _ := out["_status_text"].(string)
	qt.Check(t, qt.IsFalse(strings.Contains(raw, "memberships")), qt.Commentf("%s", raw))
	qt.Check(t, qt.Equals(readToken(t, out["access_token"]).Tenant, annasFirst.TenantID))
}

// A service account in two organisations asking for one: as before, and the
// answer lists nothing.
func TestAServiceAccountsAnswerListsNoOrganisations(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		named(orgA, "Alpha Ltd", "things:read"),
		named(orgB, "Beta Ltd", "things:read"),
	}}
	app, _ := signInApp(t, withRegister(fake))
	svc := newEdge(t, app)
	svc.basic = []string{"svc:caller", "caller-secret"}

	status, body := svc.post("/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc:caller"}, "audience": {"svc:target"}, "tenant": {orgA},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	qt.Check(t, qt.Equals(tenantOf(t, body), orgA))
	qt.Check(t, qt.DeepEquals(keysOf(body), []string{"access_token", "expires_in", "token_type"}))
	qt.Check(t, qt.IsFalse(strings.Contains(body["_raw"].(string), "memberships")))
}

// steadyRegister answers one fixed list and records nothing, so requests at once
// may ask it.
type steadyRegister struct{ memberships []rolebyte.Membership }

func (s steadyRegister) Memberships(*azugo.Context, string, string) ([]rolebyte.Membership, error) {
	return s.memberships, nil
}

func (steadyRegister) Admit(*azugo.Context, string, rolebyte.DirectoryLogin) (bool, error) {
	return false, nil
}

func (steadyRegister) Assistants(*azugo.Context, string) ([]rolebyte.Assistant, error) {
	return nil, nil
}

// A code presented a second time is refused as it is for anyone, and two
// refreshes at once both answer the list.
func TestASecondCodeAndTwoRefreshesForAPersonInTwoOrganisations(t *testing.T) {
	register := steadyRegister{[]rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a"), named(orgB, "Beta Ltd", "b:b")}}
	app, mem := signInApp(t, func(a *authbytecore.App) { a.SetScopeResolver(register) })
	e := newEdge(t, app)

	in, status, body := exchanged(t, mem, e, "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	refresh, _ := body["refresh_token"].(string)

	status, again := e.exchange(in, "product-spa", productRedirect)
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%s", again["_raw"]))
	qt.Check(t, qt.IsFalse(strings.Contains(again["_raw"].(string), "memberships")))

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	answers := make([]map[string]any, 2)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], answers[i] = e.refresh(refresh, "product-spa")
		}()
	}
	wg.Wait()

	qt.Check(t, qt.DeepEquals(statuses, []int{fasthttp.StatusOK, fasthttp.StatusOK}))
	for i, a := range answers {
		qt.Check(t, qt.DeepEquals(listed(t, a), [][2]string{{orgA, "Alpha Ltd"}, {orgB, "Beta Ltd"}}), qt.Commentf("refresh %d", i))
	}
}

// A name arrives unchanged, whatever it holds, and an organisation without one
// is listed with its key present and empty.
func TestANameArrivesUnchangedAndAnEmptyOneIsListedEmpty(t *testing.T) {
	odd := "Ķekavas ābeļu dārzs \"Ž\" <b>&</b> " + strings.Repeat("ž", 167)
	qt.Assert(t, qt.Equals(len([]rune(odd)), 200))

	fake := &fakeResolver{memberships: []rolebyte.Membership{named(orgA, odd, "a:a"), named(orgB, "", "b:b")}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	_, status, body := exchanged(t, mem, e, "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))

	qt.Check(t, qt.DeepEquals(listed(t, body), [][2]string{{orgA, odd}, {orgB, ""}}))
	qt.Check(t, qt.StringContains(body["_raw"].(string), `"name":""`))
}
