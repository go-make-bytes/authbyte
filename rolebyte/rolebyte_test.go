package rolebyte

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// The register's answer is taken only when it names the subject asked about.
// Another person's answer, or an answer that names nobody, is refused before any
// of its memberships can be minted.
func TestAnsweredForAcceptsOnlyTheSubjectAskedAbout(t *testing.T) {
	answer := func(subject string) resolveResponse {
		return resolveResponse{SubjectKey: subject, Memberships: []membership{
			{TenantID: "tenant-1", Scopes: []string{"projects:read", "projects:log"}},
		}}
	}

	got, err := answeredFor("sub:asked", answer("sub:asked"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(got, []Membership{{TenantID: "tenant-1", Scopes: []string{"projects:read", "projects:log"}}}))

	for name, subject := range map[string]string{"another person": "sub:someone-else", "nobody": ""} {
		got, err := answeredFor("sub:asked", answer(subject))
		qt.Check(t, qt.ErrorIs(err, ErrAnswerForAnotherSubject), qt.Commentf("%s", name))
		qt.Check(t, qt.IsNil(got), qt.Commentf("%s: nothing may be minted from it", name))
	}

	// An empty answer about the right person is a stranger, not a refusal.
	got, err = answeredFor("sub:asked", resolveResponse{SubjectKey: "sub:asked"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(got, 0))
}

const (
	annaSub     = "01K9ANNA0000000000000000AA"
	signInActor = "svc:authbyte-core"
)

// minted is one token the stub minter made.
type minted struct {
	Subject, Audience, Scope, Actor, Thumbprint string
}

// doorCall is one request the stub register's sign-in listener received.
type doorCall struct {
	path, token, query, body string
}

// signInRegister stands in for the register's sign-in listener. It answers each
// door from answers, by path, and records what it was asked; the token is the
// minter's own, so it says which mint it came from.
type signInRegister struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	calls   []doorCall
	mints   []minted
	answers map[string]func(w http.ResponseWriter)
}

func newSignInRegister(t *testing.T, answers map[string]func(w http.ResponseWriter)) *signInRegister {
	t.Helper()

	s := &signInRegister{t: t, answers: answers}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.calls = append(s.calls, doorCall{
			path: r.URL.Path, token: strings.TrimPrefix(r.Header.Get("Authorization"), "DPoP "),
			query: r.URL.RawQuery, body: string(raw),
		})
		s.mu.Unlock()

		answer, ok := answers[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)

			return
		}
		answer(w)
	}))
	t.Cleanup(s.srv.Close)

	return s
}

// mint is the stub minter: it records what it was asked and answers a token
// that names its own mint.
func (s *signInRegister) mint(subject, audience, scope, actor, thumbprint string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mints = append(s.mints, minted{subject, audience, scope, actor, thumbprint})

	return fmt.Sprintf("token-%d", len(s.mints)), nil
}

// resolver answers a Resolver against the stub, its client proving calls with
// its own key.
func (s *signInRegister) resolver() (*Resolver, *authclient.Client) {
	s.t.Helper()

	ac, err := authclient.New(&authclient.Configuration{
		IssuerURL:                "http://auth.invalid",
		ServiceAudience:          "svc:auth",
		ServiceClientID:          signInActor,
		ServiceClientSecret:      "secret",
		JWKSCacheTTL:             time.Minute,
		ServiceTokenEarlyRefresh: time.Second,
		DPoPProofMaxAge:          time.Minute,
		DPoPReplayBackend:        authclient.ReplayBackendMemory,
	})
	qt.Assert(s.t, qt.IsNil(err))

	return New(ac, s.mint, s.srv.URL+"/", "svc:rolebyte", signInActor), ac
}

func answerJSON(body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

// inRequest runs fn inside a real request, so the adapter has the request
// context it is called with at token issue.
func inRequest(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/t", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/t")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
}

// A person's memberships are asked at the two doors in order, the claim then the
// lookup, each with a token minted for that call alone: the person as its
// subject, this service acting, the door's one scope, bound to the client's key.
// The requests name nobody.
func TestMembershipsAsksEachDoorWithATokenForThePerson(t *testing.T) {
	reg := newSignInRegister(t, map[string]func(w http.ResponseWriter){
		doorClaims:      answerJSON(`{"claimed":[]}`),
		doorMemberships: answerJSON(`{"subjectKey":"sub:` + annaSub + `","memberships":[{"tenantId":"t1","scopes":["projects:read"]}]}`),
	})
	r, ac := reg.resolver()

	inRequest(t, func(ctx *azugo.Context) {
		got, err := r.Memberships(ctx, PersonKey(annaSub))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(got, []Membership{{TenantID: "t1", Scopes: []string{"projects:read"}}}))
	})

	qt.Assert(t, qt.DeepEquals(reg.mints, []minted{
		{annaSub, "svc:rolebyte", scopeClaim, signInActor, ac.Thumbprint()},
		{annaSub, "svc:rolebyte", scopeResolve, signInActor, ac.Thumbprint()},
	}))
	qt.Assert(t, qt.HasLen(reg.calls, 2))
	qt.Check(t, qt.Equals(reg.calls[0].path, doorClaims))
	qt.Check(t, qt.Equals(reg.calls[0].token, "token-1"))
	qt.Check(t, qt.Equals(reg.calls[1].path, doorMemberships))
	qt.Check(t, qt.Equals(reg.calls[1].token, "token-2"))
	for _, c := range reg.calls {
		qt.Check(t, qt.Equals(c.query, ""), qt.Commentf("%s names nobody in its address", c.path))
		qt.Check(t, qt.Equals(c.body, ""), qt.Commentf("%s carries no body", c.path))
	}
}

// A machine member is asked about by its client id, which is its token subject.
func TestAMachineMembersTokenNamesItsClientID(t *testing.T) {
	reg := newSignInRegister(t, map[string]func(w http.ResponseWriter){
		doorClaims:      answerJSON(`{"claimed":[]}`),
		doorMemberships: answerJSON(`{"subjectKey":"svc:a-machine","memberships":[]}`),
	})
	r, _ := reg.resolver()

	inRequest(t, func(ctx *azugo.Context) {
		_, err := r.Memberships(ctx, "svc:a-machine")
		qt.Assert(t, qt.IsNil(err))
	})

	for _, m := range reg.mints {
		qt.Check(t, qt.Equals(m.Subject, "svc:a-machine"))
	}
}

// An answer about anyone but the person asked about mints nothing: it is
// refused with the error the token route raises a security event on.
func TestAnAnswerAboutAnotherPersonIsRefused(t *testing.T) {
	reg := newSignInRegister(t, map[string]func(w http.ResponseWriter){
		doorClaims:      answerJSON(`{"claimed":[]}`),
		doorMemberships: answerJSON(`{"subjectKey":"sub:01K9BERTS000000000000000BB","memberships":[{"tenantId":"t1","scopes":["projects:admin"]}]}`),
	})
	r, _ := reg.resolver()

	inRequest(t, func(ctx *azugo.Context) {
		got, err := r.Memberships(ctx, PersonKey(annaSub))
		qt.Check(t, qt.ErrorIs(err, ErrAnswerForAnotherSubject))
		qt.Check(t, qt.IsNil(got))
	})
}

// A door that refuses, or a register that cannot be reached, fails the lookup:
// the token issue fails closed on it.
func TestARefusalAtADoorFailsTheLookup(t *testing.T) {
	reg := newSignInRegister(t, map[string]func(w http.ResponseWriter){
		doorClaims: func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) },
	})
	r, _ := reg.resolver()

	inRequest(t, func(ctx *azugo.Context) {
		_, err := r.Memberships(ctx, PersonKey(annaSub))
		qt.Check(t, qt.ErrorMatches(err, `rolebyte: /api/v1/sign-in/claims answered 403`))
	})
	qt.Check(t, qt.HasLen(reg.calls, 1), qt.Commentf("the lookup is never asked after a refused claim"))
}

// The admission sends what only the login knows, the issuer and the name; the
// person rides the token alone.
func TestAdmitSendsOnlyWhatTheLoginKnows(t *testing.T) {
	reg := newSignInRegister(t, map[string]func(w http.ResponseWriter){
		doorAdmissions: answerJSON(`{"outcome":"admitted","tenantId":"t1"}`),
	})
	r, ac := reg.resolver()

	inRequest(t, func(ctx *azugo.Context) {
		admitted, err := r.Admit(ctx, PersonKey(annaSub), DirectoryLogin{Issuer: "https://login.example/t", DisplayName: "Anna"})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.IsTrue(admitted))
	})

	qt.Assert(t, qt.DeepEquals(reg.mints, []minted{{annaSub, "svc:rolebyte", scopeClaim, signInActor, ac.Thumbprint()}}))
	qt.Assert(t, qt.HasLen(reg.calls, 1))
	var body map[string]string
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(reg.calls[0].body), &body)))
	qt.Check(t, qt.DeepEquals(body, map[string]string{"issuer": "https://login.example/t", "displayName": "Anna"}))
}
