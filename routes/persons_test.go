package routes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/store"

	"azugo.io/azugo"
	"azugo.io/azugo/user"
	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// fakePeople stands in for the identity store behind the two person reads.
type fakePeople struct {
	lines     []store.SignInLine
	linesErr  error
	asked     []string // the bare ids the lines read passed down
	linesCall int

	mapping store.Mapping
	getErr  error
	getSub  string
}

func (f *fakePeople) SignInLines(_ context.Context, subs []string) ([]store.SignInLine, error) {
	f.linesCall++
	f.asked = subs

	return f.lines, f.linesErr
}

func (f *fakePeople) Get(_ context.Context, sub string) (store.Mapping, error) {
	f.getSub = sub

	return f.mapping, f.getErr
}

// A national code written the way the store keeps it, built from parts so no
// literal in this file reads as a personal code.
func storedTestCode() string { return "PNOLV-" + strings.Repeat("3", 11) }

// fakeCodeReads stands in for the record of each code read.
type fakeCodeReads struct {
	callers, persons []string
}

func (f *fakeCodeReads) IdentityCodeRead(_ *azugo.Context, caller, personSub string) {
	f.callers = append(f.callers, caller)
	f.persons = append(f.persons, personSub)
}

// The kinds of token a caller can present, as this issuer mints them.
const (
	// tokenOwn is a service's own token: the subject is its client id, and the
	// token names no organisation.
	tokenOwn = "own"
	// tokenAccount is a service account's token naming the organisation it acts for.
	tokenAccount = "account"
	// tokenDelegated is a token another service obtained by exchange to act for
	// the subject: it names the acting service and carries no client id.
	tokenDelegated = "delegated"
	// tokenDelegatedBare is a delegated token that names no organisation — not one
	// the exchange mints today, so the read must refuse it on the actor alone.
	tokenDelegatedBare = "delegated-bare"
)

// testClaims are the claims of the token the caller presents, built the way the
// issuer builds each kind, so the reads see what a real token carries once the
// authentication middleware has read it.
func testClaims(sub, scope, kind string) *claims.Claims {
	c := &claims.Claims{Scope: scope}
	c.Subject = sub
	switch kind {
	case tokenOwn:
		c.ClientID = sub
	case tokenAccount:
		c.ClientID = sub
		c.Tenant = "01TENANTULID"
	case tokenDelegated:
		c.Tenant = "01TENANTULID"
		c.Act = &claims.Actor{Subject: "svc:other"}
	case tokenDelegatedBare:
		c.Act = &claims.Actor{Subject: "svc:other"}
	}

	return c
}

// peopleApp puts the two person reads on scratch routes behind a stand-in for the
// authentication middleware: the caller's token claims come from request
// headers, so the scope and subject rules run through the real handlers.
func peopleApp(t *testing.T, fake *fakePeople) *azugo.TestApp {
	t.Helper()

	ta, _ := peopleAppRecorded(t, fake)

	return ta
}

// peopleAppRecorded is peopleApp with the record of each code read kept for the
// test to read.
func peopleAppRecorded(t *testing.T, fake *fakePeople) (*azugo.TestApp, *fakeCodeReads) {
	t.Helper()

	app := authbytecore.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	reads := &fakeCodeReads{}
	r := &router{App: app, reader: fake, codeReads: reads}
	asCaller := func(ctx *azugo.Context) {
		c := testClaims(ctx.Header.Get("X-Test-Sub"), ctx.Header.Get("X-Test-Scope"), ctx.Header.Get("X-Test-Token"))
		ctx.SetUser(user.New(c.ToUserClaims()))
	}
	app.Post("/testonly/lines", func(ctx *azugo.Context) {
		asCaller(ctx)
		r.personLines(ctx)
	})
	app.Get("/testonly/persons/{personSub}/code", func(ctx *azugo.Context) {
		asCaller(ctx)
		r.personCode(ctx)
	})

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return ta, reads
}

// caller is who makes the request: a subject, the scopes its token carries and
// the kind of token it is (a service's own when unsaid).
type caller struct{ sub, scope, token string }

var (
	linesService = caller{"svc:console", "identity:lines", tokenOwn}
	codeService  = caller{"svc:console", "identity:code", tokenOwn}
)

func send(t *testing.T, app *azugo.TestApp, c caller, method, path, body string) (int, string, string) {
	t.Helper()

	tc := app.TestClient()
	opts := []azugo.TestClientOption{
		tc.WithHeader("X-Test-Sub", c.sub),
		tc.WithHeader("X-Test-Scope", c.scope),
		tc.WithHeader("X-Test-Token", c.token),
	}

	var (
		resp *fasthttp.Response
		err  error
	)
	if method == fasthttp.MethodPost {
		opts = append(opts, tc.WithHeader("Content-Type", "application/json"))
		resp, err = tc.Post(path, []byte(body), opts...)
	} else {
		resp, err = tc.Get(path, opts...)
	}
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	return resp.StatusCode(), string(resp.Body()), string(resp.Header.Peek("Cache-Control"))
}

func linesBody(subjects ...string) string {
	b, _ := json.Marshal(map[string]any{"subjects": subjects})

	return string(b)
}

// The lines read is for a service that holds the lines level: a person's token
// never reads it even with the scope, a service without the scope is refused, and
// a service holding only the code level is refused too.
func TestPersonLinesRefusesEveryoneButAServiceHoldingLines(t *testing.T) {
	fake := &fakePeople{}
	app := peopleApp(t, fake)
	body := linesBody("sub:" + testPersonSub(1))

	for name, c := range map[string]caller{
		"a person holding the scope":            {"sub:" + testPersonSub(2), "identity:lines", ""},
		"a service without it":                  {"svc:console", "envelopes:read", tokenOwn},
		"a service holding code":                {"svc:console", "identity:code", tokenOwn},
		"a service holding admin":               {"svc:console", "identity:admin", tokenOwn},
		"a service account for an organisation": {"svc:console", "identity:lines", tokenAccount},
		"another service acting for a service":  {"svc:console", "identity:lines", tokenDelegated},
		"a delegated token for no organisation": {"svc:console", "identity:lines", tokenDelegatedBare},
	} {
		status, got, _ := send(t, app, c, fasthttp.MethodPost, "/testonly/lines", body)
		qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%s", name))
		qt.Check(t, qt.StringContains(got, "err:identity:forbidden"), qt.Commentf("%s", name))
	}
	qt.Check(t, qt.Equals(fake.linesCall, 0), qt.Commentf("a refused caller never reaches the store"))
}

// Every bad body is one 422 with its own code, and the refusal never repeats
// what was sent.
func TestPersonLinesRefusesBadBodies(t *testing.T) {
	fake := &fakePeople{}
	app := peopleApp(t, fake)

	tooMany := make([]string, 501)
	for i := range tooMany {
		tooMany[i] = "sub:" + testPersonSub(3)
	}

	for name, body := range map[string]string{
		"empty body":        "",
		"not a list":        `{"subjects":"sub:` + testPersonSub(4) + `"}`,
		"an object":         `{"subjects":{"a":"b"}}`,
		"an empty list":     `{"subjects":[]}`,
		"no subjects":       `{}`,
		"too many":          linesBody(tooMany...),
		"no prefix":         linesBody(testPersonSub(5)),
		"wrong prefix":      linesBody("svc:" + testPersonSub(5)),
		"short id":          linesBody("sub:ZZSENTMARKERZZ"),
		"lower case id":     linesBody("sub:" + strings.ToLower(testPersonSub(6)) + "a"),
		"letters outside":   linesBody("sub:" + strings.Repeat("U", 26)),
		"one bad among ok":  linesBody("sub:"+testPersonSub(7), "sub:BADENTRYMARKER"),
		"an entry not text": `{"subjects":[12]}`,
	} {
		status, got, _ := send(t, app, linesService, fasthttp.MethodPost, "/testonly/lines", body)
		qt.Check(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity), qt.Commentf("%s", name))
		qt.Check(t, qt.StringContains(got, "err:identity:invalid"), qt.Commentf("%s", name))
		for _, sent := range []string{"MARKER", testPersonSub(5), testPersonSub(4), testPersonSub(7)} {
			qt.Check(t, qt.IsFalse(strings.Contains(got, sent)), qt.Commentf("%s: the refusal repeats %q", name, sent))
		}
	}
	qt.Check(t, qt.Equals(fake.linesCall, 0))
}

// The store's own refusal of an id is answered as a refusal, not an outage.
func TestPersonLinesAnswersTheStoresRefusalAs422(t *testing.T) {
	fake := &fakePeople{linesErr: &store.ProcedureError{
		Procedure: "identity.sign_in_lines", Code: "identity:invalid", Message: "every entry must be a person id"}}
	app := peopleApp(t, fake)

	status, got, _ := send(t, app, linesService, fasthttp.MethodPost, "/testonly/lines", linesBody("sub:"+testPersonSub(1)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
	qt.Check(t, qt.StringContains(got, "err:identity:invalid"))
}

// The answer re-prefixes each subject, leaves absent fields out, leaves unknown
// people out, carries only the country and the length of a code and never the
// code, and is not cached.
func TestPersonLinesAnswers(t *testing.T) {
	a, b, c := testPersonSub(1), testPersonSub(2), testPersonSub(3)
	fake := &fakePeople{lines: []store.SignInLine{
		{Sub: a, SignsIn: true, Country: "LV", Length: 12},
		{Sub: b, SignsIn: false, Email: "someone@example.test"},
	}}
	app := peopleApp(t, fake)

	status, got, cache := send(t, app, linesService, fasthttp.MethodPost, "/testonly/lines",
		linesBody("sub:"+a, "sub:"+b, "sub:"+c))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Check(t, qt.Equals(cache, "no-store"))
	qt.Check(t, qt.DeepEquals(fake.asked, []string{a, b, c}), qt.Commentf("the procedure is handed bare ids"))

	var res struct {
		Lines []map[string]any `json:"lines"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(got), &res)))
	qt.Assert(t, qt.Equals(len(res.Lines), 2), qt.Commentf("the unknown person is left out"))

	qt.Check(t, qt.DeepEquals(res.Lines[0], map[string]any{
		"subject": "sub:" + a, "signsIn": true, "country": "LV", "length": float64(12)}))
	qt.Check(t, qt.DeepEquals(res.Lines[1], map[string]any{
		"subject": "sub:" + b, "signsIn": false, "email": "someone@example.test"}))

	qt.Check(t, qt.IsFalse(strings.Contains(got, "PNO")), qt.Commentf("no code in the lines"))
	qt.Check(t, qt.IsFalse(strings.Contains(got, strings.Repeat("3", 6))), qt.Commentf("no code in the lines"))
}

// Nobody known is an empty list, not a missing one.
func TestPersonLinesAnswersAnEmptyList(t *testing.T) {
	app := peopleApp(t, &fakePeople{})

	status, got, _ := send(t, app, linesService, fasthttp.MethodPost, "/testonly/lines", linesBody("sub:"+testPersonSub(1)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Check(t, qt.StringContains(got, `"lines":[]`))
}

// The code read is for a service holding the code level and acting as itself: a
// person's token never reads it, nor a service holding only the lines level, nor
// a token another service obtained to act for one, nor a service account's token
// for an organisation.
func TestPersonCodeRefusesEveryoneButAServiceHoldingCode(t *testing.T) {
	fake := &fakePeople{mapping: store.Mapping{SerialNumber: storedTestCode()}}
	app, reads := peopleAppRecorded(t, fake)
	path := "/testonly/persons/" + testPersonSub(1) + "/code"

	for name, c := range map[string]caller{
		"a person holding the scope":            {"sub:" + testPersonSub(2), "identity:code", ""},
		"a service without it":                  {"svc:console", "envelopes:read", tokenOwn},
		"a service holding lines":               {"svc:console", "identity:lines", tokenOwn},
		"a service account for an organisation": {"svc:console", "identity:code", tokenAccount},
		"another service acting for a service":  {"svc:console", "identity:code", tokenDelegated},
		"a delegated token for no organisation": {"svc:console", "identity:code", tokenDelegatedBare},
	} {
		status, got, _ := send(t, app, c, fasthttp.MethodGet, path, "")
		qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%s", name))
		qt.Check(t, qt.StringContains(got, "err:identity:forbidden"), qt.Commentf("%s", name))
		qt.Check(t, qt.IsFalse(strings.Contains(got, strings.Repeat("3", 6))), qt.Commentf("%s", name))
	}
	qt.Check(t, qt.Equals(fake.getSub, ""), qt.Commentf("a refused caller never reaches the store"))
	qt.Check(t, qt.HasLen(reads.persons, 0), qt.Commentf("a refused read is not recorded as a read"))
}

// Each code answered is recorded as a read by the service that asked, of the
// person whose code it is; a person with no code is not.
func TestPersonCodeRecordsTheRead(t *testing.T) {
	fake := &fakePeople{mapping: store.Mapping{InternalSub: testPersonSub(1), SerialNumber: storedTestCode()}}
	app, reads := peopleAppRecorded(t, fake)

	status, _, _ := send(t, app, codeService, fasthttp.MethodGet, "/testonly/persons/"+testPersonSub(1)+"/code", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Check(t, qt.DeepEquals(reads.callers, []string{"svc:console"}))
	qt.Check(t, qt.DeepEquals(reads.persons, []string{testPersonSub(1)}))

	none := &fakePeople{mapping: store.Mapping{InternalSub: testPersonSub(2)}}
	app, reads = peopleAppRecorded(t, none)
	status, _, _ = send(t, app, codeService, fasthttp.MethodGet, "/testonly/persons/"+testPersonSub(2)+"/code", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
	qt.Check(t, qt.HasLen(reads.persons, 0))
}

// A person id that is not 26 characters of the ULID alphabet is a 422 that does
// not repeat it.
func TestPersonCodeRefusesABadPersonID(t *testing.T) {
	fake := &fakePeople{mapping: store.Mapping{SerialNumber: storedTestCode()}}
	app := peopleApp(t, fake)

	for _, id := range []string{"SENTMARKER", "sub:" + testPersonSub(1), strings.Repeat("U", 26), testPersonSub(1) + "0"} {
		status, got, _ := send(t, app, codeService, fasthttp.MethodGet, "/testonly/persons/"+id+"/code", "")
		qt.Check(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity), qt.Commentf("%q", id))
		qt.Check(t, qt.StringContains(got, "err:identity:invalid"), qt.Commentf("%q", id))
		qt.Check(t, qt.IsFalse(strings.Contains(got, "SENTMARKER")), qt.Commentf("%q", id))
	}
	qt.Check(t, qt.Equals(fake.getSub, ""))
}

// A person the store does not know, and a person who holds no code, are both
// not_found — the two cannot be told apart from outside.
func TestPersonCodeNotFound(t *testing.T) {
	for name, fake := range map[string]*fakePeople{
		"unknown": {getErr: &store.ProcedureError{
			Procedure: "identity.get", Code: "identity:not_found", Message: "identity not found"}},
		"no code":    {mapping: store.Mapping{InternalSub: testPersonSub(1)}},
		"blank code": {mapping: store.Mapping{InternalSub: testPersonSub(1), SerialNumber: "  "}},
	} {
		app := peopleApp(t, fake)

		status, got, _ := send(t, app, codeService, fasthttp.MethodGet,
			"/testonly/persons/"+testPersonSub(1)+"/code", "")
		qt.Check(t, qt.Equals(status, fasthttp.StatusNotFound), qt.Commentf("%s", name))
		qt.Check(t, qt.StringContains(got, "err:identity:not_found"), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(fake.getSub, testPersonSub(1)), qt.Commentf("%s", name))
	}
}

// The answer is the code the way a person is shown it, with the country the
// parsed code names, and it is not cached.
func TestPersonCodeAnswers(t *testing.T) {
	fake := &fakePeople{mapping: store.Mapping{InternalSub: testPersonSub(1), SerialNumber: storedTestCode()}}
	app := peopleApp(t, fake)

	status, got, cache := send(t, app, codeService, fasthttp.MethodGet,
		"/testonly/persons/"+testPersonSub(1)+"/code", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Check(t, qt.Equals(cache, "no-store"))
	qt.Check(t, qt.Equals(fake.getSub, testPersonSub(1)))

	var res map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(got), &res)))
	qt.Check(t, qt.DeepEquals(res, map[string]any{
		"code":    strings.Repeat("3", 6) + "-" + strings.Repeat("3", 5),
		"country": "LV",
	}))
}

// The routes are registered in the identity group, which authenticates first:
// without a token neither is reachable.
func TestPersonReadsRequireAuth(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/identity/persons/lines", []byte(linesBody("sub:"+testPersonSub(1))))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)

	resp, err = app.TestClient().Get("/identity/persons/" + testPersonSub(1) + "/code")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}
