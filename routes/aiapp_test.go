package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/gmb-lib/go-authbyte/replay"
	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/issuer"
	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"
	"github.com/go-make-bytes/authbyte/store"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

// The AI app: Claude Code first, registered in advance with a loopback return
// and the one resource it may ask for, an MCP server.
const (
	aiResource = "https://mcp.example/mcp"
	aiReturn   = "http://localhost:33418/callback"
	aiClient   = "claude-code"
)

// aiBoxes are the six boxes the app may ask for.
var aiBoxes = []string{
	"projects/project:view", "projects/task:view", "projects/task:create", "projects/task:edit",
	"projects/task:changeStageOwn", "projects/task/comment:add",
}

const aiRegistry = `
service_clients:
  - client_id: svc:flowbyte-mcp
    secret_ref: literal:mcp-secret
    enabled: true
    act_from: [https://mcp.example/mcp]
    grants:
      - audience: svc:flowbyte-integration-api
        scopes: [projects:read, projects:write, projects/project:view, projects/task:view, projects/task:create,
                 projects/task:edit, projects/task:changeStageOwn, projects/task/comment:add]
        assistant_levels: [projects:read]
  - client_id: svc:another
    secret_ref: literal:another-secret
    enabled: true
    grants:
      - audience: svc:flowbyte-integration-api
        scopes: [projects/task:view]
  - client_id: svc:flowbyte-integration-api
    secret_ref: literal:api-secret
    enabled: true
    grants:
      - audience: svc:rolebyte
        scopes: [membership:people, membership:admin]
        assistant_levels: [membership:people]
      - audience: svc:flowbyte
        scopes: [projects:read, projects:write, membership:people, projects/task:view, projects/task:edit]
sign_in_clients:
  - client_id: claude-code
    kind: ai_app
    type: public
    client_name: Claude Code
    audience: https://mcp.example/mcp
    enabled: true
    redirect_uris: [http://localhost:33418/callback]
    methods: [upstream]
    scopes: [projects/project:view, projects/task:view, projects/task:create, projects/task:edit,
             projects/task:changeStageOwn, projects/task/comment:add]
  - client_id: plain-app
    type: public
    audience: plain-api
    enabled: true
    redirect_uris: [https://plain.example/cb]
    methods: [upstream]
`

// The people in these tests sign in through the directory as these ids, and the
// identity store keys each by their provider's handle.
const (
	annasOID  = "anna"
	janissOID = "janis"
)

func personKeyOf(oid string) string { return rolebyte.PersonKey("sub-of-" + oid) }

// Their assistants: Anna has two in two workspaces, Jānis one.
var (
	annasFirst = rolebyte.Assistant{
		TenantID: "01TENANTA0000000000000000A", TenantName: "Go Make Bytes",
		Key: "svc:assistant-01ASS1STANT00000000000000A", Name: "Assistant 2",
		Scopes: []string{"projects/project:view", "projects/task:view", "projects/task:create", "projects/task/comment:add"},
	}
	annasSecond = rolebyte.Assistant{
		TenantID: "01TENANTB0000000000000000B", TenantName: "Kalēji",
		Key: "svc:assistant-01ASS1STANT00000000000000B", Name: "Asistents",
		Scopes: []string{"projects/task:view"},
	}
	janissOwn = rolebyte.Assistant{
		TenantID: "01TENANTA0000000000000000A", TenantName: "Go Make Bytes",
		Key: "svc:assistant-01ASS1STANT00000000000000J", Name: "Assistant 3",
		Scopes: aiBoxes,
	}
)

// byHandle is the identity store here: each person is their handle's.
type byHandle struct{}

func (byHandle) EnsureMapping(_ context.Context, handle string, _ store.Profile) (string, bool, error) {
	return "sub-of-" + strings.TrimPrefix(handle, "pairwise-"), false, nil
}

// aiDeployment is the routes with the AI app registered, the directory as the
// sign-in's provider, a register answering assistants, and recorded events.
type aiDeployment struct {
	core     *authbytecore.App
	app      *azugo.TestApp
	mem      *sessiontest.Memory
	lanes    lanes
	register *fakeResolver
	events   *eventLog
}

func aiApp(t *testing.T, extra ...func(*authbytecore.App)) *aiDeployment {
	t.Helper()

	d := &aiDeployment{
		lanes:  lanes{eparaksts: newStandIn(t, false), entra: newStandIn(t, true)},
		mem:    sessiontest.NewMemory(),
		events: &eventLog{},
		register: &fakeResolver{
			memberships: []rolebyte.Membership{{TenantID: annasFirst.TenantID, Scopes: []string{"plain:read"}}},
			assistants: map[string][]rolebyte.Assistant{
				personKeyOf(annasOID):  {annasFirst, annasSecond},
				personKeyOf(janissOID): {janissOwn},
			},
		},
	}
	t.Setenv("SERVICE_CLIENT_REGISTRY", aiRegistry)
	app := authbytecore.TestApp(t, authbytecore.WithUpstreams(d.lanes.entries(t)...))
	app.SetSessionStore(d.mem)
	app.SetReplay(replay.NewMemory())
	app.SetIdentities(byHandle{})
	app.SetScopeResolver(d.register)
	recordingAudit(d.events)(app)
	qt.Assert(t, qt.IsNil(Init(app)))
	for _, f := range extra {
		f(app)
	}

	d.core = app
	d.app = azugo.NewTestApp(app.App)
	d.app.Start(t)
	t.Cleanup(d.app.Stop)

	return d
}

// aiAsk is an AI app's authorization request, PKCE from verifier.
func aiAsk(verifier string, extra url.Values) url.Values {
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {aiClient},
		"redirect_uri":          {aiReturn},
		"state":                 {"app-state"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"resource":              {aiResource},
		"scope":                 {strings.Join(aiBoxes, " ")},
		"acr_values":            {"upstream"},
	}
	for k, v := range extra {
		q[k] = v
	}

	return q
}

// signInAs runs an AI app's sign-in in tc's browser up to the assistant page,
// as the directory person oid.
func (d *aiDeployment) signInAs(t *testing.T, tc *azugo.TestClient, oid string, q url.Values) shown {
	t.Helper()

	a := got(t)(tc.Get("/authorize?"+q.Encode(), asBrowser(tc)))
	loc, err := url.Parse(a.location)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("%d %s", a.status, a.body))
	state := loc.Query().Get("state")
	raw, ok := d.mem.Entries()["flow:"+state]
	qt.Assert(t, qt.IsTrue(ok), qt.Commentf("no flow for %s: %d %s", oid, a.status, a.body))
	var f session.Flow
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(raw), &f)))
	d.lanes.entra.answer(directoryUserinfo(oid))
	d.lanes.entra.expect(f.Nonce, oid)

	page := complete(t, tc, entraPath, state)
	s := shown{answer: page}
	if m := actionRe.FindStringSubmatch(page.body); m != nil {
		s.action = html.UnescapeString(m[1])
	}
	if m := tokenRe.FindStringSubmatch(page.body); m != nil {
		s.token = m[1]
	}

	return s
}

// pick posts a choice from the assistant page, as its form does.
func pick(t *testing.T, tc *azugo.TestClient, s shown, way string) answer {
	t.Helper()

	return got(t)(tc.PostForm(s.action, map[string]any{"way": way, "csrf": s.token},
		asBrowser(tc), tc.WithHeader("Origin", selfOriginInTests)))
}

// codeFrom is the code an answer sent the app back with, after checking it went
// to the app's own address with its state and this issuer.
func codeFrom(t *testing.T, a answer) string {
	t.Helper()

	loc, err := url.Parse(a.location)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(loc.Scheme+"://"+loc.Host+loc.Path, aiReturn), qt.Commentf("%d %s %s", a.status, a.location, a.body))
	qt.Check(t, qt.Equals(loc.Query().Get("state"), "app-state"))
	qt.Check(t, qt.Not(qt.Equals(loc.Query().Get("iss"), "")))
	qt.Assert(t, qt.Not(qt.Equals(loc.Query().Get("code"), "")))

	return loc.Query().Get("code")
}

// tokenAt posts a form to the token endpoint as an AI app does: no DPoP proof.
func tokenAt(t *testing.T, d *aiDeployment, path string, form url.Values, opts ...azugo.TestClientOption) (int, map[string]any) {
	t.Helper()

	tc := d.app.TestClient()
	opts = append([]azugo.TestClientOption{tc.WithHeader("Content-Type", "application/x-www-form-urlencoded")}, opts...)
	resp, err := tc.Post(path, []byte(form.Encode()), opts...)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	out := map[string]any{"_status_text": string(resp.Body())}
	_ = json.Unmarshal(resp.Body(), &out)

	return resp.StatusCode(), out
}

func codeExchange(code, verifier string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {aiClient}, "redirect_uri": {aiReturn}, "resource": {aiResource},
	}
}

func appRefreshForm(token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {aiClient}, "resource": {aiResource}}
}

// readToken is a token's claims, its signature left to the issuer's own tests.
func readToken(t *testing.T, raw any) *claims.Claims {
	t.Helper()

	s, _ := raw.(string)
	var c claims.Claims
	_, _, err := jwt.NewParser().ParseUnverified(s, &c)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("%v", raw))

	return &c
}

// connected is an AI app connected for Anna through annasFirst: its tokens.
func (d *aiDeployment) connected(t *testing.T) map[string]any {
	t.Helper()

	tc := d.app.TestClient()
	verifier := randomToken(32)
	page := d.signInAs(t, tc, annasOID, aiAsk(verifier, nil))
	qt.Assert(t, qt.Equals(page.status, fasthttp.StatusOK), qt.Commentf("%s", page.body))
	code := codeFrom(t, pick(t, tc, page, assistantWay(annasFirst)))
	status, out := tokenAt(t, d, "/token", codeExchange(code, verifier))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", out))

	return out
}

// registryLoad loads a registry document, its secrets left unresolved.
func registryLoad(doc string) (*registry.Registry, error) {
	return registry.Load([]byte(doc), nil)
}

// Cases 1, 2: an AI app's row loads only as a public client with no secret,
// sent back to a loopback or https address, addressed to one resource with no
// fragment, listing boxes.
func TestAnAIAppsRowIsChecked(t *testing.T) {
	head := "sign_in_clients:\n  - client_id: app\n    kind: ai_app\n    enabled: true\n    methods: [upstream]\n"
	good := head + "    type: public\n    audience: https://mcp.example/mcp\n    redirect_uris: [http://localhost:33418/callback, http://127.0.0.1:9/cb, https://app.example/cb]\n    scopes: [projects/task:view]\n"
	_, err := registryLoad(good)
	qt.Check(t, qt.IsNil(err), qt.Commentf("a loopback and an https return, one resource, one box"))

	for name, row := range map[string]string{
		"a secret":             head + "    type: confidential\n    secret_ref: literal:s\n    audience: https://mcp.example/mcp\n    redirect_uris: [http://localhost:1/cb]\n    scopes: [projects/task:view]\n",
		"an http return":       head + "    type: public\n    audience: https://mcp.example/mcp\n    redirect_uris: [http://app.example/cb]\n    scopes: [projects/task:view]\n",
		"no resource":          head + "    type: public\n    audience: mcp\n    redirect_uris: [http://localhost:1/cb]\n    scopes: [projects/task:view]\n",
		"a fragment":           head + "    type: public\n    audience: https://mcp.example/mcp#x\n    redirect_uris: [http://localhost:1/cb]\n    scopes: [projects/task:view]\n",
		"no boxes":             head + "    type: public\n    audience: https://mcp.example/mcp\n    redirect_uris: [http://localhost:1/cb]\n",
		"a level for a box":    head + "    type: public\n    audience: https://mcp.example/mcp\n    redirect_uris: [http://localhost:1/cb]\n    scopes: [projects:read]\n",
		"single sign-on":       head + "    type: public\n    single_sign_on: true\n    audience: https://mcp.example/mcp\n    redirect_uris: [http://localhost:1/cb]\n    scopes: [projects/task:view]\n",
		"the identity code":    head + "    type: public\n    claims: [serial_number]\n    audience: https://mcp.example/mcp\n    redirect_uris: [http://localhost:1/cb]\n    scopes: [projects/task:view]\n",
		"boxes on another row": "sign_in_clients:\n  - client_id: app\n    type: public\n    enabled: true\n    audience: api\n    redirect_uris: [https://a.example/cb]\n    scopes: [projects/task:view]\n",
		"a user name":          head + "    type: public\n    audience: https://mcp.example/mcp\n    redirect_uris: [https://user@app.example/cb]\n    scopes: [projects/task:view]\n",
	} {
		_, err := registryLoad(row)
		qt.Check(t, qt.Not(qt.IsNil(err)), qt.Commentf("%s loads", name))
		if err != nil {
			qt.Check(t, qt.StringContains(err.Error(), `"app"`), qt.Commentf("%s: the refusal names the client", name))
		}
	}
}

// Case 3: discovery says what an MCP client checks before it starts.
func TestDiscoveryNamesWhatAnMCPClientChecks(t *testing.T) {
	d := aiApp(t)
	a := got(t)(d.app.TestClient().Get("/.well-known/openid-configuration"))
	var doc map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(a.body), &doc)))

	has := func(key, want string) bool {
		list, _ := doc[key].([]any)

		return slices.Contains(list, any(want))
	}
	qt.Check(t, qt.IsTrue(has("code_challenge_methods_supported", "S256")))
	qt.Check(t, qt.IsTrue(has("token_endpoint_auth_methods_supported", "none")))
	qt.Check(t, qt.IsTrue(has("grant_types_supported", "refresh_token")))
	qt.Check(t, qt.Equals(doc["authorization_response_iss_parameter_supported"], any(true)))
}

// Cases 4, 5, 6, 7: the request names the app's one resource, or the app hears
// invalid_target at its own address and no sign-in starts; a box beyond its row
// is invalid_scope; an unregistered return gets the error page and goes nowhere.
func TestAnAIAppAsksForItsOneResource(t *testing.T) {
	d := aiApp(t)

	started := func(q url.Values) answer {
		return got(t)(d.app.TestClient().Get("/authorize?"+q.Encode(), asBrowser(d.app.TestClient())))
	}
	flows := func() int {
		n := 0
		for k := range d.mem.Entries() {
			if strings.HasPrefix(k, "flow:") {
				n++
			}
		}

		return n
	}

	ok := started(aiAsk("v", nil))
	qt.Check(t, qt.StringContains(ok.location, d.lanes.entra.url), qt.Commentf("sent on to the directory: %s", ok.location))
	upper := started(aiAsk("v", url.Values{"resource": {"HTTPS://MCP.EXAMPLE/mcp"}}))
	qt.Check(t, qt.StringContains(upper.location, d.lanes.entra.url), qt.Commentf("scheme and host in capitals: %s", upper.location))
	before := flows()

	for name, q := range map[string]url.Values{
		"no resource":    aiAsk("v", url.Values{"resource": nil}),
		"another one":    aiAsk("v", url.Values{"resource": {"https://other.example/mcp"}}),
		"a slash more":   aiAsk("v", url.Values{"resource": {aiResource + "/"}}),
		"two resources":  aiAsk("v", url.Values{"resource": {aiResource, aiResource}}),
		"the path upper": aiAsk("v", url.Values{"resource": {"https://mcp.example/MCP"}}),
	} {
		a := started(q)
		loc, err := url.Parse(a.location)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(loc.Query().Get("error"), "invalid_target"), qt.Commentf("%s: %s", name, a.location))
		qt.Check(t, qt.Equals(loc.Scheme+"://"+loc.Host+loc.Path, aiReturn), qt.Commentf("%s: at the app's own address", name))
		qt.Check(t, qt.Equals(loc.Query().Get("state"), "app-state"))
		qt.Check(t, qt.Not(qt.Equals(loc.Query().Get("iss"), "")))
	}

	scoped := started(aiAsk("v", url.Values{"scope": {"projects/task:view projects/task:delete"}}))
	loc, _ := url.Parse(scoped.location)
	qt.Check(t, qt.Equals(loc.Query().Get("error"), "invalid_scope"), qt.Commentf("%s", scoped.location))

	for _, ret := range []string{"http://localhost:33419/callback", "http://localhost:33418/other"} {
		a := started(aiAsk("v", url.Values{"redirect_uri": {ret}}))
		qt.Check(t, qt.Equals(a.location, ""), qt.Commentf("%s: sent nowhere", ret))
		qt.Check(t, qt.IsTrue(isCannotStart(a)), qt.Commentf("%s: %d %s", ret, a.status, a.body))
	}
	qt.Check(t, qt.Equals(flows(), before), qt.Commentf("no refused request stored a flow"))
}

// Cases 8, 9, 10, 13: after the sign-in the person chooses which of their own
// assistants the app is, each named with its workspace, before any code; one is
// still asked; none is the refusal in words and no code; an application's own
// sign-in has no such page.
func TestTheAssistantPageListsThePersonsOwn(t *testing.T) {
	d := aiApp(t)

	tc := d.app.TestClient()
	anna := d.signInAs(t, tc, annasOID, aiAsk("v", nil))
	qt.Assert(t, qt.Equals(anna.status, fasthttp.StatusOK), qt.Commentf("%s", anna.body))
	qt.Check(t, qt.Equals(anna.location, ""), qt.Commentf("no code before the choice"))
	qt.Check(t, qt.DeepEquals(ways(anna.body), []string{assistantWay(annasFirst), assistantWay(annasSecond)}))
	qt.Check(t, qt.StringContains(anna.body, "Assistant 2 · Go Make Bytes"))
	qt.Check(t, qt.StringContains(anna.body, "Asistents · Kalēji"))
	qt.Check(t, qt.StringContains(anna.body, "Connect Claude Code"))
	qt.Check(t, qt.Not(qt.StringContains(anna.body, janissOwn.Key)), qt.Commentf("none of Jānis's"))

	janis := d.signInAs(t, d.app.TestClient(), janissOID, aiAsk("v", nil))
	qt.Check(t, qt.Equals(janis.status, fasthttp.StatusOK))
	qt.Check(t, qt.DeepEquals(ways(janis.body), []string{assistantWay(janissOwn)}), qt.Commentf("one, still asked"))

	codes := func() int {
		n := 0
		for k := range d.mem.Entries() {
			if strings.HasPrefix(k, "code:") {
				n++
			}
		}

		return n
	}
	none := d.signInAs(t, d.app.TestClient(), "nobody", aiAsk("v", nil))
	qt.Check(t, qt.Equals(none.status, fasthttp.StatusForbidden))
	qt.Check(t, qt.StringContains(none.body,
		"You have no assistant in any workspace. An administrator makes one for you in People &amp; access."))
	qt.Check(t, qt.HasLen(ways(none.body), 0))
	qt.Check(t, qt.Equals(none.location, ""))
	qt.Check(t, qt.Equals(codes(), 0), qt.Commentf("no code for anybody yet"))

	// An application's own sign-in: the code at once, no page.
	plain := d.app.TestClient()
	q := pageQuery("plain-app", "https://plain.example/cb")
	q.Set("acr_values", "upstream")
	a := got(t)(plain.Get("/authorize?"+q.Encode(), asBrowser(plain)))
	loc, _ := url.Parse(a.location)
	state := loc.Query().Get("state")
	var f session.Flow
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(d.mem.Entries()["flow:"+state]), &f)))
	d.lanes.entra.answer(directoryUserinfo(annasOID))
	d.lanes.entra.expect(f.Nonce, annasOID)
	back := complete(t, plain, entraPath, state)
	qt.Check(t, qt.StringContains(back.location, "https://plain.example/cb?"), qt.Commentf("%d %s", back.status, back.body))
	qt.Check(t, qt.StringContains(back.location, "code="))
}

// Cases 11, 12: only one of the person's own assistants is taken, from the page
// in the browser the sign-in began in, with its token, once; anything else mints
// no code.
func TestOnlyThePersonsOwnAssistantIsTakenOnce(t *testing.T) {
	d := aiApp(t)
	codes := func() int {
		n := 0
		for k := range d.mem.Entries() {
			if strings.HasPrefix(k, "code:") {
				n++
			}
		}

		return n
	}

	for name, way := range map[string]string{
		"Jānis's":              assistantWay(janissOwn),
		"a made-up key":        annasFirst.TenantID + "/svc:assistant-01ASS1STANT0000000000000ZZ",
		"in another workspace": annasSecond.TenantID + "/" + annasFirst.Key,
		"none":                 "",
	} {
		tc := d.app.TestClient()
		page := d.signInAs(t, tc, annasOID, aiAsk("v", nil))
		a := pick(t, tc, page, way)
		qt.Check(t, qt.Equals(a.status, fasthttp.StatusForbidden), qt.Commentf("%s: %d %s", name, a.status, a.location))
		qt.Check(t, qt.Not(qt.StringContains(a.location, "code=")), qt.Commentf("%s", name))
	}
	qt.Check(t, qt.Equals(codes(), 0))

	// Without the page's token; from another browser; twice.
	tc := d.app.TestClient()
	page := d.signInAs(t, tc, annasOID, aiAsk("v", nil))
	noToken := got(t)(tc.PostForm(page.action, map[string]any{"way": assistantWay(annasFirst)},
		asBrowser(tc), tc.WithHeader("Origin", selfOriginInTests)))
	qt.Check(t, qt.Equals(noToken.status, fasthttp.StatusForbidden))
	other := d.app.TestClient()
	elsewhere := got(t)(other.PostForm(page.action, map[string]any{"way": assistantWay(annasFirst), "csrf": page.token},
		asBrowser(other), other.WithHeader("Origin", selfOriginInTests)))
	qt.Check(t, qt.Not(qt.Equals(elsewhere.status, fasthttp.StatusSeeOther)), qt.Commentf("another browser: %d", elsewhere.status))
	crossSite := got(t)(tc.PostForm(page.action, map[string]any{"way": assistantWay(annasFirst), "csrf": page.token},
		asBrowser(tc), tc.WithHeader("Origin", "https://evil.example")))
	qt.Check(t, qt.Equals(crossSite.status, fasthttp.StatusForbidden))
	qt.Check(t, qt.Equals(codes(), 0))

	first := pick(t, tc, page, assistantWay(annasFirst))
	qt.Check(t, qt.Equals(first.status, fasthttp.StatusSeeOther))
	codeFrom(t, first)
	again := pick(t, tc, page, assistantWay(annasFirst))
	qt.Check(t, qt.Equals(again.status, fasthttp.StatusUnauthorized), qt.Commentf("a second time"))
	qt.Check(t, qt.Equals(codes(), 1), qt.Commentf("one code, no second"))
}

// Cases 14, 16: the app token is Anna's, through the assistant she chose, for
// the one resource, with the boxes she and it both hold that the app asked for,
// plain bearer, the lowest assurance, the app's own lifetime, and a refresh
// token beside it.
func TestTheAppTokenIsThePersonsThroughTheAssistant(t *testing.T) {
	d := aiApp(t)
	out := d.connected(t)

	qt.Check(t, qt.Equals(out["token_type"], any("Bearer")))
	qt.Check(t, qt.Equals(out["expires_in"], any(float64(300))))
	qt.Check(t, qt.Not(qt.Equals(out["refresh_token"], any(nil))))
	qt.Check(t, qt.Equals(out["scope"], any(strings.Join(annasFirst.Scopes, " "))))

	c := readToken(t, out["access_token"])
	qt.Check(t, qt.Equals(c.Subject, "sub-of-anna"))
	qt.Check(t, qt.DeepEquals([]string(c.Audience), []string{aiResource}))
	qt.Check(t, qt.Equals(c.Tenant, annasFirst.TenantID))
	qt.Assert(t, qt.Not(qt.IsNil(c.Act)))
	qt.Check(t, qt.Equals(c.Act.Subject, annasFirst.Key))
	qt.Check(t, qt.IsNil(c.Act.Act))
	qt.Check(t, qt.IsNil(c.Confirmation), qt.Commentf("no cnf: a plain bearer token"))
	qt.Check(t, qt.Equals(c.LoginMethod, identity.LoginAssistant))
	qt.Check(t, qt.Equals(c.LoA, identity.LoALow))
	qt.Check(t, qt.Equals(c.Scope, strings.Join(annasFirst.Scopes, " ")),
		qt.Commentf("the four both hold of the six asked, not projects/task:edit nor changeStageOwn"))
	qt.Check(t, qt.Equals(c.ClientID, aiClient))
}

// Cases 15, 17: a wrong verifier, no or another resource, a used code: refused
// in RFC 6749's words, no token; a DPoP proof sent anyway changes nothing.
func TestTheAppsCodeExchangeIsRefusedInOAuthsWords(t *testing.T) {
	d := aiApp(t)

	fresh := func() (string, string) {
		tc := d.app.TestClient()
		verifier := randomToken(32)
		page := d.signInAs(t, tc, annasOID, aiAsk(verifier, nil))

		return codeFrom(t, pick(t, tc, page, assistantWay(annasFirst))), verifier
	}

	code, verifier := fresh()
	status, out := tokenAt(t, d, "/token", codeExchange(code, verifier+"x"))
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(out["error"], any("invalid_grant")))
	qt.Check(t, qt.Equals(out["access_token"], any(nil)))

	for name, form := range map[string]url.Values{
		"no resource":      {"resource": nil},
		"another resource": {"resource": {"https://other.example/mcp"}},
	} {
		code, verifier := fresh()
		f := codeExchange(code, verifier)
		for k, v := range form {
			if v == nil {
				f.Del(k)
			} else {
				f[k] = v
			}
		}
		status, out := tokenAt(t, d, "/token", f)
		qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(out["error"], any("invalid_target")), qt.Commentf("%s", name))
		// The code was not spent on a request refused before it: it still works.
		status, _ = tokenAt(t, d, "/token", codeExchange(code, verifier))
		qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: the code still good", name))
	}

	code, verifier = fresh()
	status, out = tokenAt(t, d, "/token", codeExchange(code, verifier),
		d.app.TestClient().WithHeader("DPoP", "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.e30.sig"))
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", out))
	qt.Check(t, qt.Equals(out["token_type"], any("Bearer")))
	qt.Check(t, qt.IsNil(readToken(t, out["access_token"]).Confirmation))
	status, out = tokenAt(t, d, "/token", codeExchange(code, verifier))
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("the code a second time"))
	qt.Check(t, qt.Equals(out["error"], any("invalid_grant")))
}

// Case 18: the exception is the AI app's alone; any other client's code and
// refresh still need a DPoP proof.
func TestEveryOtherClientStillProvesItsKey(t *testing.T) {
	d := aiApp(t)
	in := seedSignIn(t, d.mem, "plain-app", "https://plain.example/cb")
	status, out := tokenAt(t, d, "/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {in.code}, "code_verifier": {in.verifier},
		"client_id": {"plain-app"}, "redirect_uri": {"https://plain.example/cb"},
	})
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%v", out))
	qt.Check(t, qt.Equals(out["access_token"], any(nil)))
	status, _ = tokenAt(t, d, "/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {"plain-app"}})
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}

// Cases 19, 20, 25, 26: a refresh token is good once; the next one works; the
// used one again ends that connection, its newest token with it, and nothing
// of another connection; another resource is invalid_target.
func TestTheAppsRefreshTokenIsGoodOnce(t *testing.T) {
	d := aiApp(t)
	one := d.connected(t)
	other := d.connected(t)

	status, two := tokenAt(t, d, "/token", appRefreshForm(one["refresh_token"].(string)))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", two))
	qt.Check(t, qt.Not(qt.Equals(two["refresh_token"], one["refresh_token"])), qt.Commentf("a new refresh token"))
	qt.Check(t, qt.Equals(two["token_type"], any("Bearer")))

	status, three := tokenAt(t, d, "/token", appRefreshForm(two["refresh_token"].(string)))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", three))

	status, out := tokenAt(t, d, "/token", appRefreshForm(one["refresh_token"].(string)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(out["error"], any("invalid_grant")))
	status, out = tokenAt(t, d, "/token", appRefreshForm(three["refresh_token"].(string)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("the connection ended with the reuse"))
	qt.Check(t, qt.Equals(out["error"], any("invalid_grant")))

	status, _ = tokenAt(t, d, "/token", appRefreshForm(other["refresh_token"].(string)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("the other connection goes on"))

	fresh := d.connected(t)
	form := appRefreshForm(fresh["refresh_token"].(string))
	form.Set("resource", "https://other.example/mcp")
	status, out = tokenAt(t, d, "/token", form)
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(out["error"], any("invalid_target")))
	form.Del("resource")
	status, _ = tokenAt(t, d, "/token", form)
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("a refresh may leave the resource out"))
}

// Cases 21, 22: every refresh asks the register again. The assistant gone,
// given to Jānis, or Anna gone from the workspace ends the connection; a box
// the assistant lost is gone from the next token.
func TestEveryRefreshAsksTheRegisterAgain(t *testing.T) {
	d := aiApp(t)
	anna := personKeyOf(annasOID)

	narrower := annasFirst
	narrower.Scopes = []string{"projects/task:view"}
	out := d.connected(t)
	d.register.assistants[anna] = []rolebyte.Assistant{narrower, annasSecond}
	status, next := tokenAt(t, d, "/token", appRefreshForm(out["refresh_token"].(string)))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", next))
	qt.Check(t, qt.Equals(readToken(t, next["access_token"]).Scope, "projects/task:view"))
	d.register.assistants[anna] = []rolebyte.Assistant{annasFirst, annasSecond}

	for name, now := range map[string][]rolebyte.Assistant{
		"removed":                      {annasSecond},
		"given to Jānis":               nil,
		"Anna gone from Go Make Bytes": {annasSecond},
		"in another workspace now":     {{TenantID: annasSecond.TenantID, TenantName: "Kalēji", Key: annasFirst.Key, Name: "Assistant 2"}},
	} {
		out := d.connected(t)
		d.register.assistants[anna] = now
		status, res := tokenAt(t, d, "/token", appRefreshForm(out["refresh_token"].(string)))
		qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(res["error"], any("invalid_grant")), qt.Commentf("%s", name))
		d.register.assistants[anna] = []rolebyte.Assistant{annasFirst, annasSecond}
		status, _ = tokenAt(t, d, "/token", appRefreshForm(out["refresh_token"].(string)))
		qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("%s: ended, not refused once", name))
	}

	// A register that cannot answer refuses the refresh and ends nothing.
	out = d.connected(t)
	d.register.assistantsErr = context.DeadlineExceeded
	status, _ = tokenAt(t, d, "/token", appRefreshForm(out["refresh_token"].(string)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadGateway))
	d.register.assistantsErr = nil
	status, _ = tokenAt(t, d, "/token", appRefreshForm(out["refresh_token"].(string)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("the connection goes on after the outage"))
}

// Case 23: a connection lives no longer than its sign-in's session.
func TestAConnectionEndsWithItsSession(t *testing.T) {
	d := aiApp(t)
	start := time.Now()
	d.mem.SetClock(func() time.Time { return start })
	out := d.connected(t)

	d.mem.SetClock(func() time.Time { return start.Add(sessionLifetime - time.Second) })
	status, next := tokenAt(t, d, "/token", appRefreshForm(out["refresh_token"].(string)))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("a second before the end: %v", next))

	d.mem.SetClock(func() time.Time { return start.Add(sessionLifetime) })
	status, res := tokenAt(t, d, "/token", appRefreshForm(next["refresh_token"].(string)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("at the end: %v", res))
	qt.Check(t, qt.Equals(res["error"], any("invalid_grant")))
}

// Case 24 (and 25): the app signs itself out with its refresh token and no key;
// that connection ends, and only that one.
func TestTheAppSignsItselfOut(t *testing.T) {
	d := aiApp(t)
	one := d.connected(t)
	other := d.connected(t)

	status, _ := tokenAt(t, d, "/revoke", url.Values{"token": {one["refresh_token"].(string)}, "client_id": {aiClient}})
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK))
	status, out := tokenAt(t, d, "/token", appRefreshForm(one["refresh_token"].(string)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(out["error"], any("invalid_grant")))

	status, _ = tokenAt(t, d, "/token", appRefreshForm(other["refresh_token"].(string)))
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("the other connection goes on"))
}

// exchangeAt exchanges token as client for a token toward audience asking scope.
func (d *aiDeployment) exchangeAt(t *testing.T, client, secret, token, audience, scope string) (int, map[string]any) {
	t.Helper()

	e := newEdge(t, d.app)
	e.basic = []string{client, secret}

	return e.post("/token", url.Values{
		"grant_type":         {grantTokenExchange},
		"client_id":          {client},
		"subject_token":      {token},
		"subject_token_type": {tokenTypeAccessToken},
		"audience":           {audience},
		"scope":              {scope},
	})
}

// Cases 27, 28, 29, 30: the MCP server exchanges the app token for a pass that is
// Anna's, through the assistant, presented by the server, at the lowest
// assurance, bound to the server's key, carrying no box the app token lacks and,
// of the levels it asks for, those its grant names for an assistant's chain;
// another client may not; an app token past its life is refused.
func TestTheServerExchangesTheAppToken(t *testing.T) {
	d := aiApp(t)
	out := d.connected(t)
	appToken := out["access_token"].(string)

	exchange := func(client, secret, token, scope string) (int, map[string]any) {
		return d.exchangeAt(t, client, secret, token, "svc:flowbyte-integration-api", scope)
	}

	status, pass := exchange("svc:flowbyte-mcp", "mcp-secret", appToken, "projects:read projects:write "+strings.Join(aiBoxes, " "))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", pass))
	c := readToken(t, pass["access_token"])
	qt.Check(t, qt.Equals(c.Subject, "sub-of-anna"))
	qt.Check(t, qt.Equals(c.Tenant, annasFirst.TenantID))
	qt.Assert(t, qt.Not(qt.IsNil(c.Act)))
	qt.Check(t, qt.Equals(c.Act.Subject, "svc:flowbyte-mcp"))
	qt.Assert(t, qt.Not(qt.IsNil(c.Act.Act)))
	qt.Check(t, qt.Equals(c.Act.Act.Subject, annasFirst.Key))
	qt.Check(t, qt.Equals(c.LoginMethod, identity.LoginAssistant))
	qt.Check(t, qt.Equals(c.LoA, identity.LoALow))
	qt.Assert(t, qt.Not(qt.IsNil(c.Confirmation)), qt.Commentf("bound to the server's key"))
	qt.Check(t, qt.Equals(c.Scope, "projects:read "+strings.Join(annasFirst.Scopes, " ")),
		qt.Commentf("the named level asked for, not the one the grant leaves unnamed, and of the boxes only the app token's"))

	status, res := exchange("svc:flowbyte-mcp", "mcp-secret", appToken, "membership:people")
	qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("a level outside the server's grant: %v", res))
	qt.Check(t, qt.Equals(res["access_token"], any(nil)))

	status, whole := exchange("svc:flowbyte-mcp", "mcp-secret", appToken, "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", whole))
	qt.Check(t, qt.Equals(readToken(t, whole["access_token"]).Scope, "projects:read "+strings.Join(annasFirst.Scopes, " ")),
		qt.Commentf("an empty ask is the server's whole grant: its named level, and its boxes narrowed to the app token's"))

	status, boxes := exchange("svc:flowbyte-mcp", "mcp-secret", appToken, strings.Join(aiBoxes, " "))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", boxes))
	qt.Check(t, qt.Equals(readToken(t, boxes["access_token"]).Scope, strings.Join(annasFirst.Scopes, " ")),
		qt.Commentf("a named level not asked for is not added"))

	status, _ = exchange("svc:another", "another-secret", appToken, "projects/task:view")
	qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("a client that does not act from the resource"))
}

// The product API, holding a pass made through an assistant, exchanges it again
// for the services it calls: of its grant's levels only those the grant toward
// that service names reach it, so it can name people for the person while an
// authority level stays behind; a box goes on only where the pass carries it.
func TestTheNextHopCarriesOnlyTheLevelsItsGrantNames(t *testing.T) {
	d := aiApp(t)
	appToken := d.connected(t)["access_token"].(string)
	status, pass := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", appToken,
		"svc:flowbyte-integration-api", "projects:read "+strings.Join(aiBoxes, " "))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", pass))
	passToken := pass["access_token"].(string)
	qt.Assert(t, qt.Equals(readToken(t, passToken).Scope, "projects:read "+strings.Join(annasFirst.Scopes, " ")))

	status, names := d.exchangeAt(t, "svc:flowbyte-integration-api", "api-secret", passToken, "svc:rolebyte",
		"membership:people membership:admin")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", names))
	c := readToken(t, names["access_token"])
	qt.Check(t, qt.Equals(c.Scope, "membership:people"), qt.Commentf("the named level, not the authority level beside it"))
	qt.Check(t, qt.Equals(c.Subject, "sub-of-anna"))
	qt.Check(t, qt.Equals(c.Tenant, annasFirst.TenantID))
	qt.Check(t, qt.Equals(c.LoginMethod, identity.LoginAssistant))
	qt.Check(t, qt.Equals(c.LoA, identity.LoALow))
	qt.Assert(t, qt.Not(qt.IsNil(c.Act)))
	qt.Check(t, qt.Equals(c.Act.Subject, "svc:flowbyte-integration-api"))
	qt.Assert(t, qt.Not(qt.IsNil(c.Act.Act)))
	qt.Check(t, qt.Equals(c.Act.Act.Subject, "svc:flowbyte-mcp"))
	qt.Assert(t, qt.Not(qt.IsNil(c.Act.Act.Act)))
	qt.Check(t, qt.Equals(c.Act.Act.Act.Subject, annasFirst.Key))

	status, engine := d.exchangeAt(t, "svc:flowbyte-integration-api", "api-secret", passToken, "svc:flowbyte",
		"projects:read projects:write membership:people projects/task:view projects/task:edit")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", engine))
	qt.Check(t, qt.Equals(readToken(t, engine["access_token"]).Scope, "projects/task:view"),
		qt.Commentf("a grant naming no level passes none, not one the pass carries nor one named toward another "+
			"service; a box the pass lacks stays out"))
}

// A token not made through an assistant is not narrowed: the exchanging client's
// grant decides, as for every exchange, a level it does not name included.
func TestAnOrdinaryTokenIsExchangedByTheGrantAlone(t *testing.T) {
	d := aiApp(t)
	tok, _, err := d.core.Issuer().IssueUser(issuer.UserTokenInput{
		Subject:     "sub-of-anna",
		Audience:    aiResource,
		Scopes:      []string{"projects/task:view"},
		LoA:         identity.LoAHigh,
		LoginMethod: identity.LoginEParakstsMobile,
		Tenant:      annasFirst.TenantID,
		Thumbprint:  "thumbprint-of-anna",
		ClientID:    "plain-app",
	})
	qt.Assert(t, qt.IsNil(err))

	status, pass := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", tok, "svc:flowbyte-integration-api",
		"projects:write projects/task:edit")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", pass))
	qt.Check(t, qt.Equals(readToken(t, pass["access_token"]).Scope, "projects:write projects/task:edit"))
}

// Case 30: an app token past its lifetime is exchanged for nothing.
func TestAnAppTokenPastItsLifeIsNotExchanged(t *testing.T) {
	t.Setenv("APP_TOKEN_TTL", "1s")
	d := aiApp(t)
	appToken := d.connected(t)["access_token"].(string)
	qt.Check(t, qt.Equals(readToken(t, appToken).ExpiresAt.Sub(readToken(t, appToken).IssuedAt.Time), time.Second))

	time.Sleep(2100 * time.Millisecond)
	e := newEdge(t, d.app)
	e.basic = []string{"svc:flowbyte-mcp", "mcp-secret"}
	status, res := e.post("/token", url.Values{
		"grant_type": {grantTokenExchange}, "client_id": {"svc:flowbyte-mcp"}, "subject_token": {appToken},
		"subject_token_type": {tokenTypeAccessToken}, "audience": {"svc:flowbyte-integration-api"}, "scope": {"projects/task:view"},
	})
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%v", res))
	qt.Check(t, qt.Equals(res["access_token"], any(nil)))
}

// Review finding 2: one refresh token sent many times at once renews the
// connection once at most, and leaves at most one live chain.
func TestARefreshTokenSentManyTimesAtOnceRenewsOnce(t *testing.T) {
	d := aiApp(t)
	for round := 0; round < 5; round++ {
		token := d.connected(t)["refresh_token"].(string)

		const n = 12
		var wg sync.WaitGroup
		next := make(chan string, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if status, out := tokenAt(t, d, "/token", appRefreshForm(token)); status == fasthttp.StatusOK {
					next <- out["refresh_token"].(string)
				}
			}()
		}
		wg.Wait()
		close(next)

		renewed := []string{}
		for tok := range next {
			renewed = append(renewed, tok)
		}
		qt.Check(t, qt.IsTrue(len(renewed) <= 1), qt.Commentf("round %d: %d renewals of one token", round, len(renewed)))
		live := 0
		for _, tok := range renewed {
			if status, _ := tokenAt(t, d, "/token", appRefreshForm(tok)); status == fasthttp.StatusOK {
				live++
			}
		}
		qt.Check(t, qt.IsTrue(live <= 1), qt.Commentf("round %d: %d live chains", round, live))
	}
}

// Review finding 4: a box the app's row no longer lists is gone from the next
// token of a connection made while it did.
func TestTheAppsRowNarrowsItsConnections(t *testing.T) {
	d := aiApp(t)
	out := d.connected(t)

	// The connection as if made when the row also listed a box it lists no more,
	// one the person and the assistant both still hold.
	extra := "projects/task:delete"
	anna := personKeyOf(annasOID)
	held := annasFirst
	held.Scopes = append(append([]string{}, annasFirst.Scopes...), extra)
	d.register.assistants[anna] = []rolebyte.Assistant{held, annasSecond}
	changed := 0
	for key, raw := range d.mem.Entries() {
		if !strings.HasPrefix(key, "sess:") {
			continue
		}
		var s session.Session
		qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(raw), &s)))
		if s.Assistant == annasFirst.Key {
			s.AppScopes = append(s.AppScopes, extra)
			qt.Assert(t, qt.IsNil(d.mem.ReplaceSession(context.Background(), strings.TrimPrefix(key, "sess:"), &s)))
			changed++
		}
	}
	qt.Assert(t, qt.Equals(changed, 1), qt.Commentf("the connection's session was changed"))

	status, next := tokenAt(t, d, "/token", appRefreshForm(out["refresh_token"].(string)))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", next))
	qt.Check(t, qt.Not(qt.StringContains(readToken(t, next["access_token"]).Scope, extra)))
}

// Review finding 7: a provider's return naming an assistant page's ticket as its
// state spends nothing; the page's choice still goes through.
func TestAProvidersReturnCannotSpendThePagesTicket(t *testing.T) {
	d := aiApp(t)
	tc := d.app.TestClient()
	page := d.signInAs(t, tc, annasOID, aiAsk("v", nil))
	u, err := url.Parse(page.action)
	qt.Assert(t, qt.IsNil(err))
	ticket := u.Query().Get("ticket")
	qt.Assert(t, qt.Not(qt.Equals(ticket, "")))

	back := complete(t, tc, entraPath, assistantTicketPrefix+ticket)
	qt.Check(t, qt.Equals(back.status, fasthttp.StatusUnauthorized))
	failed := got(t)(tc.Get(entraPath+"?error=access_denied&state="+url.QueryEscape(assistantTicketPrefix+ticket), asBrowser(tc)))
	qt.Check(t, qt.Equals(failed.status, fasthttp.StatusUnauthorized))

	codeFrom(t, pick(t, tc, page, assistantWay(annasFirst)))
}
