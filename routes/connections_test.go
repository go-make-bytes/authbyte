package routes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gmb-lib/go-authbyte/claims"
	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/issuer"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/azugo"
	"azugo.io/azugo/user"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The connections' routes run behind the identity door's authentication; here
// they sit on scratch routes behind a stand-in for it, the caller's claims read
// from request headers, so the rights rules run through the real handlers. The
// door itself is proved on the stack.
func connectionRoutes(app *authbytecore.App) {
	r := &router{App: app}
	as := func(h azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			c := &claims.Claims{Scope: ctx.Header.Get("X-Test-Scope"), Tenant: ctx.Header.Get("X-Test-Tenant")}
			c.Subject = ctx.Header.Get("X-Test-Sub")
			switch ctx.Header.Get("X-Test-Kind") {
			case "app":
				c.ClientID = aiClient
				c.Act = &claims.Actor{Subject: annasFirst.Key}
			case "app-bare":
				// Not one the issuer mints (an app token always names its
				// assistant): the second guard, proved on its own.
				c.ClientID = aiClient
			case "delegated":
				c.Act = &claims.Actor{Subject: "svc:flowbyte-bff"}
			case "service":
				c.ClientID = c.Subject
			default:
				c.ClientID = "plain-app"
			}
			ctx.SetUser(user.New(c.ToUserClaims()))
			h(ctx)
		}
	}
	app.Get("/testonly/connections", as(r.ownConnections))
	app.Delete("/testonly/connections/{id}", as(r.signOutOwnConnection))
	app.Get("/testonly/assistants/{assistant}/connections", as(r.assistantConnections))
	app.Delete("/testonly/assistants/{assistant}/connections/{id}", as(r.signOutAssistantConnection))
	app.Delete("/testonly/assistants/{assistant}/connections", as(r.endAssistantConnections))
}

// who is a caller of the connections' routes.
type who struct{ sub, tenant, scope, kind string }

var (
	annaInA  = who{sub: "sub-of-anna", tenant: annasFirst.TenantID}
	annaInB  = who{sub: "sub-of-anna", tenant: annasSecond.TenantID}
	janisInA = who{sub: "sub-of-janis", tenant: janissOwn.TenantID}
	// The administrator of workspace A, and one of workspace B.
	adminOfA = who{sub: "sub-of-gatis", tenant: annasFirst.TenantID, scope: "membership:admin"}
	adminOfB = who{sub: "sub-of-gatis", tenant: annasSecond.TenantID, scope: "membership:admin"}
	// A member of A who is not its administrator.
	memberOfA = who{sub: "sub-of-maris", tenant: annasFirst.TenantID, scope: "membership:people membership:self"}
)

func (d *aiDeployment) call(t *testing.T, w who, method, path string) (int, map[string]any) {
	t.Helper()

	tc := d.app.TestClient()
	opts := []azugo.TestClientOption{
		tc.WithHeader("X-Test-Sub", w.sub), tc.WithHeader("X-Test-Tenant", w.tenant),
		tc.WithHeader("X-Test-Scope", w.scope), tc.WithHeader("X-Test-Kind", w.kind),
	}
	var (
		resp *fasthttp.Response
		err  error
	)
	if method == fasthttp.MethodDelete {
		resp, err = tc.Delete("/testonly"+path, opts...)
	} else {
		resp, err = tc.Get("/testonly"+path, opts...)
	}
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	out := map[string]any{"_body": string(resp.Body())}
	_ = json.Unmarshal(resp.Body(), &out)

	return resp.StatusCode(), out
}

// connectAs connects an AI app for the directory person oid as assistant a, and
// answers its tokens.
func (d *aiDeployment) connectAs(t *testing.T, oid string, a rolebyte.Assistant) map[string]any {
	t.Helper()

	tc := d.app.TestClient()
	verifier := randomToken(32)
	page := d.signInAs(t, tc, oid, aiAsk(verifier, nil))
	qt.Assert(t, qt.Equals(page.status, fasthttp.StatusOK), qt.Commentf("%s", page.body))
	code := codeFrom(t, pick(t, tc, page, assistantWay(a)))
	status, out := tokenAt(t, d, "/token", codeExchange(code, verifier))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", out))

	return out
}

// toolCall is the MCP server's exchange of an app token, as one tool call makes it.
func (d *aiDeployment) toolCall(t *testing.T, appToken string) int {
	t.Helper()

	status, _ := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", appToken, "svc:flowbyte-integration-api", "projects/task:view")

	return status
}

func (d *aiDeployment) refreshes(t *testing.T, tokens map[string]any) (bool, map[string]any) {
	t.Helper()

	status, out := tokenAt(t, d, "/token", appRefreshForm(tokens["refresh_token"].(string)))

	return status == fasthttp.StatusOK, out
}

// connectionsOf is the connections an answer lists for assistant key, own or not.
func connectionsOf(out map[string]any, key string) []map[string]any {
	var list []any
	if as, ok := out["assistants"].([]any); ok {
		for _, a := range as {
			if m, _ := a.(map[string]any); m["key"] == key {
				list, _ = m["connections"].([]any)
			}
		}
	} else {
		list, _ = out["connections"].([]any)
	}
	res := make([]map[string]any, 0, len(list))
	for _, c := range list {
		m, _ := c.(map[string]any)
		res = append(res, m)
	}

	return res
}

func idsOf(cs []map[string]any) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c["id"].(string))
	}

	return out
}

func withClock(t *testing.T, now func() time.Time) {
	t.Helper()

	before := clock
	clock = now
	t.Cleanup(func() { clock = before })
}

// A person's own connections, by assistant, in the workspace
// their token names: the app by its registered name, when it connected, not used
// yet; another workspace's and another person's are not among them; an assistant
// with none is listed with none; and the id is the connection's own, never a key
// the store keeps or a refresh token.
func TestAPersonsOwnConnectionsAreListedByAssistant(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	before := time.Now().Add(-time.Second)
	one := d.connectAs(t, annasOID, annasFirst)
	two := d.connectAs(t, annasOID, annasFirst)
	d.connectAs(t, annasOID, annasSecond)

	status, out := d.call(t, janisInA, fasthttp.MethodGet, "/connections")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", out))
	as, _ := out["assistants"].([]any)
	qt.Assert(t, qt.HasLen(as, 1), qt.Commentf("Jānis's own assistant, with no app yet: %v", out))
	qt.Check(t, qt.Equals(as[0].(map[string]any)["name"], any(janissOwn.Name)))
	qt.Check(t, qt.HasLen(connectionsOf(out, janissOwn.Key), 0))
	d.connectAs(t, janissOID, janissOwn)

	status, out = d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", out))
	as, _ = out["assistants"].([]any)
	qt.Assert(t, qt.HasLen(as, 1), qt.Commentf("workspace A's assistant only: %v", out))
	qt.Check(t, qt.Equals(as[0].(map[string]any)["key"], any(annasFirst.Key)))
	qt.Check(t, qt.Equals(as[0].(map[string]any)["name"], any(annasFirst.Name)))
	listed := connectionsOf(out, annasFirst.Key)
	qt.Assert(t, qt.HasLen(listed, 2))
	for _, c := range listed {
		qt.Check(t, qt.Equals(c["app"], any("Claude Code")))
		qt.Check(t, qt.IsNil(c["lastUsed"]), qt.Commentf("not used yet"))
		at, err := time.Parse(time.RFC3339, c["connectedAt"].(string))
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.IsTrue(at.After(before) && at.Before(time.Now().Add(time.Second))), qt.Commentf("connected now: %v", at))
	}

	// The ids are the connections' own: no key the store keeps, no token.
	body := out["_body"].(string)
	for key := range d.mem.Entries() {
		if s, ok := strings.CutPrefix(key, "sess:"); ok {
			qt.Check(t, qt.IsFalse(strings.Contains(body, s)), qt.Commentf("a session key in the answer"))
		}
	}
	for _, tok := range []map[string]any{one, two} {
		qt.Check(t, qt.IsFalse(strings.Contains(body, tok["refresh_token"].(string))))
		qt.Check(t, qt.IsFalse(strings.Contains(body, tok["access_token"].(string))))
	}

	status, out = d.call(t, annaInB, fasthttp.MethodGet, "/connections")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Check(t, qt.HasLen(connectionsOf(out, annasSecond.Key), 1), qt.Commentf("workspace B's, asked with B's token: %v", out))
	qt.Check(t, qt.HasLen(connectionsOf(out, annasFirst.Key), 0))
}

// A tool call through the app marks the connection used; when it
// connected never moves; a second call within the minute writes nothing new.
func TestAToolCallMarksTheConnectionUsed(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	t0 := time.Now().Truncate(time.Second)
	withClock(t, func() time.Time { return t0 })
	tokens := d.connectAs(t, annasOID, annasFirst)

	withClock(t, func() time.Time { return t0.Add(10 * time.Second) })
	qt.Assert(t, qt.Equals(d.toolCall(t, tokens["access_token"].(string)), fasthttp.StatusOK))
	withClock(t, func() time.Time { return t0.Add(40 * time.Second) })
	qt.Assert(t, qt.Equals(d.toolCall(t, tokens["access_token"].(string)), fasthttp.StatusOK))

	_, out := d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	c := connectionsOf(out, annasFirst.Key)
	qt.Assert(t, qt.HasLen(c, 1))
	qt.Check(t, qt.Equals(c[0]["connectedAt"], any(t0.UTC().Format(time.RFC3339))))
	qt.Check(t, qt.Equals(c[0]["lastUsed"], any(t0.Add(10*time.Second).UTC().Format(time.RFC3339))),
		qt.Commentf("the second call, within the minute, writes nothing"))

	withClock(t, func() time.Time { return t0.Add(80 * time.Second) })
	qt.Assert(t, qt.Equals(d.toolCall(t, tokens["access_token"].(string)), fasthttp.StatusOK))
	_, out = d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	c = connectionsOf(out, annasFirst.Key)
	qt.Check(t, qt.Equals(c[0]["lastUsed"], any(t0.Add(80*time.Second).UTC().Format(time.RFC3339))))
	qt.Check(t, qt.Equals(c[0]["connectedAt"], any(t0.UTC().Format(time.RFC3339))))
}

// The person signs one of two apps out: its refresh is refused, its
// next tool call is refused at once though its token has not expired, and the
// other app goes on.
func TestAPersonSignsOneAppOutAndItStopsAtOnce(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	one := d.connectAs(t, annasOID, annasFirst)
	other := d.connectAs(t, annasOID, annasFirst)
	qt.Assert(t, qt.Equals(d.toolCall(t, one["access_token"].(string)), fasthttp.StatusOK))

	_, out := d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	listed := connectionsOf(out, annasFirst.Key)
	qt.Assert(t, qt.HasLen(listed, 2))
	// The connection the first app holds is the one its token names.
	target := readSID(t, one["access_token"].(string))
	qt.Assert(t, qt.Not(qt.Equals(target, "")))
	qt.Assert(t, qt.IsTrue(slices.Contains(idsOf(listed), target)), qt.Commentf("%v %s", idsOf(listed), target))

	status, res := d.call(t, annaInA, fasthttp.MethodDelete, "/connections/"+url.PathEscape(target))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNoContent), qt.Commentf("%v", res))
	indexed, err := d.mem.Connections(context.Background(), annasFirst.TenantID, annasFirst.Key)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(indexed, 1), qt.Commentf("out of its assistant's index at its end, not left for a list to drop"))

	qt.Check(t, qt.Equals(d.toolCall(t, one["access_token"].(string)), fasthttp.StatusUnauthorized),
		qt.Commentf("its token is still within its lifetime, and refused"))
	_, refused := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", one["access_token"].(string), "svc:flowbyte-integration-api", "projects/task:view")
	qt.Check(t, qt.Equals(refused["code"], any("err:connection:ended")), qt.Commentf("named, so the app is told to sign in again: %v", refused))
	ok, ans := d.refreshes(t, one)
	qt.Check(t, qt.IsFalse(ok))
	qt.Check(t, qt.Equals(ans["error"], any("invalid_grant")))

	qt.Check(t, qt.Equals(d.toolCall(t, other["access_token"].(string)), fasthttp.StatusOK), qt.Commentf("the other goes on"))
	ok, _ = d.refreshes(t, other)
	qt.Check(t, qt.IsTrue(ok))
	_, out = d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	qt.Check(t, qt.HasLen(connectionsOf(out, annasFirst.Key), 1))
}

// readSID is the connection an app token names.
func readSID(t *testing.T, raw string) string {
	t.Helper()

	parts := strings.Split(raw, ".")
	qt.Assert(t, qt.HasLen(parts, 3))
	var c struct {
		SID string `json:"sid"`
	}
	qt.Assert(t, qt.IsNil(decodeSegment(parts[1], &c)))

	return c.SID
}

// Another person neither sees nor signs out Anna's connection.
func TestAnotherPersonCannotSignOutAConnection(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	annas := d.connectAs(t, annasOID, annasFirst)
	target := readSID(t, annas["access_token"].(string))

	_, out := d.call(t, janisInA, fasthttp.MethodGet, "/connections")
	qt.Check(t, qt.IsFalse(strings.Contains(out["_body"].(string), target)))

	status, res := d.call(t, janisInA, fasthttp.MethodDelete, "/connections/"+url.PathEscape(target))
	qt.Check(t, qt.Equals(status, fasthttp.StatusNotFound), qt.Commentf("%v", res))
	qt.Check(t, qt.Equals(res["code"], any("err:connection:not_found")))
	qt.Check(t, qt.Equals(d.toolCall(t, annas["access_token"].(string)), fasthttp.StatusOK), qt.Commentf("Anna's goes on"))
	ok, _ := d.refreshes(t, annas)
	qt.Check(t, qt.IsTrue(ok))
}

// The workspace's administrator lists an assistant's apps and signs one
// out; the sign-out is recorded with the administrator as its doer.
func TestAnAdministratorSignsOutAnAssistantsApp(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	one := d.connectAs(t, annasOID, annasFirst)
	other := d.connectAs(t, annasOID, annasFirst)

	status, out := d.call(t, adminOfA, fasthttp.MethodGet, "/assistants/"+annasFirst.Key+"/connections")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", out))
	listed := connectionsOf(out, "")
	qt.Assert(t, qt.HasLen(listed, 2))
	qt.Check(t, qt.Equals(listed[0]["app"], any("Claude Code")))

	target := readSID(t, one["access_token"].(string))
	status, res := d.call(t, adminOfA, fasthttp.MethodDelete, "/assistants/"+annasFirst.Key+"/connections/"+url.PathEscape(target))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNoContent), qt.Commentf("%v", res))
	qt.Check(t, qt.Equals(d.toolCall(t, one["access_token"].(string)), fasthttp.StatusUnauthorized))
	qt.Check(t, qt.Equals(d.toolCall(t, other["access_token"].(string)), fasthttp.StatusOK))

	ended := d.events.sharedEvents("connection_signed_out")
	qt.Assert(t, qt.HasLen(ended, 1))
	qt.Check(t, qt.Equals(ended[0]["person"], any("sub-of-anna")))
	qt.Check(t, qt.Equals(ended[0]["by"], any("administrator")))
	qt.Check(t, qt.Equals(d.events.actorOf("connection_signed_out"), "sub-of-gatis"))
}

// Only an administrator of the assistant's workspace reads or ends its
// apps: a member who is not is refused, and an administrator of another
// workspace reads nothing of this one and ends nothing.
func TestOnlyTheWorkspacesAdministratorReadsAnAssistantsApps(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	annas := d.connectAs(t, annasOID, annasFirst)
	target := readSID(t, annas["access_token"].(string))
	path := "/assistants/" + annasFirst.Key + "/connections"

	for _, c := range []struct {
		name          string
		w             who
		get, del, all int
	}{
		{"a member who is not the administrator", memberOfA, fasthttp.StatusForbidden, fasthttp.StatusForbidden, fasthttp.StatusForbidden},
		{"the person herself, on the administrator's route", annaInA, fasthttp.StatusForbidden, fasthttp.StatusForbidden, fasthttp.StatusForbidden},
		// Workspace B's index of that key is empty: B reads none and ends none of A's.
		{"another workspace's administrator", adminOfB, fasthttp.StatusOK, fasthttp.StatusNotFound, fasthttp.StatusNoContent},
	} {
		status, out := d.call(t, c.w, fasthttp.MethodGet, path)
		qt.Check(t, qt.Equals(status, c.get), qt.Commentf("%s: %v", c.name, out))
		qt.Check(t, qt.HasLen(connectionsOf(out, ""), 0), qt.Commentf("%s reads nothing", c.name))
		status, _ = d.call(t, c.w, fasthttp.MethodDelete, path+"/"+url.PathEscape(target))
		qt.Check(t, qt.Equals(status, c.del), qt.Commentf("%s", c.name))
		status, _ = d.call(t, c.w, fasthttp.MethodDelete, path)
		qt.Check(t, qt.Equals(status, c.all), qt.Commentf("%s", c.name))
		qt.Check(t, qt.Equals(d.toolCall(t, annas["access_token"].(string)), fasthttp.StatusOK), qt.Commentf("%s ended nothing", c.name))
	}
	qt.Check(t, qt.HasLen(d.events.sharedEvents("connection_signed_out"), 0))
}

// Ending every app of an assistant (its removal) ends its own, at once,
// and nobody else's.
func TestEndingAnAssistantsAppsEndsOnlyItsOwn(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	one := d.connectAs(t, annasOID, annasFirst)
	two := d.connectAs(t, annasOID, annasFirst)
	inB := d.connectAs(t, annasOID, annasSecond)
	janis := d.connectAs(t, janissOID, janissOwn)

	status, res := d.call(t, adminOfA, fasthttp.MethodDelete, "/assistants/"+annasFirst.Key+"/connections")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNoContent), qt.Commentf("%v", res))
	for _, tok := range []map[string]any{one, two} {
		qt.Check(t, qt.Equals(d.toolCall(t, tok["access_token"].(string)), fasthttp.StatusUnauthorized))
		ok, _ := d.refreshes(t, tok)
		qt.Check(t, qt.IsFalse(ok))
	}
	for _, tok := range []map[string]any{inB, janis} {
		qt.Check(t, qt.Equals(d.toolCall(t, tok["access_token"].(string)), fasthttp.StatusOK))
	}
	qt.Check(t, qt.HasLen(d.events.sharedEvents("connection_signed_out"), 2))

	status, _ = d.call(t, adminOfA, fasthttp.MethodDelete, "/assistants/"+annasFirst.Key+"/connections")
	qt.Check(t, qt.Equals(status, fasthttp.StatusNoContent), qt.Commentf("an assistant with none: nothing to end"))
}

// A sign-out sent twice, and an id that never was, are not found and
// end nothing else.
func TestASignOutSentTwiceIsNotFound(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	one := d.connectAs(t, annasOID, annasFirst)
	other := d.connectAs(t, annasOID, annasFirst)
	target := readSID(t, one["access_token"].(string))

	status, _ := d.call(t, annaInA, fasthttp.MethodDelete, "/connections/"+url.PathEscape(target))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNoContent))
	status, _ = d.call(t, annaInA, fasthttp.MethodDelete, "/connections/"+url.PathEscape(target))
	qt.Check(t, qt.Equals(status, fasthttp.StatusNotFound))
	status, _ = d.call(t, annaInA, fasthttp.MethodDelete, "/connections/never-a-connection")
	qt.Check(t, qt.Equals(status, fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(d.toolCall(t, other["access_token"].(string)), fasthttp.StatusOK))
	qt.Check(t, qt.HasLen(d.events.sharedEvents("connection_signed_out"), 1))
}

// A connection is listed a second before its sign-in's session ends and
// not at its end.
func TestAConnectionIsListedUntilItsSessionEnds(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	start := time.Now()
	d.mem.SetClock(func() time.Time { return start })
	d.connectAs(t, annasOID, annasFirst)

	d.mem.SetClock(func() time.Time { return start.Add(sessionLifetime - time.Second) })
	_, out := d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	qt.Check(t, qt.HasLen(connectionsOf(out, annasFirst.Key), 1), qt.Commentf("a second before its end"))

	d.mem.SetClock(func() time.Time { return start.Add(sessionLifetime) })
	_, out = d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	qt.Check(t, qt.HasLen(connectionsOf(out, annasFirst.Key), 0), qt.Commentf("at its end"))
}

// A sign-in that is not an AI app's is never a connection: its session's
// public name signs nothing out.
func TestABrowserSignInIsNeverAConnection(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	browser := &session.Session{Subject: "sub-of-anna", ClientID: "plain-app", Tenant: annasFirst.TenantID, SID: "browser-public-name"}
	qt.Assert(t, qt.IsNil(d.mem.CreateSession(context.Background(), "browser-session", browser, time.Hour)))

	_, out := d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	qt.Check(t, qt.IsFalse(strings.Contains(out["_body"].(string), "browser-public-name")))
	status, _ := d.call(t, annaInA, fasthttp.MethodDelete, "/connections/browser-public-name")
	qt.Check(t, qt.Equals(status, fasthttp.StatusNotFound))
	_, err := d.mem.LoadSession(context.Background(), "browser-session")
	qt.Check(t, qt.IsNil(err), qt.Commentf("the browser's session stays"))
}

// An AI app's own token, a token another service obtained to act for the
// person, and a service's own token neither list nor sign out.
func TestOnlyAPersonsOwnTokenListsOrSignsOut(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	annas := d.connectAs(t, annasOID, annasFirst)
	target := readSID(t, annas["access_token"].(string))

	for _, w := range []who{
		{sub: "sub-of-anna", tenant: annasFirst.TenantID, kind: "app"},
		{sub: "sub-of-anna", tenant: annasFirst.TenantID, kind: "app-bare"},
		{sub: "sub-of-anna", tenant: annasFirst.TenantID, kind: "delegated"},
		{sub: "svc:flowbyte-bff", tenant: annasFirst.TenantID, kind: "service", scope: "membership:admin"},
		{sub: "sub-of-anna", kind: "person"},
	} {
		status, out := d.call(t, w, fasthttp.MethodGet, "/connections")
		qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%v: %v", w, out))
		qt.Check(t, qt.Equals(out["code"], any("err:connection:forbidden")))
		status, _ = d.call(t, w, fasthttp.MethodDelete, "/connections/"+url.PathEscape(target))
		qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%v", w))
		w.scope = "membership:admin"
		status, _ = d.call(t, w, fasthttp.MethodGet, "/assistants/"+annasFirst.Key+"/connections")
		qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%v", w))
	}
	qt.Check(t, qt.Equals(d.toolCall(t, annas["access_token"].(string)), fasthttp.StatusOK))
}

// A store or a register that cannot answer is said so,
// and nothing is claimed ended.
func TestAStoreOrRegisterThatCannotAnswerIsSaidSo(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	annas := d.connectAs(t, annasOID, annasFirst)
	target := readSID(t, annas["access_token"].(string))

	d.register.assistantsErr = errors.New("register down")
	status, out := d.call(t, annaInA, fasthttp.MethodGet, "/connections")
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadGateway), qt.Commentf("%v", out))
	qt.Check(t, qt.Equals(out["code"], any("err:upstream:unavailable")))
	status, _ = d.call(t, annaInA, fasthttp.MethodDelete, "/connections/"+url.PathEscape(target))
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadGateway))
	d.register.assistantsErr = nil

	d.core.SetSessionStore(failingStore{d.mem})
	status, out = d.call(t, adminOfA, fasthttp.MethodGet, "/assistants/"+annasFirst.Key+"/connections")
	qt.Check(t, qt.Equals(status, fasthttp.StatusServiceUnavailable), qt.Commentf("%v", out))
	qt.Check(t, qt.Equals(out["code"], any("err:upstream:unavailable")))
	status, _ = d.call(t, adminOfA, fasthttp.MethodDelete, "/assistants/"+annasFirst.Key+"/connections/"+url.PathEscape(target))
	qt.Check(t, qt.Equals(status, fasthttp.StatusServiceUnavailable))
	status, _ = d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", annas["access_token"].(string), "svc:flowbyte-integration-api", "projects/task:view")
	qt.Check(t, qt.Equals(status, fasthttp.StatusServiceUnavailable), qt.Commentf("the exchange cannot tell the connection is live"))
	d.core.SetSessionStore(d.mem)

	qt.Check(t, qt.Equals(d.toolCall(t, annas["access_token"].(string)), fasthttp.StatusOK), qt.Commentf("nothing ended"))
}

// failingStore is the session store whose index of connections cannot answer.
type failingStore struct{ *sessiontest.Memory }

func (failingStore) Connections(context.Context, string, string) ([]session.Connection, error) {
	return nil, errors.New("store down")
}

// An app token naming no connection (one made before connections were
// named): refused at the exchange, as no live connection can be found for it.
func TestAnAppTokenNamingNoConnectionIsNotExchanged(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	d.connectAs(t, annasOID, annasFirst)
	tok, _, err := d.core.Issuer().IssueApp(issuer.AppTokenInput{
		Subject: "sub-of-anna", Audience: aiResource, ClientID: aiClient, Scopes: annasFirst.Scopes,
		Tenant: annasFirst.TenantID, Assistant: annasFirst.Key, LoA: identity.LoALow,
		LoginMethod: identity.LoginAssistant, TTL: time.Minute,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(readSID(t, tok), ""))

	qt.Check(t, qt.Equals(d.toolCall(t, tok), fasthttp.StatusUnauthorized))
}

// An AI app's token is checked by what it is, not by the
// registry; the token of an app no longer enabled there is refused though its
// connection is named and live, rather than exchanged unchecked.
func TestTheTokenOfAnAppNoLongerEnabledIsNotExchanged(t *testing.T) {
	d := aiApp(t, connectionRoutes)
	live := d.connectAs(t, annasOID, annasFirst)
	tok, _, err := d.core.Issuer().IssueApp(issuer.AppTokenInput{
		Subject: "sub-of-anna", Audience: aiResource, ClientID: "a-retired-app", Scopes: annasFirst.Scopes,
		Tenant: annasFirst.TenantID, Assistant: annasFirst.Key, LoA: identity.LoALow,
		LoginMethod: identity.LoginAssistant, Connection: readSID(t, live["access_token"].(string)), TTL: time.Minute,
	})
	qt.Assert(t, qt.IsNil(err))

	status, out := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", tok, "svc:flowbyte-integration-api", "projects/task:view")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("%v", out))
	qt.Check(t, qt.Equals(out["code"], any("err:connection:ended")))
	qt.Check(t, qt.Equals(d.toolCall(t, live["access_token"].(string)), fasthttp.StatusOK), qt.Commentf("the enabled app's own goes on"))
}

// decodeSegment reads one part of a token.
func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}

// actorOf is the doer of the first recorded event of kind.
func (l *eventLog) actorOf(kind string) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, ev := range l.events {
		if ev.Attributes["kind"] == kind && ev.Actor != nil {
			return ev.Actor.ID
		}
	}

	return ""
}
