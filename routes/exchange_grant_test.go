package routes

import (
	"net/url"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/issuer"
)

// observedApp is the assistant deployment with its logger swapped, once it has
// started, for one the test reads.
func observedApp(t *testing.T) (*aiDeployment, *observer.ObservedLogs) {
	t.Helper()

	d := aiApp(t)
	core, observed := observer.New(zapcore.InfoLevel)
	qt.Assert(t, qt.IsNil(d.core.ReplaceLogger(zap.New(core))))

	return d, observed
}

// annasPlainToken is a token Anna's own sign-in made for the resource the MCP
// server acts from: not made through an assistant, so nothing narrows it.
func annasPlainToken(t *testing.T, d *aiDeployment) string {
	t.Helper()

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

	return tok
}

// leftOutLines are the warnings that an exchange asked scopes outside the grant.
func leftOutLines(logs *observer.ObservedLogs) []observer.LoggedEntry {
	return logs.FilterMessage(leftOutScopesMessage).All()
}

// An exchange for a person that asks one box the client's grant lacks beside ones
// it holds is answered with the ones it holds, in the order asked, rather than
// refused whole; the answer names the scope it issued; and the box left out is
// named in one warning with the client and the audience, while a scope of no
// valid shape is only counted and the person is not named.
func TestAnExchangeLeavesOutABoxTheGrantLacks(t *testing.T) {
	d, logs := observedApp(t)

	status, pass := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", annasPlainToken(t, d), "svc:flowbyte-integration-api",
		"projects:write projects/task:remove projects/task:edit not-a-scope projects/task:remove\u200bx a/b:\x1bred")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", pass))
	qt.Check(t, qt.Equals(readToken(t, pass["access_token"]).Scope, "projects:write projects/task:edit"),
		qt.Commentf("the two the grant holds, in the order asked; the box it lacks and the shapeless one left out"))
	qt.Check(t, qt.Equals(pass["scope"], any("projects:write projects/task:edit")),
		qt.Commentf("the answer names the scope issued, which differs from the one asked [RFC 8693 §2.2.1]"))

	lines := leftOutLines(logs)
	qt.Assert(t, qt.HasLen(lines, 1))
	fields := lines[0].ContextMap()
	qt.Check(t, qt.Equals(lines[0].Level, zapcore.WarnLevel))
	qt.Check(t, qt.Equals(fields["client"], any("svc:flowbyte-mcp")))
	qt.Check(t, qt.Equals(fields["audience"], any("svc:flowbyte-integration-api")))
	qt.Check(t, qt.DeepEquals(fields["scopes"], any([]any{"projects/task:remove"})))
	qt.Check(t, qt.Equals(fields["unnamed"], any(int64(3))),
		qt.Commentf("the shapeless scope, and the two carrying a zero-width space and an escape, are counted, not named"))
	for k, v := range fields {
		qt.Check(t, qt.Not(qt.StringContains(strings.ToLower(k+"="+toString(v)), "anna")),
			qt.Commentf("the person is not named in the warning: %s", k))
	}
}

// An exchange that asks only scopes the client's grant lacks is refused and
// issues nothing: never the whole grant, which is only for an exchange that asks
// nothing. The scope asked is still named, so the missing line can be found.
func TestAnExchangeAskingOnlyWhatTheGrantLacksIsRefused(t *testing.T) {
	d, logs := observedApp(t)

	status, res := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", annasPlainToken(t, d), "svc:flowbyte-integration-api",
		"projects/task:remove")
	qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%v", res))
	qt.Check(t, qt.Equals(res["access_token"], any(nil)), qt.Commentf("no token on a refusal"))
	qt.Check(t, qt.Equals(res["scope"], any(nil)))

	lines := leftOutLines(logs)
	qt.Assert(t, qt.HasLen(lines, 1))
	qt.Check(t, qt.DeepEquals(lines[0].ContextMap()["scopes"], any([]any{"projects/task:remove"})))
}

// An exchange toward an audience the client is not granted is refused before
// any scope is weighed, and names nothing.
func TestAnExchangeTowardAnUngrantedAudienceIsRefused(t *testing.T) {
	d, logs := observedApp(t)

	status, res := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", annasPlainToken(t, d), "svc:rolebyte",
		"membership:people")
	qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%v", res))
	qt.Check(t, qt.Equals(res["access_token"], any(nil)))
	qt.Check(t, qt.HasLen(leftOutLines(logs), 0))
}

// A service's own sign-in is unchanged: one scope outside its grant refuses the
// whole request, though the scope beside it alone is granted.
func TestAServicesOwnSignInStillRefusesAScopeOutsideItsGrant(t *testing.T) {
	d := aiApp(t)
	svc := newEdge(t, d.app)
	svc.basic = []string{"svc:another", "another-secret"}
	ask := func(scope string) (int, map[string]any) {
		return svc.post("/token", url.Values{
			"grant_type": {"client_credentials"}, "client_id": {"svc:another"},
			"audience": {"svc:flowbyte-integration-api"}, "scope": {scope},
		})
	}

	status, alone := ask("projects/task:view")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("the granted scope alone: %v", alone))

	status, mixed := ask("projects/task:view projects/task:edit")
	qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%v", mixed))
	qt.Check(t, qt.Equals(mixed["access_token"], any(nil)), qt.Commentf("no token on a refusal"))
}

// An exchange of a token made through an assistant names, in its answer, the
// scope it issued, which the assistant's narrowing makes differ from the one asked.
func TestAnAssistantsExchangeNamesTheScopeItIssued(t *testing.T) {
	d := aiApp(t)
	appToken := d.connected(t)["access_token"].(string)

	status, pass := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", appToken, "svc:flowbyte-integration-api",
		"projects:read projects:write "+strings.Join(aiBoxes, " "))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", pass))
	issued := readToken(t, pass["access_token"]).Scope
	qt.Assert(t, qt.Equals(issued, "projects:read "+strings.Join(annasFirst.Scopes, " ")))
	qt.Check(t, qt.Equals(pass["scope"], any(issued)))
}

// An exchange of an assistant's token whose scopes the grant and the narrowing
// leave empty says so in its answer, an empty `scope`, rather than leaving the
// field out, which would read as "the scope asked for" [RFC 8693 §2.2.1].
func TestAnExchangeNarrowedToNothingSaysSo(t *testing.T) {
	d := aiApp(t)
	appToken := d.connected(t)["access_token"].(string)

	status, pass := d.exchangeAt(t, "svc:flowbyte-mcp", "mcp-secret", appToken, "svc:flowbyte-integration-api",
		"projects:write projects/task:remove")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%v", pass))
	qt.Assert(t, qt.Equals(readToken(t, pass["access_token"]).Scope, ""),
		qt.Commentf("the box outside the grant left out, the level the grant does not name for an assistant narrowed away"))
	scope, present := pass["scope"]
	qt.Check(t, qt.IsTrue(present), qt.Commentf("the answer must name the empty scope it issued: %v", pass))
	qt.Check(t, qt.Equals(scope, any("")))
}

func toString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []any:
		parts := make([]string, 0, len(s))
		for _, p := range s {
			parts = append(parts, toString(p))
		}

		return strings.Join(parts, " ")
	}

	return ""
}
