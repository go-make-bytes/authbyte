package routes

import (
	"encoding/json"
	"testing"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/rolebyte"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

const highOnly = "deployment:admin"

// withHigh is a membership whose roles grant scopes and whose register marks
// highScopes as counting only on a high sign-in.
func withHigh(tenant string, scopes, high []string) rolebyte.Membership {
	return rolebyte.Membership{TenantID: tenant, Scopes: scopes, HighScopes: high}
}

type scopesAnswer struct {
	Scopes []string `json:"scopes"`
}

func decodeScopes(t *testing.T, body string) []string {
	t.Helper()

	var a scopesAnswer
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(body), &a)), qt.Commentf("%s", body))

	return a.Scopes
}

// The high-only scopes join the token only when the session's level is exactly
// high; low, substantial, an empty level and an unknown one add nothing.
func TestUserScopesHighScopesOnlyAtTheHighLevel(t *testing.T) {
	for name, tc := range map[string]struct {
		loa  string
		want []string
	}{
		"high":        {identity.LoAHigh, []string{"a:b", highOnly}},
		"substantial": {identity.LoASubstantial, []string{"a:b"}},
		"low":         {identity.LoALow, []string{"a:b"}},
		"empty":       {"", []string{"a:b"}},
		"unknown":     {"HIGH", []string{"a:b"}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeResolver{memberships: []rolebyte.Membership{withHigh("01TENANTA", []string{"a:b"}, []string{highOnly})}}
			app := scopesApp(t, fake)

			status, body := get(t, app, "/testonly/scopes?client=admin-spa&loa="+tc.loa)
			qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
			qt.Check(t, qt.DeepEquals(decodeScopes(t, body), tc.want))
		})
	}
}

// A register that sends no highScopes member (an older register) gives only
// the scopes, at every level.
func TestUserScopesWithoutHighScopesAtEveryLevel(t *testing.T) {
	for _, loa := range []string{identity.LoAHigh, identity.LoASubstantial, identity.LoALow, "", "other"} {
		fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTA", "a:b")}}
		app := scopesApp(t, fake)

		status, body := get(t, app, "/testonly/scopes?client=product-spa&loa="+loa)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
		qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"a:b"}), qt.Commentf("level %q", loa))
	}
}

// A high-only scope the membership already holds is not added twice, and the
// existing scopes keep their order.
func TestUserScopesHighScopesAreNotDuplicated(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		withHigh("01TENANTA", []string{"z:z", "a:b", highOnly}, []string{"a:b", highOnly, "x:y", "x:y"}),
	}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=admin-spa&loa="+identity.LoAHigh)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"z:z", "a:b", highOnly, "x:y"}))
}

// With several memberships and a named organisation, only the chosen
// membership's high-only scopes are used.
func TestUserScopesOnlyTheChosenMembershipsHighScopes(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		withHigh("01TENANTA", []string{"a:b"}, []string{highOnly}),
		withHigh("01TENANTB", []string{"c:d"}, []string{"other:high"}),
	}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=admin-spa&tenant=01TENANTB&loa="+identity.LoAHigh)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"c:d", "other:high"}))
}

// A refresh decides again from the register's current answer and the level the
// session holds: a high session whose answer stops carrying the high-only
// scopes loses them, and a substantial session never gets them.
func TestUserScopesRefreshReadsHighScopesAgain(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{withHigh("01TENANTA", []string{"a:b"}, []string{highOnly})}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=admin-spa&refresh=1&loa="+identity.LoAHigh)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"a:b", highOnly}))

	// A substantial session, while the register still answers the scope.
	status, body = get(t, app, "/testonly/scopes?client=admin-spa&refresh=1&loa="+identity.LoASubstantial)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"a:b"}))

	// The register stops answering it: the high session's next token drops it.
	fake.memberships = []rolebyte.Membership{member("01TENANTA", "a:b")}
	status, body = get(t, app, "/testonly/scopes?client=admin-spa&refresh=1&loa="+identity.LoAHigh)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"a:b"}))
}

// A client that needs no membership keeps its baseline, whatever the register
// would answer.
func TestUserScopesBaselineClientNeverGetsHighScopes(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{withHigh("01TENANTA", []string{"a:b"}, []string{highOnly})}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=portal-spa&loa="+identity.LoAHigh)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"envelopes:read", "envelopes:write", "documents:read"}))
}

// The scopes that count only on a high sign-in reach a token only when the
// session's level is high AND the client it is issued to is set to carry them,
// at the sign-in and at a refresh alike.
func TestUserScopesHighScopesNeedTheLevelAndTheClientSetting(t *testing.T) {
	for _, moment := range []string{"", "&refresh=1"} {
		for name, tc := range map[string]struct {
			loa, client string
			want        []string
		}{
			"high, setting on":        {identity.LoAHigh, "admin-spa", []string{"a:b", highOnly}},
			"high, setting off":       {identity.LoAHigh, "product-spa", []string{"a:b"}},
			"substantial, setting on": {identity.LoASubstantial, "admin-spa", []string{"a:b"}},
			"substantial, off":        {identity.LoASubstantial, "product-spa", []string{"a:b"}},
		} {
			t.Run(name+moment, func(t *testing.T) {
				fake := &fakeResolver{memberships: []rolebyte.Membership{withHigh("01TENANTA", []string{"a:b"}, []string{highOnly})}}
				app := scopesApp(t, fake)

				status, body := get(t, app, "/testonly/scopes?client="+tc.client+moment+"&loa="+tc.loa)
				qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
				qt.Check(t, qt.DeepEquals(decodeScopes(t, body), tc.want))
			})
		}
	}
}

// A scope the register answers that is neither a box nor a level is left out of
// the token, and the issue goes on with the good ones. A token's scopes are one
// string split on white space where it is read, so a scope holding white space,
// a no-break space included, would be read as two.
func TestUserScopesLeaveOutScopesOfNoShape(t *testing.T) {
	bad := []string{"x deployment:admin", "x deployment:admin", "a:b:c", ""}
	good := []string{"a:b", "projects/task:view"}

	t.Run("scopes", func(t *testing.T) {
		scopes := append(append([]string{bad[0], bad[1]}, good[0]), append([]string{bad[2], bad[3]}, good[1])...)
		fake := &fakeResolver{memberships: []rolebyte.Membership{{TenantID: "01TENANTA", Scopes: scopes}}}
		app := scopesApp(t, fake)

		status, body := get(t, app, "/testonly/scopes?client=product-spa&loa="+identity.LoAHigh)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
		qt.Check(t, qt.DeepEquals(decodeScopes(t, body), good))
	})

	t.Run("high scopes at high with the setting on", func(t *testing.T) {
		fake := &fakeResolver{memberships: []rolebyte.Membership{
			{TenantID: "01TENANTA", Scopes: []string{good[0]}, HighScopes: []string{bad[0], bad[1], highOnly, bad[2], bad[3]}},
		}}
		app := scopesApp(t, fake)

		status, body := get(t, app, "/testonly/scopes?client=admin-spa&loa="+identity.LoAHigh)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
		qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{good[0], highOnly}))
	})
}

// The same filter holds a service account's tenant token: what the membership
// answers of no shape is never intersected into it.
func TestServiceAccountScopesLeaveOutScopesOfNoShape(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		member("01TENANTACME", "signing-requests:write", "x signing-requests:read", "a:b:c", ""),
	}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/service?tenant=01TENANTACME&allowed=signing-requests:write,a:b:c")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"signing-requests:write"}))
}

// A service account's tenant token is the registry grant narrowed by the
// membership's scopes alone: the high-only scopes never reach it, even when the
// grant would allow the name.
func TestServiceAccountScopesNeverCarryHighScopes(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		withHigh("01TENANTACME", []string{"signing-requests:write"}, []string{highOnly}),
	}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/service?tenant=01TENANTACME&allowed=signing-requests:write,"+highOnly)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.DeepEquals(decodeScopes(t, body), []string{"signing-requests:write"}))
}
