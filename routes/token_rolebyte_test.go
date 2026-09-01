package routes

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// testIDCodeLV returns a Latvian personal identity code in the PNO form a token
// carries: the country, a six-digit leading group and a five-digit serial, built
// from one repeated digit so it reads as a placeholder at a glance.
//
// It is assembled from those parts at run time rather than written as a literal —
// an identifier-shaped constant in the source is indistinguishable from a
// credential to a secret scanner, and indistinguishable from a real person's code
// to a reader.
func testIDCodeLV(digit int) string {
	d := strconv.Itoa(digit)

	return "PNOLV-" + strings.Repeat(d, 6) + "-" + strings.Repeat(d, 5)
}

// fakeResolver drives userScopes without a live membership service.
type fakeResolver struct {
	scopes []string
	tenant string
	err    error
	serial string // records what the seam passed down
}

func (f *fakeResolver) UserScopes(_ *azugo.Context, serialNumber string) ([]string, string, error) {
	f.serial = serialNumber
	if f.err != nil {
		return nil, "", f.err
	}

	return f.scopes, f.tenant, nil
}

// scopesApp exposes the real userScopes seam on a scratch route, so the
// mapping and its error rendering run through the real middleware/renderer —
// the full login→token wire needs live Redis and is covered by the stack
// verify instead.
func scopesApp(t *testing.T, resolver authbytecore.ScopeResolver) *azugo.TestApp {
	t.Helper()

	app := authbytecore.TestApp(t)
	if resolver != nil {
		app.SetScopeResolver(resolver)
	}
	qt.Assert(t, qt.IsNil(Init(app)))

	r := &router{App: app}
	app.Get("/testonly/scopes", func(ctx *azugo.Context) {
		sess := &session.Session{
			Scopes:       []string{"static:baseline"},
			SerialNumber: testIDCodeLV(0),
		}
		scopes, tenant, ok := r.userScopes(ctx, sess)
		if !ok {
			return
		}
		ctx.JSON(map[string]any{"scopes": scopes, "tenant": tenant})
	})

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return ta
}

// Resolver absent — standalone mode, the default: the session's static
// baseline passes through untouched.
func TestUserScopesStaticWithoutResolver(t *testing.T) {
	app := scopesApp(t, nil)

	resp, err := app.TestClient().Get("/testonly/scopes")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(string(resp.Body()), `"static:baseline"`))
}

// Resolver wired: the register's scopes AND tenant are minted, not the
// session baseline, and the seam passes the login's identity code down.
func TestUserScopesResolvedFromMembership(t *testing.T) {
	fake := &fakeResolver{scopes: []string{"estimating:estimator", "membership:admin"}, tenant: "01TENANTULID"}
	app := scopesApp(t, fake)

	resp, err := app.TestClient().Get("/testonly/scopes")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := string(resp.Body())
	qt.Assert(t, qt.StringContains(body, `"estimating:estimator"`))
	qt.Assert(t, qt.StringContains(body, `"01TENANTULID"`))
	qt.Assert(t, qt.Not(qt.StringContains(body, "static:baseline")))
	qt.Assert(t, qt.Equals(fake.serial, testIDCodeLV(0)))
}

// Resolver absent — standalone mode: no tenant is minted.
func TestUserScopesNoResolverMintsNoTenant(t *testing.T) {
	app := scopesApp(t, nil)

	resp, err := app.TestClient().Get("/testonly/scopes")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.StringContains(string(resp.Body()), `"tenant":""`))
}

// No membership: token issue is refused — login is not access.
func TestUserScopesNoMembershipRefuses(t *testing.T) {
	app := scopesApp(t, &fakeResolver{err: rolebyte.ErrNotMember})

	resp, err := app.TestClient().Get("/testonly/scopes")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	qt.Assert(t, qt.StringContains(string(resp.Body()), `"code":"err:membership:notMember"`))
}

// Multiple memberships cannot ride a single-tenant token — refused, never guessed.
func TestUserScopesAmbiguousMembershipRefuses(t *testing.T) {
	app := scopesApp(t, &fakeResolver{err: rolebyte.ErrAmbiguous})

	resp, err := app.TestClient().Get("/testonly/scopes")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	qt.Assert(t, qt.StringContains(string(resp.Body()), `"code":"err:membership:ambiguous"`))
}

// The register unreachable: fail closed — an empty-scope or guessed-scope
// token is never minted.
func TestUserScopesResolverFailureFailsClosed(t *testing.T) {
	app := scopesApp(t, &fakeResolver{err: errors.New("connection refused")})

	resp, err := app.TestClient().Get("/testonly/scopes")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
	qt.Assert(t, qt.StringContains(string(resp.Body()), `"code":"err:upstream:unavailable"`))
}
