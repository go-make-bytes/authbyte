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

// testRegistry registers two browser clients: a public portal whose people
// stay on the baseline, and a product portal that leaves the requirement
// unset — required whenever a register is wired.
const testRegistry = `
public_clients:
  - client_id: portal-spa
    enabled: true
    membership_required: false
    allowed_redirect_uris: [https://portal.example/callback]
  - client_id: product-spa
    enabled: true
    allowed_redirect_uris: [https://product.example/callback]
`

// fakeResolver drives the membership seams without a live register.
type fakeResolver struct {
	memberships []rolebyte.Membership
	err         error
	asked       string // the subject key the seam passed down ("" = never asked)
}

func (f *fakeResolver) Memberships(_ *azugo.Context, subjectKey string) ([]rolebyte.Membership, error) {
	f.asked = subjectKey
	if f.err != nil {
		return nil, f.err
	}

	return f.memberships, nil
}

// scopesApp exposes the real membership seams on scratch routes, so the mapping
// and its error rendering run through the real middleware/renderer — the full
// login→token wire needs live Redis and is covered by the stack verify instead.
//
//   - GET /testonly/scopes?client=&tenant= runs the person seam (userScopes)
//   - GET /testonly/service?tenant=&allowed=a,b runs the service-account seam
func scopesApp(t *testing.T, resolver authbytecore.ScopeResolver) *azugo.TestApp {
	t.Helper()

	t.Setenv("SERVICE_CLIENT_REGISTRY", testRegistry)
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
		client, tenant := "", ""
		if c := ctx.Query.StringOptional("client"); c != nil {
			client = *c
		}
		if tn := ctx.Query.StringOptional("tenant"); tn != nil {
			tenant = *tn
		}
		outcome, ok := r.userScopes(ctx, sess, client, tenant)
		if !ok {
			return
		}
		ctx.JSON(map[string]any{"scopes": outcome.scopes, "tenant": outcome.tenant, "choices": outcome.choices})
	})
	app.Get("/testonly/service", func(ctx *azugo.Context) {
		tenant := ""
		if tn := ctx.Query.StringOptional("tenant"); tn != nil {
			tenant = *tn
		}
		var allowed []string
		if a := ctx.Query.StringOptional("allowed"); a != nil {
			allowed = strings.Split(*a, ",")
		}
		scopes, err := r.serviceAccountScopes(ctx, "svc:acme-dms", tenant, allowed)
		if err != nil {
			return
		}
		ctx.JSON(map[string]any{"scopes": scopes})
	})

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return ta
}

func get(t *testing.T, app *azugo.TestApp, path string) (int, string) {
	t.Helper()

	resp, err := app.TestClient().Get(path)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	return resp.StatusCode(), string(resp.Body())
}

func member(tenant string, scopes ...string) rolebyte.Membership {
	return rolebyte.Membership{TenantID: tenant, Scopes: scopes}
}

// --- people -----------------------------------------------------------------

// Resolver absent — standalone, the default: the session's static baseline
// passes through untouched, whatever the client, and no tenant is minted.
func TestUserScopesStaticWithoutResolver(t *testing.T) {
	app := scopesApp(t, nil)

	status, body := get(t, app, "/testonly/scopes?client=product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(body, `"static:baseline"`))
	qt.Assert(t, qt.StringContains(body, `"tenant":""`))
}

// A public portal's people stay on the baseline even with a register wired —
// and the register is never asked about them.
func TestUserScopesPublicPortalNeverAsksTheRegister(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTULID", "estimating:estimator")}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=portal-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(body, `"static:baseline"`))
	qt.Assert(t, qt.StringContains(body, `"tenant":""`))
	qt.Assert(t, qt.Equals(fake.asked, ""))
}

// A product portal's people are resolved from the register: one membership
// mints its scopes AND its tenant, and the seam asks by the typed person key.
func TestUserScopesResolvedFromMembership(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTULID", "estimating:estimator", "membership:admin")}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(body, `"estimating:estimator"`))
	qt.Assert(t, qt.StringContains(body, `"01TENANTULID"`))
	qt.Assert(t, qt.Not(qt.StringContains(body, "static:baseline")))
	qt.Assert(t, qt.Equals(fake.asked, "pno:"+testIDCodeLV(0)))
}

// A client the registry does not know follows the register — required, never
// the baseline by accident.
func TestUserScopesUnknownClientFollowsTheRegister(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTULID", "projects:read")}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=nobody-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(body, `"01TENANTULID"`))
	qt.Assert(t, qt.Not(qt.Equals(fake.asked, "")))
}

// No membership: token issue is refused — login is not access.
func TestUserScopesNoMembershipRefuses(t *testing.T) {
	app := scopesApp(t, &fakeResolver{})

	status, body := get(t, app, "/testonly/scopes?client=product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Assert(t, qt.StringContains(body, `"code":"err:membership:notMember"`))
}

// Several memberships and none named: the person chooses — the token carries
// no scopes and no tenant, and the organisations to choose from are listed.
// Never the union, never a guess.
func TestUserScopesSeveralMembershipsOfferTheChoice(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		member("01TENANTA", "membership:admin"),
		member("01TENANTB", "projects:read"),
	}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(body, `"choices":["01TENANTA","01TENANTB"]`))
	qt.Assert(t, qt.StringContains(body, `"tenant":""`))
	qt.Assert(t, qt.Not(qt.StringContains(body, "membership:admin")))
	qt.Assert(t, qt.Not(qt.StringContains(body, "projects:read")))
}

// The named organisation is minted — with that membership's scopes only.
func TestUserScopesNamedTenantIsMinted(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		member("01TENANTA", "membership:admin"),
		member("01TENANTB", "projects:read"),
	}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa&tenant=01TENANTB")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(body, `"tenant":"01TENANTB"`))
	qt.Assert(t, qt.StringContains(body, `"projects:read"`))
	qt.Assert(t, qt.Not(qt.StringContains(body, "membership:admin")))
	qt.Assert(t, qt.StringContains(body, `"choices":null`))
}

// Naming an organisation the person is not a member of is a refusal, not a
// fallback to one they do belong to.
func TestUserScopesNamedTenantWithoutMembershipRefuses(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTA", "membership:admin")}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa&tenant=01TENANTZ")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Assert(t, qt.StringContains(body, `"code":"err:membership:notMember"`))
}

// The register unreachable: fail closed — an empty-scope or guessed-scope
// token is never minted.
func TestUserScopesResolverFailureFailsClosed(t *testing.T) {
	app := scopesApp(t, &fakeResolver{err: errors.New("connection refused")})

	status, body := get(t, app, "/testonly/scopes?client=product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadGateway))
	qt.Assert(t, qt.StringContains(body, `"code":"err:upstream:unavailable"`))
}

// --- service accounts ---------------------------------------------------------

// A tenant-named issue without a register cannot exist: refused, not minted
// as a plain service token.
func TestServiceAccountScopesWithoutRegisterRefuses(t *testing.T) {
	app := scopesApp(t, nil)

	status, body := get(t, app, "/testonly/service?tenant=01TENANTACME&allowed=signing-requests:write")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Assert(t, qt.StringContains(body, `"code":"err:membership:notMember"`))
}

// A member's scopes are what the registry grant allows AND the membership
// grants; the seam asks the register by the client id itself.
func TestServiceAccountScopesIntersectGrantAndMembership(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		member("01TENANTACME", "signing-requests:read", "signing-requests:write", "membership:admin"),
	}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/service?tenant=01TENANTACME&allowed=signing-requests:write,documents:read")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.Equals(body, `{"scopes":["signing-requests:write"]}`))
	qt.Assert(t, qt.Equals(fake.asked, "svc:acme-dms"))
}

// Not a member of the named organisation: refused.
func TestServiceAccountScopesNotAMemberRefuses(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTOTHER", "signing-requests:write")}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/service?tenant=01TENANTACME&allowed=signing-requests:write")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Assert(t, qt.StringContains(body, `"code":"err:membership:notMember"`))
}

// A member with no role toward this audience gets nothing — an empty token is
// never minted.
func TestServiceAccountScopesEmptyIntersectionRefuses(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTACME", "membership:admin")}}
	app := scopesApp(t, fake)

	status, _ := get(t, app, "/testonly/service?tenant=01TENANTACME&allowed=signing-requests:write")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
}

// The register unreachable during a tenant-named issue: fail closed.
func TestServiceAccountScopesResolverFailureFailsClosed(t *testing.T) {
	app := scopesApp(t, &fakeResolver{err: errors.New("connection refused")})

	status, body := get(t, app, "/testonly/service?tenant=01TENANTACME&allowed=signing-requests:write")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadGateway))
	qt.Assert(t, qt.StringContains(body, `"code":"err:upstream:unavailable"`))
}
