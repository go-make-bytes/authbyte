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

// testPersonSub returns a platform subject of the shape the identity store
// mints — 26 characters of the ULID alphabet — built from one repeated digit so
// it reads as a placeholder at a glance.
func testPersonSub(digit int) string {
	return "0" + strings.Repeat(strconv.Itoa(digit), 25)
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

	// The admission door: what it answers, what it was asked, and what the
	// register answers AFTER a successful admission.
	admit       bool
	admitErr    error
	admittedKey string                   // the subject key offered ("" = never offered)
	admitted    *rolebyte.DirectoryLogin // the login offered (nil = never offered)
	afterAdmit  []rolebyte.Membership
}

func (f *fakeResolver) Memberships(_ *azugo.Context, subjectKey string) ([]rolebyte.Membership, error) {
	f.asked = subjectKey
	if f.err != nil {
		return nil, f.err
	}
	if f.admitted != nil && f.admit {
		return f.afterAdmit, nil
	}

	return f.memberships, nil
}

func (f *fakeResolver) Admit(_ *azugo.Context, subjectKey string, login rolebyte.DirectoryLogin) (bool, error) {
	f.admittedKey = subjectKey
	l := login
	f.admitted = &l
	if f.admitErr != nil {
		return false, f.admitErr
	}

	return f.admit, nil
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
		subject := testPersonSub(0)
		if s := ctx.Query.StringOptional("subject"); s != nil {
			subject = *s
		}
		sess := &session.Session{
			Subject: subject,
			Scopes:  []string{"static:baseline"},
		}
		// A login through an organisation's directory: the issuer it came through,
		// whether the provider called the person a guest there, and their name.
		if iss := ctx.Query.StringOptional("issuer"); iss != nil {
			sess.DirectoryIssuer = *iss
		}
		if g := ctx.Query.StringOptional("guest"); g != nil && *g == "1" {
			sess.DirectoryGuest = true
		}
		if n := ctx.Query.StringOptional("name"); n != nil {
			sess.Name = *n
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
	qt.Assert(t, qt.Equals(fake.asked, "sub:"+testPersonSub(0)))
}

// The register is asked by the person's TYPED PLATFORM SUBJECT — the session's
// subject, which is the token's `sub` — and by nothing about the person: no
// identity code travels into the register. A person invited under the subject
// the identity store answered and the same person logging in produce the same
// key by construction.
func TestUserScopesAsksTheRegisterByTheTypedSubject(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTULID", "estimating:estimator")}}
	app := scopesApp(t, fake)

	status, _ := get(t, app, "/testonly/scopes?client=product-spa&subject="+testPersonSub(7))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.Equals(fake.asked, "sub:"+testPersonSub(7)))
	qt.Assert(t, qt.IsFalse(strings.Contains(fake.asked, "PNO")))
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

// No membership: token issue is refused — login is not access. A login that
// came through no directory (a card login) is offered to no admission door.
func TestUserScopesNoMembershipRefuses(t *testing.T) {
	fake := &fakeResolver{}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Assert(t, qt.StringContains(body, `"code":"err:membership:notMember"`))
	qt.Assert(t, qt.IsNil(fake.admitted))
}

// --- the attached directory -----------------------------------------------------

const directoryIssuer = "https://login.example/tenant-id/v2.0"

// A person who came through an organisation's directory and holds no
// membership is offered to the register's admission door — by their typed
// subject, with the issuer and the name the login carried — and, admitted, is
// asked about again: the token carries the tenant that admitted them and no
// scopes, a member who holds nothing until an administrator assigns a role.
func TestUserScopesDirectoryPersonIsAdmittedThenResolved(t *testing.T) {
	fake := &fakeResolver{admit: true, afterAdmit: []rolebyte.Membership{{TenantID: "01TENANTDIR", Scopes: []string{}}}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa&issuer="+directoryIssuer+"&name=Anna+Example&subject="+testPersonSub(5))
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Assert(t, qt.StringContains(body, `"tenant":"01TENANTDIR"`))
	qt.Assert(t, qt.StringContains(body, `"scopes":[]`))
	qt.Assert(t, qt.Equals(fake.admittedKey, "sub:"+testPersonSub(5)))
	qt.Assert(t, qt.IsNotNil(fake.admitted))
	qt.Assert(t, qt.Equals(fake.admitted.Issuer, directoryIssuer))
	qt.Assert(t, qt.Equals(fake.admitted.DisplayName, "Anna Example"))
}

// The door admits nobody (no tenant attached this issuer): the refusal is the
// plain one — login is not access — and the register is not asked again.
func TestUserScopesDirectoryPersonNobodyAttachedRefuses(t *testing.T) {
	fake := &fakeResolver{admit: false}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa&issuer="+directoryIssuer)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Assert(t, qt.StringContains(body, `"code":"err:membership:notMember"`))
	qt.Assert(t, qt.IsNotNil(fake.admitted))
}

// A guest in the provider's directory is not offered to the door at all: a
// tenant attached its own people, not its visitors. Refused like any stranger.
func TestUserScopesDirectoryGuestIsNotOffered(t *testing.T) {
	fake := &fakeResolver{admit: true, afterAdmit: []rolebyte.Membership{{TenantID: "01TENANTDIR", Scopes: []string{}}}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa&issuer="+directoryIssuer+"&guest=1")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Assert(t, qt.StringContains(body, `"code":"err:membership:notMember"`))
	qt.Assert(t, qt.IsNil(fake.admitted))
}

// A person who already holds a membership is not offered again — the door is
// for the first arrival only, and a refresh costs no extra register call.
func TestUserScopesDirectoryMemberIsNotOfferedAgain(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{member("01TENANTDIR", "projects:read")}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa&issuer="+directoryIssuer)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(body, `"projects:read"`))
	qt.Assert(t, qt.IsNil(fake.admitted))
}

// The door unreachable: fail closed, like the resolve itself.
func TestUserScopesDirectoryAdmissionFailureFailsClosed(t *testing.T) {
	fake := &fakeResolver{admitErr: errors.New("connection refused")}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/scopes?client=product-spa&issuer="+directoryIssuer)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadGateway))
	qt.Assert(t, qt.StringContains(body, `"code":"err:upstream:unavailable"`))
}

// A session that carries no full name still hands the register a name: the
// given and family names, else the subject — a membership row needs one.
func TestSessionDisplayNameFallsBack(t *testing.T) {
	qt.Assert(t, qt.Equals((&session.Session{Name: "Anna Example", GivenName: "A"}).DisplayName(), "Anna Example"))
	qt.Assert(t, qt.Equals((&session.Session{GivenName: "Anna", FamilyName: "Example"}).DisplayName(), "Anna Example"))
	qt.Assert(t, qt.Equals((&session.Session{Subject: testPersonSub(3)}).DisplayName(), testPersonSub(3)))
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
