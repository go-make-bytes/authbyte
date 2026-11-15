package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/go-make-bytes/authbyte/rolebyte"
)

// A sign-in that names an organisation tells the register which one the token
// is for; one that names none tells it none.
func TestASignInTellsTheRegisterTheOrganisationItNames(t *testing.T) {
	two := []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a"), named(orgB, "Beta Ltd", "b:b")}

	for name, tc := range map[string]struct{ named, want string }{
		"names one":  {orgA, orgA},
		"names none": {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeResolver{memberships: two}
			app, mem := signInApp(t, withRegister(fake))
			e := newEdge(t, app)

			_, status, body := exchanged(t, mem, e, tc.named)
			qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
			qt.Check(t, qt.Equals(fake.askedTenant, tc.want))
		})
	}
}

// An organisation named in the request that is not an organisation id is never
// passed to the register, which would refuse it: the answer is the one a name no
// membership matches always got, and the register is called with no company. The
// same holds for a service account's request.
func TestANameThatIsNotAnOrganisationIdIsNotPassedToTheRegister(t *testing.T) {
	two := []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a"), named(orgB, "Beta Ltd", "b:b")}

	t.Run("sign-in", func(t *testing.T) {
		fake := &fakeResolver{memberships: two}
		app, mem := signInApp(t, withRegister(fake))
		e := newEdge(t, app)

		_, status, body := exchanged(t, mem, e, "not-a-company")
		qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%s", body["_raw"]))
		qt.Check(t, qt.StringContains(body["_raw"].(string), "err:membership:notMember"))
		qt.Check(t, qt.Equals(fake.asked, "sub:"+testPersonSub(5)), qt.Commentf("the register was asked"))
		qt.Check(t, qt.Equals(fake.askedTenant, ""))
	})

	t.Run("service account", func(t *testing.T) {
		fake := &fakeResolver{memberships: []rolebyte.Membership{member(orgA, "signing-requests:write")}}
		app := scopesApp(t, fake)

		status, body := get(t, app, "/testonly/service?tenant=not-a-company&allowed=signing-requests:write")
		qt.Check(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("%s", body))
		qt.Check(t, qt.StringContains(body, "err:membership:notMember"))
		qt.Check(t, qt.Equals(fake.asked, "svc:acme-dms"), qt.Commentf("the register was asked"))
		qt.Check(t, qt.Equals(fake.askedTenant, ""))
	})
}

// A refresh tells the register the organisation its session is in.
func TestARefreshTellsTheRegisterTheOrganisationOfItsSession(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{named(orgA, "Alpha Ltd", "a:a")}}
	app, mem := signInApp(t, withRegister(fake))
	e := newEdge(t, app)

	_, status, body := exchanged(t, mem, e, "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	qt.Check(t, qt.Equals(fake.askedTenant, ""), qt.Commentf("the sign-in named none and the person is in one"))
	refresh, _ := body["refresh_token"].(string)

	fake.askedTenant = "unset"
	status, body = e.refresh(refresh, "product-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	qt.Check(t, qt.Equals(fake.askedTenant, orgA))
}

// A service account's token for an organisation tells the register that one.
func TestAServiceAccountsTokenTellsTheRegisterTheOrganisationItAsksFor(t *testing.T) {
	fake := &fakeResolver{memberships: []rolebyte.Membership{
		member(orgA, "signing-requests:write"),
	}}
	app := scopesApp(t, fake)

	status, body := get(t, app, "/testonly/service?tenant="+orgA+"&allowed=signing-requests:write")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
	qt.Check(t, qt.Equals(fake.askedTenant, orgA))
}
