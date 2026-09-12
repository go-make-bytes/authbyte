package routes

import (
	"testing"

	"github.com/go-make-bytes/authbyte/rolebyte"

	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

func memberships(tenants ...string) []rolebyte.Membership {
	out := make([]rolebyte.Membership, 0, len(tenants))
	for _, id := range tenants {
		out = append(out, rolebyte.Membership{TenantID: id, Scopes: []string{"projects:read", id + ":role"}})
	}

	return out
}

// One membership is the one minted; several with nothing named are the
// person's to choose from; a named organisation is minted only if the subject
// is a member there — never a guess in any direction.
func TestChooseMembership(t *testing.T) {
	single := memberships("A")
	chosen, choices := chooseMembership(single, "")
	qt.Assert(t, qt.IsNotNil(chosen))
	qt.Check(t, qt.Equals(chosen.TenantID, "A"))
	qt.Check(t, qt.HasLen(choices, 0))

	several := memberships("A", "B")
	chosen, choices = chooseMembership(several, "")
	qt.Check(t, qt.IsNil(chosen))
	qt.Check(t, qt.DeepEquals(choices, []string{"A", "B"}))

	chosen, choices = chooseMembership(several, "B")
	qt.Assert(t, qt.IsNotNil(chosen))
	qt.Check(t, qt.Equals(chosen.TenantID, "B"))
	qt.Check(t, qt.HasLen(choices, 0))

	chosen, choices = chooseMembership(several, "C")
	qt.Check(t, qt.IsNil(chosen))
	qt.Check(t, qt.HasLen(choices, 0))

	chosen, choices = chooseMembership(nil, "")
	qt.Check(t, qt.IsNil(chosen))
	qt.Check(t, qt.HasLen(choices, 0))

	// Naming a tenant while holding exactly one membership elsewhere is a
	// refusal, not a fallback to the one held.
	chosen, _ = chooseMembership(single, "B")
	qt.Check(t, qt.IsNil(chosen))
}

// What a service account receives is what its registry grant allows AND its
// membership grants — in the grant's order, nothing from either side alone.
func TestIntersectScopes(t *testing.T) {
	got := intersectScopes(
		[]string{"signing-requests:write", "signing-requests:read", "documents:read"},
		[]string{"signing-requests:read", "signing-requests:write", "membership:admin"},
	)
	qt.Check(t, qt.DeepEquals(got, []string{"signing-requests:write", "signing-requests:read"}))

	qt.Check(t, qt.HasLen(intersectScopes([]string{"a:b"}, []string{"c:d"}), 0))
	qt.Check(t, qt.HasLen(intersectScopes(nil, []string{"c:d"}), 0))
	qt.Check(t, qt.HasLen(intersectScopes([]string{"a:b"}, nil), 0))
}

// A person may be acted for; a service only when its token names the
// organisation it acts for — a platform service acting as itself cannot be
// impersonated.
func TestMayBeActedFor(t *testing.T) {
	person := &claims.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "01PERSON"}}
	qt.Check(t, qt.IsTrue(mayBeActedFor(person)))

	delegatedPerson := &claims.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "01PERSON"}, Act: &claims.Actor{Subject: "svc:portal-api"}}
	qt.Check(t, qt.IsTrue(mayBeActedFor(delegatedPerson)))

	fleetService := &claims.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "svc:signflow"}, ClientID: "svc:signflow"}
	qt.Check(t, qt.IsFalse(mayBeActedFor(fleetService)))

	serviceAccount := &claims.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "svc:acme-dms"}, ClientID: "svc:acme-dms", Tenant: "01TENANTACME"}
	qt.Check(t, qt.IsTrue(mayBeActedFor(serviceAccount)))

	// The second hop: the delegated token minted for the service account still
	// carries its tenant, so the envelope service's re-exchange is admitted too.
	secondHop := &claims.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "svc:acme-dms"}, Tenant: "01TENANTACME", Act: &claims.Actor{Subject: "svc:signbyte-integration-api"}}
	qt.Check(t, qt.IsTrue(mayBeActedFor(secondHop)))
}
