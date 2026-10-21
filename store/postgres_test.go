package store

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// The upsert request carries the email next to the rest of the profile, empty
// when the login sent none — the procedure decides whether to keep it.
func TestUpsertInputCarriesTheEmail(t *testing.T) {
	in := upsertInput("idp-1", Profile{
		Name:        "Anna Example",
		LoginMethod: "upstream",
		Email:       "anna@example.test",
	})
	qt.Check(t, qt.Equals(in["email"], any("anna@example.test")))
	qt.Check(t, qt.Equals(in["idp_sub"], any("idp-1")))
	qt.Check(t, qt.Equals(in["login_method"], any("upstream")))

	none := upsertInput("idp-2", Profile{})
	v, present := none["email"]
	qt.Check(t, qt.IsTrue(present))
	qt.Check(t, qt.Equals(v, any("")))
}
