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

// Case 20: the upsert request names the provider the handle came from, since a
// handle is unique only there; a login through the deployment's first provider
// (and the card) names the empty one, as every stored credential does.
func TestUpsertInputNamesTheProvider(t *testing.T) {
	in := upsertInput("oid-1", Profile{Provider: "https://accounts.example", LoginMethod: "google"})
	qt.Check(t, qt.Equals(in["provider"], any("https://accounts.example")))
	qt.Check(t, qt.Equals(in["idp_sub"], any("oid-1")))

	first := upsertInput("oid-2", Profile{LoginMethod: "upstream"})
	v, present := first["provider"]
	qt.Check(t, qt.IsTrue(present))
	qt.Check(t, qt.Equals(v, any("")))
}
