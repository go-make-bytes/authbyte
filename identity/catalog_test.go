package identity

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// traceCatalog builds a catalog shaped like the provider's real profile
// response: a serverid signing identity, an eid signing identity, the two
// paired auth identities, and any number of seals.
func traceCatalog(seals ...SignIdentity) []SignIdentity {
	base := []SignIdentity{
		{
			ID: "id-serverid-sign", Description: "eparaksts:serverid:sign", Status: "enabled",
			Labels:      []string{"serverid", "x509:keyUsage:contentCommitment"},
			Permissions: []string{"sign"},
		},
		{
			ID: "id-eid-sign", Description: "eparaksts:eid:sign", Status: "enabled",
			Labels:      []string{"eid", "x509:keyUsage:contentCommitment"},
			Permissions: []string{"sign"},
		},
		{
			ID: "id-mobileid-auth", Description: "eparaksts:mobileid:auth", Status: "enabled",
			Labels: []string{"mobileid", "x509:keyUsage:digitalSignature"},
		},
		{
			ID: "id-eid-auth", Description: "eparaksts:eid:auth", Status: "enabled",
			Labels: []string{"eid", "x509:keyUsage:digitalSignature"},
		},
	}

	return append(base, seals...)
}

func seal(id, cn, status string) SignIdentity {
	return SignIdentity{
		ID: id, Description: "eparaksts:qsealc:sign", Status: status,
		Labels:      []string{"qsealc", "CN:" + cn, "x509:keyUsage:contentCommitment"},
		Permissions: []string{"sign"},
	}
}

func TestSelectSigningPerMethod(t *testing.T) {
	cat := traceCatalog()

	s, ok := SelectSigning(cat, LoginEParakstsMobile)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(s.ID, "id-serverid-sign"))

	s, ok = SelectSigning(cat, LoginEIDScan)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(s.ID, "id-eid-sign"))

	// A method with no signing vocabulary (a card login) selects nothing.
	_, ok = SelectSigning(cat, LoginWebEID)
	qt.Check(t, qt.IsFalse(ok))
}

func TestSelectSigningAbsentIsNotAnError(t *testing.T) {
	// A person with only auth identities — no signing certificate — is a
	// valid state: selection reports absence, it does not invent a match.
	cat := []SignIdentity{
		{
			ID: "id-mobileid-auth", Description: "eparaksts:mobileid:auth", Status: "enabled",
			Labels: []string{"mobileid", "x509:keyUsage:digitalSignature"},
		},
	}
	_, ok := SelectSigning(cat, LoginEParakstsMobile)
	qt.Check(t, qt.IsFalse(ok))
}

func TestSelectSigningFiltersStatusAndPermission(t *testing.T) {
	disabled := traceCatalog()
	disabled[0].Status = "disabled"
	_, ok := SelectSigning(disabled, LoginEParakstsMobile)
	qt.Check(t, qt.IsFalse(ok))

	noSign := traceCatalog()
	noSign[0].Permissions = []string{"read"}
	_, ok = SelectSigning(noSign, LoginEParakstsMobile)
	qt.Check(t, qt.IsFalse(ok))

	// An absent permissions list is permissive — the provider enforces the
	// grant on the sign call itself.
	open := traceCatalog()
	open[0].Permissions = nil
	_, ok = SelectSigning(open, LoginEParakstsMobile)
	qt.Check(t, qt.IsTrue(ok))
}

func TestSelectAuthPerMethodWithFallback(t *testing.T) {
	cat := traceCatalog()

	a, ok := SelectAuth(cat, LoginEParakstsMobile)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(a.ID, "id-mobileid-auth"))

	a, ok = SelectAuth(cat, LoginEIDScan)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(a.ID, "id-eid-auth"))

	// Missing primary falls back to whichever auth identity is present.
	onlyEIDAuth := []SignIdentity{
		{
			ID: "id-eid-auth", Description: "eparaksts:eid:auth", Status: "enabled",
			Labels: []string{"eid", "x509:keyUsage:digitalSignature"},
		},
	}
	a, ok = SelectAuth(onlyEIDAuth, LoginEParakstsMobile)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(a.ID, "id-eid-auth"))
}

func TestSealsListWithCNLabels(t *testing.T) {
	cat := traceCatalog(
		seal("id-seal-1", "ORG ONE SIA : eZimogs", "enabled"),
		seal("id-seal-2", "ORG TWO SIA : eZimogs", "enabled"),
		seal("id-seal-3", "GONE SIA : eZimogs", "disabled"),
	)

	got := Seals(cat)
	qt.Assert(t, qt.HasLen(got, 2))
	qt.Check(t, qt.Equals(got[0].ID, "id-seal-1"))
	qt.Check(t, qt.Equals(got[0].Label, "ORG ONE SIA : eZimogs"))
	qt.Check(t, qt.Equals(got[1].ID, "id-seal-2"))
	qt.Check(t, qt.Equals(got[1].Label, "ORG TWO SIA : eZimogs"))
}

func TestSealsEmptyMeansNone(t *testing.T) {
	got := Seals(traceCatalog())
	qt.Check(t, qt.HasLen(got, 0))
}

func TestSealsMatchesESealCLabelDefensively(t *testing.T) {
	s := seal("id-seal-e", "ORG E SIA : eZimogs", "enabled")
	s.Labels = []string{"esealc", "CN:ORG E SIA : eZimogs", "x509:keyUsage:contentCommitment"}

	got := Seals(traceCatalog(s))
	qt.Assert(t, qt.HasLen(got, 1))
	qt.Check(t, qt.Equals(got[0].ID, "id-seal-e"))
}
