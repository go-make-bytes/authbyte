package routes

import (
	"strconv"
	"strings"
	"testing"

	"github.com/gmb-lib/go-authbyte/identitycode"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/webeid"

	"github.com/go-quicktest/qt"
)

// A card's certificate writes the identity code the way its country writes it.
// The platform keys the person on one spelling, so the card path collapses it
// before the code becomes either the person's key or this credential's handle.
func TestWebEIDIdentityCanonicalisesTheCardCode(t *testing.T) {
	d := strconv.Itoa(5)
	subj := &webeid.Subject{
		IDCode:      "PNOLV-" + strings.Repeat(d, 6) + "-" + strings.Repeat(d, 5),
		CountryCode: "LV",
		GivenName:   "JĀNIS",
		Surname:     "BĒRZIŅŠ",
	}

	id, err := webeidIdentity(subj)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(id.SerialNumber, "PNOLV-"+strings.Repeat(d, 11)))
	// The credential handle for this method IS the national id. Letting the two
	// diverge would make a re-issued card, spelled differently, a second
	// credential for a person the platform already knows.
	qt.Check(t, qt.Equals(id.IdPSubject, id.SerialNumber))
	qt.Check(t, qt.Equals(id.Name, "JĀNIS BĒRZIŅŠ"))
	qt.Check(t, qt.Equals(id.LoA, "high"))
	qt.Check(t, qt.Equals(id.LoginMethod, identity.LoginWebEID))
}

// A certificate that states only the national code is keyed under the country
// the certificate itself states — the subject country attribute. That is the
// nearest fact about this person there is: they are holding the card.
func TestWebEIDIdentityTakesTheCountryFromTheCertificate(t *testing.T) {
	d := strconv.Itoa(6)
	subj := &webeid.Subject{
		IDCode:      strings.Repeat(d, 6) + "-" + strings.Repeat(d, 5),
		CountryCode: "LV",
		CommonName:  "BĒRZIŅŠ,JĀNIS",
	}

	id, err := webeidIdentity(subj)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(id.SerialNumber, "PNOLV-"+strings.Repeat(d, 11)))
	qt.Check(t, qt.Equals(id.Name, "BĒRZIŅŠ,JĀNIS"))
}

// A country the CODE states wins over the certificate's own country attribute.
// A Lithuanian card read on a Latvian screen still belongs to a Lithuanian: the
// same digits in two countries are two people.
func TestWebEIDIdentityCodeCountryWinsOverTheCertificate(t *testing.T) {
	d := strconv.Itoa(7)
	subj := &webeid.Subject{
		IDCode:      "PNOLT-" + strings.Repeat(d, 5) + " " + strings.Repeat(d, 6),
		CountryCode: "LV",
		GivenName:   "JONAS",
		Surname:     "KAZLAUSKAS",
	}

	id, err := webeidIdentity(subj)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(id.SerialNumber, "PNOLT-"+strings.Repeat(d, 11)))
}

// A card whose certificate states neither a country in the code nor a subject
// country is REFUSED, not filed under a guess. The login fails closed, and the
// reason names no identity code — it is written to service logs.
func TestWebEIDIdentityRefusesACodeWithNoCountry(t *testing.T) {
	bare := strings.Repeat("8", 11)
	subj := &webeid.Subject{IDCode: bare}

	_, err := webeidIdentity(subj)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.ErrorIs(err, identitycode.ErrCountryRequired))
	qt.Check(t, qt.Not(qt.StringContains(err.Error(), bare)))
}

// An identity type this platform does not recognise is refused rather than
// keyed as something else — the fail-closed half of the rule.
func TestWebEIDIdentityRefusesAnUnknownIdentityType(t *testing.T) {
	subj := &webeid.Subject{IDCode: "XYZLV-" + strings.Repeat("9", 11), CountryCode: "LV"}

	_, err := webeidIdentity(subj)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.ErrorIs(err, identitycode.ErrUnknownSemantics))
}
