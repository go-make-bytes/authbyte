package routes

import (
	"strings"
	"testing"

	"github.com/gmb-lib/go-authbyte/identitycode"
	"github.com/go-quicktest/qt"
)

// Every way an administrator may write one person's identity code registers the
// same person: the code is reduced to the one spelling the identity store keys on,
// which is the spelling the person's own login produces.
func TestCanonicalIdentityCodeCollapsesTheSpellings(t *testing.T) {
	want := "PNOLV-" + strings.Repeat("3", 11)
	for _, raw := range []string{
		"PNOLV-" + strings.Repeat("3", 11),
		"PNOLV-" + strings.Repeat("3", 6) + "-" + strings.Repeat("3", 5),
		"  pnolv-" + strings.Repeat("3", 6) + "-" + strings.Repeat("3", 5) + "  ",
	} {
		got, err := canonicalIdentityCode(raw)
		qt.Assert(t, qt.IsNil(err), qt.Commentf("%q", raw))
		qt.Check(t, qt.Equals(got, want), qt.Commentf("%q", raw))
	}
}

// A bare national code names no country, and the country is never guessed: the
// registration is refused with a reason that says what would fix it and does not
// repeat the code.
func TestCanonicalIdentityCodeRefusesABareCode(t *testing.T) {
	code := strings.Repeat("4", 6) + "-" + strings.Repeat("4", 5)
	_, err := canonicalIdentityCode(code)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.ErrorIs(err, identitycode.ErrCountryRequired))

	reason := identityCodeReason(err)
	qt.Check(t, qt.IsTrue(strings.Contains(reason, "country")))
	qt.Check(t, qt.IsFalse(strings.Contains(reason, strings.Repeat("4", 5))))
}

// No code at all is its own refusal, before any question of spelling.
func TestCanonicalIdentityCodeRefusesNothing(t *testing.T) {
	for _, raw := range []string{"", "   "} {
		_, err := canonicalIdentityCode(raw)
		qt.Check(t, qt.ErrorIs(err, errIdentityCodeRequired), qt.Commentf("%q", raw))
		qt.Check(t, qt.Equals(identityCodeReason(err), "identityCode is required"))
	}
}

// An identity type the platform does not know is refused as such, and a code that
// merely begins like one is told apart from it.
func TestIdentityCodeReasonNamesTheDefect(t *testing.T) {
	_, err := canonicalIdentityCode("VATLV-" + strings.Repeat("5", 11))
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(identityCodeReason(err), "identity type")))
}
