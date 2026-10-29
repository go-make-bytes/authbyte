package authbytecore

import (
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// The token for one call at the register's sign-in doors lives as long as that
// call needs and no longer, and it is always bound to the key that proves it: a
// token with no key thumbprint would be a bearer token anyone holding it could use.
func TestTheSignInDoorTokenIsShortAndBound(t *testing.T) {
	app := TestApp(t)

	_, err := app.mintSignInToken("01K9ANNA0000000000000000AA", "svc:rolebyte", "membership:resolve", "svc:authbyte-core", "")
	qt.Check(t, qt.ErrorMatches(err, `.*thumbprint.*`))

	tok, err := app.mintSignInToken("01K9ANNA0000000000000000AA", "svc:rolebyte", "membership:resolve", "svc:authbyte-core", "the-outbound-key")
	qt.Assert(t, qt.IsNil(err))

	c, err := app.Issuer().ParseSubjectToken(tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(c.ExpiresAt.Sub(c.IssuedAt.Time) <= signInTokenTTL))
	qt.Check(t, qt.Equals(signInTokenTTL, time.Minute))
	qt.Check(t, qt.Equals(c.Confirmation.JKT, "the-outbound-key"))
}
