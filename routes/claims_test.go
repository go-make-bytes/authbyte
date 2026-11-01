package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// seedPersonSignIn is seedSignIn for a login that carried a name and an
// identity code.
func seedPersonSignIn(t *testing.T, mem *sessiontest.Memory, clientID, redirectURI string) signIn {
	t.Helper()

	in := signIn{sid: randomToken(24), code: randomToken(24), verifier: randomToken(32)}
	sum := sha256.Sum256([]byte(in.verifier))

	ctx := context.Background()
	qt.Assert(t, qt.IsNil(mem.CreateSession(ctx, in.sid, &session.Session{
		Subject:      testPersonSub(6),
		Name:         "Anna Berzina",
		GivenName:    "Anna",
		FamilyName:   "Berzina",
		SerialNumber: codeA,
		LoA:          "high",
		LoginMethod:  "webEid",
	}, sessionLifetime)))
	qt.Assert(t, qt.IsNil(mem.SaveAppCode(ctx, in.code, &session.AppCode{
		SessionID:           in.sid,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(sum[:]),
		CodeChallengeMethod: "S256",
		ClientID:            clientID,
		RedirectURI:         redirectURI,
	}, time.Minute)))

	return in
}

// Each client's tokens carry only the personal claims its row lists: the
// identity code only where the row asks for it, the names only where it lists
// them, at the code exchange and at refresh. The session keeps them all.
func TestATokenCarriesOnlyTheClaimsItsClientLists(t *testing.T) {
	app, mem := signInApp(t)

	for _, tc := range []struct {
		client, redirect string
		basic            []string
		names, code      bool
	}{
		{"portal-spa", portalRedirect, nil, true, true},
		{"product-spa", productRedirect, nil, true, false},
		{"edge-app", edgeRedirect, []string{"edge-app", "edge-secret"}, false, false},
	} {
		e := newEdge(t, app)
		e.basic = tc.basic
		in := seedPersonSignIn(t, mem, tc.client, tc.redirect)

		status, body := e.exchange(in, tc.client, tc.redirect)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", tc.client, body["_raw"]))
		tokens := []string{body["access_token"].(string)}

		status, body = e.refresh(body["refresh_token"].(string), tc.client)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s: %s", tc.client, body["_raw"]))
		tokens = append(tokens, body["access_token"].(string))

		for i, tok := range tokens {
			c := tokenClaims(t, tok)
			_, hasName := c["name"]
			_, hasGiven := c["given_name"]
			_, hasFamily := c["family_name"]
			_, hasCode := c["serial_number"]
			qt.Check(t, qt.Equals(hasName && hasGiven && hasFamily, tc.names), qt.Commentf("%s token %d: names", tc.client, i))
			qt.Check(t, qt.Equals(hasName || hasGiven || hasFamily, tc.names), qt.Commentf("%s token %d: no stray name", tc.client, i))
			qt.Check(t, qt.Equals(hasCode, tc.code), qt.Commentf("%s token %d: identity code", tc.client, i))
		}

		sess, err := mem.LoadSession(context.Background(), in.sid)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(sess.SerialNumber, codeA), qt.Commentf("%s: the session keeps the code", tc.client))
	}
}
