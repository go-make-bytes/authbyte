package routes

import (
	"context"
	"testing"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session"

	"github.com/go-quicktest/qt"
)

// TestStepUpMethodMatches pins the step-up binding rule: the method actually
// achieved must equal the method requested, so a session cannot be "elevated"
// by re-authenticating with a different (or the legacy) method. webEid — the
// Web eID step-up target — is exercised alongside the Entrust-federated methods.
func TestStepUpMethodMatches(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		achieved  string
		want      bool
	}{
		{"webEid satisfied by webEid", "webEid", "webEid", true},
		{"mobile satisfied by mobile", "eparakstsMobile", "eparakstsMobile", true},
		{"eidScan satisfied by eidScan", "eidScan", "eidScan", true},

		{"webEid not satisfied by mobile", "webEid", "eparakstsMobile", false},
		{"mobile not satisfied by webEid", "eparakstsMobile", "webEid", false},
		{"webEid not satisfied by legacy eid", "webEid", "eid", false},

		// Exact match only — same vocabulary on both sides, so case must agree.
		{"case-sensitive", "webEid", "WEBEID", false},

		// No requested method (e.g. a normal, non-step-up login) imposes no
		// constraint — the step-up rule only applies when a method was requested.
		{"empty requested imposes no constraint", "", "webEid", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			qt.Check(t, qt.Equals(stepUpMethodMatches(c.requested, c.achieved), c.want))
		})
	}
}

const (
	codeA    = "PNOLV-010190-10007"
	codeB    = "PNOLV-020290-20004"
	provider = "https://idp.example"
	entra    = "https://login.example/tenant/v2.0"
)

// mobileSession is person A signed in with eParaksts Mobile, the session a card
// step-up raises.
func mobileSession() *session.Session {
	return &session.Session{
		Subject:         "01PERSONA",
		SerialNumber:    codeA,
		LoA:             "substantial",
		LoginMethod:     "eparakstsMobile",
		DirectoryIssuer: provider,
		ProviderSubject: "idp-handle-a",
		ProviderIssuer:  provider,
	}
}

// directorySession is a person signed in through a directory, which sends no
// identity code.
func directorySession() *session.Session {
	return &session.Session{
		Subject:         "01PERSONDIR",
		LoA:             "low",
		LoginMethod:     "entra",
		DirectoryIssuer: entra,
		ProviderSubject: "entra-oid-1",
		ProviderIssuer:  entra,
	}
}

func card(code string) identity.Identity {
	return identity.Identity{IdPSubject: code, SerialNumber: code, LoA: "high", LoginMethod: identity.LoginWebEID}
}

func stepUp(requested string) *session.Flow {
	return &session.Flow{StepUp: true, SessionID: "sid-1", RequestedLogin: requested}
}

// A step-up raises the session only when its login is the person the session
// belongs to; every refusal leaves the session as it was.
func TestStepUpComparesThePerson(t *testing.T) {
	cases := []struct {
		name    string
		sess    *session.Session
		loadErr error
		flow    *session.Flow
		id      identity.Identity
		want    error
	}{
		{"1: the same person's card", mobileSession(), nil, stepUp(identity.LoginWebEID), card(codeA), nil},
		{"2: another person's card", mobileSession(), nil, stepUp(identity.LoginWebEID), card(codeB), errStepUpPersonMismatch},
		{"3: another person through the provider", mobileSession(), nil, stepUp("eparakstsMobile"),
			identity.Identity{IdPSubject: "idp-handle-b", SerialNumber: codeB, LoA: "high", LoginMethod: "eparakstsMobile", Issuer: provider},
			errStepUpPersonMismatch},
		{"4: the same person, another method", mobileSession(), nil, stepUp(identity.LoginWebEID),
			identity.Identity{IdPSubject: "idp-handle-a", SerialNumber: codeA, LoA: "high", LoginMethod: "eparakstsMobile", Issuer: provider},
			errStepUpMethodMismatch},
		{"5: a directory session stepped up by a card", directorySession(), nil, stepUp(identity.LoginWebEID), card(codeA), errStepUpPersonMismatch},
		{"5: a directory session, the same credential", directorySession(), nil, stepUp("entra"),
			identity.Identity{IdPSubject: "entra-oid-1", LoA: "substantial", LoginMethod: "entra", Issuer: entra}, nil},
		{"5: a directory session, another credential", directorySession(), nil, stepUp("entra"),
			identity.Identity{IdPSubject: "entra-oid-2", LoA: "substantial", LoginMethod: "entra", Issuer: entra}, errStepUpPersonMismatch},
		{"5: a directory session, the same handle at another provider", directorySession(), nil, stepUp("entra"),
			identity.Identity{IdPSubject: "entra-oid-1", LoA: "substantial", LoginMethod: "entra", Issuer: provider}, errStepUpPersonMismatch},
		{"6: a session that was signed out", nil, session.ErrNotFound, stepUp(identity.LoginWebEID), card(codeA), errStepUpSessionGone},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var before session.Session
			if c.sess != nil {
				before = *c.sess
			}

			got, err := stepUpSession(context.Background(), loaderAnswering{sess: c.sess, err: c.loadErr}, c.flow, c.id)
			if c.want != nil {
				qt.Assert(t, qt.ErrorIs(err, c.want))
				qt.Check(t, qt.IsNil(got))
				if c.sess != nil {
					qt.Check(t, qt.DeepEquals(*c.sess, before))
				}

				return
			}

			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(got.Subject, before.Subject))
			qt.Check(t, qt.Equals(got.LoA, c.id.LoA))
			qt.Check(t, qt.Equals(got.LoginMethod, c.id.LoginMethod))
		})
	}
}
