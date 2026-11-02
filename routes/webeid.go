package routes

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/identitycode"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/webeid"

	"azugo.io/azugo"
)

var (
	// errCardRefused is a card answer that signs no one in: the engine refused
	// it, it names a person this platform cannot key, or the person or method is
	// not the one the flow allows. Audited where it is found.
	errCardRefused = errors.New("card answer refused")
	// errCardAnswered is a failure whose answer is already written.
	errCardAnswered = errors.New("card answer already written")
)

// completeCard has the engine check the card's answer to flow's challenge, signs
// the person in, and mints the client's application code. Its refusals are
// audited here and returned as errCardRefused.
func (r *router) completeCard(ctx *azugo.Context, flow *session.Flow, authToken json.RawMessage) (string, error) {
	refused := func(reason string) (string, error) {
		r.Audit().LoginFailure(ctx, reason)

		return "", errCardRefused
	}

	subj, err := r.WebEID().Validate(ctx, authToken, flow.WebEIDNonce)
	if err != nil {
		return refused("web eid token validation failed")
	}

	id, err := webeidIdentity(subj)
	if err != nil {
		// The card presented a code this platform cannot key. Fail closed and
		// record why: the reason names no value, because an identity code is
		// personal data.
		return refused("web eid identity code: " + err.Error())
	}

	sess, sid, err := r.establishSession(ctx, flow, id, "")
	switch {
	case errors.Is(err, errMethodNotRequested):
		return refused("login method not requested: " + id.LoginMethod)
	case err != nil:
		r.Audit().LoginFailure(ctx, "session establishment failed")

		return "", err
	}

	// The card's own certificate, for a signing client's session.
	client, _ := r.Registry().SignInClient(flow.ClientID)
	sess.Capabilities = cardCapabilities(client, authToken)
	// The card signed this sign-in's own challenge just now: the person
	// authenticated at this moment, by the card's key and its PIN.
	stampSignIn(sess, time.Now().Unix(), cardAMR)

	if !r.saveSignedIn(ctx, flow.ClientID, sid, sess) {
		return "", errCardAnswered
	}

	appCode := randomToken(24)
	if err := r.Session().SaveAppCode(ctx, appCode, &session.AppCode{
		SessionID:           sid,
		CodeChallenge:       flow.CodeChallenge,
		CodeChallengeMethod: flow.CodeChallengeMethod,
		ClientID:            flow.ClientID,
		RedirectURI:         flow.AppRedirectURI,
		Tenant:              flow.Tenant,
		OpenID:              flow.OpenID,
		Nonce:               flow.ClientNonce,
	}, appCodeTTL); err != nil {
		return "", err
	}

	r.Audit().LoginSuccess(ctx, sess.Subject, sess.LoA, sess.LoginMethod)

	return appCode, nil
}

// cardCapabilities are a card login's signing capabilities: the card's own
// authentication certificate, lifted from the token whose possession the engine
// just validated. Seal availability stays unknown (no SealsKnown): this path
// never sees the provider's sign-identity profile. Only a signing client's login
// keeps the certificate; another product's sign-in has no use for it.
func cardCapabilities(client registry.SignInClient, authToken json.RawMessage) *session.Capabilities {
	if !client.Signing {
		return nil
	}

	var tok struct {
		UnverifiedCertificate string `json:"unverifiedCertificate"`
	}
	if err := json.Unmarshal(authToken, &tok); err != nil || tok.UnverifiedCertificate == "" {
		return nil
	}

	return &session.Capabilities{AuthCertificate: tok.UnverifiedCertificate}
}

// webeidIdentity maps a validated Web eID subject to the platform identity. The
// national id (IDCode) is the stable IdP subject + serial number; LoA is "high"
// (physical eID smart card + QSCD); login_method "webEid" distinguishes the
// Web eID card path from the eParaksts redirect flows.
//
// The code is reduced to the one spelling the platform stores and compares
// before it becomes either, and the country it is keyed under comes from the
// card's own certificate — the subject country attribute the engine read off
// it. That is the nearest fact about this person there is: they are holding the
// card. A card whose certificate states the country in the code itself keeps
// what it states.
//
// A code that cannot be canonicalised refuses the login rather than producing
// an identity keyed some other way. Both fields take the canonical value: the
// credential handle for this method IS the national id, so letting the two
// spellings diverge would mean a re-issued card, spelled differently, became a
// second credential for a person the platform already knows.
func webeidIdentity(s *webeid.Subject) (identity.Identity, error) {
	code, err := identitycode.Canonical(s.IDCode, s.CountryCode)
	if err != nil {
		return identity.Identity{}, err
	}

	name := strings.TrimSpace(s.GivenName + " " + s.Surname)
	if name == "" {
		name = s.CommonName
	}

	return identity.Identity{
		IdPSubject:   code,
		Name:         name,
		GivenName:    s.GivenName,
		FamilyName:   s.Surname,
		SerialNumber: code,
		LoA:          "high",
		LoginMethod:  identity.LoginWebEID,
	}, nil
}

// webeidNonce generates a Web eID challenge nonce: base64 of 32 cryptographically
// random bytes (≥ the 256-bit entropy the Web eID spec requires).
func webeidNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}
