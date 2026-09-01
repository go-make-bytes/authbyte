package routes

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/webeid"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
)

// webeidChallengeResponse is returned by GET /webeid/challenge.
type webeidChallengeResponse struct {
	Nonce string `json:"nonce"`
	State string `json:"state"`
}

// webeidLoginRequest is the body of POST /webeid/login. AuthToken is the Web eID
// authentication token produced by web-eid.js on the SPA; it is opaque here and
// forwarded verbatim to the engine.
type webeidLoginRequest struct {
	State     string          `json:"state"`
	AuthToken json.RawMessage `json:"authToken"`
}

// webeidLoginResponse returns the application authorization code; the SPA then
// exchanges it at /token exactly like the eParaksts flow.
type webeidLoginResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// webeidChallenge begins a Web eID card login. Like /authorize it takes the
// SPA's PKCE challenge + redirect/client, but instead of redirecting to an IdP
// it issues a Web eID challenge nonce (the SPA runs web-eid.js with it) and
// persists the flow. Returns {nonce, state}.
//
// @route /webeid/challenge [get].
func (r *router) webeidChallenge(ctx *azugo.Context) {
	challenge, err := ctx.Query.String("code_challenge")
	if err != nil {
		ctx.Error(err)

		return
	}

	method := "S256"
	if m := ctx.Query.StringOptional("code_challenge_method"); m != nil {
		method = *m
	}

	redirectURI, err := ctx.Query.String("redirect_uri")
	if err != nil {
		ctx.Error(err)

		return
	}

	clientID, err := ctx.Query.String("client_id")
	if err != nil {
		ctx.Error(err)

		return
	}

	// Open-redirect guard, same as /authorize ([RFC 6749 §10.6]).
	if err := r.Registry().ValidateRedirectURI(clientID, redirectURI); err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "redirect_uri", Tag: "registered"})

		return
	}

	spaState := ""
	if s := ctx.Query.StringOptional("state"); s != nil {
		spaState = *s
	}

	nonce, err := webeidNonce()
	if err != nil {
		ctx.Error(err)

		return
	}

	state := randomToken(24)
	flow := &session.Flow{
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		AppRedirectURI:      redirectURI,
		SPAState:            spaState,
		ClientID:            clientID,
		WebEIDNonce:         nonce,
	}
	if err := r.Session().SaveFlow(ctx, state, flow, flowTTL); err != nil {
		ctx.Error(err)

		return
	}

	ctx.JSON(webeidChallengeResponse{Nonce: nonce, State: state})
}

// webeidLogin completes a Web eID card login: it validates the auth token via
// the engine's stateless /auth/validate (against the flow's nonce), maps the
// subject to an identity, establishes the session, and returns an application
// authorization code. When the flow is a step-up (issued by /step-up
// method=webEid), establishSession elevates the existing session in place
// instead of creating a new one, and the audit events are step-up events.
//
// @route /webeid/login [post].
func (r *router) webeidLogin(ctx *azugo.Context) {
	var req webeidLoginRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}
	if req.State == "" || len(req.AuthToken) == 0 {
		ctx.Error(azugo.ParamInvalidError{Name: "authToken", Tag: "required"})

		return
	}

	flow, err := r.Session().ConsumeFlow(ctx, req.State)
	if err != nil {
		// Unknown/expired state — fail closed.
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	subj, err := r.WebEID().Validate(ctx, req.AuthToken, flow.WebEIDNonce)
	if err != nil {
		if flow.StepUp {
			r.Audit().StepUpFailure(ctx, flow.RequestedLogin, "web eid token validation failed")
		} else {
			r.Audit().LoginFailure(ctx, "web eid token validation failed")
		}
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	id := webeidIdentity(subj)

	sess, sid, err := r.establishSession(ctx, flow, id)
	if err != nil {
		if flow.StepUp {
			// err is errStepUpSessionGone or errStepUpMethodMismatch — its message
			// is the true cause; either way the step-up is unauthorized.
			r.Audit().StepUpFailure(ctx, id.LoginMethod, err.Error())
			ctx.Error(corehttp.UnauthorizedError{})
		} else {
			r.Audit().LoginFailure(ctx, "session establishment failed")
			ctx.Error(err)
		}

		return
	}

	// A card login's capabilities are the card's own authentication
	// certificate — lifted from the token whose possession the engine just
	// validated. Seal availability stays unknown (no SealsKnown): this path
	// never sees the provider's sign-identity profile. Assigned
	// unconditionally — capabilities describe the CURRENT login method, so a
	// step-up replaces what the previous login captured.
	sess.Capabilities = nil
	var tok struct {
		UnverifiedCertificate string `json:"unverifiedCertificate"`
	}
	if jerr := json.Unmarshal(req.AuthToken, &tok); jerr == nil && tok.UnverifiedCertificate != "" {
		sess.Capabilities = &session.Capabilities{AuthCertificate: tok.UnverifiedCertificate}
	}

	if err := r.Session().SaveSession(ctx, sid, sess, sessionTTL); err != nil {
		ctx.Error(err)

		return
	}

	appCode := randomToken(24)
	if err := r.Session().SaveAppCode(ctx, appCode, &session.AppCode{
		SessionID:           sid,
		CodeChallenge:       flow.CodeChallenge,
		CodeChallengeMethod: flow.CodeChallengeMethod,
		ClientID:            flow.ClientID,
		RedirectURI:         flow.AppRedirectURI,
	}, appCodeTTL); err != nil {
		ctx.Error(err)

		return
	}

	if flow.StepUp {
		r.Audit().StepUpSuccess(ctx, sess.Subject, sess.LoA, sess.LoginMethod)
	} else {
		r.Audit().LoginSuccess(ctx, sess.Subject, sess.LoA, sess.LoginMethod)
	}

	ctx.JSON(webeidLoginResponse{Code: appCode, State: flow.SPAState})
}

// webeidIdentity maps a validated Web eID subject to the platform identity. The
// national id (IDCode) is the stable IdP subject + serial number; LoA is "high"
// (physical eID smart card + QSCD); login_method "webEid" distinguishes the
// Web eID card path from the eParaksts redirect flows.
func webeidIdentity(s *webeid.Subject) identity.Identity {
	name := strings.TrimSpace(s.GivenName + " " + s.Surname)
	if name == "" {
		name = s.CommonName
	}

	return identity.Identity{
		IdPSubject:   s.IDCode,
		Name:         name,
		GivenName:    s.GivenName,
		FamilyName:   s.Surname,
		SerialNumber: s.IDCode,
		LoA:          "high",
		LoginMethod:  identity.LoginWebEID,
	}
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
