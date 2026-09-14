package routes

import (
	"errors"
	"time"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/store"
	"github.com/go-make-bytes/authbyte/upstream"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
)

// TTLs for transient auth-flow artifacts.
const (
	flowTTL    = 10 * time.Minute
	appCodeTTL = 60 * time.Second
	sessionTTL = 12 * time.Hour
)

// Step-up elevation can fail two distinguishable ways. They are surfaced as
// separate errors so the audit trail records the true cause instead of
// attributing every failure to a method mismatch: either the session to elevate
// is gone (it expired between starting the step-up and completing it), or the
// login method actually achieved did not match the one requested.
var (
	errStepUpSessionGone    = errors.New("step-up session not found or expired")
	errStepUpMethodMismatch = errors.New("achieved login method did not match the requested step-up method")
)

// authorize begins user login. The SPA (via the BFF) calls this with its PKCE
// challenge; the service starts an Authorization Code flow against Entrust and
// redirects the browser to the IdP.
//
// @route /authorize [get].
func (r *router) authorize(ctx *azugo.Context) {
	rt := ctx.Query.StringOptional("response_type")
	if rt == nil || *rt != "code" {
		ctx.Error(azugo.ParamInvalidError{Name: "response_type", Tag: "oneof=code"})

		return
	}

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

	// Validate the redirect_uri against the registered allowlist BEFORE saving
	// any state or redirecting — prevents open-redirect attacks ([RFC 6749 §10.6]).
	if err := r.Registry().ValidateRedirectURI(clientID, redirectURI); err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "redirect_uri", Tag: "registered"})

		return
	}

	spaState := ""
	if s := ctx.Query.StringOptional("state"); s != nil {
		spaState = *s
	}

	// The organisation the person asks to act under, when they belong to more
	// than one. Optional; it is checked against their memberships at the token
	// issue, never trusted on its own.
	tenant := ""
	if t := ctx.Query.StringOptional("tenant"); t != nil {
		tenant = *t
	}

	entrustRedirect := r.entrustRedirectURI()
	if entrustRedirect == "" {
		ctx.Error(corehttp.NotFoundError{Resource: "eParaksts redirect uri"})

		return
	}

	state := randomToken(24)
	// The nonce binds the id_token the provider issues to this flow: it travels
	// out with the authorize request and must come back inside the token.
	nonce := randomToken(24)
	flow := &session.Flow{
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		AppRedirectURI:      redirectURI,
		SPAState:            spaState,
		EntrustRedirectURI:  entrustRedirect,
		ClientID:            clientID,
		Tenant:              tenant,
		Nonce:               nonce,
	}

	if err := r.Session().SaveFlow(ctx, state, flow, flowTTL); err != nil {
		ctx.Error(err)

		return
	}

	params := upstream.AuthorizeParams{
		State:       state,
		RedirectURI: entrustRedirect,
		Nonce:       nonce,
	}
	if acr := ctx.Query.StringOptional("acr_values"); acr != nil {
		params.ACRValues = *acr
	}

	// External IdP authorize endpoint — use the unsanitized redirect so the
	// cross-origin target is preserved (a same-origin-only redirect would drop it).
	ctx.RedirectUnsafe(r.Upstream().AuthorizeURL(params))
}

// callback handles the Entrust redirect: it exchanges the code, maps the user,
// establishes a session, and returns an application authorization code to the
// SPA's redirect URI.
//
// @route /callback [get].
func (r *router) callback(ctx *azugo.Context) {
	// The IdP may return an error instead of a code — the user cancelled or denied
	// access, or consent failed. There is no code in that case, so handle it before
	// the required-code binding: propagate the error back to the client that began
	// the login (its redirect URI), rather than surfacing a raw binding error.
	if idpErr := ctx.Query.StringOptional("error"); idpErr != nil {
		var desc string
		if d := ctx.Query.StringOptional("error_description"); d != nil {
			desc = *d
		}
		r.Audit().LoginFailure(ctx, "eParaksts IdP returned an error: "+*idpErr)

		// Resolve the originating client so the error lands where login began.
		if state := ctx.Query.StringOptional("state"); state != nil {
			if flow, ferr := r.Session().ConsumeFlow(ctx, *state); ferr == nil {
				// Client app redirect URI (cross-origin) — bypass same-origin sanitizing.
				ctx.RedirectUnsafe(appendErrorState(flow.AppRedirectURI, *idpErr, desc, flow.SPAState))

				return
			}
		}
		// Unknown/expired state — cannot safely bounce to a client; fail closed.
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	code, err := ctx.Query.String("code")
	if err != nil {
		ctx.Error(err)

		return
	}

	state, err := ctx.Query.String("state")
	if err != nil {
		ctx.Error(err)

		return
	}

	flow, err := r.Session().ConsumeFlow(ctx, state)
	if err != nil {
		// Unknown/expired state — fail closed.
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	// Exchange the code with the provider and read the person's claims: the
	// verified id_token where the provider publishes a key set, userinfo always.
	tokens, err := r.Upstream().Exchange(ctx, code, flow.EntrustRedirectURI)
	if err != nil {
		ctx.Error(err)

		return
	}

	info, err := r.Upstream().Claims(ctx, tokens, flow.Nonce)
	if err != nil {
		switch {
		case errors.Is(err, upstream.ErrIdentityCode):
			// An identity code the platform cannot key is a refused login, not a
			// service fault: the person exists, but storing their code under a
			// second spelling would make them a second person.
			r.Audit().LoginFailure(ctx, "upstream identity code: "+err.Error())
			ctx.Error(corehttp.UnauthorizedError{})
		case errors.Is(err, upstream.ErrIDToken):
			// The provider's own assertion of who logged in was missing or did
			// not verify: a refused login, audited with the reason, answered
			// with the refusal every other failed login gets.
			r.Audit().LoginFailure(ctx, "upstream id_token: "+err.Error())
			ctx.Error(corehttp.UnauthorizedError{})
		default:
			// Everything else from the provider stays a plain error.
			ctx.Error(err)
		}

		return
	}

	id := r.Resolver().Resolve(info)

	// Enforce the provider's allowed-method set (fail closed) even if the IdP's
	// hosted page offered something else, so removing the request-side
	// acr/button is not the only protection. For the eParaksts profile this is
	// what rejects the legacy plugin eID card (sc_plugin → "eid" — eID cards
	// log in through Web eID); for a generic provider it pins the callback to
	// the methods its configuration declares.
	if !r.Upstream().MethodAllowed(id.LoginMethod) {
		r.Audit().LoginFailure(ctx, "login method not permitted via the upstream IdP: "+id.LoginMethod)
		ctx.Error(corehttp.ForbiddenError{})

		return
	}

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

	// This login's identification also read the person's sign-identity
	// catalog (when the profile scope is on) — derive the session's signing
	// capabilities from it while the upstream token is still at hand. Assigned
	// unconditionally: capabilities describe the CURRENT login method, so a
	// step-up replaces (or clears) whatever the previous login captured.
	sess.Capabilities = r.captureCapabilities(ctx, tokens.AccessToken, info, id.LoginMethod)

	if err := r.Session().SaveSession(ctx, sid, sess, sessionTTL); err != nil {
		ctx.Error(err)

		return
	}

	// Mint a single-use application authorization code bound to the session and
	// the SPA's PKCE challenge.
	appCode := randomToken(24)
	if err := r.Session().SaveAppCode(ctx, appCode, &session.AppCode{
		SessionID:           sid,
		CodeChallenge:       flow.CodeChallenge,
		CodeChallengeMethod: flow.CodeChallengeMethod,
		ClientID:            flow.ClientID,
		RedirectURI:         flow.AppRedirectURI,
		Tenant:              flow.Tenant,
	}, appCodeTTL); err != nil {
		ctx.Error(err)

		return
	}

	if flow.StepUp {
		r.Audit().StepUpSuccess(ctx, sess.Subject, sess.LoA, sess.LoginMethod)
	} else {
		r.Audit().LoginSuccess(ctx, sess.Subject, sess.LoA, sess.LoginMethod)
	}

	// Client app redirect URI (cross-origin) — bypass same-origin sanitizing.
	ctx.RedirectUnsafe(appendCodeState(flow.AppRedirectURI, appCode, flow.SPAState))
}

// establishSession either creates a new session (normal login) or updates the
// existing one with elevated assurance / a new login method (step-up).
func (r *router) establishSession(ctx *azugo.Context, flow *session.Flow, id identity.Identity) (*session.Session, string, error) {
	if flow.StepUp {
		sess, err := r.Session().LoadSession(ctx, flow.SessionID)
		if err != nil {
			return nil, "", errStepUpSessionGone
		}

		// Enforce that the achieved method matches the one requested at step-up.
		// Without this, an eID-logged-in user could "step up" to eParaksts Mobile
		// yet authenticate with eID again and the binding would not actually
		// change.
		if !stepUpMethodMatches(flow.RequestedLogin, id.LoginMethod) {
			return nil, "", errStepUpMethodMismatch
		}

		// Reflect the new assurance/method; identity and scopes are unchanged.
		sess.LoA = id.LoA
		sess.LoginMethod = id.LoginMethod
		// A step-up through an upstream provider is a login through that
		// provider's directory too; a card step-up says nothing about one.
		if id.Issuer != "" {
			sess.DirectoryIssuer = id.Issuer
			sess.DirectoryGuest = id.DirectoryGuest
		}

		return sess, flow.SessionID, nil
	}

	// Normal login: resolve the stable internal subject (the PERSON, keyed on the
	// national id / SerialNumber) and link this method's credential.
	internal, created, err := r.Store().EnsureMapping(ctx, id.IdPSubject, store.Profile{
		Name:         id.Name,
		GivenName:    id.GivenName,
		FamilyName:   id.FamilyName,
		SerialNumber: id.SerialNumber,
		LoginMethod:  id.LoginMethod,
	})
	if err != nil {
		return nil, "", err
	}
	id.Subject = internal

	// GDPR-audit: the login wrote the identity record (created on first login,
	// updated on a profile refresh). Routine/fail-open — never blocks login.
	r.Audit().IdentityWritten(ctx, internal, id.LoA, created)

	return &session.Session{
		Subject:      id.Subject,
		Name:         id.Name,
		GivenName:    id.GivenName,
		FamilyName:   id.FamilyName,
		SerialNumber: id.SerialNumber,
		LoA:          id.LoA,
		LoginMethod:  id.LoginMethod,
		Scopes:       defaultUserScopes,
		// The directory the login came through, for the register's admission
		// door at token issue ("" for a card login).
		DirectoryIssuer: id.Issuer,
		DirectoryGuest:  id.DirectoryGuest,
	}, randomToken(24), nil
}

// stepUpMethodMatches reports whether the login method actually achieved during
// a step-up satisfies the method requested when it began. An empty requested
// method imposes no constraint. The match is exact (case-sensitive): both values
// come from the same fixed login-method vocabulary, so any difference is a real
// mismatch, not a formatting one.
func stepUpMethodMatches(requested, achieved string) bool {
	return requested == "" || achieved == requested
}

// defaultUserScopes is the baseline scope set granted to an authenticated user.
// A richer authorization policy would derive these per-user.
var defaultUserScopes = []string{"envelopes:read", "envelopes:write", "documents:read"}

func (r *router) entrustRedirectURI() string {
	return r.Config().RedirectURI()
}
