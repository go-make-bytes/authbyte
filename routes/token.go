package routes

import (
	"errors"

	"github.com/gmb-lib/go-authbyte/claims"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/go-make-bytes/authbyte/issuer"
	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/routes/response"
	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
	"github.com/valyala/fasthttp"
)

// userScopes answers the scopes and tenant a user token should carry: the
// session's static baseline with no tenant, or — when the membership resolver
// is wired — the person's live register-resolved scopes plus the membership's
// tenant (multi-tenant resource services scope by the token's tenant, never
// request data). Resolution runs on EVERY user-token issue (first issue and
// refresh alike), so a revoked membership dies at the next session refresh.
// Any resolution failure fails the issuance closed: an error is written and
// ok is false — a token with guessed or empty-by-error scopes is never
// minted.
func (r *router) userScopes(ctx *azugo.Context, sess *session.Session) ([]string, string, bool) {
	resolver := r.ScopeResolver()
	if resolver == nil {
		return sess.Scopes, "", true
	}

	scopes, tenant, err := resolver.UserScopes(ctx, sess.SerialNumber)
	switch {
	case errors.Is(err, rolebyte.ErrNotMember):
		// Login is not access: the person authenticated, but no membership
		// grants them anything here.
		ctx.Error(pkerrors.NewProblem("err:membership:notMember",
			pkerrors.WithStatus(fasthttp.StatusForbidden),
			pkerrors.WithPublicDetail("this account has no membership here")))

		return nil, "", false
	case errors.Is(err, rolebyte.ErrAmbiguous):
		// More than one membership cannot be expressed in a single-tenant
		// token yet — refused rather than guessed.
		ctx.Error(pkerrors.NewProblem("err:membership:ambiguous",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithPublicDetail("this account belongs to more than one organisation")))

		return nil, "", false
	case err != nil:
		// The register is unreachable or answered garbage: fail closed. The
		// outbound helper surfaces no downstream body, so this is a produced
		// upstream failure, not a relay.
		ctx.Log().Warn("membership resolve failed — refusing token issue: " + err.Error())
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))

		return nil, "", false
	}

	return scopes, tenant, true
}

// tokenTypeDPoP is the token_type for sender-constrained tokens.
const tokenTypeDPoP = "DPoP"

// RFC 8693 token-exchange grant + the access-token type URI it operates on.
const (
	grantTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// token is the OAuth2 token endpoint. It dispatches on grant_type and always
// requires a valid DPoP proof (with server nonce).
//
// @route /token [post].
func (r *router) token(ctx *azugo.Context) {
	grant, err := ctx.Form.String("grant_type")
	if err != nil {
		ctx.Error(err)

		return
	}

	// Every issuance hop is DPoP-bound; the proof carries no access token.
	thumbprint, ok := r.verifyEndpointDPoP(ctx, "")
	if !ok {
		return
	}

	switch grant {
	case "authorization_code":
		r.grantAuthorizationCode(ctx, thumbprint)
	case "client_credentials":
		r.grantClientCredentials(ctx, thumbprint)
	case "refresh_token":
		r.grantRefreshToken(ctx, thumbprint)
	case grantTokenExchange:
		r.grantTokenExchange(ctx, thumbprint)
	default:
		ctx.Error(azugo.ParamInvalidError{Name: "grant_type", Tag: "oneof=authorization_code client_credentials refresh_token " + grantTokenExchange})
	}
}

// grantAuthorizationCode exchanges an application authorization code (+ PKCE
// verifier) for a DPoP-bound user token.
func (r *router) grantAuthorizationCode(ctx *azugo.Context, thumbprint string) {
	code, err := ctx.Form.String("code")
	if err != nil {
		ctx.Error(err)

		return
	}

	verifier, err := ctx.Form.String("code_verifier")
	if err != nil {
		ctx.Error(err)

		return
	}

	clientID, err := ctx.Form.String("client_id")
	if err != nil {
		ctx.Error(err)

		return
	}

	redirectURI, err := ctx.Form.String("redirect_uri")
	if err != nil {
		ctx.Error(err)

		return
	}

	appCode, err := r.Session().ConsumeAppCode(ctx, code)
	if err != nil {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	// Echo-check: client_id and redirect_uri must match what was registered at
	// authorization time ([RFC 6749 §4.1.3]).
	if appCode.ClientID != clientID || appCode.RedirectURI != redirectURI {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	if !verifyPKCE(verifier, appCode.CodeChallenge, appCode.CodeChallengeMethod) {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	sess, err := r.Session().LoadSession(ctx, appCode.SessionID)
	if err != nil {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	// Bind the session to the SPA's DPoP key so refreshes stay sender-constrained.
	sess.Thumbprint = thumbprint
	if err := r.Session().SaveSession(ctx, appCode.SessionID, sess, sessionTTL); err != nil {
		ctx.Error(err)

		return
	}

	scopes, tenant, ok := r.userScopes(ctx, sess)
	if !ok {
		return
	}

	tok, exp, err := r.Issuer().IssueUser(issuer.UserTokenInput{
		Subject:      sess.Subject,
		Audience:     r.Config().UserAudience,
		Scopes:       scopes,
		LoA:          sess.LoA,
		LoginMethod:  sess.LoginMethod,
		Name:         sess.Name,
		GivenName:    sess.GivenName,
		FamilyName:   sess.FamilyName,
		SerialNumber: sess.SerialNumber,
		Tenant:       tenant,
		Thumbprint:   thumbprint,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().UserTokenIssued(ctx, sess.Subject, sess.LoA, sess.LoginMethod, r.Config().UserAudience, scopes)

	ctx.JSON(&response.Token{
		AccessToken:  tok,
		TokenType:    tokenTypeDPoP,
		ExpiresIn:    exp,
		RefreshToken: appCode.SessionID,
		// The login-captured signing capabilities ride the code exchange (and
		// only the code exchange — a refresh re-issues a token, it is not a
		// new identification), so the caller can hold them for the session.
		Capabilities: capabilitiesResponse(sess.Capabilities),
	})
}

// capabilitiesResponse maps the session's captured capabilities onto the
// token-response DTO. nil in, nil out — absent capabilities stay absent.
func capabilitiesResponse(c *session.Capabilities) *response.Capabilities {
	if c == nil {
		return nil
	}
	out := &response.Capabilities{
		SignIdentityID:     c.SignIdentityID,
		SigningCertificate: c.SigningCertificate,
		AuthCertificate:    c.AuthCertificate,
		SealsKnown:         c.SealsKnown,
	}
	for _, s := range c.Seals {
		out.Seals = append(out.Seals, response.Seal(s))
	}

	return out
}

// grantClientCredentials mints a DPoP-bound service token, enforcing the
// registry's client ↔ audience ↔ scope matrix.
func (r *router) grantClientCredentials(ctx *azugo.Context, thumbprint string) {
	clientID, err := ctx.Form.String("client_id")
	if err != nil {
		ctx.Error(err)

		return
	}

	secret, err := ctx.Form.String("client_secret")
	if err != nil {
		ctx.Error(err)

		return
	}

	audience, err := ctx.Form.String("audience")
	if err != nil {
		ctx.Error(err)

		return
	}

	var requested []string
	if s := ctx.Form.StringOptional("scope"); s != nil {
		requested = registry.ParseScopeString(*s)
	}

	if _, err := r.Registry().Authenticate(clientID, secret); err != nil {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	scopes, err := r.Registry().AllowedScopes(clientID, audience, requested)
	if err != nil {
		if errors.Is(err, registry.ErrGrantDenied) {
			ctx.Error(corehttp.ForbiddenError{})

			return
		}

		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	tok, exp, err := r.Issuer().IssueService(issuer.ServiceTokenInput{
		ClientID:   clientID,
		Audience:   audience,
		Scopes:     scopes,
		Thumbprint: thumbprint,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().ServiceTokenIssued(ctx, clientID, audience, scopes)

	ctx.JSON(&response.Token{
		AccessToken: tok,
		TokenType:   tokenTypeDPoP,
		ExpiresIn:   exp,
	})
}

// grantRefreshToken re-issues a user token within an existing session. The
// caller must present the same DPoP key the session is bound to.
func (r *router) grantRefreshToken(ctx *azugo.Context, thumbprint string) {
	refresh, err := ctx.Form.String("refresh_token")
	if err != nil {
		ctx.Error(err)

		return
	}

	sess, err := r.Session().LoadSession(ctx, refresh)
	if err != nil {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	if sess.Thumbprint == "" || sess.Thumbprint != thumbprint {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	// Re-resolved on every refresh: this is where a revoked membership
	// actually dies (the leaver guarantee rides short sessions).
	scopes, tenant, ok := r.userScopes(ctx, sess)
	if !ok {
		return
	}

	tok, exp, err := r.Issuer().IssueUser(issuer.UserTokenInput{
		Subject:      sess.Subject,
		Audience:     r.Config().UserAudience,
		Scopes:       scopes,
		LoA:          sess.LoA,
		LoginMethod:  sess.LoginMethod,
		Name:         sess.Name,
		GivenName:    sess.GivenName,
		FamilyName:   sess.FamilyName,
		SerialNumber: sess.SerialNumber,
		Tenant:       tenant,
		Thumbprint:   thumbprint,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().UserTokenIssued(ctx, sess.Subject, sess.LoA, sess.LoginMethod, r.Config().UserAudience, scopes)

	ctx.JSON(&response.Token{
		AccessToken:  tok,
		TokenType:    tokenTypeDPoP,
		ExpiresIn:    exp,
		RefreshToken: refresh,
	})
}

// grantTokenExchange implements RFC 8693 token exchange so a confidential
// client can obtain a token that acts on behalf of an end user toward another
// service. The presented subject token (one this issuer minted) names the user;
// the minted token carries that user as its subject, records the requesting
// client in the actor chain, is sender-constrained to the requesting client's
// DPoP key, and carries the login method + assurance forward so a downstream
// login⇒signing binding still applies. Downstream services owner-filter on the
// user subject exactly as for a direct user call.
func (r *router) grantTokenExchange(ctx *azugo.Context, thumbprint string) {
	clientID, err := ctx.Form.String("client_id")
	if err != nil {
		ctx.Error(err)

		return
	}

	secret, err := ctx.Form.String("client_secret")
	if err != nil {
		ctx.Error(err)

		return
	}

	audience, err := ctx.Form.String("audience")
	if err != nil {
		ctx.Error(err)

		return
	}

	subjectToken, err := ctx.Form.String("subject_token")
	if err != nil {
		ctx.Error(err)

		return
	}

	// subject_token_type, when supplied, must name an access token — the only
	// token type the platform exchanges.
	if st := ctx.Form.StringOptional("subject_token_type"); st != nil && *st != tokenTypeAccessToken {
		ctx.Error(azugo.ParamInvalidError{Name: "subject_token_type", Tag: "eq=" + tokenTypeAccessToken})

		return
	}

	var requested []string
	if s := ctx.Form.StringOptional("scope"); s != nil {
		requested = registry.ParseScopeString(*s)
	}

	// Authenticate the requesting (delegating) client.
	if _, err := r.Registry().Authenticate(clientID, secret); err != nil {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	// The presented subject token must be one this issuer minted and still
	// valid; its subject names the user being acted for.
	subject, err := r.Issuer().ParseSubjectToken(subjectToken)
	if err != nil {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	// Only a user (or an already-delegated token, which still names a user) may
	// be acted for — a service cannot be impersonated. This keeps "service acts
	// as itself" (client_credentials) distinct from "service acts for a user".
	if subject.IsService() {
		ctx.Error(corehttp.ForbiddenError{})

		return
	}

	// The target audience + scopes are authorized against the same grant matrix
	// that governs client-credentials.
	scopes, err := r.Registry().AllowedScopes(clientID, audience, requested)
	if err != nil {
		if errors.Is(err, registry.ErrGrantDenied) {
			ctx.Error(corehttp.ForbiddenError{})

			return
		}

		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	tok, exp, err := r.Issuer().IssueDelegated(issuer.DelegatedTokenInput{
		Subject:      subject.Subject,
		Audience:     audience,
		Scopes:       scopes,
		LoA:          subject.LoA,
		LoginMethod:  subject.LoginMethod,
		SerialNumber: subject.SerialNumber,
		Tenant:       subject.Tenant,
		Actor:        &claims.Actor{Subject: clientID, Act: subject.Act},
		Thumbprint:   thumbprint,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().DelegatedTokenIssued(ctx, clientID, subject.Subject, audience, scopes)

	ctx.JSON(&response.Token{
		AccessToken:     tok,
		TokenType:       tokenTypeDPoP,
		ExpiresIn:       exp,
		IssuedTokenType: tokenTypeAccessToken,
	})
}
