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

// membershipOutcome is what a user token is minted with: the scopes and the
// tenant of the membership chosen for it — or, when the person belongs to
// several organisations and none was named, no scopes, no tenant and the list
// they may choose from.
type membershipOutcome struct {
	scopes  []string
	tenant  string
	choices []string
}

// userScopes answers what a user token should carry. The public client the
// token is issued to decides whether the register is asked at all: a client
// registered without a membership requirement (a public portal) keeps its
// people on the session's static baseline with no tenant; a client that
// requires one has the person resolved from the register at EVERY issue (first
// issue and refresh alike, so a revoked membership dies at the next refresh) —
// no membership is refused, one is minted, several are the person's to choose
// from (tenantHint names their choice; it is checked, never trusted). Any
// resolution failure fails the issuance closed: an error is written and ok is
// false — a token with guessed or empty-by-error scopes is never minted.
func (r *router) userScopes(ctx *azugo.Context, sess *session.Session, clientID, tenantHint string) (membershipOutcome, bool) {
	resolver := r.ScopeResolver()
	if resolver == nil || !r.Registry().MembershipRequired(clientID, resolver != nil) {
		return membershipOutcome{scopes: sess.Scopes}, true
	}

	if sess.SerialNumber == "" {
		// Without an identity code there is no register key to look up — and
		// every supported login method provides one, so this is a wiring
		// fault, not a person condition. Fail closed.
		ctx.Log().Warn("membership resolve impossible — the login carries no identity code; refusing token issue")
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))

		return membershipOutcome{}, false
	}

	memberships, err := resolver.Memberships(ctx, rolebyte.PersonKey(sess.SerialNumber))
	if err != nil {
		// The register is unreachable or answered garbage: fail closed. The
		// outbound helper surfaces no downstream body, so this is a produced
		// upstream failure, not a relay.
		ctx.Log().Warn("membership resolve failed — refusing token issue: " + err.Error())
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))

		return membershipOutcome{}, false
	}

	chosen, choices := chooseMembership(memberships, tenantHint)
	switch {
	case len(memberships) == 0, chosen == nil && tenantHint != "":
		// Login is not access: the person authenticated, but no membership —
		// or none in the organisation they named — grants them anything here.
		ctx.Error(pkerrors.NewProblem("err:membership:notMember",
			pkerrors.WithStatus(fasthttp.StatusForbidden),
			pkerrors.WithPublicDetail("this account has no membership here")))

		return membershipOutcome{}, false
	case chosen == nil:
		// Several organisations and none named: the choice is the person's.
		// The token carries no tenant and no scopes until they make it.
		return membershipOutcome{choices: choices}, true
	}

	return membershipOutcome{scopes: chosen.Scopes, tenant: chosen.TenantID}, true
}

// chooseMembership picks the membership a token is minted for: the named one
// when a tenant was named (nil when the subject holds no membership there),
// the only one when there is exactly one, and none — with the organisations
// to choose from — when there are several. Never a guess: minting one
// organisation's roles while acting in another would be a privilege leak.
func chooseMembership(ms []rolebyte.Membership, hint string) (*rolebyte.Membership, []string) {
	if hint != "" {
		for i := range ms {
			if ms[i].TenantID == hint {
				return &ms[i], nil
			}
		}

		return nil, nil
	}

	if len(ms) == 1 {
		return &ms[0], nil
	}

	choices := make([]string, 0, len(ms))
	for _, m := range ms {
		choices = append(choices, m.TenantID)
	}

	return nil, choices
}

// intersectScopes keeps the scopes present in both lists, in the order of the
// first — what a service account may receive is what its registry grant allows
// AND its membership grants.
func intersectScopes(allowed, granted []string) []string {
	set := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		set[s] = struct{}{}
	}

	out := make([]string, 0, len(allowed))
	for _, s := range allowed {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}

	return out
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

	// The organisation named when the login began wins over one chosen
	// earlier in this session (a step-up re-enters the login without naming
	// one and keeps the session's choice).
	hint := appCode.Tenant
	if hint == "" {
		hint = sess.Tenant
	}

	outcome, ok := r.userScopes(ctx, sess, clientID, hint)
	if !ok {
		return
	}

	// Bind the session to the SPA's DPoP key so refreshes stay
	// sender-constrained, and record the client and the membership the
	// session's tokens are minted for, so a refresh re-resolves the same.
	sess.Thumbprint = thumbprint
	sess.ClientID = clientID
	sess.Tenant = outcome.tenant
	if err := r.Session().SaveSession(ctx, appCode.SessionID, sess, sessionTTL); err != nil {
		ctx.Error(err)

		return
	}

	tok, exp, err := r.Issuer().IssueUser(issuer.UserTokenInput{
		Subject:      sess.Subject,
		Audience:     r.Config().UserAudience,
		Scopes:       outcome.scopes,
		LoA:          sess.LoA,
		LoginMethod:  sess.LoginMethod,
		Name:         sess.Name,
		GivenName:    sess.GivenName,
		FamilyName:   sess.FamilyName,
		SerialNumber: sess.SerialNumber,
		Tenant:       outcome.tenant,
		Thumbprint:   thumbprint,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().UserTokenIssued(ctx, sess.Subject, sess.LoA, sess.LoginMethod, r.Config().UserAudience, outcome.scopes)

	ctx.JSON(&response.Token{
		AccessToken:  tok,
		TokenType:    tokenTypeDPoP,
		ExpiresIn:    exp,
		RefreshToken: appCode.SessionID,
		Tenants:      outcome.choices,
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
// registry's client ↔ audience ↔ scope matrix. A client that names a tenant is
// a service account acting for that organisation: its membership there is
// checked in the register, the tenant is minted into the token, and its scopes
// are what the registry grant allows AND the membership grants. A client that
// names none is a platform service acting as itself — the registry alone
// decides, no register is consulted, no tenant is minted.
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

	tenant := ""
	if t := ctx.Form.StringOptional("tenant"); t != nil {
		tenant = *t
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

	if tenant != "" {
		scopes, err = r.serviceAccountScopes(ctx, clientID, tenant, scopes)
		if err != nil {
			return
		}
	}

	tok, exp, err := r.Issuer().IssueService(issuer.ServiceTokenInput{
		ClientID:   clientID,
		Audience:   audience,
		Scopes:     scopes,
		Tenant:     tenant,
		Thumbprint: thumbprint,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().ServiceTokenIssued(ctx, clientID, audience, tenant, scopes)

	ctx.JSON(&response.Token{
		AccessToken: tok,
		TokenType:   tokenTypeDPoP,
		ExpiresIn:   exp,
	})
}

// serviceAccountScopes checks that the client is a member of the named
// organisation and narrows the registry-allowed scopes to what that membership
// grants. On a refusal the error is already written to ctx and a non-nil error
// is returned so the caller stops; the returned scopes are never empty.
func (r *router) serviceAccountScopes(ctx *azugo.Context, clientID, tenant string, allowed []string) ([]string, error) {
	resolver := r.ScopeResolver()
	if resolver == nil {
		// No register, no members: a tenant-named token cannot exist here.
		err := pkerrors.NewProblem("err:membership:notMember",
			pkerrors.WithStatus(fasthttp.StatusForbidden),
			pkerrors.WithPublicDetail("this deployment has no membership register"))
		ctx.Error(err)

		return nil, err
	}

	// The register key of a service account is its own client id — the name
	// it authenticated with and carries as its token subject.
	memberships, err := resolver.Memberships(ctx, clientID)
	if err != nil {
		ctx.Log().Warn("membership resolve failed — refusing token issue: " + err.Error())
		problem := pkerrors.NewProblem("err:upstream:unavailable", pkerrors.WithStatus(fasthttp.StatusBadGateway))
		ctx.Error(problem)

		return nil, problem
	}

	chosen, _ := chooseMembership(memberships, tenant)
	if chosen == nil {
		err := pkerrors.NewProblem("err:membership:notMember",
			pkerrors.WithStatus(fasthttp.StatusForbidden),
			pkerrors.WithPublicDetail("this account is not a member of that organisation"))
		ctx.Error(err)

		return nil, err
	}

	scopes := intersectScopes(allowed, chosen.Scopes)
	if len(scopes) == 0 {
		// A member, but with no role toward this audience: nothing to mint.
		err := corehttp.ForbiddenError{}
		ctx.Error(err)

		return nil, err
	}

	return scopes, nil
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

	// Re-resolved on every refresh, for the client and the membership the
	// session was issued for: this is where a revoked membership actually dies
	// (the leaver guarantee rides short sessions).
	outcome, ok := r.userScopes(ctx, sess, sess.ClientID, sess.Tenant)
	if !ok {
		return
	}

	tok, exp, err := r.Issuer().IssueUser(issuer.UserTokenInput{
		Subject:      sess.Subject,
		Audience:     r.Config().UserAudience,
		Scopes:       outcome.scopes,
		LoA:          sess.LoA,
		LoginMethod:  sess.LoginMethod,
		Name:         sess.Name,
		GivenName:    sess.GivenName,
		FamilyName:   sess.FamilyName,
		SerialNumber: sess.SerialNumber,
		Tenant:       outcome.tenant,
		Thumbprint:   thumbprint,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().UserTokenIssued(ctx, sess.Subject, sess.LoA, sess.LoginMethod, r.Config().UserAudience, outcome.scopes)

	ctx.JSON(&response.Token{
		AccessToken:  tok,
		TokenType:    tokenTypeDPoP,
		ExpiresIn:    exp,
		RefreshToken: refresh,
		Tenants:      outcome.choices,
	})
}

// mayBeActedFor reports whether a subject token may be exchanged for a token
// acting on its subject's behalf: any person, and a service only when the
// token carries the tenant a service account acts for.
func mayBeActedFor(subject *claims.Claims) bool {
	return !subject.IsService() || subject.Tenant != ""
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

	// A user (or an already-delegated token, which still names a user) may be
	// acted for. A service subject may be acted for only when its token names
	// the organisation it acts for — a service account's tenant-named token,
	// which nothing but a verified membership mints. A platform service acting
	// as itself (no tenant) cannot be impersonated: "service acts as itself"
	// stays distinct from "someone acts for a service account".
	if !mayBeActedFor(subject) {
		r.Audit().DelegationRefused(ctx, clientID, subject.Subject, "a platform service acting as itself cannot be acted for")
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
