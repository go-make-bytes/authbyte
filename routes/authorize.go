package routes

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/store"
	"github.com/go-make-bytes/authbyte/upstream"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
	"github.com/valyala/fasthttp"
)

// TTLs for transient auth-flow artifacts.
const (
	flowTTL    = 10 * time.Minute
	appCodeTTL = 60 * time.Second
)

// authorizeRequest is an authorization request that passed every check.
type authorizeRequest struct {
	// params is the request as it came, to repeat on the page's own addresses.
	params      authParams
	redirectURI string
	clientID    string
	spaState    string
	challenge   string
	method      string
	idAsk       idTokenAsk
	signAsk     signInAsk
	// named are the methods acr_values asked for, in authbyte's own names. None
	// means the person picks on this service's page.
	named  []string
	tenant string
	client registry.SignInClient
}

// authorize begins a sign-in. A request that names a way (acr_values) is sent
// straight to the provider; one that names none is shown this service's own
// page, which lists the ways the client may use.
//
// @route /authorize [get].
// @route /authorize [post].
func (r *router) authorize(ctx *azugo.Context) {
	req, ok := r.readAuthorize(ctx, requestParams(ctx))
	if !ok {
		return
	}

	// A form post from another site arrives without the Lax binding the browser
	// may hold. A new one here would replace it and fail that browser's sign-ins
	// under way in other tabs, so the post sets none: the browser asks again by
	// GET, which carries the binding it holds.
	if ctx.Method() == fasthttp.MethodPost && browserBinding(ctx) == "" {
		ctx.StatusCode(fasthttp.StatusSeeOther)
		ctx.Redirect("/authorize?" + req.params.encode())

		return
	}

	// A person already signed in in this browser, whom the request fits, is
	// answered with no page [OIDC Core §3.1.2.3].
	if r.answerFromShared(ctx, req) {
		return
	}
	if req.signAsk.none {
		r.refuseAtClient(ctx, req, "login_required", "the person must sign in")

		return
	}

	binding := bindBrowser(ctx)
	if _, page := r.pageWays(req, r.offered(req.client)); page {
		r.showPage(ctx, req, binding, takeNotice(ctx))

		return
	}
	r.startProvider(ctx, req, req.named, binding, req.signAsk.uiLocales, false)
}

// refuseAtClient answers req at the client's own, validated address with code,
// as [OIDC Core §3.1.2.6] codes are answered.
func (r *router) refuseAtClient(ctx *azugo.Context, req *authorizeRequest, code, description string) {
	ctx.RedirectUnsafe(appendErrorState(req.redirectURI, r.issuerID(), code, description, req.spaState))
}

// readAuthorize checks an authorization request. What names no client or
// return address this service knows gets the cannot-start page; anything else
// that fails is answered at the client's own, validated address before anything
// is stored. ok is false when the answer is written.
func (r *router) readAuthorize(ctx *azugo.Context, p authParams) (*authorizeRequest, bool) {
	next := ""
	if ctx.Method() == fasthttp.MethodGet && strings.HasPrefix(ctx.Path(), "/authorize") {
		next = "/authorize?" + p.encode()
	}

	if rt := p.opt("response_type"); rt == nil || *rt != "code" {
		r.cannotStart(ctx, fasthttp.StatusBadRequest, azugo.ParamInvalidError{Name: "response_type", Tag: "oneof=code"}, next)

		return nil, false
	}

	redirectURI := p.get("redirect_uri")
	if redirectURI == "" {
		r.cannotStart(ctx, fasthttp.StatusBadRequest, azugo.ParamRequiredError{Name: "redirect_uri"}, next)

		return nil, false
	}

	clientID := p.get("client_id")
	if clientID == "" {
		r.cannotStart(ctx, fasthttp.StatusBadRequest, azugo.ParamRequiredError{Name: "client_id"}, next)

		return nil, false
	}

	// Validate the redirect_uri against the registered allowlist BEFORE saving
	// any state or redirecting — prevents open-redirect attacks ([RFC 6749 §10.6]).
	if err := r.Registry().ValidateRedirectURI(clientID, redirectURI); err != nil {
		r.cannotStart(ctx, fasthttp.StatusBadRequest, azugo.ParamInvalidError{Name: "redirect_uri", Tag: "registered"}, next)

		return nil, false
	}

	req := &authorizeRequest{
		params:      p,
		redirectURI: redirectURI,
		clientID:    clientID,
		spaState:    p.get("state"),
		// The organisation the person asks to act under, when they belong to
		// more than one. Optional; it is checked against their memberships at the
		// token issue, never trusted on its own.
		tenant: p.get("tenant"),
	}
	refuse := func(code, description string) (*authorizeRequest, bool) {
		ctx.RedirectUnsafe(appendErrorState(redirectURI, r.issuerID(), code, description, req.spaState))

		return nil, false
	}

	// PKCE is S256 only. A missing challenge or any other method is answered at
	// the client's own (now validated) address, before any flow is stored
	// ([RFC 7636 §4.4.1]).
	var ok bool
	if req.challenge, req.method, ok = s256Challenge(p); !ok {
		return refuse("invalid_request", "code_challenge with code_challenge_method S256 required")
	}

	// What the request asks of an ID token and of the sign-in. What can never be
	// met here is answered at the client's own address before anything is stored.
	var aerr *authError
	if req.idAsk, aerr = readIDTokenAsk(p); aerr == nil {
		req.signAsk, aerr = readSignInAsk(p)
	}
	if aerr != nil {
		return refuse(aerr.code, aerr.description)
	}

	// The methods the client asks for (acr_values, in authbyte's own method
	// names) must be ones this provider offers and the client is allowed. A
	// request that can never be met is answered at the client's own address.
	req.client, _ = r.Registry().SignInClient(clientID)
	offered := r.offered(req.client)
	if req.named, ok = requestedMethods(func(m string) bool { return slices.Contains(offered, m) }, p.get("acr_values")); !ok {
		return refuse("unmet_authentication_requirements", "acr_values names no login method this client may use here")
	}

	return req, true
}

// newFlow is a sign-in's flow for req, ending with one of methods and tied to
// the browser holding binding. One started from the page keeps the client's
// request, so a cancel or a refusal brings the person back to it.
func newFlow(req *authorizeRequest, methods []string, binding string, fromPage bool) *session.Flow {
	flow := &session.Flow{
		CodeChallenge:       req.challenge,
		CodeChallengeMethod: req.method,
		AppRedirectURI:      req.redirectURI,
		SPAState:            req.spaState,
		ClientID:            req.clientID,
		Tenant:              req.tenant,
		RequestedMethods:    methods,
		OpenID:              req.idAsk.openID,
		ClientNonce:         req.idAsk.nonce,
		ForcedLogin:         req.signAsk.forcedLogin,
		MaxAge:              req.signAsk.maxAge,
		Started:             time.Now().Unix(),
		Binding:             bindingHash(binding),
		Picker:              fromPage,
	}
	if fromPage {
		flow.Request = req.params.encode()
	}

	return flow
}

// startProvider stores the flow, bound to this browser, and sends the browser to
// the provider of methods asking for them in the provider's own words. The flow
// records the provider, whose own return path alone completes it.
func (r *router) startProvider(ctx *azugo.Context, req *authorizeRequest, methods []string, binding, uiLocales string, fromPage bool) {
	entry := r.providerOf(methods)
	if entry == nil {
		ctx.Error(corehttp.NotFoundError{Resource: "upstream provider"})

		return
	}
	entrustRedirect := strings.TrimSuffix(r.Config().BaseURL, "/") + entry.ReturnPath

	state := randomToken(24)
	flow := newFlow(req, methods, binding, fromPage)
	flow.EntrustRedirectURI = entrustRedirect
	flow.Upstream = entry.Name
	// The nonce binds the id_token the provider issues to this flow: it travels
	// out with the authorize request and must come back inside the token.
	flow.Nonce = randomToken(24)

	if err := r.Session().SaveFlow(ctx, state, flow, flowTTL); err != nil {
		ctx.Error(err)

		return
	}

	// The provider is asked in its own words: its own code for each method, and
	// a fresh sign-in when the client asked for one. Its nonce is authbyte's,
	// never the client's.
	params := upstream.AuthorizeParams{
		State:       state,
		RedirectURI: entrustRedirect,
		Nonce:       flow.Nonce,
		ACRValues:   upstreamACR(entry.ACRFor, methods),
		Prompt:      req.signAsk.upstreamPrompt(),
		MaxAge:      req.signAsk.maxAge,
		UILocales:   uiLocales,
	}

	// The page's choice is a form post, answered by sending the browser on.
	if fromPage {
		ctx.StatusCode(fasthttp.StatusSeeOther)
	}
	// External IdP authorize endpoint — use the unsanitized redirect so the
	// cross-origin target is preserved (a same-origin-only redirect would drop it).
	ctx.RedirectUnsafe(entry.Provider.AuthorizeURL(params))
}

// providerOf is the one provider that offers every one of methods, or nil when
// they are none or belong to more than one.
func (r *router) providerOf(methods []string) *upstream.Entry {
	var entry *upstream.Entry
	for _, m := range methods {
		e := r.Upstreams().ByMethod(m)
		if e == nil || (entry != nil && e != entry) {
			return nil
		}
		entry = e
	}

	return entry
}

// callbackFor handles entry's answers on its own return path.
//
// @route /callback [get].
func (r *router) callbackFor(entry *upstream.Entry) azugo.RequestHandler {
	return func(ctx *azugo.Context) { r.callback(ctx, entry) }
}

// callback handles a provider's redirect: it exchanges the code, maps the user,
// establishes a session, and returns an application authorization code to the
// SPA's redirect URI. Nothing reaches the provider unless the answer came back
// to the browser that started the sign-in, on the return path of the provider
// the sign-in was sent to.
func (r *router) callback(ctx *azugo.Context, entry *upstream.Entry) {
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
				if !r.returnedHere(ctx, flow) || !r.answeredBy(ctx, flow, entry) {
					return
				}
				// A sign-in begun on this service's page goes back to the page,
				// which says what happened; the client is not told.
				if flow.Picker {
					notice := noticeProvider
					if *idpErr == "access_denied" {
						notice = noticeCancelled
					}
					setCookie(ctx, noticeCookie, notice, noticeLifetime)
					ctx.Redirect("/authorize?" + flow.Request)

					return
				}
				// Client app redirect URI (cross-origin) — bypass same-origin sanitizing.
				ctx.RedirectUnsafe(appendErrorState(flow.AppRedirectURI, r.issuerID(), *idpErr, desc, flow.SPAState))

				return
			}
		}
		// Unknown/expired state — cannot safely bounce to a client; fail closed.
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

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
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return
	}
	// Checked before the provider's code is exchanged: a return that reached
	// another browser, or another provider's return path, sends nothing to any
	// provider.
	if !r.returnedHere(ctx, flow) || !r.answeredBy(ctx, flow, entry) {
		return
	}
	provider := entry.Provider

	// Exchange the code with the provider and read the person's claims: the
	// verified id_token where the provider publishes a key set, userinfo always.
	tokens, err := provider.Exchange(ctx, code, flow.EntrustRedirectURI)
	if err != nil {
		ctx.Error(err)

		return
	}

	info, err := provider.Claims(ctx, tokens, flow.Nonce)
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

	id := entry.Resolver().Resolve(info)

	// Enforce the provider's allowed-method set (fail closed) even if the IdP's
	// hosted page offered something else, so removing the request-side
	// acr/button is not the only protection. For the eParaksts profile this is
	// what rejects the legacy plugin eID card (sc_plugin → "eid" — eID cards
	// log in through Web eID); for a generic provider it pins the callback to
	// the methods its configuration declares.
	if !provider.MethodAllowed(id.LoginMethod) {
		r.Audit().LoginFailure(ctx, "login method not permitted via the upstream IdP: "+id.LoginMethod)
		ctx.Error(corehttp.ForbiddenError{})

		return
	}

	// When the person authenticated, held against the client's max_age before
	// anything is written: a provider answering from a session older than the
	// client allows refuses the sign-in at the client's address.
	authTime, err := signInMoment(info, flow, time.Now())
	if err != nil {
		r.Audit().LoginFailure(ctx, "authentication older than the client allows")
		ctx.RedirectUnsafe(appendErrorState(flow.AppRedirectURI, r.issuerID(), "unmet_authentication_requirements", "the sign-in is older than the request allows", flow.SPAState))

		return
	}

	sess, sid, err := r.establishSession(ctx, flow, id, entry.CredentialProvider())
	if err != nil {
		if errors.Is(err, errMethodNotRequested) {
			// The provider answered with a method the client did not ask for: no
			// session, and the client hears it at its own address.
			r.Audit().LoginFailure(ctx, "login method not requested: "+id.LoginMethod)
			ctx.RedirectUnsafe(appendErrorState(flow.AppRedirectURI, r.issuerID(), "unmet_authentication_requirements", "the sign-in used a login method the request did not ask for", flow.SPAState))
		} else {
			r.Audit().LoginFailure(ctx, "session establishment failed")
			ctx.Error(err)
		}

		return
	}

	// This login's identification also read the person's sign-identity
	// catalog (when the profile scope is on) — derive the session's signing
	// capabilities from it while the upstream token is still at hand.
	client, _ := r.Registry().SignInClient(flow.ClientID)
	sess.Capabilities = r.captureCapabilities(ctx, client, provider, tokens.AccessToken, info, id.LoginMethod)
	// What the sign-in's ID tokens will state: the moment, and the means the
	// provider named that are registered ones; nothing authbyte did not see.
	stampSignIn(sess, authTime, registeredAMR(info.AMR))

	if !r.saveSignedIn(ctx, flow.ClientID, sid, sess) {
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
		OpenID:              flow.OpenID,
		Nonce:               flow.ClientNonce,
	}, appCodeTTL); err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().LoginSuccess(ctx, sess.Subject, sess.LoA, sess.LoginMethod)

	// Client app redirect URI (cross-origin) — bypass same-origin sanitizing.
	ctx.RedirectUnsafe(appendCodeState(flow.AppRedirectURI, r.issuerID(), appCode, flow.SPAState))
}

// establishSession resolves the person a sign-in proved and makes their new
// session. provider names where the sign-in's handle came from ("" for the
// deployment's first provider, identity.ProviderWebEID for the card).
func (r *router) establishSession(ctx *azugo.Context, flow *session.Flow, id identity.Identity, provider string) (*session.Session, string, error) {
	// A sign-in completes only with a method the request asked for. Checked before
	// the identity store is touched, so a refused sign-in writes nothing.
	if !methodRequested(flow.RequestedMethods, id.LoginMethod) {
		return nil, "", errMethodNotRequested
	}

	// Normal login: resolve the stable internal subject (the PERSON, keyed on the
	// national id / SerialNumber) and link this method's credential.
	internal, created, err := r.Identities().EnsureMapping(ctx, id.IdPSubject, store.Profile{
		Name:         id.Name,
		GivenName:    id.GivenName,
		FamilyName:   id.FamilyName,
		SerialNumber: id.SerialNumber,
		LoginMethod:  id.LoginMethod,
		Email:        id.Email,
		Provider:     provider,
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
		// The directory the login came through, for the register's admission
		// door at token issue ("" for a card login).
		DirectoryIssuer: id.Issuer,
		DirectoryGuest:  id.DirectoryGuest,
	}, randomToken(24), nil
}

// saveSignedIn makes a completed sign-in the browser's shared session and stores
// its new app session for client, given its whole lifetime from now. ok is false
// when the answer is already written.
func (r *router) saveSignedIn(ctx *azugo.Context, client, sid string, sess *session.Session) bool {
	shared, until, err := r.joinShared(ctx, sess)
	if err != nil {
		ctx.Error(err)

		return false
	}
	sess.Shared = shared

	if err := r.Session().CreateSession(ctx, sid, sess, r.Config().SessionTTL); err != nil {
		ctx.Error(err)

		return false
	}
	r.addSharedApp(ctx, shared, until, client, sid)

	return true
}

// answeredBy reports whether a provider's answer came from the provider the
// sign-in was sent to, and answers the refusal when it did not: it arrived on
// another provider's return path, or names another issuer than that provider's
// [RFC 9700 §4.4.2; RFC 9207 §2.4]. A flow stored before providers were named
// was sent to the only one there was.
func (r *router) answeredBy(ctx *azugo.Context, flow *session.Flow, entry *upstream.Entry) bool {
	sent := flow.Upstream == entry.Name || (flow.Upstream == "" && len(r.Upstreams().Entries()) == 1)
	if !sent {
		r.Audit().LoginFailure(ctx, "the provider's answer arrived on another provider's return path")
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return false
	}
	if iss := ctx.Query.StringOptional("iss"); iss != nil && entry.Provider.Issuer() != "" && *iss != entry.Provider.Issuer() {
		r.Audit().LoginFailure(ctx, "the provider's answer names another issuer")
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return false
	}

	return true
}

// returnedHere reports whether the provider's answer reached the browser that
// started the sign-in, and answers the refusal when it did not. Every sign-in is
// bound to a browser, so a flow bound to none (a step-up saved before the
// step-up was removed) completes nowhere.
func (r *router) returnedHere(ctx *azugo.Context, flow *session.Flow) bool {
	if boundHere(ctx, flow.Binding) {
		return true
	}
	r.Audit().LoginFailure(ctx, "the provider's answer reached a browser that did not start the sign-in")
	r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

	return false
}
