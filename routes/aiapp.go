package routes

import (
	"crypto/subtle"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/issuer"
	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/routes/response"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/signin"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
	"github.com/valyala/fasthttp"
)

// An AI app is a sign-in client a person connects to one resource, an MCP server,
// as one of their own assistants [MCP 2026-07-28 basic/authorization]. Its
// sign-in is the person's usual one, then a page where they choose the assistant;
// its token is the person's, with the assistant in the actor chain, the boxes
// both hold that the app asked for, its one resource as the audience, the lowest
// assurance, and no proof-of-possession key, since an AI app holds none. Its
// refresh token is good once, and every refresh asks the register again whether
// the person still has that assistant there. A connection is a session of its
// own, never the browser's shared one, so ending it ends nothing else.

// assistantTicketPrefix keeps the assistant page's tickets apart from the
// providers' states in the flow store.
const assistantTicketPrefix = "assistant:"

// Scopes an AI app may send besides its boxes, which ask for no box: an ID token
// (never issued to an app) and a refresh token (always issued to one).
const (
	scopeOfflineAccess = "offline_access"
	tokenTypeBearer    = "Bearer"
)

// readAIAppAsk checks what an AI app's authorization request asks beyond any
// other's: its one resource, named once [RFC 8707 §2], and boxes from its row
// only, all of them when it names none.
func readAIAppAsk(app registry.SignInClient, p authParams) ([]string, *authError) {
	resources := url.Values(p)["resource"]
	if len(resources) != 1 || !registry.SameResource(app.Audience, resources[0]) {
		return nil, &authError{"invalid_target", "resource must name the one resource this app may ask for"}
	}

	asked := []string{}
	for _, s := range registry.ParseScopeString(p.get("scope")) {
		if s == scopeOpenID || s == scopeOfflineAccess {
			continue
		}
		if !slices.Contains(app.Scopes, s) {
			return nil, &authError{"invalid_scope", "scope names a box this app may not ask for"}
		}
		if !slices.Contains(asked, s) {
			asked = append(asked, s)
		}
	}
	if len(asked) == 0 {
		asked = append(asked, app.Scopes...)
	}

	return asked, nil
}

// isAssistantTicket reports whether a state is an assistant page's ticket, which
// no provider's or card's return may spend.
func isAssistantTicket(state string) bool {
	return strings.HasPrefix(state, assistantTicketPrefix)
}

// isAIApp reports whether clientID is an enabled AI app.
func (r *router) isAIApp(clientID string) bool {
	_, ok := r.Registry().AIApp(clientID)

	return ok
}

// askAssistant ends an AI app's completed sign-in with the page where the person
// chooses which of their assistants the app works as, in place of the code. The
// sign-in's flow is kept under the page's own ticket, with the session it made.
func (r *router) askAssistant(ctx *azugo.Context, flow *session.Flow, sid string, sess *session.Session) {
	ticket := randomToken(24)
	choice := *flow
	choice.SessionID = sid
	if err := r.Session().SaveFlow(ctx, assistantTicketPrefix+ticket, &choice, flowTTL); err != nil {
		ctx.Error(err)

		return
	}

	own, err := r.personsAssistants(ctx, sess.Subject)
	if err != nil {
		r.registerUnavailable(ctx, rolebyte.PersonKey(sess.Subject), err)

		return
	}

	app, _ := r.Registry().AIApp(flow.ClientID)
	r.showAssistantPage(ctx, app, ticket, own)
}

// personsAssistants is the person's own assistants from the register; none when
// no register is wired, since an assistant lives only there.
func (r *router) personsAssistants(ctx *azugo.Context, subject string) ([]rolebyte.Assistant, error) {
	resolver := r.ScopeResolver()
	if resolver == nil {
		return nil, nil
	}

	return resolver.Assistants(ctx, rolebyte.PersonKey(subject))
}

// showAssistantPage answers with the sign-in page listing the person's own
// assistants, each by its name and its workspace; one is still asked, so the
// person sees which. None is the refusal in words, and no code.
func (r *router) showAssistantPage(ctx *azugo.Context, app registry.SignInClient, ticket string, own []rolebyte.Assistant) {
	lang := pageLanguage(ctx, "")
	w := signin.For(lang)
	name := appName(app)
	binding := bindBrowser(ctx)

	p := signin.Page{
		Lang:         lang,
		Words:        w,
		Title:        signin.Fill(w.AssistantTitle, map[string]string{"app": name}),
		Operator:     r.operatorLine(w, name),
		OperatorMark: r.operatorMark != nil,
	}
	if len(own) == 0 {
		p.Notice = &signin.Notice{Text: w.NoAssistant}
		r.renderPage(ctx, fasthttp.StatusForbidden, p)

		return
	}

	p.Lead = signin.Fill(w.AssistantLead, map[string]string{"app": name})
	p.Action = "/authorize/assistant?" + url.Values{"ticket": {ticket}}.Encode()
	p.Token = choiceToken(binding)
	for i, a := range own {
		way := signin.Way{Code: assistantWay(a), Name: a.Name + " · " + a.TenantName}
		if i == 0 {
			way.Hint = signin.Fill(w.AssistantHint, map[string]string{"app": name})
		}
		p.Ways = append(p.Ways, way)
	}

	// The choice's answer redirects to the app's own address, which the form must
	// be allowed to send the browser to.
	back := ""
	if len(app.RedirectURIs) > 0 {
		back = webOrigin(app.RedirectURIs[0])
	}
	targets := []string{}
	for _, u := range app.RedirectURIs {
		if o := webOrigin(u); o != "" && o != back {
			targets = append(targets, o)
		}
	}
	r.renderPage(ctx, fasthttp.StatusOK, p, append([]string{back}, targets...)...)
}

// assistantWay is how the page names an assistant in its form: the tenant where
// it is the person's and its key.
func assistantWay(a rolebyte.Assistant) string {
	return a.TenantID + "/" + a.Key
}

// chooseAssistant takes the person's choice of assistant for an AI app: posted
// from this service's own page, in the browser the sign-in was bound to, with the
// page's token, once. The assistant must be one of the person's own as the
// register answers now; the session then names it, and the app gets its code.
//
// @route /authorize/assistant [post].
func (r *router) chooseAssistant(ctx *azugo.Context) {
	if !r.fromOwnPage(ctx) {
		r.Audit().LoginFailure(ctx, "assistant choice sent from another origin")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	binding := browserBinding(ctx)
	form := ctx.Request().PostArgs()
	if binding == "" || subtle.ConstantTimeCompare(form.Peek("csrf"), []byte(choiceToken(binding))) != 1 {
		r.Audit().LoginFailure(ctx, "assistant choice without the page's token")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	ticket := ctx.Query.StringOptional("ticket")
	if ticket == nil || *ticket == "" {
		r.cannotStart(ctx, fasthttp.StatusBadRequest, azugo.ParamRequiredError{Name: "ticket"}, "")

		return
	}
	flow, err := r.Session().ConsumeFlow(ctx, assistantTicketPrefix+*ticket)
	if err != nil || flow.SessionID == "" {
		// Used, expired, or never a page's: the sign-in starts again at the app.
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return
	}
	if !boundHere(ctx, flow.Binding) {
		r.Audit().LoginFailure(ctx, "assistant choice in a browser the sign-in did not start in")
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return
	}
	if !r.isAIApp(flow.ClientID) {
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return
	}

	sess, err := r.Session().LoadSession(ctx, flow.SessionID)
	if err != nil {
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return
	}
	own, err := r.personsAssistants(ctx, sess.Subject)
	if err != nil {
		r.registerUnavailable(ctx, rolebyte.PersonKey(sess.Subject), err)

		return
	}
	way := string(form.Peek("way"))
	i := slices.IndexFunc(own, func(a rolebyte.Assistant) bool { return assistantWay(a) == way })
	if i < 0 {
		r.Audit().LoginFailure(ctx, "assistant choice names no assistant of the person's")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	sess.ClientID = flow.ClientID
	sess.Tenant = own[i].TenantID
	sess.Assistant = own[i].Key
	sess.AppScopes = flow.AppScopes
	if err := r.Session().ReplaceSession(ctx, flow.SessionID, sess); err != nil {
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return
	}

	code := randomToken(24)
	if err := r.Session().SaveAppCode(ctx, code, &session.AppCode{
		SessionID:           flow.SessionID,
		CodeChallenge:       flow.CodeChallenge,
		CodeChallengeMethod: flow.CodeChallengeMethod,
		ClientID:            flow.ClientID,
		RedirectURI:         flow.AppRedirectURI,
		Tenant:              own[i].TenantID,
		Assistant:           own[i].Key,
		AppScopes:           flow.AppScopes,
	}, appCodeTTL); err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(fasthttp.StatusSeeOther)
	ctx.RedirectUnsafe(appendCodeState(flow.AppRedirectURI, r.issuerID(), code, flow.SPAState))
}

// oauthError answers a token request with an error of RFC 6749 §5.2: the code
// alone, no description, kept by no cache.
func oauthError(ctx *azugo.Context, status int, code string) {
	noStore(ctx)
	ctx.StatusCode(status)
	ctx.JSON(map[string]string{"error": code})
}

// grantForApp answers an AI app at the token endpoint: the code exchange or a
// refresh, with no proof-of-possession key, which an AI app holds none of.
func (r *router) grantForApp(ctx *azugo.Context, grant string, app registry.SignInClient) {
	if _, ok := r.authenticateSignIn(ctx, app.ClientID); !ok {
		return
	}
	// Named again at the token endpoint, it must be the app's one resource
	// [RFC 8707 §2.2]; a refresh may leave it out.
	resources := ctx.Request().PostArgs().PeekMulti("resource")
	if len(resources) > 1 || (len(resources) == 1 && !registry.SameResource(app.Audience, string(resources[0]))) ||
		(len(resources) == 0 && grant == "authorization_code") {
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_target")

		return
	}

	if grant == "authorization_code" {
		r.appCodeExchange(ctx, app)

		return
	}
	r.appRefresh(ctx, app)
}

// appCodeExchange exchanges an AI app's code, with its PKCE verifier, for the
// app's first token and its refresh token.
func (r *router) appCodeExchange(ctx *azugo.Context, app registry.SignInClient) {
	form := ctx.Request().PostArgs()
	code, verifier, redirectURI := string(form.Peek("code")), string(form.Peek("code_verifier")), string(form.Peek("redirect_uri"))
	if code == "" || verifier == "" || redirectURI == "" {
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_request")

		return
	}

	appCode, err := r.Session().ConsumeAppCode(ctx, code)
	if err != nil {
		if !errors.Is(err, session.ErrNotFound) {
			storeRefusal(ctx, err)

			return
		}
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")

		return
	}
	if appCode.ClientID != app.ClientID || appCode.RedirectURI != redirectURI || appCode.Assistant == "" ||
		!verifyPKCE(verifier, appCode.CodeChallenge, appCode.CodeChallengeMethod) {
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")

		return
	}

	sess, err := r.Session().LoadSession(ctx, appCode.SessionID)
	if err != nil || sess.Assistant != appCode.Assistant || sess.ClientID != app.ClientID {
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")

		return
	}

	scopes, ok := r.connectionScopes(ctx, app, appCode.SessionID, sess)
	if !ok {
		return
	}

	refresh := randomToken(refreshTokenBytes)
	sess.RefreshKey = refreshKey(refresh)
	if err := r.Session().SaveRefresh(ctx, sess.RefreshKey, &session.RefreshGrant{
		SessionID: appCode.SessionID,
		ClientID:  app.ClientID,
	}, sess.ExpiresAt); err != nil {
		storeRefusal(ctx, err)

		return
	}
	if err := r.Session().ReplaceSession(ctx, appCode.SessionID, sess); err != nil {
		storeRefusal(ctx, err)

		return
	}

	r.answerAppToken(ctx, app, sess, scopes, refresh)
}

// appRefresh renews an AI app's connection: its refresh token is good once, and
// one used again ends the connection [MCP 2026-07-28
// basic/authorization/security-considerations#token-theft]; the person must
// still have the assistant there, or the connection ends too.
func (r *router) appRefresh(ctx *azugo.Context, app registry.SignInClient) {
	token := string(ctx.Request().PostArgs().Peek("refresh_token"))
	if token == "" {
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_request")

		return
	}

	key := refreshKey(token)
	grant, err := r.Session().LoadRefresh(ctx, key)
	if err != nil {
		if !errors.Is(err, session.ErrNotFound) {
			storeRefusal(ctx, err)

			return
		}
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")

		return
	}
	if grant.ClientID != app.ClientID {
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")

		return
	}

	sess, err := r.Session().LoadSession(ctx, grant.SessionID)
	if err != nil {
		if !errors.Is(err, session.ErrNotFound) {
			storeRefusal(ctx, err)

			return
		}
		// The connection has ended; its grant outlived it.
		_ = r.Session().DeleteRefresh(ctx, key)
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")

		return
	}
	if grant.Rotated {
		r.reusedRefresh(ctx, grant.SessionID, sess, key)

		return
	}

	// The register first: one that cannot answer leaves the token as it was.
	scopes, ok := r.connectionScopes(ctx, app, grant.SessionID, sess, key)
	if !ok {
		return
	}

	// Then the token is claimed in one step: of two refreshes with it at once,
	// one gets it and the other hears invalid_grant (or, if the first has already
	// marked it used, ends the connection), so a token raced by its thief never
	// forks the connection into two live chains.
	claimed, err := r.Session().TakeRefresh(ctx, key)
	if err != nil {
		if !errors.Is(err, session.ErrNotFound) {
			storeRefusal(ctx, err)

			return
		}
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")

		return
	}
	if claimed.Rotated || claimed.SessionID != grant.SessionID {
		r.reusedRefresh(ctx, grant.SessionID, sess, key)

		return
	}

	next := randomToken(refreshTokenBytes)
	nextKey := refreshKey(next)
	if err := r.Session().SaveRefresh(ctx, nextKey, &session.RefreshGrant{
		SessionID: grant.SessionID,
		ClientID:  app.ClientID,
	}, sess.ExpiresAt); err != nil {
		storeRefusal(ctx, err)

		return
	}
	if err := r.Session().SaveRefresh(ctx, key, &session.RefreshGrant{
		SessionID: grant.SessionID,
		ClientID:  app.ClientID,
		Rotated:   true,
	}, sess.ExpiresAt); err != nil {
		storeRefusal(ctx, err)

		return
	}
	sess.RefreshKey = nextKey
	if err := r.Session().ReplaceSession(ctx, grant.SessionID, sess); err != nil {
		if errors.Is(err, session.ErrNotFound) {
			oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")

			return
		}
		storeRefusal(ctx, err)

		return
	}

	r.answerAppToken(ctx, app, sess, scopes, next)
}

// reusedRefresh answers a refresh token presented after it was used: the
// connection ends, and the app hears invalid_grant.
func (r *router) reusedRefresh(ctx *azugo.Context, sid string, sess *session.Session, key string) {
	r.Audit().LoginFailure(ctx, "an AI app's refresh token used a second time; the connection is ended")
	if r.endConnection(ctx, sid, sess, key) {
		oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")
	}
}

// connectionScopes asks the register whether the person still has the
// connection's assistant in its tenant, and answers the boxes the app asked for
// that both hold there now. An assistant gone, given to another person, or a
// person gone from the tenant ends the connection, and the app hears
// invalid_grant; a register that cannot answer refuses the issue and ends
// nothing. ok is false when the answer is already written.
func (r *router) connectionScopes(ctx *azugo.Context, app registry.SignInClient, sid string, sess *session.Session, keys ...string) ([]string, bool) {
	own, err := r.personsAssistants(ctx, sess.Subject)
	if err != nil {
		r.registerUnavailable(ctx, rolebyte.PersonKey(sess.Subject), err)

		return nil, false
	}
	i := slices.IndexFunc(own, func(a rolebyte.Assistant) bool {
		return a.TenantID == sess.Tenant && a.Key == sess.Assistant
	})
	if i < 0 || sess.Assistant == "" {
		if r.endConnection(ctx, sid, sess, keys...) {
			oauthError(ctx, fasthttp.StatusBadRequest, "invalid_grant")
		}

		return nil, false
	}

	// What the app asked for, as its row allows it now, that both hold now.
	return intersectScopes(intersectScopes(sess.AppScopes, app.Scopes), own[i].Scopes), true
}

// endConnection ends an AI app's connection: its session and every refresh grant
// named, and nothing else. ok is false when the store could not delete them,
// and the answer, 503, is then written: the app tries again, and the connection
// is ended then, rather than said ended while it goes on.
func (r *router) endConnection(ctx *azugo.Context, sid string, sess *session.Session, keys ...string) bool {
	if err := r.Session().DeleteSession(ctx, sid); err != nil && !errors.Is(err, session.ErrNotFound) {
		storeRefusal(ctx, err)

		return false
	}
	for _, k := range append([]string{sess.RefreshKey}, keys...) {
		if k == "" {
			continue
		}
		if err := r.Session().DeleteRefresh(ctx, k); err != nil && !errors.Is(err, session.ErrNotFound) {
			storeRefusal(ctx, err)

			return false
		}
	}
	r.Audit().SessionEnded(ctx, sess.Subject, identity.LoginAssistant)

	return true
}

// answerAppToken mints and answers an AI app's token: the person's, through the
// assistant, for the app's one resource, with the lowest assurance.
func (r *router) answerAppToken(ctx *azugo.Context, app registry.SignInClient, sess *session.Session, scopes []string, refresh string) {
	tok, exp, err := r.Issuer().IssueApp(issuer.AppTokenInput{
		Subject:     sess.Subject,
		Audience:    app.Audience,
		ClientID:    app.ClientID,
		Scopes:      scopes,
		Tenant:      sess.Tenant,
		Assistant:   sess.Assistant,
		LoA:         identity.LoALow,
		LoginMethod: identity.LoginAssistant,
		TTL:         r.Config().AppTokenTTL,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Audit().UserTokenIssued(ctx, sess.Subject, identity.LoALow, identity.LoginAssistant, app.Audience, scopes)

	ctx.JSON(&response.Token{
		AccessToken:  tok,
		TokenType:    tokenTypeBearer,
		ExpiresIn:    exp,
		RefreshToken: refresh,
		Scope:        strings.Join(scopes, " "),
	})
}

// revokeApp ends an AI app's connection at its own request [RFC 7009]: the app
// presents a refresh token of the connection and its client id, and no key, which
// it holds none of. Only that connection ends.
func (r *router) revokeApp(ctx *azugo.Context, app registry.SignInClient, token string) {
	key := refreshKey(token)
	grant, err := r.Session().LoadRefresh(ctx, key)
	if errors.Is(err, session.ErrNotFound) {
		ctx.StatusCode(fasthttp.StatusOK)

		return
	}
	if err != nil {
		storeRefusal(ctx, err)

		return
	}
	if grant.ClientID != app.ClientID {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	sess, err := r.Session().LoadSession(ctx, grant.SessionID)
	if err != nil {
		_ = r.Session().DeleteRefresh(ctx, key)
		ctx.StatusCode(fasthttp.StatusOK)

		return
	}
	if r.endConnection(ctx, grant.SessionID, sess, key) {
		ctx.StatusCode(fasthttp.StatusOK)
	}
}

// narrowToSubject keeps, of an exchange's scopes, only those the subject token
// carries. A token made for an AI app's person through an assistant carries what
// both may do, and boxes alone; a token exchanged from it carries nothing beyond
// that, a level included, whatever the exchanging client's grant allows, at every
// hop, so a service along the chain never sees a scope the assistant was not
// given.
func narrowToSubject(scopes []string, subjectScope string) []string {
	held := registry.ParseScopeString(subjectScope)
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if slices.Contains(held, s) {
			out = append(out, s)
		}
	}

	return out
}
