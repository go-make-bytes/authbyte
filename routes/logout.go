package routes

import (
	"azugo.io/azugo"
)

// logout terminates the user session and, for eParaksts-federated logins, sends
// the browser on to the eParaksts IdP logout endpoint so its SSO cookie is
// cleared. Without this, the next user on a shared device is silently logged in
// as the previous one — the eParaksts IdP keeps a ~10-minute SSO session, so a
// fresh /authorize is answered from that session instead of prompting for a new
// login.
//
// It is a FRONT-CHANNEL endpoint: the browser MUST navigate here (a top-level
// redirect). A server-to-server call cannot clear a cookie that lives in the
// user's browser on the eParaksts domain.
//
// Query:
//
//	client_id (required) — the client, used to scope the redirect_uri allowlist.
//	redirect_uri (required) — where to land after logout; validated against the
//	 client's registered redirect allowlist (open-redirect guard).
//	sid (optional) — the server session id (the SPA's refresh_token). When
//	 present the session is deleted and the login method is read from it.
//	login_method (optional) — federation hint used when sid is absent/expired.
//
// @route /logout [get].
func (r *router) logout(ctx *azugo.Context) {
	clientID, err := ctx.Query.String("client_id")
	if err != nil {
		ctx.Error(err)

		return
	}

	redirectURI, err := ctx.Query.String("redirect_uri")
	if err != nil {
		ctx.Error(err)

		return
	}

	// Validate the post-logout redirect_uri against the registered allowlist
	// BEFORE redirecting — it is reflected in both our 302 and the IdP's
	// redirect_uri bounce, so an unvalidated value is an open redirect
	// ([RFC 6749 §10.6]).
	if err := r.Registry().ValidateRedirectURI(clientID, redirectURI); err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "redirect_uri", Tag: "registered"})

		return
	}

	// Resolve the login method + actor from the session (best-effort) and delete
	// the session so the refresh handle is dead immediately. The session id is
	// the value the SPA received as `refresh_token` at /token.
	method := ""
	actor := ""
	if sid := ctx.Query.StringOptional("sid"); sid != nil && *sid != "" {
		if sess, e := r.Session().LoadSession(ctx, *sid); e == nil {
			method = sess.LoginMethod
			actor = sess.Subject
		}
		_ = r.Session().DeleteSession(ctx, *sid)
	}
	// An explicit hint lets the SPA drive federation when it did not keep the sid.
	if m := ctx.Query.StringOptional("login_method"); m != nil && *m != "" {
		method = *m
	}

	federated := r.Upstream().FederatedMethod(method)
	r.Audit().Logout(ctx, actor, method, federated)

	if idpLogout := r.Upstream().LogoutURL(redirectURI); federated && idpLogout != "" {
		// Front-channel: navigate to the upstream IdP's logout, which clears its
		// SSO cookie and then redirects the browser back to redirectURI. A
		// provider with no logout endpoint falls through to the local redirect.
		// External IdP target (cross-origin) — bypass same-origin sanitizing.
		ctx.RedirectUnsafe(idpLogout)

		return
	}

	// Non-federated (e.g. Web eID card login) — no IdP cookie to clear.
	// Post-logout target may be cross-origin — bypass same-origin sanitizing.
	ctx.RedirectUnsafe(redirectURI)
}
