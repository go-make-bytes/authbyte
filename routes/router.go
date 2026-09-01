// Package routes registers the Identity/Auth HTTP endpoints.
package routes

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	authbytecore "github.com/go-make-bytes/authbyte"

	"azugo.io/azugo"
	"azugo.io/azugo/healthz"
)

type router struct {
	*authbytecore.App
}

// Init registers all routes on the application.
func Init(a *authbytecore.App) error {
	r := &router{App: a}

	// Health + discovery (anonymous). /healthz is liveness; /readyz is a
	// dependency-aware readiness probe (pings Redis + PostgreSQL).
	a.Get("/healthz", healthz.Handler())
	a.Get("/readyz", r.readyz)
	a.Get("/.well-known/jwks.json", r.jwks)
	a.Get("/.well-known/openid-configuration", r.discovery)

	// User login (Authorization Code + PKCE + DPoP).
	a.Get("/authorize", r.authorize)
	a.Get(a.Config().CallbackPath(), r.callback)

	// Logout (front-channel): clears the server session and, for eParaksts-
	// federated logins, bounces the browser through the eParaksts IdP logout so
	// its ~10-minute SSO cookie is cleared (otherwise a shared device logs the
	// next user in as the previous one).
	a.Get("/logout", r.logout)

	// Web eID card login (browser reads the card via web-eid.js; validated by
	// the web-eid engine). Off unless WEBEID_ENGINE_URL is configured.
	if a.Config().WebEIDEnabled() {
		a.Get("/webeid/challenge", r.webeidChallenge)
		a.Post("/webeid/login", r.webeidLogin)
	}

	// Token endpoint (authorization_code | client_credentials | refresh_token).
	a.Post("/token", r.token)

	// Step-up / re-auth (existing session).
	a.Post("/step-up", r.stepUp)

	// Internal identity (valid user token required).
	identityGroup := a.Group("/identity")
	identityGroup.Use(a.AuthClient().Authenticate())
	identityGroup.Get("", r.identity)

	// Development conveniences (guarded by configuration; never on in prod).
	if dir := a.Config().DemoDir; dir != "" {
		r.registerDemo(dir)
	}

	return nil
}

// randomToken returns a URL-safe random identifier of n bytes of entropy.
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}

// requestURL reconstructs the absolute URL of the current request (scheme,
// host, path) for DPoP htu matching.
//
// Behind the edge gateway/WAF, TLS is terminated before the pod, so the
// connection appears as plain HTTP on an internal host. We therefore honour the
// gateway-set X-Forwarded-Proto / X-Forwarded-Host so the reconstructed htu
// matches the public URL the client signed its proof for. The gateway MUST
// strip/overwrite these headers from inbound client traffic (trusted-proxy
// assumption); they are never accepted from arbitrary origins.
func requestURL(ctx *azugo.Context) string {
	scheme := "http"
	if ctx.IsTLS() {
		scheme = "https"
	}
	if p := firstForwardedValue(ctx.Header.Get("X-Forwarded-Proto")); p != "" {
		scheme = p
	}

	host := ctx.Host()
	if h := firstForwardedValue(ctx.Header.Get("X-Forwarded-Host")); h != "" {
		host = h
	}

	return scheme + "://" + host + ctx.Path()
}

// firstForwardedValue returns the first, trimmed value of a possibly
// comma-separated forwarded header (e.g. "https, http").
func firstForwardedValue(v string) string {
	if v == "" {
		return ""
	}

	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}

	return strings.TrimSpace(v)
}
