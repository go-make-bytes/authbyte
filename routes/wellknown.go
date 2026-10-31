package routes

import (
	"strings"

	"azugo.io/azugo"
)

// jwks publishes the signing public keys.
//
// @route /.well-known/jwks.json [get].
func (r *router) jwks(ctx *azugo.Context) {
	doc, err := r.Keys().JWKS()
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.ContentType("application/json")
	ctx.Raw(doc)
}

// discovery serves minimal OIDC discovery metadata for this issuer.
//
// @route /.well-known/openid-configuration [get].
func (r *router) discovery(ctx *azugo.Context) {
	base := strings.TrimSuffix(r.Config().IssuerURL, "/")

	ctx.JSON(map[string]any{
		"issuer":                   base,
		"authorization_endpoint":   base + "/authorize",
		"token_endpoint":           base + "/token",
		"jwks_uri":                 base + "/.well-known/jwks.json",
		"userinfo_endpoint":        base + "/identity",
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "client_credentials", "refresh_token", grantTokenExchange},
		// A confidential client proves itself with its secret, by HTTP Basic or in the
		// form; a public client (none) proves PKCE instead.
		"token_endpoint_auth_methods_supported": clientAuthMethods,
		"code_challenge_methods_supported":      []string{pkceS256},
		"dpop_signing_alg_values_supported":     []string{"ES256"},
		// A client ends its session here, server to server, proving itself as at the
		// token endpoint and holding the session's DPoP key.
		"revocation_endpoint":                        base + "/revoke",
		"revocation_endpoint_auth_methods_supported": clientAuthMethods,
		// No ID token is issued, so nothing about one is advertised.
	})
}

// clientAuthMethods are the ways a client proves itself at the token and
// revocation endpoints.
var clientAuthMethods = []string{"client_secret_basic", "client_secret_post", "none"}
