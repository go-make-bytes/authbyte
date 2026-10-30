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
		// none: a browser client proves PKCE instead of a secret.
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"code_challenge_methods_supported":      []string{pkceS256},
		"dpop_signing_alg_values_supported":     []string{"ES256"},
		// A client ends its session here, server to server, proving itself by the
		// session's DPoP key and never by a secret.
		"revocation_endpoint":                        base + "/revoke",
		"revocation_endpoint_auth_methods_supported": []string{"none"},
		// No ID token is issued, so nothing about one is advertised.
	})
}
