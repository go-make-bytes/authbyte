package routes

import (
	"strings"

	"github.com/go-make-bytes/authbyte/identity"

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
		// The ID token, answered to a sign-in that asks openid ([OIDC Discovery §3]).
		// It is signed with the one key type the key manager holds: ES256 alone,
		// where the standard asks RS256 be supported too. Every client is first-party
		// and checks ES256.
		"scopes_supported":                      []string{scopeOpenID},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{r.Keys().Alg()},
		"claims_supported":                      claimsSupported,
		"acr_values_supported":                  r.offeredMethods(),
		// Every answer to the browser names this issuer ([RFC 9207 §2.3]); request
		// objects are not taken, which must be said, since unsaid means yes.
		"authorization_response_iss_parameter_supported": true,
		"request_uri_parameter_supported":                false,
	})
}

// claimsSupported are the claims this server may state about a person: in the ID
// token, and in the access token or at /identity as a client's row lists them.
var claimsSupported = []string{
	"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid",
	"name", "given_name", "family_name", "serial_number",
}

// offeredMethods are the sign-in methods this deployment offers, the names
// acr_values may use: its provider's, and the card's when it has a card door.
func (r *router) offeredMethods() []string {
	methods := r.Upstream().Methods()
	if r.Config().WebEIDEnabled() {
		methods = append(methods, identity.LoginWebEID)
	}

	return methods
}

// clientAuthMethods are the ways a client proves itself at the token and
// revocation endpoints.
var clientAuthMethods = []string{"client_secret_basic", "client_secret_post", "none"}
