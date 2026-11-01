package routes

import (
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/go-make-bytes/authbyte/registry"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
)

// clientSecret reads the secret clientID presented at the token or revocation
// endpoint: by HTTP Basic, each part form-decoded first [RFC 6749 §2.3.1], or as
// the form's client_secret. A request that uses both is refused, one method per
// request [RFC 6749 §2.3], and so is Basic naming another client than clientID.
// presented says whether any secret came, so an empty one still counts as sent.
// The secret is compared in the request and never kept. ok is false when the
// refusal is already written.
func clientSecret(ctx *azugo.Context, clientID string) (secret string, presented, ok bool) {
	basicID, basicSecret, hasBasic, valid := basicCredentials(ctx.Header.Get("Authorization"))
	if !valid || (hasBasic && basicID != clientID) {
		ctx.Error(corehttp.UnauthorizedError{})

		return "", false, false
	}

	form := ctx.Form.StringOptional("client_secret")
	if hasBasic && form != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "client_secret", Tag: "one-method"})

		return "", false, false
	}

	switch {
	case hasBasic:
		return basicSecret, true, true
	case form != nil:
		return *form, true, true
	default:
		return "", false, true
	}
}

// basicCredentials decodes an Authorization header carrying HTTP Basic client
// credentials. Another scheme, or none, is not client credentials (has is
// false); a Basic header that does not decode is invalid.
func basicCredentials(header string) (id, secret string, has, valid bool) {
	scheme, value, _ := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, "Basic") {
		return "", "", false, true
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", "", true, false
	}
	encID, encSecret, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", true, false
	}
	if id, err = url.QueryUnescape(encID); err != nil {
		return "", "", true, false
	}
	if secret, err = url.QueryUnescape(encSecret); err != nil {
		return "", "", true, false
	}

	return id, secret, true, true
}

// authenticateSignIn checks that the sign-in client clientID proved itself as its
// type requires: a confidential client with its secret, a public client with
// none, and answers its registration. ok is false when the refusal is already
// written.
func (r *router) authenticateSignIn(ctx *azugo.Context, clientID string) (registry.SignInClient, bool) {
	secret, presented, ok := clientSecret(ctx, clientID)
	if !ok {
		return registry.SignInClient{}, false
	}
	client, err := r.Registry().AuthenticateSignIn(clientID, secret, presented)
	if err != nil {
		ctx.Error(corehttp.UnauthorizedError{})

		return registry.SignInClient{}, false
	}

	return client, true
}
