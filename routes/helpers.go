package routes

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"

	"azugo.io/azugo"
)

// appendCodeState appends the application authorization code and state to a
// redirect URI.
func appendCodeState(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// appendErrorState appends an authorization error (and optional description) plus
// the state to a redirect URI, so a cancelled or denied login is reported back to
// the client that began it instead of failing as a raw missing-code error.
func appendErrorState(redirectURI, errCode, errDescription, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}

	q := u.Query()
	q.Set("error", errCode)
	if errDescription != "" {
		q.Set("error_description", errDescription)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// pkceS256 is the one PKCE method accepted: the plain form puts the verifier
// itself in the authorization request ([RFC 9700 §2.1.1]).
const pkceS256 = "S256"

// s256Challenge reads the request's PKCE challenge. ok is false when the
// challenge is missing or the method is anything but S256, an absent method
// included: absent means plain ([RFC 7636 §4.3]).
func s256Challenge(ctx *azugo.Context) (challenge, method string, ok bool) {
	c := ctx.Query.StringOptional("code_challenge")
	m := ctx.Query.StringOptional("code_challenge_method")
	if c == nil || *c == "" || m == nil || *m != pkceS256 {
		return "", "", false
	}

	return *c, pkceS256, true
}

// verifyPKCE validates a PKCE code_verifier against the stored S256 challenge.
// Any other method never verifies.
func verifyPKCE(verifier, challenge, method string) bool {
	if method != pkceS256 {
		return false
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
