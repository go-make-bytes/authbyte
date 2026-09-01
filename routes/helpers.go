package routes

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
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

// verifyPKCE validates a PKCE code_verifier against the stored challenge.
func verifyPKCE(verifier, challenge, method string) bool {
	switch method {
	case "", "S256":
		sum := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])

		return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
	case "plain":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	default:
		return false
	}
}
