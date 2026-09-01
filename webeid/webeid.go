// Package webeid is the adapter to the Web eID engine's STATELESS
// authentication-token validation. The Auth service owns the challenge nonce
// (issued at /webeid/challenge) and calls the engine's POST /auth/validate
// server-to-server with a DPoP-bound service token, receiving the validated
// eID subject which is then mapped to an internal identity.
//
// The auth token itself is opaque here — it is produced by web-eid.js on the
// SPA (the browser extension + native app read the card) and forwarded verbatim.
package webeid

import (
	"encoding/json"
	"fmt"
	"strings"

	"azugo.io/azugo"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// Subject is the validated eID identity returned by the engine's stateless
// /auth/validate (mirrors go-web-eid's SubjectResponse).
type Subject struct {
	CommonName  string `json:"commonName"`
	IDCode      string `json:"idCode"`
	CountryCode string `json:"countryCode"`
	GivenName   string `json:"givenName"`
	Surname     string `json:"surname"`
}

// Adapter calls the Web eID engine's stateless validate endpoint.
type Adapter struct {
	auth        *authclient.Client
	validateURL string
	audience    string
	scope       string
}

// New builds an Adapter targeting engineBaseURL's /auth/validate, authenticating
// with a service token for audience/scope minted via ac.
func New(ac *authclient.Client, engineBaseURL, audience, scope string) *Adapter {
	return &Adapter{
		auth:        ac,
		validateURL: strings.TrimSuffix(engineBaseURL, "/") + "/auth/validate",
		audience:    audience,
		scope:       scope,
	}
}

// validateRequest is the engine's ValidateRequest body.
type validateRequest struct {
	AuthToken json.RawMessage `json:"authToken"`
	Nonce     string          `json:"nonce"`
}

// Validate sends the auth token + the expected challenge nonce to the engine and
// returns the validated subject. A non-2xx response from the engine (e.g. 401/422
// on an invalid token, expired/mismatched nonce, or failed cert/OCSP checks)
// surfaces as an error.
func (a *Adapter) Validate(ctx *azugo.Context, authToken json.RawMessage, nonce string) (*Subject, error) {
	if len(authToken) == 0 {
		return nil, fmt.Errorf("webeid: empty auth token")
	}
	if nonce == "" {
		return nil, fmt.Errorf("webeid: empty challenge nonce")
	}

	var subj Subject
	if err := a.auth.PostJSON(ctx, a.audience, a.scope, a.validateURL,
		validateRequest{AuthToken: authToken, Nonce: nonce}, &subj); err != nil {
		return nil, fmt.Errorf("webeid: engine validate: %w", err)
	}

	return &subj, nil
}
