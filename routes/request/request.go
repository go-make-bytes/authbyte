// Package request holds the Identity/Auth request DTOs.
package request

import "azugo.io/azugo"

// StepUp asks the service to re-authenticate the current session with a
// stronger / different login method (for the signing-flow binding).
type StepUp struct {
	// RefreshToken names the existing session: the refresh token the client was
	// answered at its code exchange.
	RefreshToken string `json:"refresh_token" validate:"required"`
	// ClientID is the public client initiating the step-up: the client the refresh
	// token was issued to. Its redirect_uri is validated against the registry
	// allowlist (open-redirect protection).
	ClientID string `json:"client_id" validate:"required"`
	// ClientSecret is a confidential client's secret. It travels in the body
	// because the Authorization header carries the person's token; a public
	// client sends none.
	ClientSecret *string `json:"client_secret"`
	// Method is the login method to step up to, one of the client's
	// step_up_methods. eparakstsMobile and eidScan are Entrust-federated (the
	// response carries an authorize_url to follow); webEid is Web eID, not an
	// Entrust method, so the response carries a challenge nonce the SPA answers
	// with web-eid.js.
	Method string `json:"method" validate:"required"`
	// CodeChallenge is a fresh PKCE challenge for the re-issued token exchange.
	CodeChallenge string `json:"code_challenge" validate:"required"`
	// RedirectURI is where the SPA expects the new application code returned.
	RedirectURI string `json:"redirect_uri" validate:"required"`
	// State echoes the SPA's state parameter.
	State string `json:"state"`
}

// Validate implements azugo.Validator.
func (r *StepUp) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}
