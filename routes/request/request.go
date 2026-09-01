// Package request holds the Identity/Auth request DTOs.
package request

import "azugo.io/azugo"

// StepUp asks the service to re-authenticate the current session with a
// stronger / different login method (for the signing-flow binding).
type StepUp struct {
	// SessionID identifies the existing session (the refresh handle).
	SessionID string `json:"session_id" validate:"required"`
	// ClientID is the public client initiating the step-up; its redirect_uri is
	// validated against the registry allowlist (open-redirect protection).
	ClientID string `json:"client_id" validate:"required"`
	// Method is the login method to step up to. eparakstsMobile and eidScan are
	// Entrust-federated (the response carries an authorize_url to follow); webEid
	// is Web eID, not an Entrust method, so the response carries a challenge nonce
	// the SPA answers with web-eid.js. The legacy "eid" sc_plugin flow is removed
	// and is not a valid step-up target.
	Method string `json:"method" validate:"required,oneof=eparakstsMobile eidScan webEid"`
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
