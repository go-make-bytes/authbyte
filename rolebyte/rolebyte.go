// Package rolebyte is the adapter to the central membership service: at user
// token issue, the Auth service asks it which memberships the authenticated
// person holds and mints the returned group:level scopes — so role
// administration lives in one register while every resource service keeps
// checking plain token scopes.
//
// The adapter also attaches the person to any still-pending invitations
// first (the claim call): an invited user's first login is exactly the
// moment their membership row activates. Both calls ride a DPoP-bound
// service token minted with this service's own identity — resolving a
// membership is the identity provider's question, never the user's.
package rolebyte

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"azugo.io/azugo"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// Scopes the membership service's API demands per call — its contract, not
// configuration.
const (
	scopeClaim   = "membership:claim"
	scopeResolve = "membership:resolve"
)

// subjectKeyPrefix types the register's person key: the value after the
// prefix is the eIDAS identity code from the login, verbatim.
const subjectKeyPrefix = "pno:"

// ErrNotMember reports that the authenticated person holds no membership —
// login succeeded, access is refused (login is not access).
var ErrNotMember = errors.New("rolebyte: subject holds no membership")

// ErrAmbiguous reports that the person holds more than one membership, which
// single-tenant token minting cannot express yet — refused rather than
// guessed (minting one tenant's scopes while acting in another would be a
// privilege leak).
var ErrAmbiguous = errors.New("rolebyte: subject holds multiple memberships")

// Resolver derives a user's scopes from the membership register.
type Resolver struct {
	auth       *authclient.Client
	claimsURL  string
	resolveURL string
	audience   string
}

// New builds a Resolver against the membership service's base URL,
// authenticating with service tokens for audience minted via ac.
func New(ac *authclient.Client, baseURL, audience string) *Resolver {
	base := strings.TrimSuffix(baseURL, "/")

	return &Resolver{
		auth:       ac,
		claimsURL:  base + "/api/v1/claims",
		resolveURL: base + "/api/v1/resolve",
		audience:   audience,
	}
}

// membership is one tenant the subject may act under.
type membership struct {
	TenantID string   `json:"tenantId"`
	Scopes   []string `json:"scopes"`
}

type resolveResponse struct {
	Memberships []membership `json:"memberships"`
}

type claimRequest struct {
	SubjectKey string `json:"subjectKey"`
}

type claimResponse struct {
	Claimed []struct {
		UserID   string `json:"userId"`
		TenantID string `json:"tenantId"`
	} `json:"claimed"`
}

// UserScopes attaches any pending invitations for the person and answers the
// scope set AND the tenant of their single active membership — the tenant is
// minted into the token so every multi-tenant resource service scopes by it
// ("tenant from the token", never request data). No membership yields
// ErrNotMember; more than one yields ErrAmbiguous; any transport or service
// failure surfaces as an error — the caller fails the token issue closed.
func (r *Resolver) UserScopes(ctx *azugo.Context, serialNumber string) ([]string, string, error) {
	if serialNumber == "" {
		// Without an identity code there is no register key to look up — and
		// every supported login method provides one, so this is a wiring
		// fault, not a user condition.
		return nil, "", fmt.Errorf("rolebyte: login carries no identity code")
	}

	subjectKey := subjectKeyPrefix + serialNumber

	// First login claims pending invitations; on every later call this is an
	// idempotent no-op. It must precede resolve so the very first token
	// already carries the invited roles.
	var claimed claimResponse
	if err := r.auth.PostJSON(ctx, r.audience, scopeClaim, r.claimsURL,
		claimRequest{SubjectKey: subjectKey}, &claimed); err != nil {
		return nil, "", fmt.Errorf("rolebyte: claim: %w", err)
	}

	var res resolveResponse
	if err := r.auth.GetJSON(ctx, r.audience, scopeResolve,
		r.resolveURL+"?subject="+url.QueryEscape(subjectKey), &res); err != nil {
		return nil, "", fmt.Errorf("rolebyte: resolve: %w", err)
	}

	switch len(res.Memberships) {
	case 0:
		return nil, "", ErrNotMember
	case 1:
		return res.Memberships[0].Scopes, res.Memberships[0].TenantID, nil
	default:
		return nil, "", ErrAmbiguous
	}
}
