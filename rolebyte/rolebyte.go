// Package rolebyte is the adapter to the central membership register: at
// token issue the Auth service asks it which memberships a subject holds and
// mints the returned group:level scopes and the membership's tenant — so role
// administration lives in one register while every resource service keeps
// checking plain token scopes.
//
// The subject is a typed key. A person is keyed by the eIDAS identity code
// from their login (`pno:<code>`); a service account — a machine that is a
// member of an organisation — is keyed by its own client id (`svc:<name>`),
// the same name it authenticates with and carries as its token subject.
//
// The adapter attaches the subject to any still-pending invitations first
// (the claim call): an invited subject's first token issue is exactly the
// moment its membership row activates. Both calls ride a DPoP-bound service
// token minted with this service's own identity — resolving a membership is
// the identity provider's question, never the subject's.
package rolebyte

import (
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

// personKeyPrefix types the register's person key: the value after the
// prefix is the eIDAS identity code from the login, verbatim.
const personKeyPrefix = "pno:"

// PersonKey is the register key of a person: the identity code from their
// login, typed.
func PersonKey(serialNumber string) string {
	return personKeyPrefix + serialNumber
}

// Membership is one organisation a subject may act under, with the
// group:level scopes its roles grant there.
type Membership struct {
	TenantID string
	Scopes   []string
}

// Resolver answers membership questions from the register.
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

// Memberships attaches any pending invitations for the subject, then answers
// its active memberships — the organisations it may act under, each with the
// scopes its roles grant there. An empty answer means the subject holds no
// membership; which one to mint, when there are several, is the caller's
// question. Any transport or service failure surfaces as an error — the caller
// fails the token issue closed.
func (r *Resolver) Memberships(ctx *azugo.Context, subjectKey string) ([]Membership, error) {
	if subjectKey == "" {
		// Without a key there is nothing to look up — and every caller has one
		// (an identity code or a client id), so this is a wiring fault, not a
		// subject condition.
		return nil, fmt.Errorf("rolebyte: subject key is empty")
	}

	// First presentation claims pending invitations; on every later call this
	// is an idempotent no-op. It must precede resolve so the very first token
	// already carries the invited roles.
	var claimed claimResponse
	if err := r.auth.PostJSON(ctx, r.audience, scopeClaim, r.claimsURL,
		claimRequest{SubjectKey: subjectKey}, &claimed); err != nil {
		return nil, fmt.Errorf("rolebyte: claim: %w", err)
	}

	var res resolveResponse
	if err := r.auth.GetJSON(ctx, r.audience, scopeResolve,
		r.resolveURL+"?subject="+url.QueryEscape(subjectKey), &res); err != nil {
		return nil, fmt.Errorf("rolebyte: resolve: %w", err)
	}

	out := make([]Membership, 0, len(res.Memberships))
	for _, m := range res.Memberships {
		out = append(out, Membership(m))
	}

	return out, nil
}
