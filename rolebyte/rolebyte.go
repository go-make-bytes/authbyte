// Package rolebyte is the adapter to the central membership register: at
// token issue the Auth service asks it which memberships a subject holds and
// mints the returned group:level scopes and the membership's tenant — so role
// administration lives in one register while every resource service keeps
// checking plain token scopes.
//
// The subject is a typed key. A person is keyed by their platform subject —
// the stable id the identity store gives them, which is also the `sub` of every
// token issued for them (`sub:<person id>`); a service account — a machine that
// is a member of an organisation — is keyed by its own client id (`svc:<name>`),
// the same name it authenticates with and carries as its token subject. A key
// carries nothing about the person: the national identity code stays in the
// identity store and appears in no register.
//
// The adapter attaches the subject to any still-pending invitations first
// (the claim call): an invited subject's first token issue is exactly the
// moment its membership row activates. Both calls ride a DPoP-bound service
// token minted with this service's own identity — resolving a membership is
// the identity provider's question, never the subject's.
package rolebyte

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// Scopes the membership service's API demands per call — its contract, not
// configuration.
const (
	scopeClaim   = "membership:claim"
	scopeResolve = "membership:resolve"
)

// personKeyPrefix types the register's person key. The prefix is lower-case and
// the register matches it exactly, so it is written here once and never
// assembled at a call site.
const personKeyPrefix = "sub:"

// PersonKey is the register key of a person: their platform subject — the
// identity store's stable id, equal to the token's `sub` — typed. A subject has
// exactly one spelling, so nothing is rewritten: an invitation addressed to the
// subject the identity store answered and the login that claims it are the same
// bytes by construction.
func PersonKey(personSub string) string {
	return personKeyPrefix + personSub
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
	admitURL   string
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
		admitURL:   base + "/api/v1/directory-admissions",
		audience:   audience,
	}
}

// DirectoryLogin is what a login through an organisation's own directory brings
// to the register's admission door: the issuer the person authenticated through
// and the name the login carried.
type DirectoryLogin struct {
	Issuer      string
	DisplayName string
}

type admitRequest struct {
	SubjectKey  string `json:"subjectKey"`
	Issuer      string `json:"issuer"`
	DisplayName string `json:"displayName"`
}

type admitResponse struct {
	Outcome  string `json:"outcome"`
	TenantID string `json:"tenantId"`
}

// admissionAdmitted is the register's word for an admission that created or
// activated a membership; every other outcome changed nothing.
const admissionAdmitted = "admitted"

// Admit presents a person who has just authenticated through an organisation's
// directory to the register's admission door: the tenant that attached that
// issuer as its directory admits them as an active member with no grants. The
// answer is whether a membership was created or activated by this call — an
// existing member, a revoked one and an issuer no tenant attached all answer
// false and change nothing; the refusal that may follow is the caller's. Rides
// the claim scope: it is the same moment and the same trust as the invitation
// claim, the identity provider saying who has just authenticated.
func (r *Resolver) Admit(ctx *azugo.Context, subjectKey string, login DirectoryLogin) (bool, error) {
	if subjectKey == "" || login.Issuer == "" {
		return false, fmt.Errorf("rolebyte: an admission needs the subject key and the issuer")
	}

	var res admitResponse
	if err := r.auth.PostJSON(ctx, r.audience, scopeClaim, r.admitURL,
		admitRequest{SubjectKey: subjectKey, Issuer: login.Issuer, DisplayName: login.DisplayName}, &res); err != nil {
		return false, fmt.Errorf("rolebyte: admit: %w", err)
	}

	return res.Outcome == admissionAdmitted, nil
}

type membership struct {
	TenantID string   `json:"tenantId"`
	Scopes   []string `json:"scopes"`
}

type resolveResponse struct {
	// SubjectKey is the key the register says this answer is about.
	SubjectKey  string       `json:"subjectKey"`
	Memberships []membership `json:"memberships"`
}

// errAnswerForAnotherSubject is a resolve answer that is not about the subject
// asked about. Minting from it would hand one person another's access, so the
// token issue fails closed instead.
var errAnswerForAnotherSubject = errors.New("rolebyte: resolve answered for another subject")

// answeredFor accepts the register's answer only when it names the subject that
// was asked about. An answer that names nobody is refused the same way: a register
// that does not say whom it answered for cannot be told apart from one that
// answered for somebody else.
func answeredFor(asked string, res resolveResponse) ([]Membership, error) {
	// The register matches a key with surrounding whitespace trimmed, and names
	// the key it matched.
	if res.SubjectKey != strings.TrimSpace(asked) {
		return nil, fmt.Errorf("%w: asked %q, answered %q", errAnswerForAnotherSubject, asked, res.SubjectKey)
	}

	out := make([]Membership, 0, len(res.Memberships))
	for _, m := range res.Memberships {
		out = append(out, Membership(m))
	}

	return out, nil
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

	// Who was asked about and what came back, on every resolve: if one person's
	// login ever carries another's access, this line says whether the register
	// answered for the wrong person or the answer was right and the fault lies
	// after it.
	tenants := make([]string, 0, len(res.Memberships))
	for _, m := range res.Memberships {
		tenants = append(tenants, m.TenantID+"="+strings.Join(m.Scopes, ","))
	}
	ctx.Log().Info("membership resolved",
		zap.String("asked", subjectKey), zap.String("answered_for", res.SubjectKey), zap.Strings("memberships", tenants))

	return answeredFor(subjectKey, res)
}
