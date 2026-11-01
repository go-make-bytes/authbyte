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
// The register's sign-in doors answer only for the person being signed in. For
// each call this service mints a token in its own process naming that subject,
// with itself as the acting client and the door's one scope, bound to the
// outbound client's DPoP key, and sends it to the register's sign-in listener.
// The request names nobody: the register reads the subject from the token, so
// no call can ask about anyone else. The adapter attaches the subject to any
// still-pending invitations first (the claim door): an invited subject's first
// token issue is exactly the moment its membership row activates.
package rolebyte

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// Scopes the register's sign-in doors demand — its contract, not configuration.
const (
	scopeClaim   = "membership:claim"
	scopeResolve = "membership:resolve"
)

// The register's sign-in doors, on its sign-in listener.
const (
	doorClaims      = "/api/v1/sign-in/claims"
	doorMemberships = "/api/v1/sign-in/memberships"
	doorAdmissions  = "/api/v1/sign-in/directory-admissions"
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

// tokenSubject is the `sub` of the token the register reads a key from: a
// person's platform subject without its type, a service account's client id as
// it stands.
func tokenSubject(subjectKey string) string {
	return strings.TrimPrefix(subjectKey, personKeyPrefix)
}

// Minter mints, in this service's own process, the token for one sign-in door
// call: the subject being signed in, the register's audience, the door's one
// scope, the acting client and the thumbprint of the key the call is proven
// with.
type Minter func(subject, audience, scope, actor, thumbprint string) (string, error)

// Membership is one organisation a subject may act under, with the
// group:level scopes its roles grant there.
type Membership struct {
	TenantID string
	Scopes   []string
}

// Resolver answers membership questions from the register.
type Resolver struct {
	auth     *authclient.Client
	mint     Minter
	base     string
	audience string
	actor    string
}

// New builds a Resolver against the register's sign-in listener (signInURL),
// proving each call with ac's DPoP key and a token mint makes for it, with
// actor — this service's own client id — as the acting client.
func New(ac *authclient.Client, mint Minter, signInURL, audience, actor string) *Resolver {
	return &Resolver{
		auth:     ac,
		mint:     mint,
		base:     strings.TrimSuffix(signInURL, "/"),
		audience: audience,
		actor:    actor,
	}
}

// call sends one sign-in door call for the subject: a token minted for it at the
// door's scope, the body if any, and the answer decoded into out. Anything but a
// 200 is an error; the caller fails the token issue closed.
func (r *Resolver) call(ctx *azugo.Context, subjectKey, scope, door string, in, out any) error {
	token, err := r.mint(tokenSubject(subjectKey), r.audience, scope, r.actor, r.auth.Thumbprint())
	if err != nil {
		return fmt.Errorf("rolebyte: %s: mint: %w", door, err)
	}

	var body []byte
	if in != nil {
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("rolebyte: %s: %w", door, err)
		}
	}

	res, err := r.auth.DoWithToken(ctx, r.audience, token, http.MethodPost, r.base+door,
		http.Header{"Accept": {"application/json"}}, body)
	if err != nil {
		return fmt.Errorf("rolebyte: %s: %w", door, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("rolebyte: %s answered %d", door, res.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(res.Body, out); err != nil {
			return fmt.Errorf("rolebyte: %s: unreadable answer: %w", door, err)
		}
	}

	return nil
}

// DirectoryLogin is what a login through an organisation's own directory brings
// to the register's admission door: the issuer the person authenticated through
// and the name the login carried.
type DirectoryLogin struct {
	Issuer      string
	DisplayName string
}

type admitRequest struct {
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
		return false, errors.New("rolebyte: an admission needs the subject key and the issuer")
	}

	var res admitResponse
	if err := r.call(ctx, subjectKey, scopeClaim, doorAdmissions, admitRequest(login), &res); err != nil {
		return false, err
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

// ErrAnswerForAnotherSubject is a register answer that is not about the subject
// asked about. Minting from it would hand one person another's access, so the
// token issue fails closed instead, and the caller raises a security event: a
// healthy deployment never produces one.
var ErrAnswerForAnotherSubject = errors.New("rolebyte: resolve answered for another subject")

// answeredFor accepts the register's answer only when it names the subject that
// was asked about. An answer that names nobody is refused the same way: a register
// that does not say whom it answered for cannot be told apart from one that
// answered for somebody else.
func answeredFor(asked string, res resolveResponse) ([]Membership, error) {
	if res.SubjectKey != asked {
		return nil, fmt.Errorf("%w: asked %q, answered %q", ErrAnswerForAnotherSubject, asked, res.SubjectKey)
	}

	out := make([]Membership, 0, len(res.Memberships))
	for _, m := range res.Memberships {
		out = append(out, Membership(m))
	}

	return out, nil
}

// Memberships attaches any pending invitations for the subject, then answers
// its active memberships — the organisations it may act under, each with the
// scopes its roles grant there. An empty answer means the subject holds no
// membership; which one to mint, when there are several, is the caller's
// question. Any transport or service failure surfaces as an error — the caller
// fails the token issue closed.
func (r *Resolver) Memberships(ctx *azugo.Context, subjectKey string) ([]Membership, error) {
	if strings.TrimSpace(subjectKey) == "" {
		// Without a key there is nothing to look up — and every caller has one
		// (a platform subject or a client id), so this is a wiring fault, not a
		// subject condition.
		return nil, errors.New("rolebyte: subject key is empty")
	}

	// First presentation claims pending invitations; on every later call this
	// is an idempotent no-op. It must precede the lookup so the very first token
	// already carries the invited roles.
	if err := r.call(ctx, subjectKey, scopeClaim, doorClaims, nil, nil); err != nil {
		return nil, err
	}

	var res resolveResponse
	if err := r.call(ctx, subjectKey, scopeResolve, doorMemberships, nil, &res); err != nil {
		return nil, err
	}

	// Who was asked about and what came back, on every lookup: if one person's
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
