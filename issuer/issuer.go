// Package issuer mints user and service identity tokens. It stamps the DPoP
// key thumbprint into cnf.jkt, scopes service tokens to a single audience, and
// signs everything through the key manager.
package issuer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/go-make-bytes/authbyte/keys"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer mints signed tokens.
type Issuer struct {
	km         *keys.Manager
	issuerURL  string
	userTTL    time.Duration
	serviceTTL time.Duration
	now        func() time.Time
}

// New creates a token issuer.
func New(km *keys.Manager, issuerURL string, userTTL, serviceTTL time.Duration) *Issuer {
	return &Issuer{
		km:         km,
		issuerURL:  issuerURL,
		userTTL:    userTTL,
		serviceTTL: serviceTTL,
		now:        time.Now,
	}
}

// UserTokenInput describes a user token to mint.
type UserTokenInput struct {
	Subject      string // internal subject id
	Audience     string // the sign-in client's user audience
	Scopes       []string
	LoA          string
	LoginMethod  string
	Name         string
	GivenName    string
	FamilyName   string
	SerialNumber string // eIDAS identity code, canonical (e.g. "PNOLV-XXXXXXXXXXX")
	Tenant       string // the membership's tenant (register-resolved); empty on deployments without one
	Thumbprint   string // DPoP key thumbprint (cnf.jkt); always set
	ClientID     string // the sign-in client the token is issued to (client_id, [RFC 9068 §2.2])
}

// IssueUser mints a DPoP-bound user access token.
func (i *Issuer) IssueUser(in UserTokenInput) (string, int64, error) {
	c := claims.Claims{
		RegisteredClaims: i.base(in.Subject, in.Audience, i.userTTL),
		Scope:            strings.Join(in.Scopes, " "),
		LoA:              in.LoA,
		LoginMethod:      in.LoginMethod,
		Name:             in.Name,
		GivenName:        in.GivenName,
		FamilyName:       in.FamilyName,
		SerialNumber:     in.SerialNumber,
		Tenant:           in.Tenant,
		ClientID:         in.ClientID,
	}
	if in.Thumbprint != "" {
		c.Confirmation = &claims.Confirmation{JKT: in.Thumbprint}
	}

	return i.sign(c, i.userTTL)
}

// ServiceTokenInput describes a service token to mint.
type ServiceTokenInput struct {
	ClientID   string // e.g. svc:signflow
	Audience   string // single target, e.g. svc:document
	Scopes     []string
	Tenant     string // the organisation a service account acts for; empty for a platform service acting as itself
	Thumbprint string // DPoP key thumbprint (cnf.jkt); mandatory
}

// IssueService mints a DPoP-bound service identity token scoped to a single
// audience. A tenant is present only when the token was issued to a service
// account for a named organisation — it is what lets the token be acted for
// downstream, so nothing but a verified membership may put it there.
func (i *Issuer) IssueService(in ServiceTokenInput) (string, int64, error) {
	c := claims.Claims{
		RegisteredClaims: i.base(in.ClientID, in.Audience, i.serviceTTL),
		ClientID:         in.ClientID,
		Scope:            strings.Join(in.Scopes, " "),
		Tenant:           in.Tenant,
	}
	if in.Thumbprint != "" {
		c.Confirmation = &claims.Confirmation{JKT: in.Thumbprint}
	}

	return i.sign(c, i.serviceTTL)
}

// AppTokenInput describes the token an AI app is given: its person as the
// subject, the assistant it works as in the actor chain, its one resource as the
// audience.
type AppTokenInput struct {
	Subject     string   // the person, as in their user tokens
	Audience    string   // the app's one resource, the MCP server's canonical address
	ClientID    string   // the AI app's client id
	Scopes      []string // the boxes the app asked for that the person and the assistant both hold
	Tenant      string   // the tenant where the assistant is the person's
	Assistant   string   // the assistant's key, svc:assistant-<ULID>
	LoA         string   // always the lowest: the app holds no sign-in of its own
	LoginMethod string   // always identity.LoginAssistant
	TTL         time.Duration
}

// IssueApp mints an AI app's token: a plain bearer token, with no cnf, since an
// AI app holds no proof-of-possession key [MCP 2026-07-28 basic/authorization];
// the one kind of token this issuer mints unbound, kept to its one resource by
// its audience and to minutes by its lifetime.
func (i *Issuer) IssueApp(in AppTokenInput) (string, int64, error) {
	if in.Assistant == "" || in.TTL <= 0 {
		return "", 0, fmt.Errorf("issuer: an app token names its assistant and its lifetime")
	}
	c := claims.Claims{
		RegisteredClaims: i.base(in.Subject, in.Audience, in.TTL),
		Scope:            strings.Join(in.Scopes, " "),
		LoA:              in.LoA,
		LoginMethod:      in.LoginMethod,
		Tenant:           in.Tenant,
		ClientID:         in.ClientID,
		Act:              &claims.Actor{Subject: in.Assistant},
	}

	return i.sign(c, in.TTL)
}

// DelegatedTokenInput describes an on-behalf-of token minted via token
// exchange. The token names the end user as its subject while recording, in the
// actor chain, the service acting on the user's behalf.
type DelegatedTokenInput struct {
	Subject      string        // the end user the token acts for (from the subject token)
	Audience     string        // single target service, e.g. svc:document
	Scopes       []string      // least-privilege scopes toward the audience
	LoA          string        // carried forward from the subject token
	LoginMethod  string        // carried forward — keeps the login⇒signing binding working downstream
	SerialNumber string        // carried forward — keeps the user's identity code visible downstream (e.g. co-signer slot match)
	Tenant       string        // carried forward — a downstream multi-tenant service scopes by the token's tenant
	Actor        *claims.Actor // the acting service, nesting any prior actor
	Thumbprint   string        // acting client's DPoP key thumbprint (cnf.jkt)
	TTL          time.Duration // a shorter lifetime than a service token's, for a token one call needs; 0 = the service token's
}

// IssueDelegated mints a DPoP-bound token that carries the end user as its
// subject (so downstream services owner-filter on the user exactly as for a
// direct user call) while recording the acting service in the `act` claim. It
// is sender-constrained to the acting client's key and short-lived like a
// service token.
func (i *Issuer) IssueDelegated(in DelegatedTokenInput) (string, int64, error) {
	ttl := i.serviceTTL
	if in.TTL > 0 && in.TTL < ttl {
		ttl = in.TTL
	}
	c := claims.Claims{
		RegisteredClaims: i.base(in.Subject, in.Audience, ttl),
		Scope:            strings.Join(in.Scopes, " "),
		LoA:              in.LoA,
		LoginMethod:      in.LoginMethod,
		SerialNumber:     in.SerialNumber,
		Tenant:           in.Tenant,
		Act:              in.Actor,
	}
	if in.Thumbprint != "" {
		c.Confirmation = &claims.Confirmation{JKT: in.Thumbprint}
	}

	return i.sign(c, ttl)
}

// ParseSubjectToken verifies a token this issuer minted — signature against the
// active or a still-trusted retired key, issuer, and expiry — and returns its
// claims. It is the validation step for a token-exchange subject token. The
// audience is not checked here: a subject token's audience is the previous hop
// (e.g. the portal API), not this endpoint, and which hops a client may act from
// is the registry's to say, so the exchange checks it (registry.MayActFrom).
func (i *Issuer) ParseSubjectToken(raw string) (*claims.Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{i.km.Alg()}),
		jwt.WithIssuer(i.issuerURL),
		jwt.WithExpirationRequired(),
	)

	var c claims.Claims
	if _, err := parser.ParseWithClaims(raw, &c, func(tok *jwt.Token) (any, error) {
		// Only an access token is exchanged; an ID token signed with the same
		// key is refused by its type [RFC 9068 §5].
		if typ, _ := tok.Header["typ"].(string); typ != typeAccessToken {
			return nil, fmt.Errorf("issuer: a subject token typed %q is not an access token", typ)
		}
		kid, _ := tok.Header["kid"].(string)
		pk, ok := i.km.PublicKeyByKID(kid)
		if !ok {
			return nil, fmt.Errorf("issuer: unknown signing key %q", kid)
		}

		return pk, nil
	}); err != nil {
		return nil, err
	}

	return &c, nil
}

func (i *Issuer) base(subject, audience string, ttl time.Duration) jwt.RegisteredClaims {
	now := i.now()

	return jwt.RegisteredClaims{
		Issuer:    i.issuerURL,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        randomJTI(),
	}
}

// sign signs an access token, typed as one [RFC 9068 §2.1].
func (i *Issuer) sign(c claims.Claims, ttl time.Duration) (string, int64, error) {
	tok, err := i.km.SignTyped(c, typeAccessToken)
	if err != nil {
		return "", 0, err
	}

	return tok, int64(ttl.Seconds()), nil
}

// The JOSE typ of each kind of token this issuer signs. They share one key, so
// the type is what tells an access token from an ID token [RFC 9068 §5].
const (
	typeAccessToken = "at+jwt"
	typeIDToken     = "JWT"
)

// IDTokenInput is what an ID token states about one sign-in [OIDC Core §2].
type IDTokenInput struct {
	Subject  string   // the person, as the access token names them
	ClientID string   // the client the sign-in was for: the token's only audience
	Nonce    string   // the client's nonce; "" when it sent none
	AuthTime int64    // when the person authenticated, Unix seconds; 0 when unknown
	ACR      string   // the sign-in method met
	AMR      []string // the registered means of the authentication
	SID      string   // the session's public name
}

// idTokenClaims are an ID token's claims. aud is the one client, written as a
// string; nothing personal beyond the subject is carried.
type idTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	AuthTime  int64    `json:"auth_time,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	ACR       string   `json:"acr,omitempty"`
	AMR       []string `json:"amr,omitempty"`
	SID       string   `json:"sid,omitempty"`
}

func (c idTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

func (c idTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c idTokenClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c idTokenClaims) GetIssuer() (string, error)              { return c.Issuer, nil }
func (c idTokenClaims) GetSubject() (string, error)             { return c.Subject, nil }
func (c idTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{c.Audience}, nil
}

// IssueID signs the ID token of a sign-in [OIDC Core §2]: this issuer, the
// person, the client as its only audience, the user token's lifetime, and what
// the sign-in proved. No azp: the client is the audience alone.
func (i *Issuer) IssueID(in IDTokenInput) (string, error) {
	now := i.now()

	return i.km.SignTyped(idTokenClaims{
		Issuer:    i.issuerURL,
		Subject:   in.Subject,
		Audience:  in.ClientID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(i.userTTL).Unix(),
		AuthTime:  in.AuthTime,
		Nonce:     in.Nonce,
		ACR:       in.ACR,
		AMR:       in.AMR,
		SID:       in.SID,
	}, typeIDToken)
}

func randomJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}
