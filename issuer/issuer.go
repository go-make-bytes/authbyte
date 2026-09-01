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
	Audience     string // portal API audience
	Scopes       []string
	LoA          string
	LoginMethod  string
	Name         string
	GivenName    string
	FamilyName   string
	SerialNumber string // eIDAS identity code (e.g. "PNOLV-XXXXXX-XXXXX")
	Tenant       string // the membership's tenant (register-resolved); empty on deployments without one
	Thumbprint   string // DPoP key thumbprint (cnf.jkt); always set
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
	Thumbprint string // DPoP key thumbprint (cnf.jkt); mandatory
}

// IssueService mints a DPoP-bound service identity token scoped to a single
// audience.
func (i *Issuer) IssueService(in ServiceTokenInput) (string, int64, error) {
	c := claims.Claims{
		RegisteredClaims: i.base(in.ClientID, in.Audience, i.serviceTTL),
		ClientID:         in.ClientID,
		Scope:            strings.Join(in.Scopes, " "),
	}
	if in.Thumbprint != "" {
		c.Confirmation = &claims.Confirmation{JKT: in.Thumbprint}
	}

	return i.sign(c, i.serviceTTL)
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
}

// IssueDelegated mints a DPoP-bound token that carries the end user as its
// subject (so downstream services owner-filter on the user exactly as for a
// direct user call) while recording the acting service in the `act` claim. It
// is sender-constrained to the acting client's key and short-lived like a
// service token.
func (i *Issuer) IssueDelegated(in DelegatedTokenInput) (string, int64, error) {
	c := claims.Claims{
		RegisteredClaims: i.base(in.Subject, in.Audience, i.serviceTTL),
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

	return i.sign(c, i.serviceTTL)
}

// ParseSubjectToken verifies a token this issuer minted — signature against the
// active or a still-trusted retired key, issuer, and expiry — and returns its
// claims. It is the validation step for a token-exchange subject token. The
// audience is deliberately NOT checked: a subject token's audience is the
// previous hop (e.g. the portal API), not this endpoint.
func (i *Issuer) ParseSubjectToken(raw string) (*claims.Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{i.km.Alg()}),
		jwt.WithIssuer(i.issuerURL),
		jwt.WithExpirationRequired(),
	)

	var c claims.Claims
	if _, err := parser.ParseWithClaims(raw, &c, func(tok *jwt.Token) (any, error) {
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

func (i *Issuer) sign(c claims.Claims, ttl time.Duration) (string, int64, error) {
	tok, err := i.km.Sign(c)
	if err != nil {
		return "", 0, err
	}

	return tok, int64(ttl.Seconds()), nil
}

func randomJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}
