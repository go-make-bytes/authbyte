package issuer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/gmb-lib/go-authbyte/jwks"
	"github.com/go-make-bytes/authbyte/issuer"
	"github.com/go-make-bytes/authbyte/keys"

	"github.com/golang-jwt/jwt/v5"
)

const issuerURL = "http://auth.local"

// newStack wires a key manager + issuer and a JWKS endpoint served over HTTP,
// returning an issuer and a parser keyed on the published JWKS — exactly the
// path a consuming service follows.
func newStack(t *testing.T) (*issuer.Issuer, *jwks.Client, func(token string, opts ...jwt.ParserOption) (*claims.Claims, error)) {
	t.Helper()

	km, err := keys.New("")
	if err != nil {
		t.Fatalf("keys.New: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doc, err := km.JWKS()
		if err != nil {
			t.Errorf("JWKS: %v", err)
		}
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)

	jc := jwks.New(srv.URL, time.Minute)

	parse := func(token string, opts ...jwt.ParserOption) (*claims.Claims, error) {
		var c claims.Claims
		base := []jwt.ParserOption{
			jwt.WithValidMethods([]string{"ES256"}),
			jwt.WithIssuer(issuerURL),
			jwt.WithExpirationRequired(),
		}
		parser := jwt.NewParser(append(base, opts...)...)
		_, err := parser.ParseWithClaims(token, &c, func(tok *jwt.Token) (any, error) {
			kid, _ := tok.Header["kid"].(string)

			return jc.Key(context.Background(), kid)
		})

		return &c, err
	}

	return issuer.New(km, issuerURL, 15*time.Minute, 5*time.Minute), jc, parse
}

func TestIssueServiceTokenValidates(t *testing.T) {
	iss, _, parse := newStack(t)

	tok, exp, err := iss.IssueService(issuer.ServiceTokenInput{
		ClientID:   "svc:signflow",
		Audience:   "svc:document",
		Scopes:     []string{"documents:read"},
		Thumbprint: "thumb-abc",
	})
	if err != nil {
		t.Fatalf("IssueService: %v", err)
	}
	if exp != int64((5 * time.Minute).Seconds()) {
		t.Fatalf("unexpected expires_in: %d", exp)
	}

	c, err := parse(tok)
	if err != nil {
		t.Fatalf("token did not validate against JWKS: %v", err)
	}

	if c.Subject != "svc:signflow" {
		t.Fatalf("sub = %q", c.Subject)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "svc:document" {
		t.Fatalf("aud = %v", c.Audience)
	}
	if !c.IsService() {
		t.Fatal("expected IsService() true")
	}
	if c.Thumbprint() != "thumb-abc" {
		t.Fatalf("cnf.jkt = %q", c.Thumbprint())
	}
	if c.Scope != "documents:read" {
		t.Fatalf("scope = %q", c.Scope)
	}
}

func TestIssueUserTokenValidates(t *testing.T) {
	iss, _, parse := newStack(t)

	tok, _, err := iss.IssueUser(issuer.UserTokenInput{
		Subject:     "internal-123",
		Audience:    "portal-api",
		Scopes:      []string{"envelopes:write", "documents:read"},
		LoA:         "high",
		LoginMethod: "eid",
		Name:        "ANDRIS PARAUDZINS",
		GivenName:   "ANDRIS",
		FamilyName:  "PARAUDZINS",
		Thumbprint:  "user-thumb",
	})
	if err != nil {
		t.Fatalf("IssueUser: %v", err)
	}

	c, err := parse(tok)
	if err != nil {
		t.Fatalf("token did not validate against JWKS: %v", err)
	}

	if c.IsService() {
		t.Fatal("user token must not be a service token")
	}
	if c.LoA != "high" || c.LoginMethod != "eid" {
		t.Fatalf("loa/login_method = %q/%q", c.LoA, c.LoginMethod)
	}
	if c.Thumbprint() != "user-thumb" {
		t.Fatalf("cnf.jkt = %q", c.Thumbprint())
	}

	scopes := c.Scopes()
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %v", scopes)
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	iss, _, parse := newStack(t)

	tok, _, err := iss.IssueService(issuer.ServiceTokenInput{
		ClientID:   "svc:x",
		Audience:   "svc:document",
		Thumbprint: "t",
	})
	if err != nil {
		t.Fatalf("IssueService: %v", err)
	}

	// The signature is valid (verified via JWKS) but the audience check fails:
	// a svc:document token must be rejected by a svc:envelope consumer.
	if _, err := parse(tok, jwt.WithAudience("svc:envelope")); err == nil {
		t.Fatal("expected token bound to svc:document to be rejected for svc:envelope")
	}
}
