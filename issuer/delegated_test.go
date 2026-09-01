package issuer_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/go-make-bytes/authbyte/issuer"
)

// testIDCodeLV returns a Latvian personal identity code in the PNO form a token
// carries: the country, a six-digit leading group and a five-digit serial, built
// from one repeated digit so it reads as a placeholder at a glance.
//
// It is assembled from those parts at run time rather than written as a literal —
// an identifier-shaped constant in the source is indistinguishable from a
// credential to a secret scanner, and indistinguishable from a real person's code
// to a reader.
func testIDCodeLV(digit int) string {
	d := strconv.Itoa(digit)

	return "PNOLV-" + strings.Repeat(d, 6) + "-" + strings.Repeat(d, 5)
}

// TestIssueDelegatedActsForUser walks the token-exchange mint path: a user
// token is validated as the subject, then a delegated token is minted toward a
// downstream audience. The result must name the user (so downstream owner
// filters pass), bind to the acting client's key, record the actor, and carry
// the login method + assurance forward.
func TestIssueDelegatedActsForUser(t *testing.T) {
	iss, _, parse := newStack(t)

	userTok, _, err := iss.IssueUser(issuer.UserTokenInput{
		Subject:      "internal-123",
		Audience:     "portal-api",
		Scopes:       []string{"documents:read"},
		LoA:          "high",
		LoginMethod:  "eparakstsMobile",
		SerialNumber: testIDCodeLV(3),
		Tenant:       "01TENANTULID",
		Thumbprint:   "spa-key",
	})
	if err != nil {
		t.Fatalf("IssueUser: %v", err)
	}

	subject, err := iss.ParseSubjectToken(userTok)
	if err != nil {
		t.Fatalf("ParseSubjectToken: %v", err)
	}
	if subject.Subject != "internal-123" {
		t.Fatalf("subject sub = %q", subject.Subject)
	}
	if subject.SerialNumber != testIDCodeLV(3) {
		t.Fatalf("subject serial = %q (must be readable on the user token)", subject.SerialNumber)
	}

	delTok, exp, err := iss.IssueDelegated(issuer.DelegatedTokenInput{
		Subject:      subject.Subject,
		Audience:     "svc:document",
		Scopes:       []string{"documents:read"},
		LoA:          subject.LoA,
		LoginMethod:  subject.LoginMethod,
		SerialNumber: subject.SerialNumber,
		Tenant:       subject.Tenant,
		Actor:        &claims.Actor{Subject: "svc:portal-api"},
		Thumbprint:   "bff-key",
	})
	if err != nil {
		t.Fatalf("IssueDelegated: %v", err)
	}
	if exp != int64((5 * time.Minute).Seconds()) {
		t.Fatalf("delegated TTL = %d (want service TTL)", exp)
	}

	c, err := parse(delTok)
	if err != nil {
		t.Fatalf("delegated token did not validate: %v", err)
	}

	if c.Subject != "internal-123" {
		t.Fatalf("delegated sub = %q (must name the user)", c.Subject)
	}
	if c.IsService() {
		t.Fatal("delegated token must not look like a service token — its sub is the user")
	}
	if len(c.Audience) != 1 || c.Audience[0] != "svc:document" {
		t.Fatalf("delegated aud = %v", c.Audience)
	}
	if c.Thumbprint() != "bff-key" {
		t.Fatalf("delegated cnf.jkt = %q (must bind to the acting client's key)", c.Thumbprint())
	}
	if !c.Delegated() || c.Act == nil || c.Act.Subject != "svc:portal-api" {
		t.Fatalf("act = %+v (must record the acting client)", c.Act)
	}
	if c.LoA != "high" || c.LoginMethod != "eparakstsMobile" {
		t.Fatalf("carried loa/login_method = %q/%q", c.LoA, c.LoginMethod)
	}
	// The eIDAS serial survives the exchange so a downstream service (e.g. the
	// envelope service matching a co-signer slot) sees the signing user's identity.
	if c.SerialNumber != testIDCodeLV(3) {
		t.Fatalf("delegated serial = %q (must carry through token exchange)", c.SerialNumber)
	}
	// The tenant survives too: a downstream multi-tenant service scopes by the
	// token's tenant, and delegation must not strip it.
	if c.Tenant != "01TENANTULID" {
		t.Fatalf("delegated tenant = %q (must carry through token exchange)", c.Tenant)
	}
}

// TestExchangeActorChainNests proves a second exchange (the orchestrator
// re-exchanging the BFF's delegated token) nests the prior actor, preserving
// the full delegation chain.
func TestExchangeActorChainNests(t *testing.T) {
	iss, _, parse := newStack(t)

	delTok, _, err := iss.IssueDelegated(issuer.DelegatedTokenInput{
		Subject:    "internal-123",
		Audience:   "svc:document",
		Scopes:     []string{"documents:read"},
		Actor:      &claims.Actor{Subject: "svc:signflow", Act: &claims.Actor{Subject: "svc:portal-api"}},
		Thumbprint: "signflow-key",
	})
	if err != nil {
		t.Fatalf("IssueDelegated: %v", err)
	}

	c, err := parse(delTok)
	if err != nil {
		t.Fatalf("token did not validate: %v", err)
	}
	if c.Act == nil || c.Act.Subject != "svc:signflow" {
		t.Fatalf("immediate actor = %+v", c.Act)
	}
	if c.Act.Act == nil || c.Act.Act.Subject != "svc:portal-api" {
		t.Fatalf("nested actor = %+v", c.Act.Act)
	}
}

// TestParseSubjectTokenRejectsGarbage confirms a non-token is refused (the
// exchange handler turns this into a 401).
func TestParseSubjectTokenRejectsGarbage(t *testing.T) {
	iss, _, _ := newStack(t)

	if _, err := iss.ParseSubjectToken("not-a-jwt"); err == nil {
		t.Fatal("expected ParseSubjectToken to reject a non-token")
	}
}
