package authbytecore

import (
	"strings"
	"testing"
)

// The clientSecretResolver understands three explicit schemes (literal:, env:,
// file:) plus a derived-name fallback. These cover the literal: scheme (secrets
// carried inline in the registry document) and the guarantee that a literal
// secret is never echoed back in an error.

func TestClientSecretResolver_Literal(t *testing.T) {
	got, err := clientSecretResolver("svc:notification", "literal:s3cr3t-value")
	if err != nil {
		t.Fatalf("literal ref: unexpected error: %v", err)
	}
	if got != "s3cr3t-value" {
		t.Fatalf("literal ref = %q, want %q", got, "s3cr3t-value")
	}
}

func TestClientSecretResolver_LiteralKeepsColons(t *testing.T) {
	// A literal value may itself contain the scheme separator; only the first
	// "literal:" prefix is stripped.
	const secret = "p@ss:with:colons"
	got, err := clientSecretResolver("svc:x", "literal:"+secret)
	if err != nil {
		t.Fatalf("literal ref with colons: unexpected error: %v", err)
	}
	if got != secret {
		t.Fatalf("literal ref = %q, want %q", got, secret)
	}
}

func TestClientSecretResolver_Env(t *testing.T) {
	t.Setenv("AUTHBYTE_TEST_SECRET", "from-env")
	got, err := clientSecretResolver("svc:x", "env:AUTHBYTE_TEST_SECRET")
	if err != nil {
		t.Fatalf("env ref: unexpected error: %v", err)
	}
	if got != "from-env" {
		t.Fatalf("env ref = %q, want %q", got, "from-env")
	}
}

func TestClientSecretResolver_EmptyLiteralFails(t *testing.T) {
	// An empty literal resolves nothing and (with no derived-name env set) errors.
	if _, err := clientSecretResolver("svc:no-such-client-xyz", "literal:"); err == nil {
		t.Fatal("empty literal ref: want error, got nil")
	}
}

func TestClientSecretResolver_ErrorRedactsLiteralRef(t *testing.T) {
	// A non-empty literal always resolves, so the only literal that reaches the
	// error is an empty one — but the error must still redact rather than echo
	// the ref verbatim (defence in depth: the literal ref carries the value, so
	// it must never be logged like an env:/file: name).
	_, err := clientSecretResolver("svc:no-such-client-xyz", "literal:")
	if err == nil {
		t.Fatal("want error for an unresolved (empty) literal ref")
	}
	if !strings.Contains(err.Error(), "literal:<redacted>") {
		t.Fatalf("error did not redact the literal ref: %v", err)
	}
}
