package authbytecore

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

// TestApp constructs an App wired for tests. Backing-store clients are created
// lazily (no dial), so this works without live Redis/PostgreSQL; tests that
// exercise login/sessions require those services.
func TestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("ALLOW_EPHEMERAL_SIGNING_KEY", "true")
	// SERVICE_NAME is required by go-platform-kit's base config. ENVIRONMENT is
	// Azugo's own (development|test|staging|production) — it drives service.name's
	// sibling service.environment and the OTel deployment.environment.
	tb.Setenv("SERVICE_NAME", "authbyte")
	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("AUTH_ISSUER_URL", "http://localhost:8080")
	tb.Setenv("AUTH_USER_AUDIENCE", "portal-api")
	// The eParaksts profile is the default upstream for tests. A test that puts the
	// generic connector in the environment first (OIDC_UPSTREAM_AUTHORITY_URL, or
	// the three explicit endpoints) gets that one instead — the service refuses to
	// start with both families configured, so only one may be set here.
	if os.Getenv("OIDC_UPSTREAM_AUTHORITY_URL") == "" && os.Getenv("OIDC_UPSTREAM_AUTHORIZE_URL") == "" {
		tb.Setenv("EPARAKSTS_AUTHORITY_URL", "http://localhost:9999")
		tb.Setenv("EPARAKSTS_CLIENT_ID", "test-client")
	}
	tb.Setenv("BASE_URL", "http://localhost:8080")
	tb.Setenv("POSTGRES_DSN", "postgres://localhost:5432/authbyte_test?sslmode=disable")
	tb.Setenv("REDIS_URL", "redis://localhost:6379/0")

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	return app
}
