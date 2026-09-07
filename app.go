// Package authbytecore is the Identity/Auth service (the authority): it brokers
// login against one configured upstream OIDC provider (eParaksts, or any
// standard OIDC provider — see the upstream package), maps claims to an
// internal identity, and issues DPoP-bound user and service tokens, publishing
// its signing keys as JWKS.
package authbytecore

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-authbyte/nonce"
	"github.com/gmb-lib/go-authbyte/replay"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/platform"
	"github.com/gmb-lib/go-sec-events/secevents"
	"github.com/go-make-bytes/authbyte/audit"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/issuer"
	"github.com/go-make-bytes/authbyte/keys"
	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/store"
	"github.com/go-make-bytes/authbyte/upstream"
	"github.com/go-make-bytes/authbyte/webeid"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	corecfg "azugo.io/core/config"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// App is the Identity/Auth service application container.
type App struct {
	*azugo.App

	config *Configuration

	keys       *keys.Manager
	issuer     *issuer.Issuer
	registry   *registry.Registry
	upstream   *upstream.Provider
	resolver   *identity.Resolver
	binding    identity.BindingResolver
	nonce      *nonce.Issuer
	session    *session.Store
	store      *store.Store
	authClient *authclient.Client
	replay     replay.Store
	redis      redis.UniversalClient

	// Audit emitters: NIS2-audit security telemetry (always) and the optional
	// GDPR-audit GDPR access client + its outbound auth-client (set only when
	// access-audit is configured).
	secEvents   *secevents.Emitter
	auditClient *authclient.Client
	gdprAudit   *gdpr.Client
	audit       *audit.Recorder

	// Web eID card-login adapter (calls the engine's stateless validate). Set
	// only when WEBEID_ENGINE_URL is configured.
	webeid *webeid.Adapter

	// Membership scope resolver: when set (ROLEBYTE_URL configured), user
	// tokens carry the register-resolved scopes instead of the static
	// baseline, and a person with no membership is refused at token issue.
	scopeResolver ScopeResolver
}

// ScopeResolver derives an authenticated person's scopes AND tenant from the
// membership register at token issue. It is the boundary between the two
// supported modes of this service:
//
//   - standalone (nil resolver, the default): every authenticated person is
//     minted the static baseline scope set and no tenant claim —
//     authentication is access.
//   - register-backed (resolver wired): scopes and tenant come from the
//     membership register at every issue, and a person with no membership is
//     refused at token issue — the register, not the login, grants access.
//
// Choosing a mode is choosing that access-control behaviour; neither mode is
// a degraded form of the other. Implemented by rolebyte.Resolver; the full
// contract (answers, refusals, unreachability, compatibility) is in the
// README's "Two supported modes" section.
type ScopeResolver interface {
	UserScopes(ctx *azugo.Context, serialNumber string) ([]string, string, error)
}

// New constructs the Identity/Auth application.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Identity/Auth Service",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	instance := &App{App: a, config: config}

	if err := instance.init(); err != nil {
		return nil, err
	}

	return instance, nil
}

func (a *App) init() error {
	cfg := a.config

	// Platform glue FIRST (before any service routes/middleware): standardized
	// logging+redaction, OpenTelemetry tracing, and the correlation middleware —
	// wired identically across the fleet via go-platform-kit.
	if err := platform.Setup(a.App, platform.Options{
		Config: cfg.BaseConfiguration,
	}); err != nil {
		return err
	}

	// Key manager + token issuer.
	km, err := keys.New(cfg.TokenSigningKey)
	if err != nil {
		return err
	}
	if km.Generated() {
		// Fail closed in production: an ephemeral key cannot validate tokens
		// across pods/restarts and is a silent security downgrade. Only dev/tests
		// may opt in via ALLOW_EPHEMERAL_SIGNING_KEY.
		if !cfg.AllowEphemeralSigningKey {
			return fmt.Errorf("no TOKEN_SIGNING_KEY provided: refusing to start with an ephemeral signing key (set ALLOW_EPHEMERAL_SIGNING_KEY=true for development only)")
		}
		a.Log().Warn("no TOKEN_SIGNING_KEY provided — using an ephemeral signing key (development only)")
	}
	a.keys = km
	a.issuer = issuer.New(km, cfg.IssuerURL, cfg.UserTokenTTL, cfg.ServiceTokenTTL)

	// Service client registry (declarative document from Vault).
	reg, err := registry.Load([]byte(cfg.ServiceClientRegistry), clientSecretResolver)
	if err != nil {
		return err
	}
	a.registry = reg

	// Upstream OIDC provider + identity resolution. The provider is built from
	// one Config value (profile-resolved by the configuration) and handed to
	// the routes as a value; when the generic profile has no explicit
	// endpoints, construction performs OIDC discovery — bounded, fail closed.
	upCtx, upCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer upCancel()
	up, err := upstream.New(upCtx, cfg.UpstreamConfig(), a.Log())
	if err != nil {
		return fmt.Errorf("upstream provider: %w", err)
	}
	a.upstream = up
	a.resolver = up.Resolver()

	// Server nonce issuer for the /token issuance hop.
	if cfg.DPoPNonceEnabled {
		ni, err := nonce.New(cfg.DPoPNonceTTL)
		if err != nil {
			return err
		}
		a.nonce = ni
	}

	// Redis (sessions, flow state) and PostgreSQL (identity mapping).
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("invalid REDIS_URL: %w", err)
	}
	a.redis = redis.NewClient(opts)
	a.session = session.New(a.redis)
	// The authority enforces jti replay on its own endpoints via Redis.
	a.replay = replay.NewRedis(a.redis)

	st, err := store.New(a.BackgroundContext(), cfg.PostgresDSN)
	if err != nil {
		return err
	}
	a.store = st

	// Auth-client to protect this service's own endpoints (validates user
	// tokens). It never calls out, so it carries no client id/secret.
	ac, err := authclient.New(cfg.AuthClientConfig())
	if err != nil {
		return err
	}
	a.authClient = ac

	// Audit emitters. NIS2-audit (NIS2 security telemetry) always emits via the
	// log sink → SIEM. GDPR-audit (GDPR personal-data access) is wired only when
	// access-audit is configured (ACCESS_AUDIT_URL): an outbound auth-client mints
	// the DPoP-bound service token, and the gdpr client posts access records with
	// a local outbox (durable when ACCESS_AUDIT_OUTBOX_DIR is set).
	a.secEvents = secevents.NewEmitter(secevents.NewLogSink())

	if cfg.AccessAuditEnabled() {
		oc, err := authclient.New(cfg.AuditAuthClientConfig())
		if err != nil {
			return fmt.Errorf("audit auth-client: %w", err)
		}
		a.auditClient = oc

		var outbox gdpr.Outbox
		if dir := cfg.AccessAuditOutboxDir; dir != "" {
			ob, err := gdpr.NewFileOutbox(dir, gdpr.DefaultOutboxCapacity)
			if err != nil {
				return fmt.Errorf("audit outbox: %w", err)
			}
			outbox = ob
		}

		gc, err := gdpr.New(
			cfg.GDPRConfig(),
			newAccessAuditPoster(oc, cfg.AccessAuditURL, cfg.AccessAuditAudience, cfg.AccessAuditScope),
			gdpr.Options{Outbox: outbox, Logger: a.Log()},
		)
		if err != nil {
			return fmt.Errorf("gdpr-audit client: %w", err)
		}
		a.gdprAudit = gc
	} else {
		a.Log().Warn("ACCESS_AUDIT_URL not set — GDPR (GDPR-audit) identity-access records will NOT be posted (development); NIS2-audit security telemetry still emits")
	}

	a.audit = audit.New(a.secEvents, a.gdprAudit, a.Log())

	// Web eID card login: an outbound service-client (the same authbyte
	// client the audit poster uses, reused when present) calls the engine's
	// stateless /auth/validate. Off unless WEBEID_ENGINE_URL is set.
	if cfg.WebEIDEnabled() {
		wc := a.auditClient
		if wc == nil {
			oc, err := authclient.New(cfg.AuditAuthClientConfig())
			if err != nil {
				return fmt.Errorf("web-eid auth-client: %w", err)
			}
			wc = oc
		}
		a.webeid = webeid.New(wc, cfg.WebEIDEngineURL, cfg.WebEIDAudience, cfg.WebEIDScope)
	} else {
		a.Log().Warn("WEBEID_ENGINE_URL not set — Web eID card-login routes (/webeid/*) are disabled")
	}

	// Membership-driven scopes (register-backed mode): an outbound
	// service-client (the same client the audit poster uses, reused when
	// present) asks the membership register for the person's scopes at every
	// user-token issue. Off unless ROLEBYTE_URL is set — the service then
	// runs standalone and mints the static baseline set.
	if cfg.RolebyteEnabled() {
		rc := a.auditClient
		if rc == nil {
			oc, err := authclient.New(cfg.AuditAuthClientConfig())
			if err != nil {
				return fmt.Errorf("rolebyte auth-client: %w", err)
			}
			rc = oc
		}
		a.scopeResolver = rolebyte.New(rc, cfg.RolebyteURL, cfg.RolebyteAudience)
	}

	return nil
}

// Start verifies backing-store connectivity (best effort), starts the
// signing-key rotation reloader (if configured), and starts the HTTP server.
func (a *App) Start() error {
	ctx, cancel := context.WithTimeout(a.BackgroundContext(), 5*time.Second)
	defer cancel()

	if err := a.session.Ping(ctx); err != nil {
		a.Log().Warn("redis not reachable at startup — sessions/login degraded", zap.Error(err))
	}
	if err := a.store.Ping(ctx); err != nil {
		a.Log().Warn("postgres not reachable at startup — new-user mapping degraded", zap.Error(err))
	}

	a.startSigningKeyRotation()

	// Deliver buffered GDPR access records in the background (no-op if GDPR-audit
	// is not configured).
	if a.gdprAudit != nil {
		go a.gdprAudit.Drain(a.BackgroundContext())
	}

	return a.App.Start()
}

// startSigningKeyRotation polls the TOKEN_SIGNING_KEY secret on the configured
// interval and performs an overlapping rotation when the key changes — no
// redeploy. A zero interval disables the reloader. The goroutine is bound to
// the app's background context and exits on shutdown.
func (a *App) startSigningKeyRotation() {
	interval := a.config.SigningKeyReloadInterval
	if interval <= 0 {
		return
	}

	ctx := a.BackgroundContext()
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pem, err := corecfg.LoadRemoteSecret("TOKEN_SIGNING_KEY")
				if err != nil || pem == "" {
					continue
				}
				rotated, err := a.keys.MaybeRotate(pem)
				if err != nil {
					a.Log().Warn("signing-key reload failed", zap.Error(err))

					continue
				}
				if rotated {
					a.Log().Info("signing key rotated", zap.String("kid", a.keys.ActiveKID()))
				}
			}
		}
	}()
}

// Stop flushes the GDPR audit outbox, releases backing-store resources, then
// stops the server.
func (a *App) Stop() {
	if a.gdprAudit != nil {
		// Fresh context: the app's background context may already be cancelled
		// during shutdown. Close stops the drainer and flushes the outbox.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := a.gdprAudit.Close(ctx); err != nil {
			a.Log().Warn("gdpr-audit: flush on shutdown incomplete", zap.Error(err))
		}
		cancel()
	}
	if a.store != nil {
		a.store.Close()
	}
	if a.redis != nil {
		_ = a.redis.Close()
	}

	a.App.Stop()
}

// Config returns the application configuration.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

// Accessors.
func (a *App) Keys() *keys.Manager               { return a.keys }
func (a *App) Issuer() *issuer.Issuer            { return a.issuer }
func (a *App) Registry() *registry.Registry      { return a.registry }
func (a *App) Upstream() *upstream.Provider      { return a.upstream }
func (a *App) Resolver() *identity.Resolver      { return a.resolver }
func (a *App) Binding() identity.BindingResolver { return a.binding }
func (a *App) Nonce() *nonce.Issuer              { return a.nonce }
func (a *App) Session() *session.Store           { return a.session }
func (a *App) Store() *store.Store               { return a.store }
func (a *App) AuthClient() *authclient.Client    { return a.authClient }
func (a *App) Replay() replay.Store              { return a.replay }
func (a *App) Audit() *audit.Recorder            { return a.audit }
func (a *App) WebEID() *webeid.Adapter           { return a.webeid }

// ScopeResolver returns the membership scope resolver, or nil when user
// tokens carry the static baseline scopes.
func (a *App) ScopeResolver() ScopeResolver { return a.scopeResolver }

// SetScopeResolver overrides the membership scope resolver (test use only).
func (a *App) SetScopeResolver(r ScopeResolver) { a.scopeResolver = r }

var nonAlphaNum = regexp.MustCompile(`[^A-Za-z0-9]+`)

// clientSecretResolver resolves a registry client's secret_ref to its secret.
// It supports the explicit schemes literal:VALUE, env:NAME and file:/path, and
// otherwise derives a conventional secret name AUTHBYTE_CLIENT_SECRET_<CLIENT_ID>
// read from the environment or the secret store (Vault agent → <NAME>_FILE).
//
// literal:VALUE carries the secret inline in the registry document itself, for
// when the whole registry is delivered as a single secret (a Vault entry / a
// Kubernetes Secret) rather than resolved reference-by-reference. env:/file: and
// the derived-name fallback are unchanged, so a reference-based registry keeps
// working exactly as before — a deployment may mix schemes per client.
func clientSecretResolver(clientID, secretRef string) (string, error) {
	switch {
	case strings.HasPrefix(secretRef, "literal:"):
		if v := strings.TrimPrefix(secretRef, "literal:"); v != "" {
			return v, nil
		}
	case strings.HasPrefix(secretRef, "env:"):
		if v := os.Getenv(strings.TrimPrefix(secretRef, "env:")); v != "" {
			return v, nil
		}
	case strings.HasPrefix(secretRef, "file:"):
		if v, err := corecfg.LoadRemoteSecret(strings.TrimPrefix(secretRef, "file:")); err == nil && v != "" {
			return v, nil
		}
	}

	name := "AUTHBYTE_CLIENT_SECRET_" + strings.ToUpper(nonAlphaNum.ReplaceAllString(clientID, "_"))
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	if v, err := corecfg.LoadRemoteSecret(name); err == nil && v != "" {
		return v, nil
	}

	// Never echo a literal secret back in the error — the ref IS the value.
	safeRef := secretRef
	if strings.HasPrefix(secretRef, "literal:") {
		safeRef = "literal:<redacted>"
	}
	return "", fmt.Errorf("no secret resolved for client %q (ref %q)", clientID, safeRef)
}
