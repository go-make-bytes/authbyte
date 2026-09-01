package authbytecore

import (
	"fmt"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/upstream"

	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration is the Identity/Auth service configuration.
// Non-secret values come from environment variables (ConfigMaps); secrets are
// loaded from the secret store (Vault) via LoadRemoteSecret and are never baked
// into images.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// IssuerURL is this service's `iss` value / public base.
	IssuerURL string `mapstructure:"issuer_url" validate:"required,url"`
	// JWKSURL overrides the JWKS endpoint used internally to validate tokens.
	// Useful when the public IssuerURL is not reachable from inside the container.
	// Defaults to IssuerURL + "/.well-known/jwks.json".
	JWKSURL string `mapstructure:"jwks_url"`
	// UserAudience is the logical audience stamped into user tokens (the portal
	// API surface) and required when validating tokens on protected endpoints.
	UserAudience string `mapstructure:"user_audience" validate:"required"`
	// BaseURL is the externally reachable root of this service, used to
	// construct absolute callback URIs (e.g. https://auth.example.com).
	BaseURL string `mapstructure:"base_url" validate:"required,url"`

	// Upstream OIDC login — the generic connector. Any standard OIDC provider
	// is configuration: the authority URL (endpoints resolved from its
	// discovery document unless the explicit *_URL overrides are set), client
	// credentials, scopes, the claim carrying the identity code, and the
	// acr/amr → method/LoA vocabularies. Exactly ONE upstream is configured
	// per deployment; setting OIDCUpstreamAuthorityURL selects the generic
	// connector, otherwise the EPARAKSTS_* variables below select the
	// eParaksts profile (fixed endpoints, bespoke logout, eParaksts
	// vocabularies) — so existing deployments run unchanged.
	OIDCUpstreamAuthorityURL  string `mapstructure:"oidc_upstream_authority_url" validate:"omitempty,url"`
	OIDCUpstreamClientID      string `mapstructure:"oidc_upstream_client_id"`
	OIDCUpstreamClientSecret  string `mapstructure:"oidc_upstream_client_secret"`
	OIDCUpstreamScopes        string `mapstructure:"oidc_upstream_scopes"`
	OIDCUpstreamAuthorizeURL  string `mapstructure:"oidc_upstream_authorize_url" validate:"omitempty,url"`
	OIDCUpstreamTokenURL      string `mapstructure:"oidc_upstream_token_url" validate:"omitempty,url"`
	OIDCUpstreamUserInfoURL   string `mapstructure:"oidc_upstream_userinfo_url" validate:"omitempty,url"`
	OIDCUpstreamEndSessionURL string `mapstructure:"oidc_upstream_end_session_url" validate:"omitempty,url"`
	// OIDCUpstreamClaimSerial names the userinfo claim carrying the person's
	// identity code (default serial_number).
	OIDCUpstreamClaimSerial string `mapstructure:"oidc_upstream_claim_serial"`
	// OIDCUpstreamMethodPolicy maps acr/amr tokens to login methods
	// ("substr=method,substr=method", longest token wins); MethodDefault is
	// the method when nothing matches; MethodsAllowed is the comma-separated
	// set a callback may resolve to (default: exactly the default method).
	OIDCUpstreamMethodPolicy   string `mapstructure:"oidc_upstream_method_policy"`
	OIDCUpstreamMethodDefault  string `mapstructure:"oidc_upstream_method_default"`
	OIDCUpstreamMethodsAllowed string `mapstructure:"oidc_upstream_methods_allowed"`
	// OIDCUpstreamLoADefault is the assurance level when no LoA-vocabulary
	// token matches (default low; a deployment whose IdP enforces MFA may
	// raise it deliberately).
	OIDCUpstreamLoADefault string `mapstructure:"oidc_upstream_loa_default"`

	// eParaksts upstream login (the eParaksts profile of the connector).
	EparakstsAuthorityURL string `mapstructure:"eparaksts_authority_url" validate:"omitempty,url"`
	EparakstsClientID     string `mapstructure:"eparaksts_client_id"`
	EparakstsClientSecret string `mapstructure:"eparaksts_client_secret"`
	EparakstsRedirectPath string `mapstructure:"eparaksts_redirect_path"`
	EparakstsScopes       string `mapstructure:"eparaksts_scopes"`
	// Step-up acr_values that force a specific login method at Entrust. These
	// MUST differ per method so step-up can actually force eParaksts Mobile vs
	// eID Scan (the login-method ↔ signing-identity binding). The concrete URNs
	// depend on the Entrust policy configuration, so they are env-configurable.
	// NB: there is deliberately NO eID-card (sc_plugin) acr here — eID-card login
	// goes through Web eID only; the eParaksts/TrustedX sc_plugin flow is not
	// permitted (a callback resolving to it is rejected).
	EparakstsACRMobile  string `mapstructure:"eparaksts_acr_mobile"`
	EparakstsACREIDScan string `mapstructure:"eparaksts_acr_eidscan"`
	// EparakstsLogoutIDP is the IdP identifier used for the session-termination
	// (logout) endpoint /trustedx-authserver/{idp}/logout. It differs from the
	// OAuth AS id (lvrtc-eipsign-as); default lvrtc-eipsign-idp. Env-configurable
	// because the demo platform may expose a different IdP id.
	EparakstsLogoutIDP string `mapstructure:"eparaksts_logout_idp"`
	// LoAPolicy overrides the acr/amr → assurance-level mapping. Format:
	// comma-separated `substring=loa` pairs (e.g.
	// "level:high=high,level:substantial=substantial,mobileid=high"). Empty uses
	// the built-in defaults (identity.DefaultLoAPolicy).
	LoAPolicy string `mapstructure:"loa_policy"`

	// Token signing.
	TokenSigningKey string `mapstructure:"token_signing_key"`
	TokenSigningAlg string `mapstructure:"token_signing_alg" validate:"required,oneof=ES256"`
	// AllowEphemeralSigningKey permits running with a generated in-memory signing
	// key when TOKEN_SIGNING_KEY is unset. OFF by default: production fails to
	// start without a real key. Set true only for dev/tests.
	AllowEphemeralSigningKey bool `mapstructure:"allow_ephemeral_signing_key"`
	// SigningKeyReloadInterval, when > 0, polls the TOKEN_SIGNING_KEY secret on
	// this cadence and performs an overlapping rotation when the key changes —
	// no redeploy. 0 disables the reloader.
	SigningKeyReloadInterval time.Duration `mapstructure:"signing_key_reload_interval" validate:"gte=0"`

	// TTLs and leeway (env-configurable; spec decision A-5).
	UserTokenTTL         time.Duration `mapstructure:"user_token_ttl" validate:"required,gt=0"`
	ServiceTokenTTL      time.Duration `mapstructure:"service_token_ttl" validate:"required,gt=0"`
	DPoPProofMaxAge      time.Duration `mapstructure:"dpop_proof_max_age" validate:"required,gt=0"`
	TokenClockSkewLeeway time.Duration `mapstructure:"token_clock_skew_leeway" validate:"gte=0"`

	// Server DPoP-Nonce (required from day one; spec decision A-3).
	DPoPNonceEnabled bool          `mapstructure:"dpop_nonce_enabled"`
	DPoPNonceTTL     time.Duration `mapstructure:"dpop_nonce_ttl" validate:"required,gt=0"`

	// ServiceClientRegistry is the declarative registry document content,
	// loaded from Vault.
	ServiceClientRegistry string `mapstructure:"service_client_registry"`

	// Backing stores.
	PostgresDSN string `mapstructure:"postgres_dsn" validate:"required"`
	RedisURL    string `mapstructure:"redis_url" validate:"required"`

	// Audit — GDPR personal-data access logging (GDPR-audit) to the access-audit
	// service. OPTIONAL: when AccessAuditURL is empty the GDPR client is not wired
	// and identity-access records are not posted (development). NIS2-audit security
	// telemetry (go-sec-events → SIEM) always emits regardless of these.
	AccessAuditURL       string `mapstructure:"access_audit_url" validate:"omitempty,url"`
	AccessAuditAudience  string `mapstructure:"access_audit_audience"`
	AccessAuditScope     string `mapstructure:"access_audit_scope"`
	AccessAuditOutboxDir string `mapstructure:"access_audit_outbox_dir"`

	// Web eID engine (card login). OPTIONAL: when WebEIDEngineURL is empty the
	// /webeid/* card-login routes are not registered. The Auth service calls the
	// engine's stateless /auth/validate server-to-server (DPoP) using the same
	// outbound service-client as the audit poster (AuditClientID), so that client
	// also needs a grant for WebEIDAudience/WebEIDScope.
	WebEIDEngineURL string `mapstructure:"webeid_engine_url" validate:"omitempty,url"`
	WebEIDAudience  string `mapstructure:"webeid_audience"`
	WebEIDScope     string `mapstructure:"webeid_scope"`

	// Membership-driven scopes. OPTIONAL — this knob selects between the two
	// supported modes. Empty: the service runs STANDALONE — every
	// authenticated person is minted the static baseline scope set (and no
	// tenant); authentication is access. Set: the service runs
	// REGISTER-BACKED — a person with no membership is refused at token
	// issue; the register, not the login, grants access. Choosing a mode is
	// choosing that access-control behaviour. When set, every user-token issue asks
	// the membership register for the person's scopes instead: the first
	// login claims their pending invitation, and the resolved group:level set
	// is minted into the token. A person with no membership is refused — the
	// register, not the login, grants access. The calls ride the same
	// outbound service-client as the audit poster (AuditClientID), so that
	// client also needs grants for RolebyteAudience with membership:claim +
	// membership:resolve.
	RolebyteURL      string `mapstructure:"rolebyte_url" validate:"omitempty,url"`
	RolebyteAudience string `mapstructure:"rolebyte_audience"`
	// AuditClientID / AuditClientSecret authenticate this service's OUTBOUND
	// client-credentials hop to its own /token endpoint, minting the DPoP-bound
	// service token used to call access-audit. AuditClientID MUST be a registered
	// service client (SERVICE_CLIENT_REGISTRY) with a grant for
	// AccessAuditAudience/AccessAuditScope; the secret must match that client's.
	AuditClientID     string `mapstructure:"audit_client_id"`
	AuditClientSecret string `mapstructure:"audit_client_secret"`
	// AuditIssuerURL overrides the issuer base used for the outbound token mint
	// (defaults to IssuerURL). Set it to an internally-reachable URL when the
	// public issuer is not reachable from inside the pod.
	AuditIssuerURL string `mapstructure:"audit_issuer_url" validate:"omitempty,url"`

	// Development conveniences (off by default).
	//
	// DemoDir, when set, serves the static demo SPA from that directory under
	// /demo (same-origin, so the browser can read the DPoP-Nonce header).
	DemoDir string `mapstructure:"demo_dir"`
}

// NewConfiguration returns a new configuration.
func NewConfiguration() *Configuration {
	return &Configuration{
		BaseConfiguration: pkconfig.New(),
	}
}

// Bind registers defaults and environment-variable bindings.
//
// ServerCore/Core/Loaded (the azugo + core Configurable contract) and the
// standard fleet env (SERVICE_NAME, ENVIRONMENT, OTEL_*, BROKER_*) are inherited
// from the embedded go-platform-kit BaseConfiguration.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)

	v.SetDefault("user_audience", "portal-api")
	v.SetDefault("token_signing_alg", "ES256")
	v.SetDefault("user_token_ttl", 15*time.Minute)
	v.SetDefault("service_token_ttl", 5*time.Minute)
	v.SetDefault("dpop_proof_max_age", 60*time.Second)
	v.SetDefault("token_clock_skew_leeway", 30*time.Second)
	v.SetDefault("dpop_nonce_enabled", true)
	v.SetDefault("dpop_nonce_ttl", 5*time.Minute)
	// Identification + the sign-identity profile: capturing the person's
	// signing capabilities at login is the default; override EPARAKSTS_SCOPES
	// without the profile scope to turn capability capture off.
	v.SetDefault("eparaksts_scopes",
		"urn:lvrtc:fpeil:aa urn:safelayer:eidas:sign:identity:profile")
	v.SetDefault("eparaksts_redirect_path", "/callback")
	v.SetDefault("base_url", "http://localhost:8080")
	// Distinct, method-forcing acr_values flow URNs (request side), per the
	// eParaksts OAuth2 docs. These differ from the response-side `amr`
	// (`...adaptive:methods:mobileid` / `...:mobile-eid`). Override per environment.
	// No eid (sc_plugin) acr — eID-card login is Web eID only.
	v.SetDefault("eparaksts_acr_mobile", "urn:eparaksts:authentication:flow:mobileid")
	v.SetDefault("eparaksts_acr_eidscan", "urn:eparaksts:authentication:flow:mobile-eid")
	v.SetDefault("eparaksts_logout_idp", upstream.EParakstsDefaultLogoutIDP)

	// Audit (GDPR-audit) defaults; AccessAuditURL stays empty (feature off) until set.
	v.SetDefault("access_audit_audience", "svc:access-audit")
	v.SetDefault("access_audit_scope", "access-audit:write")
	v.SetDefault("audit_client_id", "svc:authbyte-core")

	// Web eID (card login) defaults; WebEIDEngineURL stays empty (routes off) until set.
	v.SetDefault("webeid_audience", "svc:web-eid")
	v.SetDefault("webeid_scope", "webeid:validate")

	// Membership-driven scopes; RolebyteURL stays empty (static scopes) until set.
	v.SetDefault("rolebyte_audience", "svc:rolebyte")

	// Secrets from the secret store (Vault agent → <NAME>_FILE).
	loadSecret(v, "oidc_upstream_client_secret", "OIDC_UPSTREAM_CLIENT_SECRET")
	loadSecret(v, "eparaksts_client_secret", "EPARAKSTS_CLIENT_SECRET")
	loadSecret(v, "token_signing_key", "TOKEN_SIGNING_KEY")
	loadSecret(v, "service_client_registry", "SERVICE_CLIENT_REGISTRY")
	loadSecret(v, "postgres_dsn", "POSTGRES_DSN")
	loadSecret(v, "audit_client_secret", "AUDIT_CLIENT_SECRET")

	_ = v.BindEnv("issuer_url", "AUTH_ISSUER_URL")
	_ = v.BindEnv("jwks_url", "AUTH_JWKS_URL")
	_ = v.BindEnv("user_audience", "AUTH_USER_AUDIENCE")
	_ = v.BindEnv("oidc_upstream_authority_url", "OIDC_UPSTREAM_AUTHORITY_URL")
	_ = v.BindEnv("oidc_upstream_client_id", "OIDC_UPSTREAM_CLIENT_ID")
	_ = v.BindEnv("oidc_upstream_client_secret", "OIDC_UPSTREAM_CLIENT_SECRET")
	_ = v.BindEnv("oidc_upstream_scopes", "OIDC_UPSTREAM_SCOPES")
	_ = v.BindEnv("oidc_upstream_authorize_url", "OIDC_UPSTREAM_AUTHORIZE_URL")
	_ = v.BindEnv("oidc_upstream_token_url", "OIDC_UPSTREAM_TOKEN_URL")
	_ = v.BindEnv("oidc_upstream_userinfo_url", "OIDC_UPSTREAM_USERINFO_URL")
	_ = v.BindEnv("oidc_upstream_end_session_url", "OIDC_UPSTREAM_END_SESSION_URL")
	_ = v.BindEnv("oidc_upstream_claim_serial", "OIDC_UPSTREAM_CLAIM_SERIAL")
	_ = v.BindEnv("oidc_upstream_method_policy", "OIDC_UPSTREAM_METHOD_POLICY")
	_ = v.BindEnv("oidc_upstream_method_default", "OIDC_UPSTREAM_METHOD_DEFAULT")
	_ = v.BindEnv("oidc_upstream_methods_allowed", "OIDC_UPSTREAM_METHODS_ALLOWED")
	_ = v.BindEnv("oidc_upstream_loa_default", "OIDC_UPSTREAM_LOA_DEFAULT")
	_ = v.BindEnv("eparaksts_authority_url", "EPARAKSTS_AUTHORITY_URL")
	_ = v.BindEnv("eparaksts_client_id", "EPARAKSTS_CLIENT_ID")
	_ = v.BindEnv("eparaksts_client_secret", "EPARAKSTS_CLIENT_SECRET")
	_ = v.BindEnv("base_url", "BASE_URL")
	_ = v.BindEnv("eparaksts_redirect_path", "EPARAKSTS_REDIRECT_PATH")
	_ = v.BindEnv("eparaksts_scopes", "EPARAKSTS_SCOPES")
	_ = v.BindEnv("eparaksts_acr_mobile", "EPARAKSTS_ACR_MOBILE")
	_ = v.BindEnv("eparaksts_acr_eidscan", "EPARAKSTS_ACR_EIDSCAN")
	_ = v.BindEnv("eparaksts_logout_idp", "EPARAKSTS_LOGOUT_IDP")
	_ = v.BindEnv("loa_policy", "LOA_POLICY")
	_ = v.BindEnv("token_signing_key", "TOKEN_SIGNING_KEY")
	_ = v.BindEnv("token_signing_alg", "TOKEN_SIGNING_ALG")
	_ = v.BindEnv("allow_ephemeral_signing_key", "ALLOW_EPHEMERAL_SIGNING_KEY")
	_ = v.BindEnv("signing_key_reload_interval", "SIGNING_KEY_RELOAD_INTERVAL")
	_ = v.BindEnv("user_token_ttl", "USER_TOKEN_TTL")
	_ = v.BindEnv("service_token_ttl", "SERVICE_TOKEN_TTL")
	_ = v.BindEnv("dpop_proof_max_age", "DPOP_PROOF_MAX_AGE")
	_ = v.BindEnv("token_clock_skew_leeway", "TOKEN_CLOCK_SKEW_LEEWAY")
	_ = v.BindEnv("dpop_nonce_enabled", "DPOP_NONCE_ENABLED")
	_ = v.BindEnv("dpop_nonce_ttl", "DPOP_NONCE_TTL")
	_ = v.BindEnv("service_client_registry", "SERVICE_CLIENT_REGISTRY")
	_ = v.BindEnv("postgres_dsn", "POSTGRES_DSN")
	_ = v.BindEnv("redis_url", "REDIS_URL")
	_ = v.BindEnv("demo_dir", "DEMO_DIR")

	_ = v.BindEnv("access_audit_url", "ACCESS_AUDIT_URL")
	_ = v.BindEnv("access_audit_audience", "ACCESS_AUDIT_AUDIENCE")
	_ = v.BindEnv("access_audit_scope", "ACCESS_AUDIT_SCOPE")
	_ = v.BindEnv("access_audit_outbox_dir", "ACCESS_AUDIT_OUTBOX_DIR")
	_ = v.BindEnv("webeid_engine_url", "WEBEID_ENGINE_URL")
	_ = v.BindEnv("webeid_audience", "WEBEID_AUDIENCE")
	_ = v.BindEnv("webeid_scope", "WEBEID_SCOPE")
	_ = v.BindEnv("rolebyte_url", "ROLEBYTE_URL")
	_ = v.BindEnv("rolebyte_audience", "ROLEBYTE_AUDIENCE")
	_ = v.BindEnv("audit_client_id", "AUDIT_CLIENT_ID")
	_ = v.BindEnv("audit_client_secret", "AUDIT_CLIENT_SECRET")
	_ = v.BindEnv("audit_issuer_url", "AUDIT_ISSUER_URL")
}

// loadSecret loads a secret from the remote secret store and registers it as a
// default (so an explicit env var still overrides it).
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}

// Validate validates the configuration. The base config validates the standard
// fleet env (and recurses into the embedded Azugo config + Telemetry/Broker);
// valid.Struct(c) then covers the service-specific fields.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	if err := valid.Struct(c); err != nil {
		return err
	}

	// Exactly one upstream provider per deployment: the generic connector
	// (OIDC_UPSTREAM_AUTHORITY_URL, or a full explicit endpoint set) or the
	// eParaksts profile (EPARAKSTS_AUTHORITY_URL). Fail closed at startup —
	// an authorization server with no upstream cannot log anyone in.
	genericByEndpoints := c.OIDCUpstreamAuthorizeURL != "" && c.OIDCUpstreamTokenURL != "" && c.OIDCUpstreamUserInfoURL != ""
	generic := c.OIDCUpstreamAuthorityURL != "" || genericByEndpoints
	eparaksts := c.EparakstsAuthorityURL != ""
	switch {
	case !generic && !eparaksts:
		return fmt.Errorf("no upstream identity provider configured: set OIDC_UPSTREAM_AUTHORITY_URL (generic OIDC) or EPARAKSTS_AUTHORITY_URL (eParaksts profile)")
	case generic && c.OIDCUpstreamClientID == "":
		return fmt.Errorf("OIDC_UPSTREAM_CLIENT_ID is required with the generic OIDC upstream")
	case !generic && eparaksts && c.EparakstsClientID == "":
		return fmt.Errorf("EPARAKSTS_CLIENT_ID is required with the eParaksts upstream")
	}

	return nil
}

// UpstreamConfig resolves which upstream provider this deployment runs and
// returns its connector configuration. The generic connector
// (OIDC_UPSTREAM_*) wins when configured; otherwise the EPARAKSTS_* variables
// select the eParaksts profile, byte-identical to what those deployments have
// always run. Vocabulary and claim overrides apply to either profile.
func (c *Configuration) UpstreamConfig() upstream.Config {
	var cfg upstream.Config
	if c.OIDCUpstreamAuthorityURL != "" ||
		(c.OIDCUpstreamAuthorizeURL != "" && c.OIDCUpstreamTokenURL != "" && c.OIDCUpstreamUserInfoURL != "") {
		cfg = upstream.Config{
			AuthorityURL:  c.OIDCUpstreamAuthorityURL,
			ClientID:      c.OIDCUpstreamClientID,
			ClientSecret:  c.OIDCUpstreamClientSecret,
			Scopes:        splitSpaceList(c.OIDCUpstreamScopes),
			AuthorizeURL:  c.OIDCUpstreamAuthorizeURL,
			TokenURL:      c.OIDCUpstreamTokenURL,
			UserInfoURL:   c.OIDCUpstreamUserInfoURL,
			EndSessionURL: c.OIDCUpstreamEndSessionURL,
			MethodDefault: "upstream",
		}
	} else {
		cfg = upstream.EParakstsProfile(c.EparakstsAuthorityURL, c.EparakstsLogoutIDP)
		cfg.ClientID = c.EparakstsClientID
		cfg.ClientSecret = c.EparakstsClientSecret
		if s := splitSpaceList(c.EparakstsScopes); len(s) > 0 {
			cfg.Scopes = s
		}
	}

	// Deployment overrides, profile-independent.
	if c.OIDCUpstreamClaimSerial != "" {
		cfg.ClaimSerial = c.OIDCUpstreamClaimSerial
	}
	if m := parsePairs(c.OIDCUpstreamMethodPolicy); len(m) > 0 {
		cfg.MethodPolicy = m
	}
	if c.OIDCUpstreamMethodDefault != "" {
		cfg.MethodDefault = c.OIDCUpstreamMethodDefault
	}
	if l := splitList(c.OIDCUpstreamMethodsAllowed); len(l) > 0 {
		cfg.MethodsAllowed = l
	}
	if lp := c.LoAPolicyMap(); len(lp) > 0 {
		cfg.LoAPolicy = lp
	}
	if c.OIDCUpstreamLoADefault != "" {
		cfg.LoADefault = c.OIDCUpstreamLoADefault
	}

	return cfg
}

// splitSpaceList splits a scope-style list on spaces and/or commas.
func splitSpaceList(s string) []string {
	out := make([]string, 0, 4)
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}

	return out
}

// parsePairs parses "key=value,key=value" into a map (empty on none).
func parsePairs(s string) map[string]string {
	out := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
			if k, v = strings.TrimSpace(k), strings.TrimSpace(v); k != "" && v != "" {
				out[k] = v
			}
		}
	}

	return out
}

// jwksURL returns the JWKS endpoint to use for inbound token validation.
// If AUTH_JWKS_URL is set it is used directly; otherwise the URL is derived
// from IssuerURL so the service can reach its own JWKS from inside the container.
func (c *Configuration) jwksURL() string {
	if u := strings.TrimSpace(c.JWKSURL); u != "" {
		return u
	}

	return strings.TrimSuffix(c.IssuerURL, "/") + "/.well-known/jwks.json"
}

// CallbackPath returns the URL path on which the eParaksts callback is served,
// always with a leading slash.
func (c *Configuration) CallbackPath() string {
	p := strings.TrimSpace(c.EparakstsRedirectPath)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	return p
}

// RedirectURI returns the absolute callback URI sent to eParaksts.
func (c *Configuration) RedirectURI() string {
	return strings.TrimSuffix(c.BaseURL, "/") + c.CallbackPath()
}

// ScopeList returns the configured eParaksts scopes.
func (c *Configuration) ScopeList() []string {
	return splitList(c.EparakstsScopes)
}

// ACRForMethod returns the Entrust acr_values that force the given login method
// during step-up. Distinct values per method are what make the login-method ↔
// signing-flow binding enforceable: Entrust can only force the requested method
// if each maps to its own acr.
func (c *Configuration) ACRForMethod(method string) string {
	switch method {
	case identity.LoginEParakstsMobile:
		return c.EparakstsACRMobile
	case identity.LoginEIDScan:
		return c.EparakstsACREIDScan
	case identity.LoginWebEID:
		// Web eID card login is not an Entrust method, so it has no acr_values.
		// Step-up TO Web eID is initiated via the Web eID challenge route
		// (/webeid/challenge), not the Entrust /authorize redirect.
		return ""
	default:
		// "eid" (sc_plugin) intentionally has no acr — eID-card login is Web eID only.
		return ""
	}
}

// LoAPolicyMap parses LoAPolicy ("substr=loa,substr=loa") into a map. An empty
// or malformed-only value yields an empty map, so NewResolver falls back to the
// built-in defaults.
func (c *Configuration) LoAPolicyMap() map[string]string {
	out := make(map[string]string)
	for _, pair := range strings.Split(c.LoAPolicy, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if k, v, ok := strings.Cut(pair, "="); ok {
			if k, v = strings.TrimSpace(k), strings.TrimSpace(v); k != "" && v != "" {
				out[k] = v
			}
		}
	}

	return out
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}

	return out
}

// AuthClientConfig builds the auth-client configuration the service uses to
// protect its own endpoints (validating user tokens). It never calls out, so
// no client id/secret is needed.
func (c *Configuration) AuthClientConfig() *authclient.Configuration {
	return &authclient.Configuration{
		IssuerURL:                c.IssuerURL,
		JWKSURL:                  c.jwksURL(),
		JWKSCacheTTL:             10 * time.Minute,
		ServiceAudience:          c.UserAudience,
		ServiceTokenEarlyRefresh: 30 * time.Second,
		DPoPProofMaxAge:          c.DPoPProofMaxAge,
		TokenClockSkewLeeway:     c.TokenClockSkewLeeway,
		DPoPReplayBackend:        authclient.ReplayBackendMemory,
		DPoPNonceEnabled:         c.DPoPNonceEnabled,
		DPoPNonceTTL:             c.DPoPNonceTTL,
		RequireDPoP:              true,
	}
}

// AccessAuditEnabled reports whether GDPR (GDPR-audit) access logging is wired
// (i.e. ACCESS_AUDIT_URL is set).
func (c *Configuration) AccessAuditEnabled() bool {
	return strings.TrimSpace(c.AccessAuditURL) != ""
}

// WebEIDEnabled reports whether the Web eID card-login routes are wired (i.e.
// WEBEID_ENGINE_URL is set).
func (c *Configuration) WebEIDEnabled() bool {
	return strings.TrimSpace(c.WebEIDEngineURL) != ""
}

// RolebyteEnabled reports whether user-token scopes come from the membership
// register (ROLEBYTE_URL set) instead of the static baseline.
func (c *Configuration) RolebyteEnabled() bool {
	return strings.TrimSpace(c.RolebyteURL) != ""
}

// auditIssuer returns the issuer base used for the outbound audit token mint.
func (c *Configuration) auditIssuer() string {
	if u := strings.TrimSpace(c.AuditIssuerURL); u != "" {
		return u
	}

	return c.IssuerURL
}

// AuditAuthClientConfig builds the OUTBOUND auth-client configuration the audit
// Poster uses to mint DPoP-bound service tokens (client-credentials against this
// service's own /token) for calling access-audit. ServiceAudience is required by
// validation but is only consulted on the inbound path; outbound uses the
// per-call audience.
func (c *Configuration) AuditAuthClientConfig() *authclient.Configuration {
	return &authclient.Configuration{
		IssuerURL:                c.auditIssuer(),
		JWKSURL:                  c.jwksURL(),
		JWKSCacheTTL:             10 * time.Minute,
		ServiceAudience:          c.UserAudience,
		ServiceClientID:          c.AuditClientID,
		ServiceClientSecret:      c.AuditClientSecret,
		ServiceTokenEarlyRefresh: 30 * time.Second,
		DPoPProofMaxAge:          c.DPoPProofMaxAge,
		TokenClockSkewLeeway:     c.TokenClockSkewLeeway,
		DPoPReplayBackend:        authclient.ReplayBackendMemory,
		DPoPNonceEnabled:         c.DPoPNonceEnabled,
		DPoPNonceTTL:             c.DPoPNonceTTL,
		RequireDPoP:              true,
	}
}

// GDPRConfig builds the go-gdpr-audit client configuration from the audit
// settings, with the library's default resilience knobs.
func (c *Configuration) GDPRConfig() gdpr.Configuration {
	return gdpr.Configuration{
		Endpoint:         c.AccessAuditURL,
		Audience:         c.AccessAuditAudience,
		Scope:            c.AccessAuditScope,
		Timeout:          gdpr.DefaultTimeout,
		OutboxCapacity:   gdpr.DefaultOutboxCapacity,
		MaxRetries:       gdpr.DefaultMaxRetries,
		RetryBackoff:     gdpr.DefaultRetryBackoff,
		BreakerThreshold: gdpr.DefaultBreakerThreshold,
		BreakerCooldown:  gdpr.DefaultBreakerCooldown,
	}
}
