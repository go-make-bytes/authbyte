// Package audit records the Identity/Auth service's audit events through the
// platform's reusable emitter libraries:
//
// - NIS2-audit (NIS2 security telemetry) via go-sec-events — login / step-up,
// user- and service-token issuance, and authorization denials — emitted as
// structured security events the log pipeline ships to the SIEM.
// - GDPR-audit (GDPR personal-data access) via go-gdpr-audit — the identity-record
// writes the login flow performs (identity.upsert) — posted synchronously to
// the access-audit service.
//
// This replaces the original interim, log-only seam: the call sites are stable
// (a small Recorder façade), and the events now carry the shared broker envelope.
// The Recorder is constructed once and held on the App; the GDPR client is
// OPTIONAL — when access-audit is not configured the GDPR-audit methods are no-ops
// so the service still runs (development), while NIS2-audit always emits.
package audit

import (
	"strings"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"
)

// Security event types this service emits. Login/step-up share the canonical
// go-sec-events type; token issuance uses these service-specific types
// alongside the library's service-token type.
const (
	eventUserToken = "auth.user_token" // user access-token issued/refreshed
)

// Recorder emits the auth service's NIS2-audit security events and GDPR-audit
// personal-data-access records. It is safe for concurrent use.
type Recorder struct {
	sec  *secevents.Emitter
	gdpr *gdpr.Client // optional; nil when access-audit is not configured
	log  *zap.Logger
}

// New builds a Recorder. sec is required (NIS2-audit always emits); gdprClient may
// be nil (GDPR-audit methods then no-op).
func New(sec *secevents.Emitter, gdprClient *gdpr.Client, log *zap.Logger) *Recorder {
	if log == nil {
		log = zap.NewNop()
	}

	return &Recorder{sec: sec, gdpr: gdprClient, log: log}
}

// logger returns the request-correlated logger when a request context is present —
// so a fallback/diagnostic line is joinable to its request by correlation id +
// trace id — else the component logger for a context-free background path.
func (r *Recorder) logger(ctx *azugo.Context) *zap.Logger {
	if ctx != nil {
		return ctx.Log()
	}

	return r.log
}

// ---- NIS2-audit — security telemetry (go-sec-events → SIEM) -------------------

// LoginSuccess records a successful interactive login.
func (r *Recorder) LoginSuccess(ctx *azugo.Context, actorID, loa, method string) {
	r.auth(ctx, actorID, loa, method, false, broker.OutcomeSuccess, "")
}

// LoginFailure records a failed login (no subject established).
func (r *Recorder) LoginFailure(ctx *azugo.Context, reason string) {
	r.auth(ctx, "", "", "", false, broker.OutcomeFailure, reason)
}

// StepUpSuccess records a successful step-up / re-auth.
func (r *Recorder) StepUpSuccess(ctx *azugo.Context, actorID, loa, method string) {
	r.auth(ctx, actorID, loa, method, true, broker.OutcomeSuccess, "")
}

// StepUpFailure records a failed step-up (e.g. achieved method mismatch).
func (r *Recorder) StepUpFailure(ctx *azugo.Context, method, reason string) {
	r.auth(ctx, "", "", method, true, broker.OutcomeFailure, reason)
}

// Logout records an interactive logout (session termination). actorID/method may
// be empty when the caller could not resolve the session. Federated indicates the
// browser was sent on to the eParaksts IdP logout to clear its SSO cookie.
func (r *Recorder) Logout(ctx *azugo.Context, actorID, method string, federated bool) {
	attrs := map[string]any{secevents.AttrKind: "logout", "federated": federated}
	if method != "" {
		attrs[secevents.AttrMethod] = method
	}

	r.emit(ctx, secevents.EventAuthentication, secevents.SeverityInfo, broker.OutcomeSuccess,
		actorRef(actorID, "user", ""), attrs)
}

func (r *Recorder) auth(ctx *azugo.Context, actorID, loa, method string, stepUp bool, outcome broker.Outcome, reason string) {
	sev := secevents.SeverityInfo
	if outcome != broker.OutcomeSuccess {
		sev = secevents.SeverityWarning
	}

	attrs := map[string]any{}
	if method != "" {
		attrs[secevents.AttrMethod] = method
	}
	if loa != "" {
		attrs["loa"] = loa
	}
	if stepUp {
		attrs[secevents.AttrKind] = "step_up"
	}
	if reason != "" {
		attrs[secevents.AttrReason] = reason
	}

	r.emit(ctx, secevents.EventAuthentication, sev, outcome, actorRef(actorID, "user", loa), attrs)
}

// UserTokenIssued records issuance (or refresh) of a DPoP-bound user token.
func (r *Recorder) UserTokenIssued(ctx *azugo.Context, subject, loa, method, audience string, scopes []string) {
	attrs := map[string]any{"audience": audience, "scopes": scopes}
	if method != "" {
		attrs[secevents.AttrMethod] = method
	}

	r.emit(ctx, eventUserToken, secevents.SeverityInfo, broker.OutcomeSuccess, actorRef(subject, "user", loa), attrs)
}

// ServiceTokenIssued records issuance of a DPoP-bound service (client-credentials)
// token.
func (r *Recorder) ServiceTokenIssued(ctx *azugo.Context, clientID, audience string, scopes []string) {
	r.emit(ctx, secevents.EventServiceToken, secevents.SeverityInfo, broker.OutcomeSuccess,
		actorRef(clientID, "service", ""),
		map[string]any{secevents.AttrKind: secevents.TokenKindIssuance, "audience": audience, "scopes": scopes})
}

// DelegatedTokenIssued records issuance of a DPoP-bound on-behalf-of token
// (token exchange): the requesting service acting for a user toward an
// audience. The acting service is the event actor; the user it acts for is
// recorded as on_behalf_of so the delegation is auditable.
func (r *Recorder) DelegatedTokenIssued(ctx *azugo.Context, clientID, onBehalfOf, audience string, scopes []string) {
	r.emit(ctx, secevents.EventServiceToken, secevents.SeverityInfo, broker.OutcomeSuccess,
		actorRef(clientID, "service", ""),
		map[string]any{
			secevents.AttrKind: secevents.TokenKindIssuance,
			"delegation":       true,
			"on_behalf_of":     onBehalfOf,
			"audience":         audience,
			"scopes":           scopes,
		})
}

// emit builds a security envelope and delivers it through go-sec-events. All
// call sites are request-scoped, so ctx is always present.
func (r *Recorder) emit(ctx *azugo.Context, eventType string, sev secevents.Severity, outcome broker.Outcome, actor *broker.Actor, attrs map[string]any) {
	if r == nil || r.sec == nil {
		return
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[secevents.AttrSeverity] = string(sev)

	ev := &broker.Envelope{
		EventType:  eventType,
		Categories: []broker.Category{broker.CategorySecurity},
		Actor:      actor,
		Outcome:    outcome,
		IP:         clientIP(ctx),
		Attributes: attrs,
	}

	if err := r.sec.Emit(ctx, ev); err != nil {
		r.logger(ctx).Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
	}
}

// ---- GDPR-audit — personal-data access (go-gdpr-audit → access-audit) ---------

// IdentityWritten records the personal-data write the login flow performs on the
// identity record: IdentityCreated on first login, IdentityUpdated on a profile
// refresh. Routine (fail-open): a delivery problem is buffered by the client and
// logged, never failing the login (the back-pressure contract). No-op when the
// GDPR client is not configured.
func (r *Recorder) IdentityWritten(ctx *azugo.Context, subjectID, loa string, created bool) {
	if r == nil || r.gdpr == nil {
		return
	}

	id := gdpr.Identity{
		Actor:     broker.Actor{ID: subjectID, Type: "user", Assurance: loa},
		SubjectID: subjectID,
		Purpose:   gdpr.PurposeAccountManagement,
		Channel:   gdpr.ChannelInteractive,
	}

	var err error
	if created {
		err = r.gdpr.IdentityCreated(ctx, id)
	} else {
		err = r.gdpr.IdentityUpdated(ctx, id)
	}

	if err != nil {
		// Non-fatal for the user operation (graceful degradation); alert on the
		// client's `dropped` metric instead of failing logins on audit pressure.
		r.logger(ctx).Warn("gdpr access record not persisted (non-fatal)",
			zap.Bool("created", created), zap.Error(err))
	}
}

// actorRef returns a broker.Actor pointer when it carries any identity, else nil.
func actorRef(id, typ, assurance string) *broker.Actor {
	if id == "" && assurance == "" {
		return nil
	}

	return &broker.Actor{ID: id, Type: typ, Assurance: assurance}
}

// clientIP extracts the originating client IP from the gateway-set
// X-Forwarded-For header (first hop).
func clientIP(ctx *azugo.Context) string {
	v := ctx.Header.Get("X-Forwarded-For")
	if v == "" {
		return ""
	}

	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}

	return strings.TrimSpace(v)
}
