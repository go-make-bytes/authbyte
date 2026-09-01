package audit_test

import (
	"sync"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"

	"github.com/go-make-bytes/authbyte/audit"
)

// captureSink records the last security envelope for assertion.
type captureSink struct {
	mu   sync.Mutex
	last *broker.Envelope
}

func (s *captureSink) Emit(_ *azugo.Context, ev *broker.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = ev

	return nil
}

func (s *captureSink) latest() *broker.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.last
}

// withCtx runs fn inside a real request so ctx-based emission works.
func withCtx(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/t", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/t")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
}

func str(v any) string {
	s, _ := v.(string)

	return s
}

func TestLoginSuccessEmitsSecurityEvent(t *testing.T) {
	sink := &captureSink{}
	rec := audit.New(secevents.NewEmitter(sink), nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.LoginSuccess(ctx, "sub-1", "high", "eid")
	})

	ev := sink.latest()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, secevents.EventAuthentication))
	qt.Check(t, qt.Equals(ev.Outcome, broker.OutcomeSuccess))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrSeverity]), string(secevents.SeverityInfo)))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrMethod]), "eid"))
	qt.Check(t, qt.Equals(str(ev.Attributes["loa"]), "high"))
	qt.Assert(t, qt.IsNotNil(ev.Actor))
	qt.Check(t, qt.Equals(ev.Actor.ID, "sub-1"))
	qt.Check(t, qt.Equals(ev.Actor.Type, "user"))
}

func TestStepUpFailureIsWarning(t *testing.T) {
	sink := &captureSink{}
	rec := audit.New(secevents.NewEmitter(sink), nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.StepUpFailure(ctx, "eid", "achieved method mismatch")
	})

	ev := sink.latest()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, secevents.EventAuthentication))
	qt.Check(t, qt.Equals(ev.Outcome, broker.OutcomeFailure))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrSeverity]), string(secevents.SeverityWarning)))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrKind]), "step_up"))
}

func TestServiceTokenIssued(t *testing.T) {
	sink := &captureSink{}
	rec := audit.New(secevents.NewEmitter(sink), nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.ServiceTokenIssued(ctx, "eparaksts-signer", "svc:access-audit", []string{"access-audit:write"})
	})

	ev := sink.latest()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, secevents.EventServiceToken))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrKind]), secevents.TokenKindIssuance))
	qt.Assert(t, qt.IsNotNil(ev.Actor))
	qt.Check(t, qt.Equals(ev.Actor.Type, "service"))
}

// IdentityWritten must be a safe no-op when the GDPR client is not configured.
func TestIdentityWrittenNoopWithoutGDPR(t *testing.T) {
	sink := &captureSink{}
	rec := audit.New(secevents.NewEmitter(sink), nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.IdentityWritten(ctx, "sub-1", "high", true) // must not panic
	})

	qt.Check(t, qt.IsNil(sink.latest())) // no security event emitted by the GDPR-audit path
}
