package audit_test

import (
	"context"
	"sync"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
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
		rec.ServiceTokenIssued(ctx, "eparaksts-signer", "svc:access-audit", "", []string{"access-audit:write"})
	})

	ev := sink.latest()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, secevents.EventServiceToken))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrKind]), secevents.TokenKindIssuance))
	qt.Assert(t, qt.IsNotNil(ev.Actor))
	qt.Check(t, qt.Equals(ev.Actor.Type, "service"))
	// A platform service acting as itself names no organisation.
	_, hasTenant := ev.Attributes["tenant"]
	qt.Check(t, qt.IsFalse(hasTenant))
}

// A service account's token names the organisation it acts for, so the record
// can answer which machines minted for a tenant, and when.
func TestServiceTokenIssuedRecordsTenant(t *testing.T) {
	sink := &captureSink{}
	rec := audit.New(secevents.NewEmitter(sink), nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.ServiceTokenIssued(ctx, "svc:acme-dms", "svc:signbyte-integration-api", "01TENANTACME", []string{"signing-requests:write"})
	})

	ev := sink.latest()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(str(ev.Attributes["tenant"]), "01TENANTACME"))
	qt.Check(t, qt.Equals(ev.Actor.ID, "svc:acme-dms"))
}

// A refused delegation is an authorization denial, attributed to the client
// that asked and naming the subject it asked for.
func TestDelegationRefused(t *testing.T) {
	sink := &captureSink{}
	rec := audit.New(secevents.NewEmitter(sink), nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.DelegationRefused(ctx, "svc:signbyte-integration-api", "svc:signflow", "a platform service acting as itself cannot be acted for")
	})

	ev := sink.latest()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, secevents.EventAuthZDenied))
	qt.Check(t, qt.Equals(ev.Outcome, broker.OutcomeFailure))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrKind]), "delegation"))
	qt.Check(t, qt.Equals(str(ev.Attributes["on_behalf_of"]), "svc:signflow"))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrSeverity]), string(secevents.SeverityWarning)))
	qt.Assert(t, qt.IsNotNil(ev.Actor))
	qt.Check(t, qt.Equals(ev.Actor.ID, "svc:signbyte-integration-api"))
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

// A read of a person's identity code is recorded, naming the service that asked
// and the person whose code it was — never the code itself.
func TestIdentityCodeReadRecordsTheServiceAndThePerson(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*broker.Envelope
	)
	gc, err := gdpr.New(gdpr.Configuration{}, gdpr.PosterFunc(func(_ context.Context, rec *broker.Envelope) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, rec)

		return nil
	}))
	qt.Assert(t, qt.IsNil(err))
	rec := audit.New(secevents.NewEmitter(&captureSink{}), gc, zap.NewNop())

	const person = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	withCtx(t, func(ctx *azugo.Context) {
		rec.IdentityCodeRead(ctx, "svc:register", person)
	})

	mu.Lock()
	defer mu.Unlock()
	qt.Assert(t, qt.HasLen(got, 1))
	ev := got[0]
	qt.Check(t, qt.Equals(ev.EventType, gdpr.EventIdentityRead))
	qt.Check(t, qt.Equals(ev.Operation, broker.OpRead))
	qt.Assert(t, qt.IsNotNil(ev.Actor))
	qt.Check(t, qt.Equals(ev.Actor.ID, "svc:register"))
	qt.Check(t, qt.Equals(ev.Actor.Type, "service"))
	qt.Check(t, qt.DeepEquals(ev.DataSubjects, []string{person}))
	qt.Assert(t, qt.IsNotNil(ev.Resource))
	qt.Check(t, qt.Equals(ev.Resource.ID, person))
	qt.Check(t, qt.Equals(str(ev.Attributes["what"]), "identityCode"))
}

// A person registered by a service is recorded with the service as its actor, on
// a system-to-system channel; registered by an administrator, as a user acting
// interactively.
func TestIdentityRegisteredNamesAServiceCallerAsAService(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*broker.Envelope
	)
	gc, err := gdpr.New(gdpr.Configuration{}, gdpr.PosterFunc(func(_ context.Context, rec *broker.Envelope) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, rec)

		return nil
	}))
	qt.Assert(t, qt.IsNil(err))
	rec := audit.New(secevents.NewEmitter(&captureSink{}), gc, zap.NewNop())

	const person = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	withCtx(t, func(ctx *azugo.Context) {
		rec.IdentityRegistered(ctx, "svc:register", "", person, true)
		rec.IdentityRegistered(ctx, "01ARZ3NDEKTSV4RRFFQ69G5FAW", "high", person, false)
	})

	mu.Lock()
	defer mu.Unlock()
	qt.Assert(t, qt.HasLen(got, 2))
	qt.Check(t, qt.Equals(got[0].Actor.Type, "service"))
	qt.Check(t, qt.Equals(str(got[0].Attributes[gdpr.AttrChannel]), gdpr.ChannelBackground))
	qt.Check(t, qt.Equals(got[1].Actor.Type, "user"))
	qt.Check(t, qt.Equals(str(got[1].Attributes[gdpr.AttrChannel]), gdpr.ChannelInteractive))
}

// Without an access audit set up, a code read records nothing and does not fail.
func TestIdentityCodeReadNoopWithoutGDPR(t *testing.T) {
	rec := audit.New(secevents.NewEmitter(&captureSink{}), nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.IdentityCodeRead(ctx, "svc:register", "01ARZ3NDEKTSV4RRFFQ69G5FAV") // must not panic
	})
}
