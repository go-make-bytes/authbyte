package routes

import (
	"fmt"
	"sync"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/audit"
	"github.com/go-make-bytes/authbyte/rolebyte"
)

// eventLog records every security envelope emitted.
type eventLog struct {
	mu     sync.Mutex
	events []*broker.Envelope
}

func (l *eventLog) Emit(_ *azugo.Context, ev *broker.Envelope) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)

	return nil
}

// signInMismatches answers the recorded denials raised for a register answer
// about another subject.
func (l *eventLog) signInMismatches() []*broker.Envelope {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []*broker.Envelope
	for _, ev := range l.events {
		if ev.EventType == secevents.EventAuthZDenied && ev.Attributes[secevents.AttrKind] == "sign-in" {
			out = append(out, ev)
		}
	}

	return out
}

// recordingAudit gives the app an audit recorder whose security events the test
// reads.
func recordingAudit(l *eventLog) func(*authbytecore.App) {
	return func(app *authbytecore.App) {
		app.SetAudit(audit.New(secevents.NewEmitter(l), nil, nil))
	}
}

// The register answering about anyone but the person being signed in mints
// nothing, fails the issue closed, and is a security event naming whom it was
// asked about: a healthy deployment never produces one.
func TestARegisterAnswerAboutAnotherPersonIsASecurityEvent(t *testing.T) {
	crossed := fmt.Errorf("%w: asked %q, answered %q", rolebyte.ErrAnswerForAnotherSubject, "sub:a", "sub:b")

	for _, path := range []string{
		"/testonly/scopes?client=product-spa",
		"/testonly/service?tenant=01TENANTACME&allowed=signing-requests:write",
	} {
		events := &eventLog{}
		app := scopesApp(t, &fakeResolver{err: crossed}, recordingAudit(events))

		status, body := get(t, app, path)
		qt.Check(t, qt.Equals(status, fasthttp.StatusBadGateway), qt.Commentf("%s", path))
		qt.Check(t, qt.StringContains(body, `"code":"err:upstream:unavailable"`), qt.Commentf("%s", path))

		got := events.signInMismatches()
		qt.Assert(t, qt.HasLen(got, 1), qt.Commentf("%s: one security event", path))
		qt.Check(t, qt.Equals(got[0].Outcome, broker.OutcomeFailure))
		qt.Check(t, qt.Equals(got[0].Attributes[secevents.AttrReason], "the register answered for another subject"))
	}
}

// A register that cannot be reached is a failure, not a crossing: it fails the
// issue closed and raises no sign-in security event.
func TestAnUnreachableRegisterIsNoSignInSecurityEvent(t *testing.T) {
	events := &eventLog{}
	app := scopesApp(t, &fakeResolver{err: fmt.Errorf("connection refused")}, recordingAudit(events))

	status, _ := get(t, app, "/testonly/scopes?client=product-spa")
	qt.Check(t, qt.Equals(status, fasthttp.StatusBadGateway))
	qt.Check(t, qt.HasLen(events.signInMismatches(), 0))
}
