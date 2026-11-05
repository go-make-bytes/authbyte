package session_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"github.com/go-quicktest/qt"
)

// connectionStore is what the connections' contract checks: the index of the AI
// apps connected as each assistant.
type connectionStore interface {
	AddConnection(ctx context.Context, tenant, assistant string, c session.Connection, until time.Time) error
	Connections(ctx context.Context, tenant, assistant string) ([]session.Connection, error)
	RemoveConnection(ctx context.Context, tenant, assistant string, c session.Connection) error
}

func bothConnectionStores(t *testing.T, check func(t *testing.T, s connectionStore)) {
	t.Helper()

	t.Run("valkey", func(t *testing.T) { check(t, valkeyStore(t)) })
	t.Run("memory", func(t *testing.T) { check(t, sessiontest.NewMemory()) })
}

const (
	tenantA    = "01TENANTA0000000000000000A"
	tenantB    = "01TENANTB0000000000000000B"
	assistant1 = "svc:assistant-01ASS1STANT000000000000000A"
	assistant2 = "svc:assistant-01ASS1STANT000000000000000B"
)

func ids(cs []session.Connection) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID+"="+c.SessionID)
	}
	slices.Sort(out)

	return out
}

// An assistant's connections are kept by workspace and assistant: each is listed
// under its own pair only, and a removed one is gone while the others stay.
func TestConnectionsAreKeptPerWorkspaceAndAssistant(t *testing.T) {
	bothConnectionStores(t, func(t *testing.T, s connectionStore) {
		ctx := context.Background()
		until := time.Now().Add(time.Hour)
		one := session.Connection{ID: "public-1", SessionID: "sid-1"}
		two := session.Connection{ID: "public-2", SessionID: "sid-2"}
		other := session.Connection{ID: "public-3", SessionID: "sid-3"}
		elsewhere := session.Connection{ID: "public-4", SessionID: "sid-4"}

		qt.Assert(t, qt.IsNil(s.AddConnection(ctx, tenantA, assistant1, one, until)))
		qt.Assert(t, qt.IsNil(s.AddConnection(ctx, tenantA, assistant1, two, until)))
		qt.Assert(t, qt.IsNil(s.AddConnection(ctx, tenantA, assistant2, other, until)))
		qt.Assert(t, qt.IsNil(s.AddConnection(ctx, tenantB, assistant1, elsewhere, until)))

		got, err := s.Connections(ctx, tenantA, assistant1)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(ids(got), []string{"public-1=sid-1", "public-2=sid-2"}))

		got, err = s.Connections(ctx, tenantB, assistant1)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(ids(got), []string{"public-4=sid-4"}), qt.Commentf("another workspace's pair is its own"))

		qt.Assert(t, qt.IsNil(s.RemoveConnection(ctx, tenantA, assistant1, one)))
		qt.Assert(t, qt.IsNil(s.RemoveConnection(ctx, tenantA, assistant1, one)), qt.Commentf("removing it again is no error"))
		got, err = s.Connections(ctx, tenantA, assistant1)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(ids(got), []string{"public-2=sid-2"}))

		got, err = s.Connections(ctx, tenantA, "svc:assistant-01NEVERADDED0000000000000Z")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.HasLen(got, 0), qt.Commentf("an assistant with none answers none"))
	})
}

// A connection is listed until its end and not at it; one whose end has passed
// is never added.
func TestAConnectionIsListedUntilItsEnd(t *testing.T) {
	bothConnectionStores(t, func(t *testing.T, s connectionStore) {
		ctx := context.Background()
		short := session.Connection{ID: "public-short", SessionID: "sid-short"}
		long := session.Connection{ID: "public-long", SessionID: "sid-long"}

		qt.Assert(t, qt.IsNil(s.AddConnection(ctx, tenantA, assistant1, short, time.Now().Add(1200*time.Millisecond))))
		qt.Assert(t, qt.IsNil(s.AddConnection(ctx, tenantA, assistant1, long, time.Now().Add(time.Hour))))

		got, err := s.Connections(ctx, tenantA, assistant1)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.HasLen(got, 2), qt.Commentf("before its end"))

		time.Sleep(1300 * time.Millisecond)
		got, err = s.Connections(ctx, tenantA, assistant1)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(ids(got), []string{"public-long=sid-long"}), qt.Commentf("after its end"))

		err = s.AddConnection(ctx, tenantA, assistant1, session.Connection{ID: "p", SessionID: "s"}, time.Now().Add(-time.Second))
		notFound(t, err)
	})
}

// The in-memory store, on its own clock: a connection ending at t is listed a
// moment before t and not at t, as a session ends when now is not before its end.
func TestTheMemoryStoreEndsAConnectionAtItsEnd(t *testing.T) {
	m := sessiontest.NewMemory()
	start := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	m.SetClock(func() time.Time { return start })
	ctx := context.Background()
	end := start.Add(time.Hour)
	qt.Assert(t, qt.IsNil(m.AddConnection(ctx, tenantA, assistant1, session.Connection{ID: "p", SessionID: "s"}, end)))

	m.SetClock(func() time.Time { return end.Add(-time.Millisecond) })
	got, err := m.Connections(ctx, tenantA, assistant1)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(got, 1))

	m.SetClock(func() time.Time { return end })
	got, err = m.Connections(ctx, tenantA, assistant1)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(got, 0))
}
