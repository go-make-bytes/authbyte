package session_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"github.com/go-quicktest/qt"
)

// sharedStore is the shared-session half of the service's session store.
type sharedStore interface {
	CreateShared(ctx context.Context, id string, sh *session.Shared) error
	ReplaceShared(ctx context.Context, id string, sh *session.Shared) error
	LoadShared(ctx context.Context, id string) (*session.Shared, error)
	PutSharedApp(ctx context.Context, id, client, sid string, until time.Time) (string, error)
	SharedApps(ctx context.Context, id string) (map[string]string, error)
	EndShared(ctx context.Context, id string) error
}

// bothSharedStores runs check over the in-memory store and, with
// VALKEY_TEST_URL set, the service's store on a real Valkey.
func bothSharedStores(t *testing.T, check func(t *testing.T, s sharedStore)) {
	t.Helper()

	t.Run("memory", func(t *testing.T) { check(t, sessiontest.NewMemory()) })
	t.Run("valkey", func(t *testing.T) { check(t, valkeyStore(t)) })
}

func aShared(subject string) *session.Shared {
	sh := &session.Shared{SecretHash: "hash", Subject: subject}
	now := time.Now()
	sh.Keep(session.Way{Method: "webEid", SignedIn: now, Ends: now.Add(time.Hour)})

	return sh
}

// A shared session is made once, read back, replaced only while it lives, and
// ended with its list of app sessions.
func TestASharedSessionLivesAndEnds(t *testing.T) {
	bothSharedStores(t, func(t *testing.T, s sharedStore) {
		ctx := context.Background()
		sh := aShared("sub-anna")

		qt.Assert(t, qt.IsNil(s.CreateShared(ctx, "one", sh)))
		qt.Check(t, qt.IsNotNil(s.CreateShared(ctx, "one", aShared("sub-janis"))))
		got, err := s.LoadShared(ctx, "one")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.Subject, "sub-anna"))

		got.SecretHash = "another"
		qt.Check(t, qt.IsNil(s.ReplaceShared(ctx, "one", got)))
		again, _ := s.LoadShared(ctx, "one")
		qt.Check(t, qt.Equals(again.SecretHash, "another"))

		_, err = s.PutSharedApp(ctx, "one", "app", "sid-1", sh.ExpiresAt)
		qt.Check(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNil(s.EndShared(ctx, "one")))
		_, err = s.LoadShared(ctx, "one")
		qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
		apps, err := s.SharedApps(ctx, "one")
		qt.Check(t, qt.IsNil(err))
		qt.Check(t, qt.HasLen(apps, 0))
		qt.Check(t, qt.ErrorIs(s.ReplaceShared(ctx, "one", got), session.ErrNotFound))
	})
}

// Case 29, 36: app sessions recorded at once, by many clients, are all kept; one
// client recorded again answers the session it had, once.
func TestAppSessionsAreKeptPerClientAtOnce(t *testing.T) {
	bothSharedStores(t, func(t *testing.T, s sharedStore) {
		ctx := context.Background()
		sh := aShared("sub-anna")
		qt.Assert(t, qt.IsNil(s.CreateShared(ctx, "one", sh)))

		const n = 32
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				_, err := s.PutSharedApp(ctx, "one", fmt.Sprintf("app-%d", i), fmt.Sprintf("sid-%d", i), sh.ExpiresAt)
				qt.Check(t, qt.IsNil(err))
			})
		}
		wg.Wait()
		apps, err := s.SharedApps(ctx, "one")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.HasLen(apps, n))

		var mu sync.Mutex
		var answered []string
		for i := range 2 {
			wg.Go(func() {
				prev, err := s.PutSharedApp(ctx, "one", "twice", fmt.Sprintf("tab-%d", i), sh.ExpiresAt)
				qt.Check(t, qt.IsNil(err))
				mu.Lock()
				answered = append(answered, prev)
				mu.Unlock()
			})
		}
		wg.Wait()
		apps, _ = s.SharedApps(ctx, "one")
		last := apps["twice"]
		qt.Check(t, qt.IsTrue(last == "tab-0" || last == "tab-1"))
		// One of the two was answered nothing; the other the first one's session.
		qt.Check(t, qt.ContentEquals(answered, []string{"", map[string]string{"tab-0": "tab-1", "tab-1": "tab-0"}[last]}))

		_, err = s.PutSharedApp(ctx, "one", "late", "sid", time.Now().Add(-time.Second))
		qt.Check(t, qt.IsTrue(errors.Is(err, session.ErrNotFound)))
	})
}
