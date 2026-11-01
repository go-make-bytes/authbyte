package session_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

// store is what the contract checks: the service's session store.
type store interface {
	SaveFlow(ctx context.Context, state string, f *session.Flow, ttl time.Duration) error
	ConsumeFlow(ctx context.Context, state string) (*session.Flow, error)
	SaveAppCode(ctx context.Context, code string, c *session.AppCode, ttl time.Duration) error
	ConsumeAppCode(ctx context.Context, code string) (*session.AppCode, error)
	CreateSession(ctx context.Context, sid string, sess *session.Session, lifetime time.Duration) error
	ReplaceSession(ctx context.Context, sid string, sess *session.Session) error
	LoadSession(ctx context.Context, sid string) (*session.Session, error)
	DeleteSession(ctx context.Context, sid string) error
	SaveRefresh(ctx context.Context, key string, g *session.RefreshGrant, expiresAt time.Time) error
	LoadRefresh(ctx context.Context, key string) (*session.RefreshGrant, error)
	DeleteRefresh(ctx context.Context, key string) error
}

// valkeyCache returns a started cache on a real Valkey or Redis, named by
// VALKEY_TEST_URL (for example redis://localhost:6379/15), under prefix. Without
// the variable the test is skipped: these tests prove the store against a server,
// which a unit run does not have.
func valkeyCache(t *testing.T, prefix string) *cache.Cache {
	t.Helper()

	url := os.Getenv("VALKEY_TEST_URL")
	if url == "" {
		t.Skip("VALKEY_TEST_URL is not set")
	}

	c := cache.New(
		cache.RedisCache,
		cache.ConnectionString(url),
		cache.KeyPrefix(prefix),
		cache.ClientCache(false),
	)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)
	qt.Assert(t, qt.IsNil(c.Ping(context.Background())))

	return c
}

func testPrefix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)

	return "authbyte-session-test-" + hex.EncodeToString(b)
}

func valkeyStore(t *testing.T) *session.Store {
	t.Helper()

	s, err := session.New(valkeyCache(t, testPrefix()))
	qt.Assert(t, qt.IsNil(err))

	return s
}

// bothStores runs check over the service's store on a real Valkey and over the
// in-memory store the route tests use, so the two answer alike.
func bothStores(t *testing.T, check func(t *testing.T, s store)) {
	t.Helper()

	t.Run("valkey", func(t *testing.T) { check(t, valkeyStore(t)) })
	t.Run("memory", func(t *testing.T) { check(t, sessiontest.NewMemory()) })
}

func notFound(t *testing.T, err error) {
	t.Helper()
	qt.Check(t, qt.IsTrue(errors.Is(err, session.ErrNotFound)), qt.Commentf("got %v", err))
}

func TestAFlowAndACodeAreTakenOnce(t *testing.T) {
	bothStores(t, func(t *testing.T, s store) {
		ctx := context.Background()

		qt.Assert(t, qt.IsNil(s.SaveFlow(ctx, "state-1", &session.Flow{ClientID: "portal-spa"}, time.Minute)))
		f, err := s.ConsumeFlow(ctx, "state-1")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(f.ClientID, "portal-spa"))
		_, err = s.ConsumeFlow(ctx, "state-1")
		notFound(t, err)

		qt.Assert(t, qt.IsNil(s.SaveAppCode(ctx, "code-1", &session.AppCode{SessionID: "sid"}, time.Minute)))
		c, err := s.ConsumeAppCode(ctx, "code-1")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(c.SessionID, "sid"))
		_, err = s.ConsumeAppCode(ctx, "code-1")
		notFound(t, err)
	})
}

func TestAMissingSessionAndGrantAreNotFound(t *testing.T) {
	bothStores(t, func(t *testing.T, s store) {
		_, err := s.LoadSession(context.Background(), "no-such-session")
		notFound(t, err)
		_, err = s.LoadRefresh(context.Background(), "no-such-grant")
		notFound(t, err)
	})
}

// A session is created once, with its end fixed from now; a second create under
// the same id is refused.
func TestASessionIsCreatedOnceWithItsEnd(t *testing.T) {
	bothStores(t, func(t *testing.T, s store) {
		ctx := context.Background()
		before := time.Now()

		sess := &session.Session{Subject: "the-person"}
		qt.Assert(t, qt.IsNil(s.CreateSession(ctx, "sid", sess, time.Hour)))
		qt.Check(t, qt.IsFalse(sess.ExpiresAt.Before(before.Add(time.Hour))))
		qt.Check(t, qt.IsTrue(sess.ExpiresAt.Before(time.Now().Add(time.Hour+time.Second))))

		got, err := s.LoadSession(ctx, "sid")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.Subject, "the-person"))
		qt.Check(t, qt.IsTrue(got.ExpiresAt.Equal(sess.ExpiresAt)))

		qt.Check(t, qt.IsNotNil(s.CreateSession(ctx, "sid", &session.Session{Subject: "another"}, time.Hour)))
		got, err = s.LoadSession(ctx, "sid")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.Subject, "the-person"))
	})
}

// A replace writes over the held session and keeps its end: the session still
// ends when its lifetime from the sign-in runs out.
func TestAReplaceKeepsTheSessionsEnd(t *testing.T) {
	bothStores(t, func(t *testing.T, s store) {
		ctx := context.Background()

		sess := &session.Session{Subject: "the-person"}
		qt.Assert(t, qt.IsNil(s.CreateSession(ctx, "sid", sess, 1200*time.Millisecond)))

		time.Sleep(600 * time.Millisecond)
		sess.LoginMethod = "webEid"
		qt.Assert(t, qt.IsNil(s.ReplaceSession(ctx, "sid", sess)))

		got, err := s.LoadSession(ctx, "sid")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.LoginMethod, "webEid"))

		time.Sleep(700 * time.Millisecond)
		_, err = s.LoadSession(ctx, "sid")
		notFound(t, err)
	})
}

// A session ended while a save was under way stays ended: the save writes only
// over a session that still exists.
func TestAReplaceAfterSignOutDoesNotBringTheSessionBack(t *testing.T) {
	bothStores(t, func(t *testing.T, s store) {
		ctx := context.Background()

		sess := &session.Session{Subject: "the-person"}
		qt.Assert(t, qt.IsNil(s.CreateSession(ctx, "sid", sess, time.Hour)))
		loaded, err := s.LoadSession(ctx, "sid")
		qt.Assert(t, qt.IsNil(err))

		qt.Assert(t, qt.IsNil(s.DeleteSession(ctx, "sid")))

		loaded.LoginMethod = "webEid"
		notFound(t, s.ReplaceSession(ctx, "sid", loaded))

		_, err = s.LoadSession(ctx, "sid")
		notFound(t, err)
	})
}

// A replaced session leaves the store at its end, not later: the person's data
// it carries is not kept past the lifetime that ends it.
func TestAReplacedSessionLeavesTheStoreAtItsEnd(t *testing.T) {
	c := valkeyCache(t, testPrefix())
	s, err := session.New(c)
	qt.Assert(t, qt.IsNil(err))
	sessions, err := cache.Create[*session.Session](c, "sessions")
	qt.Assert(t, qt.IsNil(err))
	ctx := context.Background()

	sess := &session.Session{Subject: "the-person"}
	qt.Assert(t, qt.IsNil(s.CreateSession(ctx, "sid", sess, 2*time.Second)))
	time.Sleep(500 * time.Millisecond)
	qt.Assert(t, qt.IsNil(s.ReplaceSession(ctx, "sid", sess)))

	left, ok, err := sessions.TTL(ctx, "sid")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.IsTrue(left <= 1600*time.Millisecond), qt.Commentf("%s left", left))
}

// A refresh grant lives until the end it is given, and not past a deletion.
func TestARefreshGrantLivesUntilItsEnd(t *testing.T) {
	bothStores(t, func(t *testing.T, s store) {
		ctx := context.Background()
		g := &session.RefreshGrant{SessionID: "sid", ClientID: "portal-spa"}

		notFound(t, s.SaveRefresh(ctx, "ended", g, time.Now().Add(-time.Second)))
		_, err := s.LoadRefresh(ctx, "ended")
		notFound(t, err)

		qt.Assert(t, qt.IsNil(s.SaveRefresh(ctx, "short", g, time.Now().Add(500*time.Millisecond))))
		got, err := s.LoadRefresh(ctx, "short")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(got, g))

		qt.Assert(t, qt.IsNil(s.SaveRefresh(ctx, "held", g, time.Now().Add(time.Hour))))
		qt.Assert(t, qt.IsNil(s.DeleteRefresh(ctx, "held")))
		_, err = s.LoadRefresh(ctx, "held")
		notFound(t, err)

		time.Sleep(700 * time.Millisecond)
		_, err = s.LoadRefresh(ctx, "short")
		notFound(t, err)
	})
}

// The raw replace writes the key the typed read reads: this pins the raw write's
// key to the cache's own layout, with and without a configured prefix.
func TestTheReplaceWritesTheKeyTheTypedReadReads(t *testing.T) {
	for _, prefix := range []string{testPrefix(), ""} {
		s, err := session.New(valkeyCache(t, prefix))
		qt.Assert(t, qt.IsNil(err))
		ctx := context.Background()
		sid := "layout-" + testPrefix()
		t.Cleanup(func() { _ = s.DeleteSession(ctx, sid) })

		sess := &session.Session{Subject: "before"}
		qt.Assert(t, qt.IsNil(s.CreateSession(ctx, sid, sess, time.Minute)))
		sess.Subject = "after"
		qt.Assert(t, qt.IsNil(s.ReplaceSession(ctx, sid, sess)), qt.Commentf("prefix %q", prefix))

		got, err := s.LoadSession(ctx, sid)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.Subject, "after"), qt.Commentf("prefix %q", prefix))
	}
}

func TestTheStoreRefusesAMemoryCache(t *testing.T) {
	_, err := session.New(cache.New(cache.MemoryCache))
	qt.Check(t, qt.IsNotNil(err))

	_, err = session.NewProofReplay(cache.New(cache.MemoryCache))
	qt.Check(t, qt.IsNotNil(err))
}

// One DPoP proof is accepted once, also across two instances sharing the store
// [RFC 9449 §11.1].
func TestAProofIsAcceptedOnceAcrossInstances(t *testing.T) {
	prefix := testPrefix()
	one, err := session.NewProofReplay(valkeyCache(t, prefix))
	qt.Assert(t, qt.IsNil(err))
	two, err := session.NewProofReplay(valkeyCache(t, prefix))
	qt.Assert(t, qt.IsNil(err))
	ctx := context.Background()

	first, err := one.CheckAndSet(ctx, "proof-1", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(first))

	again, err := one.CheckAndSet(ctx, "proof-1", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(again))

	elsewhere, err := two.CheckAndSet(ctx, "proof-1", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(elsewhere))

	other, err := two.CheckAndSet(ctx, "proof-2", time.Minute)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(other))
}

// overBuffer returns a string that shares b's memory, the way a request value
// read from the server's reused buffer does.
func overBuffer(b []byte) string {
	return unsafe.String(&b[0], len(b)) //nolint:gosec // the aliasing a request read makes, on purpose
}

// What the store keeps does not change when the request buffer it was read from
// is reused: the store copies keys and values before the request ends.
func TestWhatIsStoredOutlivesTheRequestBuffer(t *testing.T) {
	bothStores(t, func(t *testing.T, s store) {
		ctx := context.Background()

		buf := []byte("state-from-the-request")
		state := overBuffer(buf)
		qt.Assert(t, qt.IsNil(s.SaveFlow(ctx, state, &session.Flow{SPAState: state}, time.Minute)))

		sidBuf := []byte("sid-from-the-request")
		sid := overBuffer(sidBuf)
		qt.Assert(t, qt.IsNil(s.CreateSession(ctx, sid, &session.Session{Subject: sid}, time.Minute)))

		copy(buf, "XXXXXXXXXXXXXXXXXXXXXX")
		copy(sidBuf, "YYYYYYYYYYYYYYYYYYYY")

		f, err := s.ConsumeFlow(ctx, "state-from-the-request")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(f.SPAState, "state-from-the-request"))

		sess, err := s.LoadSession(ctx, "sid-from-the-request")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(sess.Subject, "sid-from-the-request"))
	})
}
