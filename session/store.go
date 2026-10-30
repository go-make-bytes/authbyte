package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"azugo.io/core/cache"
	"github.com/valkey-io/valkey-go"
)

// The cache instance names. Each is part of every key the cache writes, so
// renaming one ends every session and every login in progress.
const (
	flowInstance    = "flows"
	codeInstance    = "codes"
	sessionInstance = "sessions"
	refreshInstance = "refresh"
)

// Store keeps flows, application codes, sessions and refresh grants in the
// application's shared cache, so they survive a restart and are shared by every
// instance. Values are serialized by the cache, so nothing stored shares memory
// with the request it came from.
type Store struct {
	cache    *cache.Cache
	flows    cache.Instance[*Flow]
	codes    cache.Instance[*AppCode]
	sessions cache.Instance[*Session]
	refresh  cache.Instance[*RefreshGrant]
	now      func() time.Time
}

// New returns a store kept in c, which must have a shared (Valkey or Redis)
// backend: in memory, a login begun on one instance would be unknown to another.
func New(c *cache.Cache) (*Store, error) {
	if c.ConfiguredType() == cache.MemoryCache {
		return nil, errors.New("session: the store needs a Valkey or Redis cache, not memory; set CACHE_TYPE and CACHE_CONNECTION")
	}

	flows, err := cache.Create[*Flow](c, flowInstance)
	if err != nil {
		return nil, err
	}

	codes, err := cache.Create[*AppCode](c, codeInstance)
	if err != nil {
		return nil, err
	}

	sessions, err := cache.Create[*Session](c, sessionInstance)
	if err != nil {
		return nil, err
	}

	refresh, err := cache.Create[*RefreshGrant](c, refreshInstance)
	if err != nil {
		return nil, err
	}

	return &Store{
		cache:    c,
		flows:    flows,
		codes:    codes,
		sessions: sessions,
		refresh:  refresh,
		now:      time.Now,
	}, nil
}

// key is the key the typed cache writes for key in instance: the configured
// prefix, the instance name and the key, joined by ':'. ReplaceSession needs it
// because it writes through the raw connection; a test pins the layout against
// the typed cache.
func (s *Store) key(instance, key string) string {
	prefix := s.cache.ConfiguredKeyPrefix()
	if prefix != "" {
		prefix += ":"
	}

	return prefix + instance + ":" + key
}

// SaveFlow stores login-flow state under the upstream state value.
func (s *Store) SaveFlow(ctx context.Context, state string, f *Flow, ttl time.Duration) error {
	return s.flows.Set(ctx, state, f, cache.TTL[*Flow](ttl))
}

// ConsumeFlow loads and deletes flow state in one step (single use).
func (s *Store) ConsumeFlow(ctx context.Context, state string) (*Flow, error) {
	return take(ctx, s.flows, state)
}

// SaveAppCode stores an issued application authorization code.
func (s *Store) SaveAppCode(ctx context.Context, code string, c *AppCode, ttl time.Duration) error {
	return s.codes.Set(ctx, code, c, cache.TTL[*AppCode](ttl))
}

// ConsumeAppCode loads and deletes an application authorization code in one step
// (single use: a code cannot be redeemed twice by callers racing each other).
func (s *Store) ConsumeAppCode(ctx context.Context, code string) (*AppCode, error) {
	return take(ctx, s.codes, code)
}

// take reads and deletes key in one step (GETDEL).
func take[T any](ctx context.Context, in cache.Instance[*T], key string) (*T, error) {
	v, err := in.Pop(ctx, key)

	var missing cache.KeyNotFoundError
	if errors.As(err, &missing) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, ErrNotFound
	}

	return v, nil
}

// CreateSession stores a new session that lives for lifetime from now and
// records that end on sess. It never writes over a session that exists.
func (s *Store) CreateSession(ctx context.Context, sid string, sess *Session, lifetime time.Duration) error {
	sess.ExpiresAt = s.now().Add(lifetime)

	added, err := s.sessions.Add(ctx, sid, sess, cache.TTL[*Session](lifetime))
	if err != nil {
		return err
	}
	if !added {
		return errors.New("session: a session with this id exists")
	}

	return nil
}

// ReplaceSession writes sess over the live session sid for what is left of its
// lifetime. It writes only over a session that still exists (SET … XX, one step),
// so a session ended while a request was saving it stays ended.
func (s *Store) ReplaceSession(ctx context.Context, sid string, sess *Session) error {
	left := sess.ExpiresAt.Sub(s.now())
	if sess.ExpiresAt.IsZero() || left <= 0 {
		return ErrNotFound
	}

	con := s.cache.Connection()
	if con == nil {
		return cache.ErrCacheUnavailable
	}

	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}

	// The typed cache has no write that is conditional on the key existing, so
	// this one goes through the raw connection under the key the typed cache reads.
	cmd := con.B().Set().Key(s.key(sessionInstance, sid)).Value(string(b)).Xx().Px(left).Build()

	err = con.Do(ctx, cmd).Error()
	if valkey.IsValkeyNil(err) {
		return ErrNotFound
	}

	return err
}

// LoadSession loads a live session.
func (s *Store) LoadSession(ctx context.Context, sid string) (*Session, error) {
	// The typed cache answers a missing key with the zero value and no error, so
	// a nil session is the miss.
	sess, err := s.sessions.Get(ctx, sid)
	if err != nil {
		return nil, err
	}
	if sess == nil || sess.Expired(s.now()) {
		return nil, ErrNotFound
	}

	return sess, nil
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, sid string) error {
	return s.sessions.Delete(ctx, sid)
}

// SaveRefresh keeps a refresh grant under key until expiresAt.
func (s *Store) SaveRefresh(ctx context.Context, key string, g *RefreshGrant, expiresAt time.Time) error {
	left := expiresAt.Sub(s.now())
	if left <= 0 {
		return ErrNotFound
	}

	return s.refresh.Set(ctx, key, g, cache.TTL[*RefreshGrant](left))
}

// LoadRefresh loads the refresh grant kept under key.
func (s *Store) LoadRefresh(ctx context.Context, key string) (*RefreshGrant, error) {
	g, err := s.refresh.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, ErrNotFound
	}

	return g, nil
}

// DeleteRefresh removes the refresh grant kept under key.
func (s *Store) DeleteRefresh(ctx context.Context, key string) error {
	return s.refresh.Delete(ctx, key)
}

// Ping verifies the cache can be reached.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.cache.Ping(ctx); err != nil {
		return fmt.Errorf("session: cache ping: %w", err)
	}

	return nil
}
