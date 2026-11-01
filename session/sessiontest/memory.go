// Package sessiontest holds an in-memory session store for tests. The service
// itself never runs on it: its sessions live in the shared cache. A contract
// test runs the same checks over this store and the real one, so the two answer
// alike.
package sessiontest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/go-make-bytes/authbyte/session"
)

// Memory is a session store kept in a map. Values are stored as JSON, as the
// real store stores them, so a caller changing what it read never changes what
// is stored.
type Memory struct {
	mu      sync.Mutex
	entries map[string]entry
	now     func() time.Time
}

type entry struct {
	value   []byte
	expires time.Time // zero = never
}

// NewMemory returns an empty store on the wall clock.
func NewMemory() *Memory {
	return &Memory{entries: map[string]entry{}, now: time.Now}
}

// SetClock makes the store read the time from now, so a test can move past a
// lifetime without waiting for it.
func (m *Memory) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// Entries returns every live key and its stored value, for a test that checks
// what the store holds.
func (m *Memory) Entries() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make(map[string]string, len(m.entries))
	for k, e := range m.entries {
		if m.live(e) {
			out[k] = string(e.value)
		}
	}

	return out
}

// Keys returns the live keys that begin with prefix.
func (m *Memory) Keys(prefix string) []string {
	var out []string
	for k := range m.Entries() {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}

	return out
}

func (m *Memory) live(e entry) bool {
	return e.expires.IsZero() || m.now().Before(e.expires)
}

func (m *Memory) put(key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	e := entry{value: b}
	if ttl > 0 {
		e.expires = m.now().Add(ttl)
	}
	m.entries[key] = e

	return nil
}

func (m *Memory) get(key string, v any, del bool) error {
	m.mu.Lock()
	e, ok := m.entries[key]
	if ok && !m.live(e) {
		delete(m.entries, key)
		ok = false
	}
	if ok && del {
		delete(m.entries, key)
	}
	m.mu.Unlock()

	if !ok {
		return session.ErrNotFound
	}

	return json.Unmarshal(e.value, v)
}

func (m *Memory) SaveFlow(_ context.Context, state string, f *session.Flow, ttl time.Duration) error {
	return m.put("flow:"+state, f, ttl)
}

func (m *Memory) ConsumeFlow(_ context.Context, state string) (*session.Flow, error) {
	var f session.Flow
	if err := m.get("flow:"+state, &f, true); err != nil {
		return nil, err
	}

	return &f, nil
}

func (m *Memory) SaveAppCode(_ context.Context, code string, c *session.AppCode, ttl time.Duration) error {
	return m.put("code:"+code, c, ttl)
}

func (m *Memory) ConsumeAppCode(_ context.Context, code string) (*session.AppCode, error) {
	var c session.AppCode
	if err := m.get("code:"+code, &c, true); err != nil {
		return nil, err
	}

	return &c, nil
}

func (m *Memory) CreateSession(_ context.Context, sid string, sess *session.Session, lifetime time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if e, ok := m.entries["sess:"+sid]; ok && m.live(e) {
		return errors.New("session: a session with this id exists")
	}

	sess.ExpiresAt = m.now().Add(lifetime)
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	m.entries["sess:"+sid] = entry{value: b, expires: sess.ExpiresAt}

	return nil
}

func (m *Memory) ReplaceSession(_ context.Context, sid string, sess *session.Session) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	e, ok := m.entries["sess:"+sid]
	if !ok || !m.live(e) || sess.Expired(now) {
		return session.ErrNotFound
	}
	m.entries["sess:"+sid] = entry{value: b, expires: sess.ExpiresAt}

	return nil
}

func (m *Memory) LoadSession(_ context.Context, sid string) (*session.Session, error) {
	var sess session.Session
	if err := m.get("sess:"+sid, &sess, false); err != nil {
		return nil, err
	}

	m.mu.Lock()
	expired := sess.Expired(m.now())
	m.mu.Unlock()
	if expired {
		return nil, session.ErrNotFound
	}

	return &sess, nil
}

func (m *Memory) DeleteSession(_ context.Context, sid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, "sess:"+sid)

	return nil
}

func (m *Memory) SaveRefresh(_ context.Context, key string, g *session.RefreshGrant, expiresAt time.Time) error {
	m.mu.Lock()
	ttl := expiresAt.Sub(m.now())
	m.mu.Unlock()
	if ttl <= 0 {
		return session.ErrNotFound
	}

	return m.put("refresh:"+key, g, ttl)
}

func (m *Memory) LoadRefresh(_ context.Context, key string) (*session.RefreshGrant, error) {
	var g session.RefreshGrant
	if err := m.get("refresh:"+key, &g, false); err != nil {
		return nil, err
	}

	return &g, nil
}

func (m *Memory) DeleteRefresh(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, "refresh:"+key)

	return nil
}

func (m *Memory) Ping(context.Context) error { return nil }
