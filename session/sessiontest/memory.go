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

func (m *Memory) TakeRefresh(_ context.Context, key string) (*session.RefreshGrant, error) {
	var g session.RefreshGrant
	if err := m.get("refresh:"+key, &g, true); err != nil {
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

func (m *Memory) CreateShared(_ context.Context, id string, sh *session.Shared) error {
	b, err := json.Marshal(sh)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if sh.Expired(m.now()) {
		return session.ErrNotFound
	}
	if e, ok := m.entries["shared:"+id]; ok && m.live(e) {
		return errors.New("session: a shared session with this id exists")
	}
	m.entries["shared:"+id] = entry{value: b, expires: sh.ExpiresAt}

	return nil
}

func (m *Memory) ReplaceShared(_ context.Context, id string, sh *session.Shared) error {
	b, err := json.Marshal(sh)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries["shared:"+id]
	if !ok || !m.live(e) || sh.Expired(m.now()) {
		return session.ErrNotFound
	}
	m.entries["shared:"+id] = entry{value: b, expires: sh.ExpiresAt}

	return nil
}

func (m *Memory) LoadShared(_ context.Context, id string) (*session.Shared, error) {
	var sh session.Shared
	if err := m.get("shared:"+id, &sh, false); err != nil {
		return nil, err
	}

	m.mu.Lock()
	expired := sh.Expired(m.now())
	m.mu.Unlock()
	if expired {
		return nil, session.ErrNotFound
	}

	return &sh, nil
}

func (m *Memory) PutSharedApp(_ context.Context, id, client, sid string, until time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.now().Before(until) {
		return "", session.ErrNotFound
	}

	apps := map[string]string{}
	if e, ok := m.entries["shared-apps:"+id]; ok && m.live(e) {
		if err := json.Unmarshal(e.value, &apps); err != nil {
			return "", err
		}
	}
	previous := apps[client]
	apps[client] = sid

	b, err := json.Marshal(apps)
	if err != nil {
		return "", err
	}
	m.entries["shared-apps:"+id] = entry{value: b, expires: until}

	return previous, nil
}

func (m *Memory) SharedApps(_ context.Context, id string) (map[string]string, error) {
	apps := map[string]string{}
	if err := m.get("shared-apps:"+id, &apps, false); err != nil && !errors.Is(err, session.ErrNotFound) {
		return nil, err
	}

	return apps, nil
}

func (m *Memory) EndShared(_ context.Context, id string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries["shared:"+id]
	delete(m.entries, "shared:"+id)
	if !ok || !m.live(e) {
		return nil, session.ErrNotFound
	}

	apps := map[string]string{}
	if e, ok := m.entries["shared-apps:"+id]; ok && m.live(e) {
		if err := json.Unmarshal(e.value, &apps); err != nil {
			return nil, err
		}
	}
	delete(m.entries, "shared-apps:"+id)

	return apps, nil
}

// connections is an index as the real store keeps it: each connection by its
// public name and session key, with its end in Unix milliseconds.
func (m *Memory) connections(tenant, assistant string) (string, map[string]int64) {
	key := "conn:" + tenant + "/" + assistant
	index := map[string]int64{}
	if e, ok := m.entries[key]; ok && m.live(e) {
		_ = json.Unmarshal(e.value, &index)
	}

	return key, index
}

func (m *Memory) AddConnection(_ context.Context, tenant, assistant string, c session.Connection, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.now().Before(until) {
		return session.ErrNotFound
	}

	key, index := m.connections(tenant, assistant)
	index[c.ID+" "+c.SessionID] = until.UnixMilli()
	b, err := json.Marshal(index)
	if err != nil {
		return err
	}
	e := entry{value: b, expires: until}
	if old, ok := m.entries[key]; ok && m.live(old) && old.expires.After(until) {
		e.expires = old.expires
	}
	m.entries[key] = e

	return nil
}

func (m *Memory) Connections(_ context.Context, tenant, assistant string) ([]session.Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, index := m.connections(tenant, assistant)
	now := m.now().UnixMilli()
	var out []session.Connection
	for k, end := range index {
		if end <= now {
			continue
		}
		if id, sid, ok := strings.Cut(k, " "); ok {
			out = append(out, session.Connection{ID: id, SessionID: sid})
		}
	}

	return out, nil
}

func (m *Memory) RemoveConnection(_ context.Context, tenant, assistant string, c session.Connection) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, index := m.connections(tenant, assistant)
	if _, ok := index[c.ID+" "+c.SessionID]; !ok {
		return nil
	}
	delete(index, c.ID+" "+c.SessionID)
	b, err := json.Marshal(index)
	if err != nil {
		return err
	}
	m.entries[key] = entry{value: b, expires: m.entries[key].expires}

	return nil
}

func (m *Memory) Ping(context.Context) error { return nil }
