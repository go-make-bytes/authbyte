// Package session holds short-lived auth-flow state (the SPA↔Auth PKCE/state
// and the Auth↔Entrust leg) and server-side user sessions / refresh material,
// in Redis.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNotFound is returned when a flow or session key is absent or expired.
var ErrNotFound = errors.New("session: not found")

// Flow is the transient state of an in-progress login, keyed by the upstream
// (Auth↔Entrust) state value.
type Flow struct {
	// SPA-side PKCE (the SPA is the client of the Auth service).
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	// RedirectURI the SPA expects the app authorization code returned to.
	AppRedirectURI string `json:"app_redirect_uri"`
	// SPAState echoes the SPA's own state parameter.
	SPAState string `json:"spa_state"`
	// Entrust leg.
	EntrustRedirectURI string `json:"entrust_redirect_uri"`
	// Whether this flow is a step-up (re-auth) and the method requested.
	StepUp         bool   `json:"step_up"`
	RequestedLogin string `json:"requested_login"`
	// ExistingSession id to update on step-up completion.
	SessionID string `json:"session_id"`
	// ClientID of the public client that initiated the authorization request.
	ClientID string `json:"client_id"`
	// WebEIDNonce is the challenge nonce issued for a Web eID card login (the Auth
	// service owns it; the engine's stateless /auth/validate checks the token
	// against it). Empty for the eParaksts redirect flow.
	WebEIDNonce string `json:"webeid_nonce,omitempty"`
}

// AppCode binds an issued application authorization code (Auth→SPA) to the
// authenticated session, pending the SPA's /token exchange.
type AppCode struct {
	SessionID           string `json:"session_id"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	// ClientID and RedirectURI are echo-checked at /token ([RFC 6749 §4.1.3]).
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

// Session is the server-side user session.
type Session struct {
	Subject      string   `json:"subject"`
	Name         string   `json:"name"`
	GivenName    string   `json:"given_name"`
	FamilyName   string   `json:"family_name"`
	SerialNumber string   `json:"serial_number"`
	LoA          string   `json:"loa"`
	LoginMethod  string   `json:"login_method"`
	Scopes       []string `json:"scopes"`
	// Thumbprint is the SPA's DPoP key thumbprint the session's tokens bind to.
	Thumbprint string `json:"thumbprint"`
	// Capabilities is the signing-capability catalog captured at login, when
	// the upstream provides one. nil = not captured (the signing-time fallback
	// resolves identities itself).
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// Capabilities is the signing capability set derived at login from the
// identity provider's sign-identity profile: which signing identity this
// session's login method uses, its certificate, the paired authentication
// certificate, and the organisation seals the person may sign with. Derived
// data only — no upstream token is ever stored. The certificates carry
// personal data: they are never logged and they die with the session. Every
// field is optional; a signing act uses what is present and falls back to
// resolving the rest itself.
type Capabilities struct {
	SignIdentityID     string `json:"sign_identity_id,omitempty"`
	SigningCertificate string `json:"signing_certificate,omitempty"`
	AuthCertificate    string `json:"auth_certificate,omitempty"`
	Seals              []Seal `json:"seals,omitempty"`
	// SealsKnown marks that the seal catalog was actually read on this login
	// path — an empty Seals list then means the person verifiably holds no
	// seals, as opposed to seal availability being unknown (e.g. a login path
	// that never sees the provider's profile).
	SealsKnown bool `json:"seals_known,omitempty"`
}

// Seal is one organisation seal the person may sign with: the sign-identity id
// a signing act selects it by, the display name a picker shows (from the
// seal's CN label), and its certificate.
type Seal struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Certificate string `json:"certificate,omitempty"`
}

// Store persists flows, app codes and sessions in Redis.
type Store struct {
	c redis.UniversalClient
}

// New creates a session store from a Redis client.
func New(c redis.UniversalClient) *Store {
	return &Store{c: c}
}

func (s *Store) put(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return s.c.Set(ctx, key, b, ttl).Err()
}

func (s *Store) get(ctx context.Context, key string, v any) error {
	b, err := s.c.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}

// getDel atomically reads and deletes a key (Redis GETDEL), so a single-use
// artifact (login flow, app authorization code) cannot be consumed twice by
// concurrent callers racing a non-atomic GET-then-DEL.
func (s *Store) getDel(ctx context.Context, key string, v any) error {
	b, err := s.c.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}

// SaveFlow stores login-flow state under the Entrust state value.
func (s *Store) SaveFlow(ctx context.Context, state string, f *Flow, ttl time.Duration) error {
	return s.put(ctx, "flow:"+state, f, ttl)
}

// ConsumeFlow atomically loads and deletes flow state (single use).
func (s *Store) ConsumeFlow(ctx context.Context, state string) (*Flow, error) {
	var f Flow
	if err := s.getDel(ctx, "flow:"+state, &f); err != nil {
		return nil, err
	}

	return &f, nil
}

// SaveAppCode stores an issued application authorization code.
func (s *Store) SaveAppCode(ctx context.Context, code string, c *AppCode, ttl time.Duration) error {
	return s.put(ctx, "code:"+code, c, ttl)
}

// ConsumeAppCode atomically loads and deletes an application authorization code
// (single use — prevents authorization-code replay under a race).
func (s *Store) ConsumeAppCode(ctx context.Context, code string) (*AppCode, error) {
	var c AppCode
	if err := s.getDel(ctx, "code:"+code, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

// SaveSession stores a user session.
func (s *Store) SaveSession(ctx context.Context, sid string, sess *Session, ttl time.Duration) error {
	return s.put(ctx, "sess:"+sid, sess, ttl)
}

// LoadSession loads a user session.
func (s *Store) LoadSession(ctx context.Context, sid string) (*Session, error) {
	var sess Session
	if err := s.get(ctx, "sess:"+sid, &sess); err != nil {
		return nil, err
	}

	return &sess, nil
}

// DeleteSession invalidates a session (blocks refresh).
func (s *Store) DeleteSession(ctx context.Context, sid string) error {
	return s.c.Del(ctx, "sess:"+sid).Err()
}

// Ping verifies connectivity.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.c.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("session: redis ping: %w", err)
	}

	return nil
}
