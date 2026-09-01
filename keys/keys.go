// Package keys is the Identity/Auth key manager. It holds the token-signing
// private key (loaded from Vault/KMS via the secret store, or generated
// ephemerally in development), signs issued tokens, and publishes the matching
// public keys as a JWKS document. Overlapping rotation is supported by serving
// multiple kids until tokens under the old kid expire.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gmb-lib/go-authbyte/dpop"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// Manager signs tokens and publishes the JWKS.
type Manager struct {
	method    jwt.SigningMethod
	ephemeral bool

	mu      sync.RWMutex
	active  *signingKey   // current signing key
	retired []*signingKey // previous keys, still trusted in JWKS until expiry
}

type signingKey struct {
	kid string
	key *ecdsa.PrivateKey
}

// New creates a key manager from a PEM-encoded EC private key. If pemKey is
// empty an ephemeral key is generated (development only — tokens will not
// validate across restarts or pods).
func New(pemKey string) (*Manager, error) {
	var (
		key *ecdsa.PrivateKey
		err error
	)

	ephemeral := pemKey == ""
	if ephemeral {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = jwt.ParseECPrivateKeyFromPEM([]byte(pemKey))
	}
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}

	kid, err := dpop.Thumbprint(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keys: thumbprint: %w", err)
	}

	return &Manager{
		method:    jwt.SigningMethodES256,
		ephemeral: ephemeral,
		active:    &signingKey{kid: kid, key: key},
	}, nil
}

// Generated reports whether the active key was generated ephemerally (no PEM
// was supplied).
func (m *Manager) Generated() bool {
	return m.ephemeral
}

// Alg returns the JWS algorithm identifier (e.g. "ES256").
func (m *Manager) Alg() string {
	return m.method.Alg()
}

// Sign signs the claims with the active key, stamping its kid into the header.
func (m *Manager) Sign(claims jwt.Claims) (string, error) {
	m.mu.RLock()
	active := m.active
	m.mu.RUnlock()

	tok := jwt.NewWithClaims(m.method, claims)
	tok.Header["kid"] = active.kid

	return tok.SignedString(active.key)
}

// JWKS renders the public JWKS document (active key plus any retired keys still
// within their expiry window).
func (m *Manager) JWKS() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]jose.JSONWebKey, 0, 1+len(m.retired))
	keys = append(keys, m.publicJWK(m.active))
	for _, k := range m.retired {
		keys = append(keys, m.publicJWK(k))
	}

	return json.Marshal(jose.JSONWebKeySet{Keys: keys})
}

func (m *Manager) publicJWK(k *signingKey) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       k.key.Public(),
		KeyID:     k.kid,
		Algorithm: m.method.Alg(),
		Use:       "sig",
	}
}

// Rotate installs a new active signing key and retains the previous one in the
// JWKS so tokens signed under it keep validating until they expire.
func (m *Manager) Rotate(pemKey string) error {
	_, err := m.MaybeRotate(pemKey)

	return err
}

// MaybeRotate installs pemKey as the active signing key only if it differs from
// the current one (by JWK thumbprint / kid), retaining the previous key in the
// JWKS for overlapping rotation. It reports whether a rotation occurred, so a
// reloader can poll the key secret and rotate without redeploy while ignoring
// unchanged reloads.
func (m *Manager) MaybeRotate(pemKey string) (bool, error) {
	if pemKey == "" {
		return false, nil
	}

	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(pemKey))
	if err != nil {
		return false, fmt.Errorf("keys: rotate: %w", err)
	}

	kid, err := dpop.Thumbprint(&key.PublicKey)
	if err != nil {
		return false, fmt.Errorf("keys: rotate thumbprint: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active != nil && m.active.kid == kid {
		return false, nil // unchanged — nothing to do
	}

	if m.active != nil {
		m.retired = append(m.retired, m.active)
	}
	m.active = &signingKey{kid: kid, key: key}
	m.ephemeral = false

	return true, nil
}

// PublicKey returns the active public key (used for local self-validation).
func (m *Manager) PublicKey() crypto.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.active.key.Public()
}

// PublicKeyByKID returns the public key for a given key id, matching the active
// key or any retired key still inside its expiry window. It lets the service
// verify a token it issued (e.g. a token-exchange subject token), including one
// signed just before a key rotation. The second return is false for an unknown
// kid.
func (m *Manager) PublicKeyByKID(kid string) (crypto.PublicKey, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.active != nil && m.active.kid == kid {
		return m.active.key.Public(), true
	}
	for _, k := range m.retired {
		if k.kid == kid {
			return k.key.Public(), true
		}
	}

	return nil, false
}

// ActiveKID returns the kid of the active signing key.
func (m *Manager) ActiveKID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.active.kid
}
