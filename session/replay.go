package session

import (
	"context"
	"errors"
	"time"

	"azugo.io/core/cache"
)

// replayInstance is the cache instance the accepted DPoP proofs are kept in.
const replayInstance = "dpop-proofs"

// ProofReplay remembers the DPoP proofs this authority has accepted, in the
// shared cache, so one proof is accepted once across every instance
// [RFC 9449 §11.1].
type ProofReplay struct {
	seen cache.Instance[bool]
}

// NewProofReplay returns a replay guard kept in c, which must have a shared
// (Valkey or Redis) backend: in memory, each instance would accept the proof once.
func NewProofReplay(c *cache.Cache) (*ProofReplay, error) {
	if c.ConfiguredType() == cache.MemoryCache {
		return nil, errors.New("session: the replay guard needs a Valkey or Redis cache, not memory")
	}

	seen, err := cache.Create[bool](c, replayInstance)
	if err != nil {
		return nil, err
	}

	return &ProofReplay{seen: seen}, nil
}

// CheckAndSet records jti for ttl and reports whether it was seen for the first
// time, in one step (SET … NX).
func (p *ProofReplay) CheckAndSet(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	return p.seen.Add(ctx, jti, true, cache.TTL[bool](ttl))
}
