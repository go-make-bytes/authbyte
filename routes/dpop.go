package routes

import (
	"errors"

	"github.com/gmb-lib/go-authbyte/dpop"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
)

// Inbound/outbound DPoP header names.
const (
	headerDPoP      = "DPoP"
	headerDPoPNonce = "DPoP-Nonce"
	headerWWWAuth   = "WWW-Authenticate"
)

// verifyEndpointDPoP verifies the inbound DPoP proof for an Identity/Auth
// issuance endpoint, applying the server-nonce challenge (required from day
// one) and jti replay protection. It returns the proof key thumbprint. When
// ok is false a 401 (challenge or failure) has already been written and the
// handler must return immediately.
//
// accessToken is "" for issuance hops (no access token is presented yet).
func (r *router) verifyEndpointDPoP(ctx *azugo.Context, accessToken string) (thumbprint string, ok bool) {
	cfg := r.Config()

	res, err := dpop.Verify(ctx.Header.Get(headerDPoP), dpop.VerifyOptions{
		Method:       string(ctx.Method()),
		URL:          requestURL(ctx),
		AccessToken:  accessToken,
		MaxAge:       cfg.DPoPProofMaxAge,
		Leeway:       cfg.TokenClockSkewLeeway,
		RequireNonce: cfg.DPoPNonceEnabled,
	})
	if err != nil {
		if cfg.DPoPNonceEnabled && errors.Is(err, dpop.ErrMissingNonce) {
			r.challengeNonce(ctx)
		} else {
			r.dpopError(ctx)
		}

		return "", false
	}

	if cfg.DPoPNonceEnabled {
		if err := r.Nonce().Verify(res.Nonce, cfg.TokenClockSkewLeeway); err != nil {
			r.challengeNonce(ctx)

			return "", false
		}
	}

	first, err := r.Replay().CheckAndSet(ctx, res.JTI, cfg.DPoPProofMaxAge+cfg.TokenClockSkewLeeway)
	if err != nil {
		ctx.Error(err)

		return "", false
	}
	if !first {
		r.dpopError(ctx)

		return "", false
	}

	return res.Thumbprint, true
}

// challengeNonce issues a fresh server nonce and returns 401 use_dpop_nonce.
func (r *router) challengeNonce(ctx *azugo.Context) {
	ctx.Error(corehttp.UnauthorizedError{})
	ctx.Header.Set(headerDPoPNonce, r.Nonce().Issue())
	ctx.Header.Set(headerWWWAuth, `DPoP error="use_dpop_nonce"`)
}

// dpopError returns 401 invalid_dpop_proof.
func (r *router) dpopError(ctx *azugo.Context) {
	ctx.Error(corehttp.UnauthorizedError{})
	ctx.Header.Set(headerWWWAuth, `DPoP error="invalid_dpop_proof"`)
}
