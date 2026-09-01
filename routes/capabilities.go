package routes

import (
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
)

// captureCapabilities derives the session's signing capabilities from the
// sign-identity catalog the login's userinfo carried: the signing identity the
// login method uses, the paired authentication identity, and every seal — each
// with its certificate, fetched with the login's own access token.
//
// Best effort by design: a login never fails, slows into retries, or loses a
// consent over capability capture. Whatever could not be resolved is simply
// absent, and the signing act falls back to resolving identities itself. nil
// is returned when there is nothing to capture (no catalog in the response, or
// capture disabled) — absent capabilities mean "unknown", never "none".
//
// The certificates and the catalog carry personal data: log identity ids at
// most, never payloads.
func (r *router) captureCapabilities(ctx *azugo.Context, idpToken string, info identity.UserInfo, loginMethod string) *session.Capabilities {
	if !r.Upstream().IdentityCatalogEnabled() || info.SignIdentities == nil {
		return nil
	}

	caps := &session.Capabilities{SealsKnown: true}

	if id, ok := identity.SelectSigning(info.SignIdentities, loginMethod); ok {
		caps.SignIdentityID = id.ID
		if cert, err := r.Upstream().SignIdentityCert(ctx, idpToken, id.ID); err != nil {
			ctx.Log().Warn("capability capture: signing certificate fetch failed for identity " + id.ID + ": " + err.Error())
		} else {
			caps.SigningCertificate = cert
		}
	}

	if id, ok := identity.SelectAuth(info.SignIdentities, loginMethod); ok {
		if cert, err := r.Upstream().SignIdentityCert(ctx, idpToken, id.ID); err != nil {
			ctx.Log().Warn("capability capture: auth certificate fetch failed for identity " + id.ID + ": " + err.Error())
		} else {
			caps.AuthCertificate = cert
		}
	}

	for _, s := range identity.Seals(info.SignIdentities) {
		seal := session.Seal{ID: s.ID, Label: s.Label}
		if cert, err := r.Upstream().SignIdentityCert(ctx, idpToken, s.ID); err != nil {
			// The seal still gates and lists without its certificate; a
			// signing act with it just takes the fallback path.
			ctx.Log().Warn("capability capture: seal certificate fetch failed for identity " + s.ID + ": " + err.Error())
		} else {
			seal.Certificate = cert
		}
		caps.Seals = append(caps.Seals, seal)
	}

	return caps
}
