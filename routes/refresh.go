package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
	"github.com/valyala/fasthttp"
)

// refreshTokenBytes is the size of a refresh token's random value.
const refreshTokenBytes = 32

// refreshKey is the key a refresh token's grant is kept under: a hash of the
// token, so the store never holds a value that renews a session.
func refreshKey(token string) string {
	sum := sha256.Sum256([]byte(token))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// refreshLoader is the store calls that follow a refresh token to its session.
type refreshLoader interface {
	LoadRefresh(ctx context.Context, key string) (*session.RefreshGrant, error)
	LoadSession(ctx context.Context, sid string) (*session.Session, error)
}

// refreshedSession follows a refresh token to the session it renews, for the
// client it was issued to. A token the store does not hold, one presented by
// another client, and one whose session has ended are refused alike with 401: the
// refresh token is no longer good for this caller, and nothing tells it more. A
// store that cannot be read is answered 503, because it says nothing about the
// session: a caller that ends what it keeps on a refusal must not end it for an
// outage here. ok is false when the answer is already written.
func refreshedSession(ctx *azugo.Context, store refreshLoader, token, clientID string) (*session.Session, string, bool) {
	grant, err := store.LoadRefresh(ctx, refreshKey(token))
	if err != nil {
		storeRefusal(ctx, err)

		return nil, "", false
	}
	if grant.ClientID == "" || grant.ClientID != clientID {
		ctx.Error(corehttp.UnauthorizedError{})

		return nil, "", false
	}

	sess, err := store.LoadSession(ctx, grant.SessionID)
	if err != nil {
		storeRefusal(ctx, err)

		return nil, "", false
	}

	return sess, grant.SessionID, true
}

// refreshBoundSession is refreshedSession for a caller proving a DPoP key: the
// session goes on only for the key it was bound to at the code exchange, so a
// refresh token taken from its client is worth nothing without the client's key.
func refreshBoundSession(ctx *azugo.Context, store refreshLoader, token, clientID, thumbprint string) (*session.Session, string, bool) {
	sess, sid, ok := refreshedSession(ctx, store, token, clientID)
	if !ok {
		return nil, "", false
	}

	if sess.Thumbprint == "" || sess.Thumbprint != thumbprint {
		ctx.Error(corehttp.UnauthorizedError{})

		return nil, "", false
	}

	return sess, sid, true
}

// storeRefusal answers a failed store read: 401 for an entry that is gone, 503
// for a store that could not answer.
func storeRefusal(ctx *azugo.Context, err error) {
	if errors.Is(err, session.ErrNotFound) {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	ctx.Log().Warn("session store could not be read: " + err.Error())
	ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
		pkerrors.WithStatus(fasthttp.StatusServiceUnavailable)))
}

// revoke ends a session at the authority, server to server [RFC 7009]: the
// client presents the session's refresh token, its own client_id and a DPoP proof
// of the session's key. A token this authority does not hold is answered as
// revoked, because there is nothing to end and the caller could do nothing with an
// error [RFC 7009 §2.2]. The right token from another client, or without the
// session's key, is refused and the session goes on. Only refresh tokens are
// revoked here; an access token lives minutes and is not tracked.
//
// Form:
//
//	token (required) — the session's refresh token.
//	token_type_hint (optional) — ignored; only refresh tokens are revoked.
//	client_id (required) — the client the token was issued to.
//
// @route /revoke [post].
func (r *router) revoke(ctx *azugo.Context) {
	token, err := ctx.Form.String("token")
	if err != nil {
		ctx.Error(err)

		return
	}

	clientID, err := ctx.Form.String("client_id")
	if err != nil {
		ctx.Error(err)

		return
	}

	thumbprint, ok := r.verifyEndpointDPoP(ctx, "")
	if !ok {
		return
	}

	key := refreshKey(token)
	grant, err := r.Session().LoadRefresh(ctx, key)
	if errors.Is(err, session.ErrNotFound) {
		ctx.StatusCode(fasthttp.StatusOK)

		return
	}
	if err != nil {
		storeRefusal(ctx, err)

		return
	}
	if grant.ClientID == "" || grant.ClientID != clientID {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	sess, err := r.Session().LoadSession(ctx, grant.SessionID)
	if errors.Is(err, session.ErrNotFound) {
		// The session has ended already; the grant outlived it.
		if err := r.Session().DeleteRefresh(ctx, key); err != nil {
			storeRefusal(ctx, err)

			return
		}
		ctx.StatusCode(fasthttp.StatusOK)

		return
	}
	if err != nil {
		storeRefusal(ctx, err)

		return
	}
	if sess.Thumbprint == "" || sess.Thumbprint != thumbprint {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	// The session first: once it is gone the grant renews nothing.
	if err := r.Session().DeleteSession(ctx, grant.SessionID); err != nil {
		storeRefusal(ctx, err)

		return
	}
	if err := r.Session().DeleteRefresh(ctx, key); err != nil {
		storeRefusal(ctx, err)

		return
	}

	r.Audit().SessionEnded(ctx, sess.Subject, sess.LoginMethod)
	ctx.StatusCode(fasthttp.StatusOK)
}
