package routes

import (
	"context"
	"errors"
	"testing"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// loaderAnswering is a session store that answers every load with one result.
type loaderAnswering struct {
	sess *session.Session
	err  error
}

func (l loaderAnswering) LoadSession(context.Context, string) (*session.Session, error) {
	return l.sess, l.err
}

// refreshApp exposes the refresh's session load on a scratch route, over the
// store given — the real store needs live Redis.
func refreshApp(t *testing.T, store sessionLoader) *azugo.TestApp {
	t.Helper()

	app := authbytecore.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.Get("/testonly/refresh-session", func(ctx *azugo.Context) {
		sess, ok := refreshSession(ctx, store, "a-refresh-token")
		if !ok {
			return
		}
		ctx.JSON(map[string]string{"subject": sess.Subject})
	})

	app.Get("/testonly/refresh-bound", func(ctx *azugo.Context) {
		sess, ok := refreshBoundSession(ctx, store, "a-refresh-token", string(ctx.Context().QueryArgs().Peek("jkt")))
		if !ok {
			return
		}
		ctx.JSON(map[string]string{"subject": sess.Subject})
	})

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return ta
}

// A refresh goes on only with the key the session was bound to at sign-in: a
// stolen refresh token presented with any other key is refused, and so is any
// refresh of a session bound to no key.
func TestARefreshWithAnotherKeyIsRefused(t *testing.T) {
	bound := refreshApp(t, loaderAnswering{sess: &session.Session{Subject: testPersonSub(4), Thumbprint: "the-browsers-key"}})

	status, body := get(t, bound, "/testonly/refresh-bound?jkt=the-browsers-key")
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))

	status, _ = get(t, bound, "/testonly/refresh-bound?jkt=a-thiefs-key")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))

	unbound := refreshApp(t, loaderAnswering{sess: &session.Session{Subject: testPersonSub(4)}})
	status, _ = get(t, unbound, "/testonly/refresh-bound?jkt=")
	qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}

// A refresh token whose session the store does not hold is no longer good: the
// caller is refused, and may end what it keeps on that session.
func TestRefreshOfASessionNoLongerHeldIsRefused(t *testing.T) {
	app := refreshApp(t, loaderAnswering{err: session.ErrNotFound})

	status, _ := get(t, app, "/testonly/refresh-session")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}

// A session store that cannot be read says nothing about the session: the caller
// is told to try again, never that the session is gone — a moment's outage here
// must not end every session that asks during it.
func TestRefreshWhileTheSessionStoreCannotBeReadIsUnavailable(t *testing.T) {
	app := refreshApp(t, loaderAnswering{err: errors.New("dial tcp: connection refused")})

	status, body := get(t, app, "/testonly/refresh-session")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusServiceUnavailable), qt.Commentf("%s", body))
	qt.Assert(t, qt.StringContains(body, `"code":"err:upstream:unavailable"`))
}

// A session the store holds is the one the refresh goes on with.
func TestRefreshLoadsTheSessionItNames(t *testing.T) {
	app := refreshApp(t, loaderAnswering{sess: &session.Session{Subject: testPersonSub(4)}})

	status, body := get(t, app, "/testonly/refresh-session")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Assert(t, qt.StringContains(body, testPersonSub(4)))
}
