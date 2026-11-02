package routes

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// sharedCookie names the browser's shared session: its id and a secret, joined
// by a dot. The store keeps only the secret's hash, replaced at every sign-in.
const (
	sharedCookie      = "authbyte_sso"
	sharedIDBytes     = 16
	sharedSecretBytes = 32
)

// Why a live shared session did not answer an app, as audited.
const (
	refusedWay        = "way"
	refusedAge        = "age"
	refusedIdentity   = "identity"
	refusedMembership = "membership"
	refusedRegister   = "register"
)

// Why a shared session ended, as audited.
const (
	endedAnotherPerson = "another person"
	endedSignOut       = "sign-out"
)

// clock is the time the shared session is measured against; a test sets it.
var clock = time.Now

func sharedSecretHash(secret string) string {
	sum := sha256.Sum256([]byte("authbyte shared session\x00" + secret))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// browserShared is the browser's live shared session and its id, or nil. A
// cookie that names none, or names one with another secret, is cleared; a store
// that cannot answer leaves it, and the request goes on as without one.
func (r *router) browserShared(ctx *azugo.Context) (string, *session.Shared) {
	v := readCookie(ctx, sharedCookie)
	if v == "" {
		return "", nil
	}

	id, secret, ok := strings.Cut(v, ".")
	if !ok || len(id) != base64.RawURLEncoding.EncodedLen(sharedIDBytes) ||
		len(secret) != base64.RawURLEncoding.EncodedLen(sharedSecretBytes) {
		clearCookie(ctx, sharedCookie)

		return "", nil
	}

	sh, err := r.Session().LoadShared(ctx, id)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			clearCookie(ctx, sharedCookie)
		} else {
			ctx.Log().Warn("the shared session could not be read", zap.Error(err))
		}

		return "", nil
	}
	if subtle.ConstantTimeCompare([]byte(sharedSecretHash(secret)), []byte(sh.SecretHash)) != 1 || sh.Expired(clock()) {
		clearCookie(ctx, sharedCookie)

		return "", nil
	}

	return id, sh
}

// sharedWay is the way of sh that may answer req with no page, or nil and why
// not. The reason is "" when the request never asked to be answered so: the
// client is not single sign-on, or it asked for a sign-in now.
func (r *router) sharedWay(ctx *azugo.Context, req *authorizeRequest, sh *session.Shared, now time.Time) (*session.Way, string) {
	ask := req.signAsk
	if !req.client.SingleSignOn || ask.login || ask.selectAccount || (ask.maxAge != nil && *ask.maxAge == 0) {
		return nil, ""
	}

	offered := r.offered(req.client)
	tooOld := false
	var way *session.Way
	for i := len(sh.Ways) - 1; i >= 0; i-- {
		w := sh.Ways[i]
		if !now.Before(w.Ends) || !slices.Contains(offered, w.Method) ||
			(len(req.named) > 0 && !slices.Contains(req.named, w.Method)) {
			continue
		}
		// [OIDC Core §3.1.2.1] max_age: an authentication older than it, or of
		// no known time, is not an answer.
		if ask.maxAge != nil && (w.AuthTime == 0 || now.Unix()-w.AuthTime > *ask.maxAge) {
			tooOld = true

			continue
		}
		way = &w

		break
	}
	switch {
	case way == nil && tooOld:
		return nil, refusedAge
	case way == nil:
		return nil, refusedWay
	}

	// The client needs no identity the person lacks: a code where its tokens
	// carry one.
	if slices.Contains(req.client.Claims, registry.ClaimSerialNumber) && sh.SerialNumber == "" {
		return nil, refusedIdentity
	}

	// A person the token issue would refuse for want of a membership is not
	// answered silently: they get the page, and so a way to choose another.
	if resolver := r.ScopeResolver(); resolver != nil && r.Registry().MembershipRequired(req.clientID, true) {
		ms, err := resolver.Memberships(ctx, rolebyte.PersonKey(sh.Subject))
		if err != nil {
			return nil, refusedRegister
		}
		if len(ms) == 0 {
			return nil, refusedMembership
		}
	}

	return way, ""
}

// answerFromShared signs req's person in from the browser's shared session, with
// no page, when it fits the request. answered is false when the request goes on
// as without one.
func (r *router) answerFromShared(ctx *azugo.Context, req *authorizeRequest) (answered bool) {
	id, sh := r.browserShared(ctx)
	if sh == nil {
		return false
	}

	now := clock()
	way, why := r.sharedWay(ctx, req, sh, now)
	if way == nil {
		if why != "" {
			r.Audit().SharedSessionRefused(ctx, req.clientID, why)
		}

		return false
	}

	// A new app session of the shared one: the person, and the way it proved,
	// ending when that way ends.
	sess := &session.Session{
		Subject:         sh.Subject,
		Name:            sh.Name,
		GivenName:       sh.GivenName,
		FamilyName:      sh.FamilyName,
		SerialNumber:    sh.SerialNumber,
		LoA:             way.LoA,
		LoginMethod:     way.Method,
		DirectoryIssuer: sh.DirectoryIssuer,
		DirectoryGuest:  sh.DirectoryGuest,
		Shared:          id,
	}
	stampSignIn(sess, way.AuthTime, way.AMR)

	sid := randomToken(24)
	if err := r.Session().CreateSession(ctx, sid, sess, way.Ends.Sub(now)); err != nil {
		ctx.Error(err)

		return true
	}
	// The answer stands only once its session is recorded under the shared one
	// and the shared one is still there: a sign-out that ended it meanwhile took
	// its list of app sessions without this one, which no sign-out would reach.
	// It is ended here and the request goes on as without a shared session.
	if !r.addSharedApp(ctx, id, sh.ExpiresAt, req.clientID, sid) || !r.sharedLive(ctx, id) {
		r.endAppSession(ctx, sid)

		return false
	}

	appCode := randomToken(24)
	if err := r.Session().SaveAppCode(ctx, appCode, &session.AppCode{
		SessionID:           sid,
		CodeChallenge:       req.challenge,
		CodeChallengeMethod: req.method,
		ClientID:            req.clientID,
		RedirectURI:         req.redirectURI,
		Tenant:              req.tenant,
		OpenID:              req.idAsk.openID,
		Nonce:               req.idAsk.nonce,
	}, appCodeTTL); err != nil {
		ctx.Error(err)

		return true
	}

	r.Audit().SharedSessionReused(ctx, sh.Subject, req.clientID, way.Method)

	if ctx.Method() == fasthttp.MethodPost {
		ctx.StatusCode(fasthttp.StatusSeeOther)
	}
	// The client's own redirect address, validated with its request.
	ctx.RedirectUnsafe(appendCodeState(req.redirectURI, r.issuerID(), appCode, req.spaState))

	return true
}

// joinShared makes a completed sign-in the browser's shared session: the same
// person's gains the way and a new secret; anyone else's is ended with the app
// sessions signed in under it, and a new one is made. It answers the shared
// session's id and end, for the sign-in's own app session, and sets the cookie.
func (r *router) joinShared(ctx *azugo.Context, sess *session.Session) (string, time.Time, error) {
	now := clock()
	way := session.Way{
		Method:   sess.LoginMethod,
		LoA:      sess.LoA,
		AuthTime: sess.AuthTime,
		AMR:      sess.AMR,
		SignedIn: now,
		Ends:     now.Add(r.Config().SessionTTL),
	}
	secret := randomToken(sharedSecretBytes)

	id, sh := r.browserShared(ctx)
	if sh != nil && sh.Subject == sess.Subject {
		sh.SecretHash = sharedSecretHash(secret)
		sh.Keep(way)
		r.keepPerson(sh, sess)
		err := r.Session().ReplaceShared(ctx, id, sh)
		if err != nil && !errors.Is(err, session.ErrNotFound) {
			return "", time.Time{}, err
		}
		if err == nil {
			r.Audit().SharedSessionCreated(ctx, sess.Subject, way.Method)
			setCookie(ctx, sharedCookie, id+"."+secret, sh.ExpiresAt.Sub(now))

			return id, sh.ExpiresAt, nil
		}
		// Ended while this sign-in completed: a new one below.
	} else if sh != nil {
		r.endShared(ctx, id, sh.Subject, endedAnotherPerson)
	}

	id = randomToken(sharedIDBytes)
	sh = &session.Shared{SecretHash: sharedSecretHash(secret)}
	sh.Keep(way)
	r.keepPerson(sh, sess)
	if err := r.Session().CreateShared(ctx, id, sh); err != nil {
		return "", time.Time{}, err
	}

	r.Audit().SharedSessionCreated(ctx, sess.Subject, way.Method)
	setCookie(ctx, sharedCookie, id+"."+secret, sh.ExpiresAt.Sub(now))

	return id, sh.ExpiresAt, nil
}

// keepPerson writes the person a sign-in proved onto the shared session.
func (r *router) keepPerson(sh *session.Shared, sess *session.Session) {
	sh.Subject = sess.Subject
	sh.Name = sess.Name
	sh.GivenName = sess.GivenName
	sh.FamilyName = sess.FamilyName
	sh.SerialNumber = sess.SerialNumber
	sh.DirectoryIssuer = sess.DirectoryIssuer
	sh.DirectoryGuest = sess.DirectoryGuest
}

// addSharedApp records sid as client's app session under the shared session id,
// and ends the session that client had there before: the app replaced its own
// cookie with this sign-in, so nothing in the browser names that one any more.
// It answers whether sid was recorded, and so whether a sign-out reaches it.
func (r *router) addSharedApp(ctx *azugo.Context, id string, until time.Time, client, sid string) bool {
	previous, err := r.Session().PutSharedApp(ctx, id, client, sid, until)
	if err != nil {
		ctx.Log().Warn("an app session could not be recorded under its shared session", zap.Error(err))

		return false
	}
	if previous != "" && previous != sid {
		r.endAppSession(ctx, previous)
	}

	return true
}

// sharedLive reports whether the shared session id is still there; a store that
// cannot answer counts as no.
func (r *router) sharedLive(ctx *azugo.Context, id string) bool {
	_, err := r.Session().LoadShared(ctx, id)

	return err == nil
}

// endShared ends the shared session id of subject and every app session signed
// in under it, with their refresh grants, so no app renews from this moment. Of
// two ends at once, the one that took the list ends the sessions and records the
// end, with how many it ended; one already gone ends nothing.
func (r *router) endShared(ctx *azugo.Context, id, subject, reason string) {
	if id == "" {
		return
	}

	apps, err := r.Session().EndShared(ctx, id)
	if err != nil {
		if !errors.Is(err, session.ErrNotFound) {
			ctx.Log().Warn("a shared session, or the app sessions under it, could not be ended", zap.Error(err))
		}

		return
	}
	for _, sid := range apps {
		r.endAppSession(ctx, sid)
	}

	r.Audit().SharedSessionEnded(ctx, subject, reason, len(apps))
}

// endAppSession ends one app session and its refresh grant: the app's next
// refresh is refused.
func (r *router) endAppSession(ctx *azugo.Context, sid string) {
	sess, err := r.Session().LoadSession(ctx, sid)
	if err == nil && sess.RefreshKey != "" {
		if err := r.Session().DeleteRefresh(ctx, sess.RefreshKey); err != nil {
			ctx.Log().Warn("an app session's refresh grant could not be removed", zap.Error(err))
		}
	}
	if err := r.Session().DeleteSession(ctx, sid); err != nil {
		ctx.Log().Warn("an app session could not be ended", zap.Error(err))
	}
}
