package routes

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/claims"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/go-make-bytes/authbyte/rolebyte"
	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// The AI apps connected as assistants, behind the identity door: a person lists
// the apps connected as their own assistants in the workspace their token names
// and signs one out; an administrator of that workspace does the same for any of
// its assistants, and ends every app of one when it is removed. Each answer
// names a connection by its public name, never its session's key or a token.
// Only a person's own token is taken: an AI app's, or one another service
// obtained to act for the person, neither lists nor signs out.

// scopeGroupMembership and scopeLevelAdministrator are the membership register's
// administering level, which a workspace's administrator holds there.
const (
	scopeGroupMembership    = "membership"
	scopeLevelAdministrator = "admin"
)

// assistantKey is the shape of an assistant's key: `svc:assistant-<ULID>`.
var assistantKey = regexp.MustCompile(`^svc:assistant-[0-9A-HJKMNP-TV-Z]{26}$`)

// connectionLine is one connected AI app: its public name, the app's own name,
// when it connected and when it was last used (null until a call went through).
type connectionLine struct {
	ID          string  `json:"id"`
	App         string  `json:"app"`
	ConnectedAt string  `json:"connectedAt"`
	LastUsed    *string `json:"lastUsed"`
}

// ownAssistant is one of the person's own assistants in the workspace, with the
// apps connected as it.
type ownAssistant struct {
	Key         string           `json:"key"`
	Name        string           `json:"name"`
	Connections []connectionLine `json:"connections"`
}

func connectionRefused(ctx *azugo.Context, status int, code, title string) {
	noStore(ctx)
	ctx.Error(pkerrors.NewProblem(code, pkerrors.WithStatus(status), pkerrors.WithTitle(title)))
}

func connectionNotFound(ctx *azugo.Context) {
	connectionRefused(ctx, fasthttp.StatusNotFound, "err:connection:not_found", "No such connected app")
}

// connectionCaller answers the person a request comes from and the workspace
// their token names: a person's own token only, never an AI app's, a service's,
// or one obtained to act for the person. ok is false when the refusal is written.
func (r *router) connectionCaller(ctx *azugo.Context) (string, string, bool) {
	u := ctx.User()
	person, tenant := u.ID(), u.ClaimValue(claims.ClaimTenant)
	if person == "" || tenant == "" || strings.HasPrefix(person, servicePrefix) ||
		strings.TrimSpace(u.ClaimValue(claims.ClaimAct)) != "" || r.isAIApp(u.ClaimValue(claims.ClaimClientID)) {
		connectionRefused(ctx, fasthttp.StatusForbidden, "err:connection:forbidden",
			"Only a person signed in to a workspace sees or signs out its connected apps")

		return "", "", false
	}

	return person, tenant, true
}

// administrator answers the workspace of a request from its administrator, and
// the assistant its address names. ok is false when the refusal is written.
func (r *router) administrator(ctx *azugo.Context) (string, string, string, bool) {
	person, tenant, ok := r.connectionCaller(ctx)
	if !ok {
		return "", "", "", false
	}
	if !ctx.User().HasScopeLevel(scopeGroupMembership, scopeLevelAdministrator) {
		connectionRefused(ctx, fasthttp.StatusForbidden, "err:connection:forbidden",
			"Only an administrator of the workspace sees or signs out an assistant's connected apps")

		return "", "", "", false
	}
	assistant := ctx.Params.String("assistant")
	if !assistantKey.MatchString(assistant) {
		connectionNotFound(ctx)

		return "", "", "", false
	}

	return person, tenant, assistant, true
}

// ownAssistants answers the person's own assistants in tenant, from the
// register. ok is false when the register could not answer and that is written.
func (r *router) ownAssistants(ctx *azugo.Context, person, tenant string) ([]rolebyte.Assistant, bool) {
	all, err := r.personsAssistants(ctx, person)
	if err != nil {
		r.registerUnavailable(ctx, rolebyte.PersonKey(person), err)

		return nil, false
	}

	own := make([]rolebyte.Assistant, 0, len(all))
	for _, a := range all {
		if a.TenantID == tenant {
			own = append(own, a)
		}
	}

	return own, true
}

// connectionLines answers the live apps connected as assistant in tenant, newest
// first; person, when named, keeps only that person's. ok is false when the
// store could not answer and that is written.
func (r *router) connectionLines(ctx *azugo.Context, tenant, assistant, person string) ([]connectionLine, bool) {
	conns, err := r.Session().Connections(ctx, tenant, assistant)
	if err != nil {
		storeRefusal(ctx, err)

		return nil, false
	}

	type dated struct {
		at   time.Time
		line connectionLine
	}
	var found []dated
	for _, c := range conns {
		sess, err := r.Session().LoadSession(ctx, c.SessionID)
		if errors.Is(err, session.ErrNotFound) {
			_ = r.Session().RemoveConnection(ctx, tenant, assistant, c)

			continue
		}
		if err != nil {
			storeRefusal(ctx, err)

			return nil, false
		}
		if sess.Tenant != tenant || sess.Assistant != assistant || sess.SID != c.ID || (person != "" && sess.Subject != person) {
			continue
		}

		line := connectionLine{ID: c.ID, App: sess.ClientID, ConnectedAt: sess.ConnectedAt.UTC().Format(time.RFC3339)}
		if app, ok := r.Registry().AIApp(sess.ClientID); ok {
			line.App = appName(app)
		}
		if !sess.LastUsed.IsZero() {
			used := sess.LastUsed.UTC().Format(time.RFC3339)
			line.LastUsed = &used
		}
		found = append(found, dated{at: sess.ConnectedAt, line: line})
	}
	slices.SortStableFunc(found, func(a, b dated) int { return b.at.Compare(a.at) })

	lines := make([]connectionLine, 0, len(found))
	for _, d := range found {
		lines = append(lines, d.line)
	}

	return lines, true
}

// signOut ends one connection and records who did it. ok is false when the
// store could not end it and that is written.
func (r *router) signOut(ctx *azugo.Context, by, sid string, sess *session.Session, administrator bool) bool {
	if !r.endConnection(ctx, sid, sess) {
		return false
	}
	r.Audit().ConnectionSignedOut(ctx, by, sess.Subject, sess.ClientID, administrator)

	return true
}

// ownConnections answers the person's own assistants in the workspace, each with
// the apps connected as it; an assistant with none is listed with none.
//
// @route /identity/connections [get].
func (r *router) ownConnections(ctx *azugo.Context) {
	person, tenant, ok := r.connectionCaller(ctx)
	if !ok {
		return
	}
	own, ok := r.ownAssistants(ctx, person, tenant)
	if !ok {
		return
	}

	out := make([]ownAssistant, 0, len(own))
	for _, a := range own {
		lines, ok := r.connectionLines(ctx, tenant, a.Key, person)
		if !ok {
			return
		}
		out = append(out, ownAssistant{Key: a.Key, Name: a.Name, Connections: lines})
	}

	noStore(ctx)
	ctx.JSON(map[string]any{"assistants": out})
}

// signOutOwnConnection signs out one of the person's own connected apps, by its
// public name: it stops at once; the others go on.
//
// @route /identity/connections/{id} [delete].
func (r *router) signOutOwnConnection(ctx *azugo.Context) {
	person, tenant, ok := r.connectionCaller(ctx)
	if !ok {
		return
	}
	own, ok := r.ownAssistants(ctx, person, tenant)
	if !ok {
		return
	}

	id := ctx.Params.String("id")
	for _, a := range own {
		sid, sess, ok := r.findConnection(ctx, tenant, a.Key, id)
		if !ok {
			return
		}
		if sid == "" || sess.Subject != person {
			continue
		}
		if r.signOut(ctx, person, sid, sess, false) {
			noStore(ctx)
			ctx.StatusCode(fasthttp.StatusNoContent)
		}

		return
	}

	connectionNotFound(ctx)
}

// assistantConnections answers, to an administrator of the workspace, the apps
// connected as one of its assistants.
//
// @route /identity/assistants/{assistant}/connections [get].
func (r *router) assistantConnections(ctx *azugo.Context) {
	_, tenant, assistant, ok := r.administrator(ctx)
	if !ok {
		return
	}
	lines, ok := r.connectionLines(ctx, tenant, assistant, "")
	if !ok {
		return
	}

	noStore(ctx)
	ctx.JSON(map[string]any{"connections": lines})
}

// signOutAssistantConnection signs out, for an administrator of the workspace,
// one app connected as one of its assistants.
//
// @route /identity/assistants/{assistant}/connections/{id} [delete].
func (r *router) signOutAssistantConnection(ctx *azugo.Context) {
	by, tenant, assistant, ok := r.administrator(ctx)
	if !ok {
		return
	}
	sid, sess, ok := r.findConnection(ctx, tenant, assistant, ctx.Params.String("id"))
	if !ok {
		return
	}
	if sid == "" {
		connectionNotFound(ctx)

		return
	}
	if r.signOut(ctx, by, sid, sess, true) {
		noStore(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	}
}

// endAssistantConnections signs out, for an administrator of the workspace,
// every app connected as one of its assistants: what its removal asks first, so
// its apps stop at once rather than at their next refresh.
//
// @route /identity/assistants/{assistant}/connections [delete].
func (r *router) endAssistantConnections(ctx *azugo.Context) {
	by, tenant, assistant, ok := r.administrator(ctx)
	if !ok {
		return
	}
	conns, err := r.Session().Connections(ctx, tenant, assistant)
	if err != nil {
		storeRefusal(ctx, err)

		return
	}
	for _, c := range conns {
		sid, sess, ok := r.findConnection(ctx, tenant, assistant, c.ID)
		if !ok {
			return
		}
		if sid == "" {
			continue
		}
		if !r.signOut(ctx, by, sid, sess, true) {
			return
		}
	}

	noStore(ctx)
	ctx.StatusCode(fasthttp.StatusNoContent)
}
