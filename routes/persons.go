package routes

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/go-make-bytes/authbyte/store"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/gmb-lib/go-authbyte/identitycode"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/valyala/fasthttp"
)

// The two service-only reads of a person's sign-in facts. Each has its own scope
// level, so a grant to read the lines never reaches a code.
const (
	scopeLevelLines = "lines"
	scopeLevelCode  = "code"

	// servicePrefix starts the subject of a service's own token; a person's
	// token never carries it.
	servicePrefix = "svc:"
	// personPrefix types a platform person subject on the wire.
	personPrefix = "sub:"

	// maxLineSubjects bounds one lines read.
	maxLineSubjects = 500
)

// personIDPattern is a bare person id: 26 characters of the ULID alphabet.
var personIDPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// personReader is what the person reads need from the identity store.
type personReader interface {
	SignInLines(ctx context.Context, subs []string) ([]store.SignInLine, error)
	Get(ctx context.Context, internalSubject string) (store.Mapping, error)
}

// codeReadRecorder records that a service read a person's identity code.
type codeReadRecorder interface {
	IdentityCodeRead(ctx *azugo.Context, callerID, personSub string)
}

// codeReadRecorder returns what records each code read.
func (r *router) codeReadRecorder() codeReadRecorder {
	if r.codeReads != nil {
		return r.codeReads
	}

	return r.Audit()
}

// personStore returns the reader behind the person reads, or nil when no
// identity store is configured.
func (r *router) personStore() personReader {
	if r.reader != nil {
		return r.reader
	}
	if s := r.Store(); s != nil {
		return s
	}

	return nil
}

// requireServiceScope answers whether the caller is a service acting as itself
// and holding the given level of the identity scope, and writes the refusal when
// it is not. These reads are for services that act on the platform's behalf, so
// a person's token is refused even when it carries the scope, and so is a token
// that acts for someone: one another service obtained by exchange (it names the
// acting service and carries no client id of its own) and a service account's
// token for an organisation.
func requireServiceScope(ctx *azugo.Context, level string) bool {
	u := ctx.User()
	actsAsItself := strings.HasPrefix(u.ID(), servicePrefix) &&
		u.ClaimValue(claims.ClaimClientID) == u.ID() &&
		u.ClaimValue(claims.ClaimTenant) == ""
	if actsAsItself && u.HasScopeLevel(scopeGroupIdentity, level) {
		return true
	}

	ctx.Error(pkerrors.NewProblem("err:identity:forbidden",
		pkerrors.WithStatus(fasthttp.StatusForbidden),
		pkerrors.WithPublicDetail("this read requires a service holding the identity:"+level+" scope")))

	return false
}

// invalidPersons answers a refusal of the request's person ids; the detail
// never repeats a value that was sent.
func invalidPersons(ctx *azugo.Context, detail string) {
	ctx.Error(pkerrors.NewProblem("err:identity:invalid",
		pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
		pkerrors.WithPublicDetail(detail)))
}

// personLinesRequest names the people to read, each as a typed `sub:` subject.
type personLinesRequest struct {
	Subjects []string `json:"subjects"`
}

// personLine is one person's sign-in facts. Country and Length describe the
// national identity code the person holds, without carrying it.
type personLine struct {
	Subject string `json:"subject"`
	SignsIn bool   `json:"signsIn"`
	Email   string `json:"email,omitempty"`
	Country string `json:"country,omitempty"`
	Length  int    `json:"length,omitempty"`
}

// personLinesResponse is the answer to a lines read; a person the platform does
// not know is left out.
type personLinesResponse struct {
	Lines []personLine `json:"lines"`
}

// personLines answers, for up to 500 people, whether each can sign in, the email
// a directory sign-in left (only when one is kept) and — for a person holding a
// national identity code — its country and displayed length. The code itself is
// never part of the answer.
//
// The caller must be a service holding `identity:lines`. The refusal's text
// never repeats a subject that was sent.
//
// @route /identity/persons/lines [post].
func (r *router) personLines(ctx *azugo.Context) {
	ctx.Header.Set("Cache-Control", "no-store")

	if !requireServiceScope(ctx, scopeLevelLines) {
		return
	}

	var req personLinesRequest
	if err := json.Unmarshal(ctx.Body.Bytes(), &req); err != nil || len(req.Subjects) == 0 {
		invalidPersons(ctx, "subjects must be a non-empty list of person subjects")

		return
	}
	if len(req.Subjects) > maxLineSubjects {
		invalidPersons(ctx, "at most 500 subjects can be read at once")

		return
	}

	subs := make([]string, 0, len(req.Subjects))
	for _, subject := range req.Subjects {
		id, ok := strings.CutPrefix(subject, personPrefix)
		if !ok || !personIDPattern.MatchString(id) {
			invalidPersons(ctx, "every subject must be a person subject typed sub: followed by a 26-character id")

			return
		}
		subs = append(subs, id)
	}

	s := r.personStore()
	if s == nil {
		ctx.Error(pkerrors.NewProblem("err:identity:error",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithPublicDetail("the identity store is not configured")))

		return
	}

	found, err := s.SignInLines(ctx, subs)
	if err != nil {
		var refused *store.ProcedureError
		if errors.As(err, &refused) && refused.Code == "identity:invalid" {
			invalidPersons(ctx, "a subject is not a well-formed person subject")

			return
		}

		ctx.Error(err)

		return
	}

	lines := make([]personLine, 0, len(found))
	for _, l := range found {
		lines = append(lines, personLine{
			Subject: personPrefix + l.Sub,
			SignsIn: l.SignsIn,
			Email:   l.Email,
			Country: l.Country,
			Length:  l.Length,
		})
	}

	ctx.JSON(&personLinesResponse{Lines: lines})
}

// personCodeResponse is a person's identity code the way a person is shown it,
// with the country whose register issued it.
type personCodeResponse struct {
	Code    string `json:"code"`
	Country string `json:"country"`
}

// personCode answers one person's national identity code, spelled the way the
// person is shown it. A person the platform does not know, or one who holds no
// code, is `not_found`.
//
// The caller must be a service holding `identity:code` — a grant for the lines
// read never reaches a code. Each code answered is recorded as a read by that
// service of that person (a routine record: a sink that is down does not stop
// the answer); the caller records the disclosure it makes onward.
//
// @route /identity/persons/{personSub}/code [get].
func (r *router) personCode(ctx *azugo.Context) {
	ctx.Header.Set("Cache-Control", "no-store")

	if !requireServiceScope(ctx, scopeLevelCode) {
		return
	}

	personSub := ctx.Params.String("personSub")
	if !personIDPattern.MatchString(personSub) {
		invalidPersons(ctx, "the person id is not a well-formed person id")

		return
	}

	s := r.personStore()
	if s == nil {
		ctx.Error(pkerrors.NewProblem("err:identity:error",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithPublicDetail("the identity store is not configured")))

		return
	}

	m, err := s.Get(ctx, personSub)
	if err != nil {
		var refused *store.ProcedureError
		if errors.As(err, &refused) && refused.Code == "identity:not_found" {
			personCodeNotFound(ctx)

			return
		}

		ctx.Error(err)

		return
	}
	if strings.TrimSpace(m.SerialNumber) == "" {
		personCodeNotFound(ctx)

		return
	}

	parsed, err := identitycode.Parse(strings.TrimSpace(m.SerialNumber))
	if err != nil {
		// A stored code is canonical by construction; one that is not is a data
		// fault, reported without the value.
		ctx.Error(errors.New("the stored identity code is not well formed"))

		return
	}

	r.codeReadRecorder().IdentityCodeRead(ctx, ctx.User().ID(), personSub)

	ctx.JSON(&personCodeResponse{
		Code:    identitycode.Display(m.SerialNumber),
		Country: parsed.Country,
	})
}

// personCodeNotFound answers that no code is held for the person asked about.
func personCodeNotFound(ctx *azugo.Context) {
	ctx.Error(pkerrors.NewProblem("err:identity:not_found",
		pkerrors.WithStatus(fasthttp.StatusNotFound),
		pkerrors.WithPublicDetail("no identity code is held for this person")))
}
