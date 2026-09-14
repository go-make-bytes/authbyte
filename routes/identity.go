package routes

import (
	"errors"
	"strings"

	"github.com/go-make-bytes/authbyte/routes/response"
	"github.com/go-make-bytes/authbyte/store"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-authbyte/identitycode"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/valyala/fasthttp"
)

// identity returns the internal Identity plus loa, login_method and the signing
// flows the login method permits, for the authenticated user token.
//
// @route /identity [get].
func (r *router) identity(ctx *azugo.Context) {
	u := ctx.User()
	loginMethod := u.ClaimValue("login_method")

	ctx.JSON(&response.Identity{
		Subject:        u.ID(),
		Name:           u.DisplayName(),
		GivenName:      u.GivenName(),
		FamilyName:     u.FamilyName(),
		LoA:            u.ClaimValue("loa"),
		LoginMethod:    loginMethod,
		Scopes:         []string(u.Claim("scope")),
		PermittedFlows: r.Binding().PermittedFlows(loginMethod),
	})
}

// The scope that lets a caller register people: minted like every other, from
// a role in the membership register (an administrator's role grants it), or
// held by a registry client as a service-token grant for bring-up.
const (
	scopeGroupIdentity = "identity"
	scopeLevelAdmin    = "admin"
)

// registerPersonRequest registers a person the platform does not know yet — an
// invitee, a record-only worker — so that they have a stable subject before
// their first login. The identity code is the person's; the names are what the
// administrator knows.
type registerPersonRequest struct {
	IdentityCode string `json:"identityCode"`
	Name         string `json:"name"`
	GivenName    string `json:"givenName"`
	FamilyName   string `json:"familyName"`
}

// registerPersonResponse is the person's platform subject — the value every
// register keys them on, typed `sub:` — and whether this call created them.
type registerPersonResponse struct {
	PersonSub string `json:"personSub"`
	Created   bool   `json:"created"`
}

// registerPerson gives a person a platform subject before their first login:
// the person row is created in the identity store with the canonical identity
// code and whatever name is known, and NO credential — a record, not an
// account; nothing can log in as them until a login attaches a credential, and
// that login lands on this row because the same canonical code is matched
// there. Idempotent on the code: a person already known (registered before, or
// already logged in) answers their existing subject with `created: false`, and
// the names on their row are kept.
//
// The caller must hold `identity:admin`. The identity code is never echoed —
// it is personal data and a refusal's text is the least controlled place it
// could end up.
//
// @route /identity/persons [post].
func (r *router) registerPerson(ctx *azugo.Context) {
	u := ctx.User()
	if !u.HasScopeLevel(scopeGroupIdentity, scopeLevelAdmin) {
		ctx.Error(pkerrors.NewProblem("err:identity:forbidden",
			pkerrors.WithStatus(fasthttp.StatusForbidden),
			pkerrors.WithPublicDetail("registering a person requires the identity:admin scope")))

		return
	}

	var req registerPersonRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	code, err := canonicalIdentityCode(req.IdentityCode)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:identity:invalid",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithPublicDetail(identityCodeReason(err))))

		return
	}

	s := r.Store()
	if s == nil {
		ctx.Error(pkerrors.NewProblem("err:identity:error",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithPublicDetail("the identity store is not configured")))

		return
	}

	personSub, created, err := s.Register(ctx, store.Registration{
		IdentityCode: code,
		Name:         strings.TrimSpace(req.Name),
		GivenName:    strings.TrimSpace(req.GivenName),
		FamilyName:   strings.TrimSpace(req.FamilyName),
	})
	if err != nil {
		// The store applies the same canonical-code rule as the check above; its
		// refusal is answered as a refusal, never as an outage.
		var refused *store.ProcedureError
		if errors.As(err, &refused) && refused.Code == "identity:invalid" {
			ctx.Error(pkerrors.NewProblem("err:identity:invalid",
				pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
				pkerrors.WithPublicDetail(refused.Message)))

			return
		}

		ctx.Error(err)

		return
	}

	// GDPR-audit: an administrator wrote an identity record. Routine/fail-open,
	// like the login path's own record.
	r.Audit().IdentityRegistered(ctx, u.ID(), u.ClaimValue("loa"), personSub, created)

	if created {
		ctx.StatusCode(fasthttp.StatusCreated)
	}

	ctx.JSON(&registerPersonResponse{PersonSub: personSub, Created: created})
}

// errIdentityCodeRequired is the refusal for a registration that names no
// identity code at all.
var errIdentityCodeRequired = errors.New("identity code is required")

// canonicalIdentityCode reduces the code an administrator typed to the one
// spelling the platform stores and compares. No country is supplied beside it:
// the code must state its own (`PNO<CC>-<code>`), because a person registered
// under a guessed country is a person their own login can never reach.
func canonicalIdentityCode(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errIdentityCodeRequired
	}

	return identitycode.Canonical(raw, "")
}

// identityCodeReason turns a refusal into the sentence an administrator can
// act on, without repeating the code back at them.
func identityCodeReason(err error) string {
	switch {
	case errors.Is(err, errIdentityCodeRequired):
		return "identityCode is required"
	case errors.Is(err, identitycode.ErrCountryRequired):
		return "identityCode names no country: write it with its identity type and country, e.g. PNO<CC>-<code>"
	case errors.Is(err, identitycode.ErrUnknownSemantics):
		return "identityCode carries an identity type this platform does not recognise"
	case errors.Is(err, identitycode.ErrAmbiguous):
		return "identityCode begins like an identity type but carries none"
	default:
		return "identityCode is not a well-formed identity code"
	}
}
