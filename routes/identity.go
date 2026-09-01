package routes

import (
	"github.com/go-make-bytes/authbyte/routes/response"

	"azugo.io/azugo"
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
