package routes

import (
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/routes/request"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/upstream"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
)

// Step-up response mode discriminator. A step-up to an Entrust-federated method
// (eidScan, eparakstsMobile) returns a redirect the SPA must follow; a step-up
// to webEid returns a Web eID challenge the SPA answers with web-eid.js. The
// "mode" field lets the SPA branch without inferring from which field is present.
const (
	stepUpModeRedirect = "redirect"
	stepUpModeWebEID   = "webeid"
)

// stepUpRedirectResponse is returned for the Entrust-federated step-up methods:
// the SPA follows AuthorizeURL and /callback elevates the existing session.
type stepUpRedirectResponse struct {
	Mode         string `json:"mode"`
	AuthorizeURL string `json:"authorize_url"`
}

// stepUpWebEIDResponse is returned for a webEid step-up: the SPA runs
// web-eid.js against Nonce, then POSTs {state, authToken} to /webeid/login. The
// flow is marked StepUp so /webeid/login elevates the existing session rather
// than creating a new one. Shape mirrors webeidChallengeResponse plus the mode tag.
type stepUpWebEIDResponse struct {
	Mode  string `json:"mode"`
	Nonce string `json:"nonce"`
	State string `json:"state"`
}

// stepUp begins a re-authentication that elevates assurance / switches the
// login method, so the signing-flow binding can be satisfied. For the Entrust
// methods (eidScan, eparakstsMobile) it returns an authorize_url the SPA must
// follow; for webEid (Web eID, not an Entrust method) it returns a Web eID
// challenge nonce instead. Either way the *existing* session is elevated on
// completion (via establishSession's step-up branch), never replaced.
//
// @route /step-up [post].
func (r *router) stepUp(ctx *azugo.Context) {
	var req request.StepUp
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	if err := req.Validate(ctx); err != nil {
		ctx.Error(err)

		return
	}

	// The session must exist (auth = existing session).
	if _, err := r.Session().LoadSession(ctx, req.SessionID); err != nil {
		ctx.Error(corehttp.UnauthorizedError{})

		return
	}

	// Validate the redirect_uri against the registered allowlist BEFORE saving
	// any state — the callback/login later returns the app code here, so an
	// unvalidated value would be an open redirect + code leak ([RFC 6749 §10.6]).
	if err := r.Registry().ValidateRedirectURI(req.ClientID, req.RedirectURI); err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "redirect_uri", Tag: "registered"})

		return
	}

	// webEid is Web eID, not an Entrust method: issue a Web eID challenge bound
	// to a step-up flow (no acr_values, no Entrust redirect).
	// /webeid/login then matches the achieved login_method against RequestedLogin
	// and elevates the existing session via establishSession's step-up branch.
	if req.Method == identity.LoginWebEID {
		nonce, err := webeidNonce()
		if err != nil {
			ctx.Error(err)

			return
		}

		state := randomToken(24)
		flow := &session.Flow{
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: "S256",
			AppRedirectURI:      req.RedirectURI,
			SPAState:            req.State,
			StepUp:              true,
			RequestedLogin:      req.Method,
			SessionID:           req.SessionID,
			ClientID:            req.ClientID,
			WebEIDNonce:         nonce,
		}

		if err := r.Session().SaveFlow(ctx, state, flow, flowTTL); err != nil {
			ctx.Error(err)

			return
		}

		ctx.JSON(stepUpWebEIDResponse{Mode: stepUpModeWebEID, Nonce: nonce, State: state})

		return
	}

	entrustRedirect := r.entrustRedirectURI()
	if entrustRedirect == "" {
		ctx.Error(corehttp.NotFoundError{Resource: "eParaksts redirect uri"})

		return
	}

	state := randomToken(24)
	flow := &session.Flow{
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: "S256",
		AppRedirectURI:      req.RedirectURI,
		SPAState:            req.State,
		EntrustRedirectURI:  entrustRedirect,
		StepUp:              true,
		RequestedLogin:      req.Method,
		SessionID:           req.SessionID,
		ClientID:            req.ClientID,
	}

	if err := r.Session().SaveFlow(ctx, state, flow, flowTTL); err != nil {
		ctx.Error(err)

		return
	}

	url := r.Upstream().AuthorizeURL(upstream.AuthorizeParams{
		State:       state,
		RedirectURI: entrustRedirect,
		ACRValues:   r.Config().ACRForMethod(req.Method),
		Prompt:      "login", // force fresh authentication
	})

	ctx.JSON(stepUpRedirectResponse{Mode: stepUpModeRedirect, AuthorizeURL: url})
}
