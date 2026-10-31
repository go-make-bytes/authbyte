package request_test

import (
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/go-make-bytes/authbyte/routes/request"
)

// withCtx runs fn inside a real request so ctx.Validate() uses the live azugo
// validator. Mirrors the audit package test harness (no Redis/registry needed).
func withCtx(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/t", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/t")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
}

// validStepUp returns a fully-populated step-up request for the given method;
// only the method varies across the validation cases.
func validStepUp(method string) *request.StepUp {
	return &request.StepUp{
		RefreshToken:  "a-refresh-token",
		ClientID:      "portal-spa",
		Method:        method,
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		RedirectURI:   "https://portal.example/callback",
		State:         "spa-state",
	}
}

// TestStepUpAcceptsLaunchMethods proves all three launch methods pass the
// request's own check. Which of them a client may step up to is its registry
// row's step_up_methods, checked by the route.
func TestStepUpAcceptsLaunchMethods(t *testing.T) {
	for _, m := range []string{"eparakstsMobile", "eidScan", "webEid"} {
		t.Run(m, func(t *testing.T) {
			withCtx(t, func(ctx *azugo.Context) {
				qt.Check(t, qt.IsNil(validStepUp(m).Validate(ctx)))
			})
		})
	}
}

// TestStepUpRequiresAMethod proves a step-up names a method. Any other value is
// refused by the route unless it is on the client's step_up_methods, the legacy
// "eid" and a wrong-case spelling included.
func TestStepUpRequiresAMethod(t *testing.T) {
	withCtx(t, func(ctx *azugo.Context) {
		qt.Check(t, qt.IsNotNil(validStepUp("").Validate(ctx)))
	})
}

// TestStepUpRequiresCoreFields proves the required fields are enforced, so a
// step-up cannot proceed without a session, client, PKCE challenge or redirect.
func TestStepUpRequiresCoreFields(t *testing.T) {
	cases := map[string]func(*request.StepUp){
		"missing_refresh_token":  func(r *request.StepUp) { r.RefreshToken = "" },
		"missing_client_id":      func(r *request.StepUp) { r.ClientID = "" },
		"missing_code_challenge": func(r *request.StepUp) { r.CodeChallenge = "" },
		"missing_redirect_uri":   func(r *request.StepUp) { r.RedirectURI = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			withCtx(t, func(ctx *azugo.Context) {
				r := validStepUp("webEid")
				mutate(r)
				qt.Check(t, qt.IsNotNil(r.Validate(ctx)))
			})
		})
	}
}
