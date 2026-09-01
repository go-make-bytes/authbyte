package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// TestLogoutRequiresClientID confirms the route is registered and rejects a call
// without the required client_id (so the redirect_uri can't be validated). This
// exercises the front-channel /logout entrypoint without needing Redis or a
// populated client registry (the happy path needs a registered client + session).
func TestLogoutRequiresClientID(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/logout")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
}

// TestLogoutRejectsUnregisteredRedirect confirms a redirect_uri that is not on
// the client's allowlist is refused (open-redirect guard) rather than reflected.
// With the test registry empty, portal-spa is unknown, so validation fails.
func TestLogoutRejectsUnregisteredRedirect(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/logout?client_id=portal-spa&redirect_uri=https%3A%2F%2Fevil.example%2Fx")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
}
