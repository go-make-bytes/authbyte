package routes

import (
	"os"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// demoDir is the local-only demo SPA, which lives in the stack/ (not a committed
// repo). File-serving tests skip when it's absent — e.g. on CI runners where the
// stack is never checked out.
const demoDir = "../../../stack/demo-portal"

// demoApp enables the demo convenience before constructing the app.
func demoApp(t *testing.T) *azugo.TestClient {
	t.Setenv("DEMO_DIR", demoDir)

	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	return app.TestClient()
}

// skipWithoutDemoAssets skips a test when the local-only demo dir is not present,
// so the file-serving tests don't fail where stack/demo-portal isn't available.
func skipWithoutDemoAssets(t *testing.T) {
	if _, err := os.Stat(demoDir); err != nil {
		t.Skip("demo-portal assets not present (local-only stack); skipping")
	}
}

func TestDemoIndexServed(t *testing.T) {
	skipWithoutDemoAssets(t)
	tc := demoApp(t)

	resp, err := tc.Get("/demo/index.html")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	body, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), "AuthByte"))
}

func TestDemoAppJSServed(t *testing.T) {
	skipWithoutDemoAssets(t)
	tc := demoApp(t)

	resp, err := tc.Get("/demo/app.js")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestDemoRejectsTraversal(t *testing.T) {
	tc := demoApp(t)

	resp, err := tc.Get("/demo/../config.go")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Equals(resp.StatusCode(), fasthttp.StatusOK)))
	fasthttp.ReleaseResponse(resp)
}
