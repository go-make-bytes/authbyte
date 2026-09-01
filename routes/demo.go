package routes

import (
	"mime"
	"os"
	"path/filepath"
	"strings"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
)

// registerDemo serves the static demo SPA from dir under /demo (same-origin so
// the browser can read the DPoP-Nonce challenge header). Development only.
func (r *router) registerDemo(dir string) {
	base := filepath.Clean(dir)

	handler := func(ctx *azugo.Context) {
		rel := ctx.Params.String("path")
		if rel == "" {
			rel = "index.html"
		}

		// Resolve within the demo dir and reject path traversal.
		full := filepath.Join(base, filepath.Clean("/"+rel))
		if full != base && !strings.HasPrefix(full, base+string(os.PathSeparator)) {
			ctx.Error(corehttp.NotFoundError{Resource: "file"})

			return
		}

		content, err := os.ReadFile(full) //nolint:gosec // path is confined to base above
		if err != nil {
			ctx.Error(corehttp.NotFoundError{Resource: "file"})

			return
		}

		if ct := mime.TypeByExtension(filepath.Ext(full)); ct != "" {
			ctx.ContentType(ct)
		}
		ctx.Raw(content)
	}

	// Bare /demo (and the mux's /demo/ → /demo trailing-slash redirect) land on
	// the SPA entry point; the wildcard serves index.html and assets.
	r.Get("/demo", func(ctx *azugo.Context) { ctx.Redirect("/demo/index.html") })
	r.Get("/demo/{path:*}", handler)
}
