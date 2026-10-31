package routes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func discoveryDocument(t *testing.T) map[string]any {
	t.Helper()

	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/openid-configuration")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var doc map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &doc)))

	return doc
}

// No ID token is issued, so the document names no ID-token field and does not
// offer the openid scope, which are what an OpenID provider promises.
func TestDiscoveryPromisesNoIDToken(t *testing.T) {
	doc := discoveryDocument(t)

	_, alg := doc["id_token_signing_alg_values_supported"]
	qt.Check(t, qt.IsFalse(alg))

	_, subjects := doc["subject_types_supported"]
	qt.Check(t, qt.IsFalse(subjects))

	if scopes, ok := doc["scopes_supported"].([]any); ok {
		for _, s := range scopes {
			qt.Check(t, qt.Not(qt.Equals(s, any("openid"))))
		}
	}
}

// The document names only S256, and the client authentication methods the
// token endpoint takes: none (a browser client proving PKCE) and a secret in
// the form (a service).
func TestDiscoveryNamesWhatTheServerTakes(t *testing.T) {
	doc := discoveryDocument(t)

	qt.Check(t, qt.DeepEquals(doc["code_challenge_methods_supported"], any([]any{"S256"})))
	qt.Check(t, qt.DeepEquals(doc["token_endpoint_auth_methods_supported"], any([]any{"client_secret_basic", "client_secret_post", "none"})))
}

// The revocation endpoint a client ends its session at is published, with the one
// ways a client proves itself there, the same as at the token endpoint.
func TestDiscoveryNamesTheRevocationEndpoint(t *testing.T) {
	doc := discoveryDocument(t)

	qt.Check(t, qt.Equals(doc["revocation_endpoint"], any(strings.TrimSuffix(doc["issuer"].(string), "/")+"/revoke")))
	qt.Check(t, qt.DeepEquals(doc["revocation_endpoint_auth_methods_supported"], any([]any{"client_secret_basic", "client_secret_post", "none"})))
}
