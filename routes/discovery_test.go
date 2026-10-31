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

// The document promises only what is issued: an ID token comes from the token
// endpoint alone, so no response type returns one from the authorization
// endpoint.
func TestDiscoveryPromisesNoIDTokenFromTheAuthorizationEndpoint(t *testing.T) {
	doc := discoveryDocument(t)

	types, _ := doc["response_types_supported"].([]any)
	for _, rt := range types {
		qt.Check(t, qt.IsFalse(strings.Contains(rt.(string), "id_token")), qt.Commentf("%v", rt))
	}
	qt.Check(t, qt.HasLen(types, 1))
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
