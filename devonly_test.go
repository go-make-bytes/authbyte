package authbytecore

import (
	"strings"
	"testing"

	"azugo.io/core"
	"github.com/go-quicktest/qt"

	"github.com/go-make-bytes/authbyte/registry"
)

const devOnlyDoc = `
service_clients:
  - client_id: svc:api
    secret_ref: env:API
    enabled: true
    grants:
      - audience: svc:document
        scopes: [documents:write]
  - client_id: svc:acme-dms
    secret_ref: env:ACME
    enabled: true
    exchange_as_subject: true
    grants:
      - audience: svc:api
        scopes: [signing-requests:write]
`

const plainDoc = `
service_clients:
  - client_id: svc:api
    secret_ref: env:API
    enabled: true
    grants:
      - audience: svc:document
        scopes: [documents:write]
`

func loadDoc(t *testing.T, doc string) *registry.Registry {
	t.Helper()
	r, err := registry.Load([]byte(doc), nil)
	qt.Assert(t, qt.IsNil(err))

	return r
}

// A registry carrying the development-only field starts only in development; every other
// environment is refused, naming the client and the field, so the concession cannot reach
// a production posture by configuration alone.
func TestDevelopmentOnlyFieldFencesTheEnvironment(t *testing.T) {
	reg := loadDoc(t, devOnlyDoc)

	qt.Assert(t, qt.IsNil(refuseDevelopmentOnlyFields(reg, core.EnvironmentDevelopment)))
	for _, env := range []core.Environment{core.EnvironmentTest, core.EnvironmentStaging, core.EnvironmentProduction} {
		err := refuseDevelopmentOnlyFields(reg, env)
		qt.Assert(t, qt.IsNotNil(err), qt.Commentf("%s", env))
		qt.Assert(t, qt.IsTrue(strings.Contains(err.Error(), "svc:acme-dms")))
		qt.Assert(t, qt.IsTrue(strings.Contains(err.Error(), "exchange_as_subject")))
		qt.Assert(t, qt.IsTrue(strings.Contains(err.Error(), string(env))))
	}

	// Without the field, every environment starts.
	plain := loadDoc(t, plainDoc)
	for _, env := range []core.Environment{core.EnvironmentDevelopment, core.EnvironmentProduction} {
		qt.Assert(t, qt.IsNil(refuseDevelopmentOnlyFields(plain, env)))
	}
}
