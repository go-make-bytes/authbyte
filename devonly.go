package authbytecore

import (
	"fmt"
	"strings"

	"azugo.io/core"

	"github.com/go-make-bytes/authbyte/registry"
)

// refuseDevelopmentOnlyFields stops the service at start when the registry document
// carries a field that exists only for development — today the exchange_as_subject
// concession — and the environment is anything but development. The point is that
// "development only" is a property of the code, not of a configuration file nobody reads
// twice: such a row cannot be present in a staging or production posture, not merely
// "not configured" there.
func refuseDevelopmentOnlyFields(reg *registry.Registry, env core.Environment) error {
	dev := reg.DevelopmentOnlyClients()
	if len(dev) == 0 || env.IsDevelopment() {
		return nil
	}

	return fmt.Errorf("service client registry: %s carries exchange_as_subject, a development-only field — refusing to start in environment %q (remove the field, or run with ENVIRONMENT=development)",
		strings.Join(dev, ", "), string(env))
}
