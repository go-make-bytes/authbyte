package authbytecore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

// boundFromTheEnvironment binds the configuration as the loader does: the core
// sections (cache, log) first, then the service's own, so the service's defaults
// win.
func boundFromTheEnvironment(t *testing.T) *Configuration {
	t.Helper()

	c := NewConfiguration()
	v := viper.New()
	c.Core().Bind("", v)
	c.Bind("", v)
	qt.Assert(t, qt.IsNil(v.Unmarshal(c)))

	return c
}

// Client-side caching is off unless a deployment turns it on: the store never
// reads through it, and a server or a user that refuses it would otherwise
// refuse the session store's connection.
func TestClientSideCachingIsOffByDefault(t *testing.T) {
	qt.Check(t, qt.IsFalse(boundFromTheEnvironment(t).Cache.ClientCache))
}

// The session store's password may arrive as a file the secret store's agent
// writes (CACHE_PASSWORD_FILE).
func TestTheSessionStorePasswordIsReadFromAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte("store-password\n"), 0o600)))
	t.Setenv("CACHE_PASSWORD_FILE", path)

	qt.Check(t, qt.Equals(boundFromTheEnvironment(t).Cache.Password, "store-password"))
}

// A password file that is named but missing or empty stops the start: read as
// "not set", the store would connect without its password and be refused.
func TestAMissingOrEmptySessionStorePasswordFileStopsTheStart(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		t.Setenv("CACHE_PASSWORD_FILE", filepath.Join(t.TempDir(), "not-written-yet"))

		err := boundFromTheEnvironment(t).Validate(nil)
		qt.Check(t, qt.ErrorMatches(err, "CACHE_PASSWORD_FILE is set but gives no value.*"))
	})

	t.Run("empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "password")
		qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte("\n"), 0o600)))
		t.Setenv("CACHE_PASSWORD_FILE", path)

		err := boundFromTheEnvironment(t).Validate(nil)
		qt.Check(t, qt.ErrorMatches(err, "CACHE_PASSWORD_FILE is set but gives no value.*"))
	})
}

// A session lives twelve hours from its sign-in unless the deployment sets
// another lifetime.
func TestTheSessionLifetimeIsTwelveHoursUnlessSet(t *testing.T) {
	qt.Check(t, qt.Equals(boundFromTheEnvironment(t).SessionTTL, 12*time.Hour))

	t.Setenv("SESSION_TTL", "8h")
	qt.Check(t, qt.Equals(boundFromTheEnvironment(t).SessionTTL, 8*time.Hour))
}

// The service never keeps its sessions in memory, in any environment: with two
// instances a login begun on one would be unknown to the other, and each would
// accept a replayed proof once.
func TestTheServiceRefusesAnInMemorySessionStore(t *testing.T) {
	for _, env := range []string{"development", "test", "staging", "production"} {
		t.Run(env, func(t *testing.T) {
			TestApp(t) // sets the rest of the environment the service needs
			t.Setenv("ENVIRONMENT", env)

			for _, typ := range []string{"memory", ""} {
				if typ == "" {
					os.Unsetenv("CACHE_TYPE") //nolint:errcheck // t.Setenv above restores it
				} else {
					t.Setenv("CACHE_TYPE", typ)
				}

				_, err := New(nil, "0.0.0-test")
				qt.Check(t, qt.ErrorMatches(err, ".*session store is in memory.*"), qt.Commentf("CACHE_TYPE=%q", typ))
			}
		})
	}
}
