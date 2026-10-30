package authbytecore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

func redisURLBound(t *testing.T) string {
	t.Helper()

	c := NewConfiguration()
	v := viper.New()
	c.Bind("", v)
	qt.Assert(t, qt.IsNil(v.Unmarshal(c)))

	return c.RedisURL
}

// The store's address carries its password, so it may arrive as a file the
// secret store's agent writes (REDIS_URL_FILE).
func TestTheStoreAddressIsReadFromAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redis")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte("redis://:pw@valkey:6379/10\n"), 0o600)))
	t.Setenv("REDIS_URL_FILE", path)

	qt.Check(t, qt.Equals(redisURLBound(t), "redis://:pw@valkey:6379/10"))
}

// An explicit environment value still wins over the file.
func TestTheStoreAddressFromTheEnvironmentWinsOverTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redis")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte("redis://from-file"), 0o600)))
	t.Setenv("REDIS_URL_FILE", path)
	t.Setenv("REDIS_URL", "redis://from-env")

	qt.Check(t, qt.Equals(redisURLBound(t), "redis://from-env"))
}
