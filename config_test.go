package authbytecore

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

// TestACRForMethodDistinct proves step-up requests a method-specific acr_values,
// and the permitted methods (eParaksts Mobile vs eID Scan) resolve to DIFFERENT
// values, so Entrust can actually force the requested method (the login-method ↔
// signing-flow binding). It also proves the eID-card (sc_plugin) "eid" method has
// NO acr — eID-card login is Web eID only.
func TestACRForMethodDistinct(t *testing.T) {
	c := &Configuration{
		EparakstsACRMobile:  "urn:test:acr:mobile",
		EparakstsACREIDScan: "urn:test:acr:eidscan",
	}

	qt.Check(t, qt.Equals(c.ACRForMethod("eparakstsMobile"), "urn:test:acr:mobile"))
	qt.Check(t, qt.Equals(c.ACRForMethod("eidScan"), "urn:test:acr:eidscan"))
	qt.Check(t, qt.Not(qt.Equals(c.ACRForMethod("eparakstsMobile"), c.ACRForMethod("eidScan"))))
	// eID (sc_plugin) is no longer a TrustedX login method → no acr.
	qt.Check(t, qt.Equals(c.ACRForMethod("eid"), ""))
	// Web eID card login is not an Entrust method → no acr (step-up to it goes
	// through the Web eID challenge route, not /authorize).
	qt.Check(t, qt.Equals(c.ACRForMethod("webEid"), ""))
	qt.Check(t, qt.Equals(c.ACRForMethod("unknown"), ""))
}

// TestDefaultsGiveDistinctACRs proves the shipped defaults are also distinct (a
// regression guard against re-introducing identical placeholder ACRs) and that
// no eid (sc_plugin) acr default is shipped.
func TestDefaultsGiveDistinctACRs(t *testing.T) {
	v := viper.New()
	NewConfiguration().Bind("", v)

	mobile := v.GetString("eparaksts_acr_mobile")
	eidScan := v.GetString("eparaksts_acr_eidscan")

	qt.Check(t, qt.IsTrue(mobile != ""))
	qt.Check(t, qt.IsTrue(eidScan != ""))
	qt.Check(t, qt.Not(qt.Equals(mobile, eidScan)))
	// No eid-card acr default — eID card is Web eID only.
	qt.Check(t, qt.Equals(v.GetString("eparaksts_acr_eid"), ""))
}

// TestUpstreamConfigKeysBindToEnvironment proves that every upstream-connector
// setting is actually REACHABLE from the environment — the property the type
// system does not check and a reader cannot see.
//
// It is derived, not listed: the keys come from the struct's own mapstructure
// tags, so a field added tomorrow is covered the day it is added rather than
// the day someone remembers to extend a list. That is the whole point. The
// defect it was written for was a field that existed at every layer — declared,
// validated, applied to the connector, documented in the README — and had no
// BindEnv call, so setting the documented variable did nothing and said
// nothing. Nothing in the build could see it, because nothing in the build
// reads an environment variable that is never bound.
//
// The convention this relies on, which holds for every key here: the
// environment variable is the mapstructure key, upper-cased.
func TestUpstreamConfigKeysBindToEnvironment(t *testing.T) {
	prefixes := []string{"oidc_upstream_", "eparaksts_"}

	typ := reflect.TypeOf(Configuration{})
	keys := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		key := typ.Field(i).Tag.Get("mapstructure")
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				keys = append(keys, key)

				break
			}
		}
	}

	// A guard on the guard: a refactor that renamed the fields away from these
	// prefixes would otherwise leave this test passing over nothing at all.
	qt.Assert(t, qt.IsTrue(len(keys) >= 10))

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			want := "probe-" + key
			t.Setenv(strings.ToUpper(key), want)

			v := viper.New()
			NewConfiguration().Bind("", v)

			qt.Check(t, qt.Equals(v.GetString(key), want),
				qt.Commentf("%s is not bound to %s — add it to the BindEnv block; "+
					"a field with no binding is invisible until an operator sets it and nothing happens",
					key, strings.ToUpper(key)))
		})
	}
}
