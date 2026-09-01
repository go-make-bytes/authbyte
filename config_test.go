package authbytecore

import (
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
