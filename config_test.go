package authbytecore

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

// TestACRForMethodDistinct proves a sign-in requests a method-specific acr_values,
// and the permitted methods (eParaksts Mobile vs eID Scan) resolve to DIFFERENT
// values, so Entrust can actually force the requested method (the login-method ↔
// signing-flow binding), the card through the provider's plugin has its own, and
// the unrecognized "eid" sentinel has none.
func TestACRForMethodDistinct(t *testing.T) {
	c := &Configuration{
		EparakstsACRMobile:    "urn:test:acr:mobile",
		EparakstsACREIDScan:   "urn:test:acr:eidscan",
		EparakstsACRLegacyEID: "urn:test:acr:plugin",
	}

	qt.Check(t, qt.Equals(c.ACRForMethod("eparakstsMobile"), "urn:test:acr:mobile"))
	qt.Check(t, qt.Equals(c.ACRForMethod("eidScan"), "urn:test:acr:eidscan"))
	qt.Check(t, qt.Equals(c.ACRForMethod("legacyEid"), "urn:test:acr:plugin"))
	qt.Check(t, qt.Not(qt.Equals(c.ACRForMethod("eparakstsMobile"), c.ACRForMethod("eidScan"))))
	// The unrecognized-method sentinel is no provider's method → no acr.
	qt.Check(t, qt.Equals(c.ACRForMethod("eid"), ""))
	// Web eID card login is not an Entrust method → no acr (the card is read on
	// this service's own sign-in page).
	qt.Check(t, qt.Equals(c.ACRForMethod("webEid"), ""))
	qt.Check(t, qt.Equals(c.ACRForMethod("unknown"), ""))
}

// TestDefaultsGiveDistinctACRs proves the shipped defaults are also distinct (a
// regression guard against re-introducing identical placeholder ACRs), the card
// through the provider's plugin asks for eParaksts' own flow name, and no acr is
// shipped for the "eid" sentinel.
func TestDefaultsGiveDistinctACRs(t *testing.T) {
	v := viper.New()
	NewConfiguration().Bind("", v)

	mobile := v.GetString("eparaksts_acr_mobile")
	eidScan := v.GetString("eparaksts_acr_eidscan")
	plugin := v.GetString("eparaksts_acr_legacy_eid")

	qt.Check(t, qt.IsTrue(mobile != ""))
	qt.Check(t, qt.IsTrue(eidScan != ""))
	qt.Check(t, qt.Not(qt.Equals(mobile, eidScan)))
	qt.Check(t, qt.Equals(plugin, "urn:eparaksts:authentication:flow:sc_plugin"))
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
// One upstream per deployment: the generic connector or the eParaksts profile,
// never both — a second configured family used to be picked over silently,
// which is how a misconfiguration goes unnoticed until somebody logs in through
// the wrong provider. And never none.
func TestValidateUpstreamRefusesTwoFamiliesAndNone(t *testing.T) {
	both := Configuration{
		OIDCUpstreamAuthorityURL: "https://login.example/tenant/v2.0", OIDCUpstreamClientID: "cid",
		EparakstsAuthorityURL: "https://eparaksts.example", EparakstsClientID: "e",
	}
	err := both.validateUpstream()
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.StringContains(err.Error(), "two upstream identity providers"))

	none := Configuration{}
	qt.Assert(t, qt.IsNotNil(none.validateUpstream()))

	generic := Configuration{OIDCUpstreamAuthorityURL: "https://login.example/tenant/v2.0", OIDCUpstreamClientID: "cid"}
	qt.Assert(t, qt.IsNil(generic.validateUpstream()))

	eparaksts := Configuration{EparakstsAuthorityURL: "https://eparaksts.example", EparakstsClientID: "e"}
	qt.Assert(t, qt.IsNil(eparaksts.validateUpstream()))

	// The explicit-endpoint form of the generic connector counts as configured too.
	explicit := Configuration{
		OIDCUpstreamAuthorizeURL: "https://idp.example/a", OIDCUpstreamTokenURL: "https://idp.example/t",
		OIDCUpstreamUserInfoURL: "https://idp.example/u", OIDCUpstreamClientID: "cid",
		EparakstsAuthorityURL: "https://eparaksts.example",
	}
	qt.Assert(t, qt.StringContains(explicit.validateUpstream().Error(), "two upstream identity providers"))
}

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

// The generic upstream is trusted with identity codes only when
// the deployment says so, the eParaksts profile always; and a generic upstream
// with a code claim named but no trust is refused at the start, naming both
// settings, so an upgrade never quietly stops matching people by the code.
func TestTheGenericUpstreamIsTrustedWithCodesOnlyWhenSaid(t *testing.T) {
	generic := Configuration{OIDCUpstreamAuthorityURL: "https://login.example/tenant/v2.0", OIDCUpstreamClientID: "cid"}
	qt.Check(t, qt.IsFalse(generic.UpstreamConfig().TrustIdentityCodes))

	trusted := generic
	trusted.OIDCUpstreamTrustIdentityCodes = true
	qt.Check(t, qt.IsTrue(trusted.UpstreamConfig().TrustIdentityCodes))

	eparaksts := Configuration{EparakstsAuthorityURL: "https://eparaksts.example", EparakstsClientID: "e"}
	qt.Check(t, qt.IsTrue(eparaksts.UpstreamConfig().TrustIdentityCodes))

	named := generic
	named.OIDCUpstreamClaimSerial = "serial_number"
	err := named.validateUpstream()
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.StringContains(err.Error(), "OIDC_UPSTREAM_CLAIM_SERIAL"))
	qt.Check(t, qt.StringContains(err.Error(), "OIDC_UPSTREAM_TRUST_IDENTITY_CODES"))

	named.OIDCUpstreamTrustIdentityCodes = true
	qt.Check(t, qt.IsNil(named.validateUpstream()))

	// A claim name changes nothing for the eParaksts profile, which is trusted.
	eparaksts.OIDCUpstreamClaimSerial = "serial_number"
	qt.Check(t, qt.IsNil(eparaksts.validateUpstream()))
}

// The email claim name reaches the connector under either profile, and an unset
// name is left for the connector's own default.
func TestUpstreamConfigCarriesTheEmailClaim(t *testing.T) {
	named := &Configuration{OIDCUpstreamClaimEmail: "mail"}
	qt.Check(t, qt.Equals(named.UpstreamConfig().ClaimEmail, "mail"))

	generic := &Configuration{
		OIDCUpstreamAuthorityURL: "https://idp.example",
		OIDCUpstreamClaimEmail:   "mail",
	}
	qt.Check(t, qt.Equals(generic.UpstreamConfig().ClaimEmail, "mail"))

	qt.Check(t, qt.Equals((&Configuration{}).UpstreamConfig().ClaimEmail, ""))
}

// Discovery, the browser's return and every token name one issuer: a trailing
// slash in the configuration is not part of it.
func TestTheIssuerIsOneValue(t *testing.T) {
	t.Setenv("AUTH_ISSUER_URL", "http://localhost:8080/")
	app := TestApp(t)

	qt.Check(t, qt.Equals(app.Config().IssuerURL, "http://localhost:8080"))
}
