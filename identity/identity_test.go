package identity

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// TestIsEParakstsLoginAllowed proves eID-card login via the TrustedX plugin
// (sc_plugin → LoginEID) is rejected from the eParaksts callback (Web eID only),
// while eParaksts Mobile and eID Scan are allowed. Unknown/empty fails closed.
func TestIsEParakstsLoginAllowed(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{LoginEParakstsMobile, true},
		{LoginEIDScan, true},
		{LoginEID, false},    // eID card via TrustedX plugin — forbidden
		{LoginWebEID, false}, // Web eID never arrives via the eParaksts callback
		{"", false},
		{"unknown", false},
	}

	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			qt.Check(t, qt.Equals(IsEParakstsLoginAllowed(c.method), c.want))
		})
	}
}

// TestIsEParakstsFederated checks which login methods set the eParaksts IdP SSO
// cookie (so a logout must bounce through the IdP). Web eID (webEid) does not.
func TestIsEParakstsFederated(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{LoginEID, true},
		{LoginEParakstsMobile, true},
		{LoginEIDScan, true},
		{LoginWebEID, false},
		{"", false},
		{"unknown", false},
	}

	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			qt.Check(t, qt.Equals(IsEParakstsFederated(c.method), c.want))
		})
	}
}

// TestInterpretMethod guards method resolution across both claim shapes. It covers
// the substring trap ("mobileid" contains "eid"), and — critically — the real
// eParaksts case where the amr is identical (`…methods:mobileid`) for both mobile
// and eID Scan and only the acr (`…flow:mobile-eid`) distinguishes them, plus the
// upstream-fixed shape where the tool moves into the amr.
func TestInterpretMethod(t *testing.T) {
	r := NewResolver(nil)
	const adaptive = "urn:eparaksts:tws:policies:authentication:adaptive:methods:"
	const flow = "urn:eparaksts:authentication:flow:"

	cases := []struct {
		name string
		acr  string
		amr  []string
		want string
	}{
		{"eParaksts mobile (amr mobileid)", "", []string{adaptive + "mobileid"}, LoginEParakstsMobile},
		{"smart card (amr sc_plugin)", "", []string{adaptive + "sc_plugin"}, LoginEID},
		{"eID Scan (amr mobile-eid)", "", []string{adaptive + "mobile-eid"}, LoginEIDScan},
		{"bare mobile fallback", "", []string{adaptive + "mobile"}, LoginEParakstsMobile},
		{"empty → eid default", "", nil, LoginEID},
		// Real eParaksts demo today: identical amr for both; only the acr differs.
		{"eID Scan via acr, amr identical to mobile", flow + "mobile-eid", []string{adaptive + "mobileid"}, LoginEIDScan},
		{"mobile via acr, same amr", flow + "mobileid", []string{adaptive + "mobileid"}, LoginEParakstsMobile},
		// Upstream-fixed shape: acr carries a level, the tool is in the amr.
		{"fixed shape: level in acr, tool in amr", "urn:safelayer:tws:policies:authentication:level:high", []string{adaptive + "mobile-eid"}, LoginEIDScan},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			method, _ := r.Interpret(c.acr, c.amr)
			qt.Check(t, qt.Equals(method, c.want))
		})
	}
}

// TestResolveBindsPermittedFlows proves the end-to-end binding: a mobileid AMR
// resolves to eParaksts Mobile, which permits the cloud/eSeal/csc flows (and not
// the eID or Web eID flows).
func TestResolveBindsPermittedFlows(t *testing.T) {
	r := NewResolver(nil)
	id := r.Resolve(UserInfo{
		ACR: "urn:safelayer:tws:policies:authentication:level:high",
		AMR: []string{"urn:eparaksts:tws:policies:authentication:adaptive:methods:mobileid"},
	})

	qt.Check(t, qt.Equals(id.LoginMethod, LoginEParakstsMobile))
	qt.Check(t, qt.DeepEquals(BindingResolver{}.PermittedFlows(id.LoginMethod),
		[]string{FlowEParakstsMobile, FlowEParakstsMobileEseal, FlowCSC}))
}

// TestEIDScanBinding proves eID Scan resolves to its own login method and binds
// to its own single signing flow (it no longer shares one with Web eID).
func TestEIDScanBinding(t *testing.T) {
	id := NewResolver(nil).Resolve(UserInfo{
		ACR: "urn:eparaksts:authentication:flow:mobile-eid",
		AMR: []string{"urn:eparaksts:tws:policies:authentication:adaptive:methods:mobile-eid"},
	})

	qt.Check(t, qt.Equals(id.LoginMethod, LoginEIDScan))
	qt.Check(t, qt.DeepEquals(BindingResolver{}.PermittedFlows(LoginEIDScan), []string{FlowEIDScan}))
	qt.Check(t, qt.Equals(id.LoA, LoAHigh)) // mobile-eid is a QSCD method
}

// TestWebEIDBinding proves the Web eID card login (set directly by the Web eID
// adapter, not via the AMR resolver) binds to its own Web eID signing flow, and
// that a login method that permits nothing (legacy plugin eID / unknown / empty)
// fails closed.
func TestWebEIDBinding(t *testing.T) {
	qt.Check(t, qt.DeepEquals(BindingResolver{}.PermittedFlows(LoginWebEID), []string{FlowWebEID}))
	qt.Check(t, qt.IsNil(BindingResolver{}.PermittedFlows(LoginEID)))
	qt.Check(t, qt.IsNil(BindingResolver{}.PermittedFlows("")))
	qt.Check(t, qt.IsNil(BindingResolver{}.PermittedFlows("unknown")))
}

// TestResolveLoA covers both acr shapes: the production Safelayer level URN and
// the demo flow URN (which is why a real mobile login previously showed "low").
func TestResolveLoA(t *testing.T) {
	r := NewResolver(nil)

	cases := []struct {
		name string
		acr  string
		amr  []string
		want string
	}{
		{"prod level:high", "urn:safelayer:tws:policies:authentication:level:high", nil, LoAHigh},
		{"prod level:substantial", "urn:safelayer:tws:policies:authentication:level:substantial", nil, LoASubstantial},
		{"demo flow:mobileid in acr", "urn:eparaksts:authentication:flow:mobileid", []string{"urn:safelayer:tws:policies:authentication:adaptive:methods:mobileid"}, LoAHigh},
		{"demo flow:sc_plugin in acr → low (no longer permitted)", "urn:eparaksts:authentication:flow:sc_plugin", nil, LoALow},
		{"explicit level wins over method", "urn:safelayer:...:level:substantial", []string{"...:methods:mobileid"}, LoASubstantial},
		{"unknown → low", "urn:something:opaque", nil, LoALow},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			qt.Check(t, qt.Equals(r.ResolveLoA(c.acr, c.amr...), c.want))
		})
	}
}
