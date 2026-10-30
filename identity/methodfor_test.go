package identity

import "testing"

// A requested acr value names a method only when the provider's vocabulary knows
// it. Unlike Interpret, an unknown value does not fall back to the default
// method: a request for a method nobody offers must be refused, not quietly
// turned into the default one.
func TestMethodForNamesOnlyAKnownValue(t *testing.T) {
	r := NewResolverPolicies(nil, nil, LoginEParakstsMobile, "")

	cases := []struct {
		acr    string
		method string
		ok     bool
	}{
		{"urn:eparaksts:authentication:flow:mobileid", LoginEParakstsMobile, true},
		{"urn:eparaksts:authentication:flow:mobile-eid", LoginEIDScan, true},
		{"URN:EPARAKSTS:AUTHENTICATION:FLOW:MOBILEID", LoginEParakstsMobile, true},
		{"urn:nobody:flow:fingerprint", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		method, ok := r.MethodFor(c.acr)
		if method != c.method || ok != c.ok {
			t.Errorf("MethodFor(%q) = %q, %v; want %q, %v", c.acr, method, ok, c.method, c.ok)
		}
	}
}
