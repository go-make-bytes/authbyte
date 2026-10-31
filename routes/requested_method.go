package routes

import (
	"errors"
	"slices"
	"strings"
)

// errMethodNotRequested is a sign-in completed with a method the request did not
// ask for. It is refused rather than issued, so a product that asked for one
// method never receives a session proven by another.
var errMethodNotRequested = errors.New("login method not among the requested ones")

// requestedMethods reads the methods a request's acr_values ask for: a
// space-separated list in order of preference ([OIDC Core §3.1.2.1]), each value
// one of authbyte's own method names, exactly and case-sensitively ([OIDC Core
// §2]: acr is case-sensitive). A provider's own code names no method: the
// provider is sent its code by authbyte. It answers false when a value names no
// method offered here: such a request can never be met. The methods returned are
// the vocabulary's own strings, never the request's, so nothing read from the
// request outlives it.
func requestedMethods(offered func(string) bool, acrValues string) ([]string, bool) {
	var methods []string
	for _, v := range strings.Fields(acrValues) {
		// offered answers for authbyte's own names only, exactly as written: a
		// provider's code, or another spelling, is no method offered here.
		if !offered(v) {
			return nil, false
		}
		if !slices.Contains(methods, v) {
			methods = append(methods, strings.Clone(v))
		}
	}

	return methods, true
}

// methodRequested reports whether a sign-in achieved with method satisfies the
// methods the request asked for. A request that asked for none accepts any
// method the provider allows.
func methodRequested(requested []string, method string) bool {
	return len(requested) == 0 || slices.Contains(requested, method)
}
