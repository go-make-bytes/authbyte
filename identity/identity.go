// Package identity normalizes Entrust/eParaksts claims into the platform's
// internal Identity, resolves the assurance level (LoA) and login method, and
// implements the login-method ↔ signing-flow binding.
package identity

import (
	"sort"
	"strings"
)

// Assurance levels.
const (
	LoALow         = "low"
	LoASubstantial = "substantial"
	LoAHigh        = "high"
)

// Login methods (drive the signing-flow binding). Values are camelCase and
// identical to the matching signing-flow token, so a login and the signing it
// authorizes correlate across services on one literal.
const (
	// LoginEID is the eID smart card via the eParaksts/TrustedX browser plugin
	// (sc_plugin). It is NO LONGER a permitted login method — eID-card login goes
	// through Web eID (LoginWebEID) only. The constant is retained as the sentinel
	// the eParaksts-callback guard rejects and to recognize the federated SSO case.
	LoginEID             = "eid"
	LoginEParakstsMobile = "eparakstsMobile" // eParaksts Mobile / Cloud (mobileid)
	LoginEIDScan         = "eidScan"         // eID Scan: phone reads the physical eID card (mobile-eid)
	LoginWebEID          = "webEid"          // Web eID browser login (web-eid engine; NOT the eParaksts IdP)
)

// IsEParakstsLoginAllowed reports whether a login method resolved from an
// eParaksts IdP (TrustedX) callback is permitted. Only eParaksts Mobile and eID
// Scan are. The eID smart card via the TrustedX plugin (sc_plugin → LoginEID) is
// NOT — eID-card login must go through Web eID (LoginWebEID). Anything else
// (incl. an unrecognized method, which ResolveLoginMethod maps to LoginEID) is
// rejected, so the eParaksts login path fails closed.
func IsEParakstsLoginAllowed(method string) bool {
	switch method {
	case LoginEParakstsMobile, LoginEIDScan:
		return true
	default:
		return false
	}
}

// IsEParakstsFederated reports whether a login method authenticated through the
// eParaksts IdP (and therefore set the IdP's SSO cookie that a logout must clear).
// The Web eID card login (LoginWebEID) goes through the web-eid engine, not the
// eParaksts IdP, so it has no SSO cookie and is not federated here.
func IsEParakstsFederated(method string) bool {
	switch method {
	case LoginEID, LoginEParakstsMobile, LoginEIDScan:
		return true
	default:
		return false
	}
}

// UserInfo is the subset of the Entrust /users/me response we consume.
// Claims are mapped from urn:lvrtc:fpeil:aa scope responses.
type UserInfo struct {
	Subject      string   `json:"sub"`
	Domain       string   `json:"domain"`
	ACR          string   `json:"acr"`
	AMR          []string `json:"amr"`
	GivenName    string   `json:"given_name"`
	FamilyName   string   `json:"family_name"`
	Name         string   `json:"name"`
	SerialNumber string   `json:"serial_number"`
	EIPS         string   `json:"eips"`
	// SignIdentities is the person's sign-identity catalog, present when the
	// login requested the sign-identity profile scope. nil = the response
	// carried no catalog (scope not granted / not requested); empty non-nil =
	// the catalog was read and the person holds no identities.
	SignIdentities []SignIdentity `json:"-"`
}

// Identity is the platform's normalized identity. Subject is the internal,
// stable id (resolved by the mapping store from the IdP subject).
type Identity struct {
	Subject      string // internal subject id
	IdPSubject   string // upstream IdP `sub`
	Name         string
	GivenName    string
	FamilyName   string
	SerialNumber string
	LoA          string
	LoginMethod  string
}

// Resolver maps IdP claims (acr + amr) to our internal login method + assurance
// level. It is the single anti-corruption point between eParaksts's (in-flux) claim
// semantics and the platform's stable identity model — see Interpret.
//
// Each of the two outputs is driven by a vocabulary: a lower-cased token substring
// (matched against the combined acr+amr) → the resolved value. The *Keys slices
// hold each vocabulary's tokens longest-first, so matching is deterministic and the
// most specific token wins.
type Resolver struct {
	loaPolicy     map[string]string
	loaKeys       []string
	methodPolicy  map[string]string
	methodKeys    []string
	methodDefault string
	loaDefault    string
}

// DefaultLoAPolicy is the built-in acr/amr → assurance-level mapping.
//
// Production Entrust returns a Safelayer *level* URN in `acr`
// (e.g. urn:safelayer:tws:policies:authentication:level:high). Some
// environments (notably eParaksts demo) instead echo the requested *flow* URN
// (e.g. urn:eparaksts:authentication:flow:mobileid) and carry the method in
// `amr`. We therefore map both: explicit `level:*` wins (longest match), and as
// a fallback the QSCD-backed eParaksts methods (mobile, eID Scan) — all
// qualified, SCAL2 — resolve to "high". Override per environment via LOA_POLICY
// once production's exact `acr` values are confirmed. No sc_plugin entry: eID-card
// login via the TrustedX plugin is not permitted (Web eID only).
func DefaultLoAPolicy() map[string]string {
	return map[string]string{
		"level:high":        LoAHigh,
		"level:substantial": LoASubstantial,
		"level:low":         LoALow,
		"mobileid":          LoAHigh,
		"mobile-eid":        LoAHigh,
	}
}

// DefaultMethodPolicy is the built-in acr/amr → login-method vocabulary. The token
// is the concrete eParaksts method segment of a flow/methods URN:
//
//	mobile-eid → eID Scan (phone reads the physical eID card)
//	mobileid / smart_id / cloud / mobile → eParaksts Mobile (Cloud signing)
//	sc_plugin / smartcard → eID (legacy smart-card-via-plugin; not a permitted login)
//
// Matched longest token first (see matchPolicy), so "mobile-eid" wins over the bare
// "mobile"/"mobileid" tokens it contains, and a bare "eid" is never matched.
//
// NB — eParaksts demo quirk (tracked upstream): the IdP currently returns an
// IDENTICAL amr (`…methods:mobileid`) for BOTH mobile and eID Scan, distinguishing
// them only in the acr (`…flow:mobileid` vs `…flow:mobile-eid`). Interpret scans
// both claims, so this resolves correctly today and keeps resolving correctly once
// the IdP moves the tool into the amr — this map is the single place to adjust if
// the token spellings change.
func DefaultMethodPolicy() map[string]string {
	return map[string]string{
		"mobile-eid": LoginEIDScan,
		"sc_plugin":  LoginEID,
		"smartcard":  LoginEID,
		"mobileid":   LoginEParakstsMobile,
		"smart_id":   LoginEParakstsMobile,
		"cloud":      LoginEParakstsMobile,
		"mobile":     LoginEParakstsMobile,
	}
}

// NewResolver builds a resolver. loaPolicy overrides the assurance-level vocabulary
// (nil/empty → DefaultLoAPolicy); the method vocabulary is DefaultMethodPolicy.
func NewResolver(loaPolicy map[string]string) *Resolver {
	return NewResolverPolicies(loaPolicy, nil, "", "")
}

// NewResolverPolicies builds a resolver with both vocabularies and both
// fallbacks supplied by the upstream provider's configuration. Empty values
// keep the eParaksts-shaped defaults: DefaultLoAPolicy, DefaultMethodPolicy,
// the never-allowed LoginEID method sentinel, and LoALow.
func NewResolverPolicies(loaPolicy, methodPolicy map[string]string, methodDefault, loaDefault string) *Resolver {
	if len(loaPolicy) == 0 {
		loaPolicy = DefaultLoAPolicy()
	}
	if len(methodPolicy) == 0 {
		methodPolicy = DefaultMethodPolicy()
	}
	if methodDefault == "" {
		methodDefault = LoginEID
	}
	if loaDefault == "" {
		loaDefault = LoALow
	}

	loa, loaKeys := indexPolicy(loaPolicy)
	method, methodKeys := indexPolicy(methodPolicy)

	return &Resolver{
		loaPolicy: loa, loaKeys: loaKeys,
		methodPolicy: method, methodKeys: methodKeys,
		methodDefault: methodDefault, loaDefault: loaDefault,
	}
}

// indexPolicy lower-cases a vocabulary and returns it with its keys sorted
// longest-first, so the most-specific token wins deterministically.
func indexPolicy(policy map[string]string) (map[string]string, []string) {
	lower := make(map[string]string, len(policy))
	keys := make([]string, 0, len(policy))
	for k, v := range policy {
		lk := strings.ToLower(k)
		lower[lk] = v
		keys = append(keys, lk)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })

	return lower, keys
}

// Resolve produces an Identity (without the internal subject, which the store
// assigns) from the IdP userinfo.
func (r *Resolver) Resolve(u UserInfo) Identity {
	method, loa := r.Interpret(u.ACR, u.AMR)

	return Identity{
		IdPSubject:   u.Subject,
		Name:         u.Name,
		GivenName:    u.GivenName,
		FamilyName:   u.FamilyName,
		SerialNumber: u.SerialNumber,
		LoA:          loa,
		LoginMethod:  method,
	}
}

// Interpret is the single anti-corruption point between the eParaksts IdP's
// (in-flux) authentication claims and our stable identity model: it maps the acr +
// amr to a login method and an assurance level by scanning BOTH claims against two
// explicit vocabularies (DefaultMethodPolicy, DefaultLoAPolicy), longest token
// first.
//
// Scanning both claims — rather than hardcoding "method comes from amr, level from
// acr" — is deliberate, because where eParaksts puts each signal is changing:
//
//   - TODAY the IdP carries the METHOD in the acr (a flow URN: `…flow:mobileid` vs
//     `…flow:mobile-eid`) and returns an IDENTICAL amr (`…methods:mobileid`) for both
//     mobile and eID Scan; the level is inferred from that same method token.
//   - The upstream fix (tracked) will carry the LoA level in the acr and the tool in
//     the amr (`…methods:mobile-eid`).
//
// Because Interpret looks in both claims for the known tokens, neither move breaks
// it: the method is found wherever it lives and the level wherever it lives. The
// only change the upstream fix needs is DATA — add the real level tokens to
// DefaultLoAPolicy so an explicit `level:*` wins. No control flow here changes.
func (r *Resolver) Interpret(acr string, amr []string) (method, loa string) {
	method = matchPolicy(r.methodKeys, r.methodPolicy, r.methodDefault, acr, amr)
	loa = matchPolicy(r.loaKeys, r.loaPolicy, r.loaDefault, acr, amr)

	return method, loa
}

// ResolveLoA derives the assurance level from the acr + amr claims (a thin wrapper
// over the LoA vocabulary; see Interpret for why both claims are scanned).
func (r *Resolver) ResolveLoA(acr string, amr ...string) string {
	return matchPolicy(r.loaKeys, r.loaPolicy, r.loaDefault, acr, amr)
}

// matchPolicy returns the value mapped to the first vocabulary token found in the
// combined, lower-cased acr+amr haystack (keys scanned longest-first, so the most
// specific token wins), or def when none match. Scanning both claims is what makes
// Interpret indifferent to which claim the IdP places a token in.
func matchPolicy(keys []string, policy map[string]string, def, acr string, amr []string) string {
	hay := strings.ToLower(acr)
	for _, m := range amr {
		hay += " " + strings.ToLower(m)
	}

	for _, k := range keys {
		if strings.Contains(hay, k) {
			return policy[k]
		}
	}

	return def
}

// Signing-flow tokens. These are the internal flow identifiers shared by name
// with the signing service (camelCase, identical to the login_method value where
// they coincide). The mapping from a flow to an external provider contract lives
// in the signing service, not here.
const (
	FlowWebEID               = "webEid"
	FlowEIDScan              = "eidScan"
	FlowEParakstsMobile      = "eparakstsMobile"
	FlowEParakstsMobileEseal = "eparakstsMobileEseal"
	FlowCSC                  = "csc"
)

// BindingResolver implements the login-method ↔ signing-flow binding: each login
// method permits a specific set of signing flows. eParaksts Mobile is the only
// method that authorizes more than one (its personal cloud signature, the
// mobile-bound organisation eSeal, and the CSC flow); a Web eID login and an eID
// Scan login each bind to their own single flow and do not cross over.
type BindingResolver struct{}

// PermittedFlows returns the signing flows a login method may drive. An unknown
// or empty method — and the legacy plugin eID, which is not a permitted login —
// permits nothing, so the binding fails closed.
func (BindingResolver) PermittedFlows(loginMethod string) []string {
	switch loginMethod {
	case LoginWebEID:
		return []string{FlowWebEID}
	case LoginEIDScan:
		return []string{FlowEIDScan}
	case LoginEParakstsMobile:
		return []string{FlowEParakstsMobile, FlowEParakstsMobileEseal, FlowCSC}
	default:
		return nil
	}
}

// StepUpRequired reports whether the current login method can satisfy a signing
// request made with requestedMethod. When it cannot, it returns the login
// method the user must re-authenticate with.
func (BindingResolver) StepUpRequired(current, requested string) (bool, string) {
	if requested == "" || current == requested {
		return false, ""
	}

	return true, requested
}
