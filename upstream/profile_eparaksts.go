package upstream

import "github.com/go-make-bytes/authbyte/identity"

// The eParaksts (Entrust / TrustedX) provider profile — the first configured
// instance of the generic connector, kept as a named profile because this
// provider's endpoints are fixed, non-discoverable paths and its logout is a
// bespoke session-termination endpoint rather than RP-initiated logout.
//
// Endpoint paths and the urn:lvrtc:fpeil:aa scope follow the eParaksts/Entrust
// identity provider documentation.
const (
	eparakstsAuthorizePath = "/trustedx-authserver/oauth/lvrtc-eipsign-as"
	eparakstsTokenPath     = "/trustedx-authserver/oauth/lvrtc-eipsign-as/token"
	eparakstsUserInfoPath  = "/trustedx-resources/openid/v1/users/me"
	// The per-identity certificate endpoint of the same platform (trailing
	// slash: the sign-identity id is appended).
	eparakstsSignIdentityPath = "/trustedx-resources/esigp/v1/sign_identities/"

	// The IdP session-termination endpoint (Identity provider API):
	// GET /trustedx-authserver/{idp}/logout?redirect_uri=...
	// Note the IdP id (default lvrtc-eipsign-idp) differs from the OAuth AS id
	// (lvrtc-eipsign-as) in the authorize path, so it is supplied separately.
	eparakstsLogoutPrefix = "/trustedx-authserver/"
	eparakstsLogoutSuffix = "/logout"

	// EParakstsDefaultLogoutIDP is the eParaksts identity-provider identifier
	// used for the logout endpoint (per the Identity provider API docs).
	EParakstsDefaultLogoutIDP = "lvrtc-eipsign-idp"

	// EParakstsDefaultScope is the eParaksts electronic-identification scope.
	EParakstsDefaultScope = "urn:lvrtc:fpeil:aa"
)

// EParakstsProfile returns the provider Config for the eParaksts/Entrust IdP:
// fixed endpoint paths under the authority, the bespoke logout template, the
// electronic-identification scope, and the acr/amr vocabularies for its
// methods. Only eParaksts Mobile and eID Scan are permitted logins — the
// legacy smart-card-via-plugin method resolves to the "eid" sentinel, which is
// outside the allowed set, so that path fails closed (eID cards log in through
// Web eID instead). The caller fills ClientID/ClientSecret and may override
// Scopes and the vocabularies.
func EParakstsProfile(authorityURL, logoutIDP string) Config {
	if logoutIDP == "" {
		logoutIDP = EParakstsDefaultLogoutIDP
	}
	base := trimSlash(authorityURL)

	return Config{
		AuthorityURL: base,
		// Identification plus the sign-identity profile: one identification at
		// login also captures the person's signing capabilities (identities +
		// certificates), so later signing acts need no separate profile
		// consent. Overridable — dropping the profile scope turns capability
		// capture off and every signing act resolves its own identities.
		Scopes:          []string{EParakstsDefaultScope, ScopeSignIdentityProfile},
		AuthorizeURL:    base + eparakstsAuthorizePath,
		TokenURL:        base + eparakstsTokenPath,
		UserInfoURL:     base + eparakstsUserInfoPath,
		SignIdentityURL: base + eparakstsSignIdentityPath,
		// %s receives the url-encoded post-logout redirect.
		LogoutTemplate: base + eparakstsLogoutPrefix + logoutIDP + eparakstsLogoutSuffix + "?redirect_uri=%s",
		ClaimSerial:    "serial_number",
		MethodPolicy:   identity.DefaultMethodPolicy(),
		MethodDefault:  identity.LoginEID, // unrecognized ⇒ the never-allowed sentinel: fail closed
		LoAPolicy:      identity.DefaultLoAPolicy(),
		LoADefault:     identity.LoALow,
		MethodsAllowed: []string{identity.LoginEParakstsMobile, identity.LoginEIDScan},
		// The legacy plugin method did authenticate at the IdP (SSO cookie set),
		// so a logout for it still clears the IdP session front-channel.
		MethodsFederated: []string{identity.LoginEParakstsMobile, identity.LoginEIDScan, identity.LoginEID},
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}

	return s
}
