// Package response holds the Identity/Auth response DTOs.
package response

// Token is the OAuth2 token-endpoint response. For DPoP-bound tokens the
// token_type is "DPoP". IssuedTokenType is set on a token-exchange response
// (RFC 8693) to name the type of the returned token.
type Token struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	// Capabilities is the session's signing-capability set captured at login.
	// Present only on the authorization-code grant, and only when the login
	// captured one — a caller stores it with its own session and threads the
	// fields into signing requests. Absent capabilities mean "unknown", never
	// "none": signing then resolves identities itself.
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// Capabilities is the signing-capability set of a logged-in session: the
// signing identity the session's login method uses, its certificate, the
// paired authentication certificate, and the organisation seals the person may
// sign with. Every field is optional. The certificates carry personal data —
// callers must never log them.
type Capabilities struct {
	SignIdentityID     string `json:"sign_identity_id,omitempty"`
	SigningCertificate string `json:"signing_certificate,omitempty"`
	AuthCertificate    string `json:"auth_certificate,omitempty"`
	Seals              []Seal `json:"seals,omitempty"`
	// SealsKnown says the seal list is authoritative: with it set, an empty
	// list means the person verifiably holds no seals rather than "unknown".
	SealsKnown bool `json:"seals_known,omitempty"`
}

// Seal is one organisation seal: the identity id a signing request selects it
// by, the display name a picker shows, and its certificate.
type Seal struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Certificate string `json:"certificate,omitempty"`
}

// Identity is the internal identity returned by GET /identity.
type Identity struct {
	Subject      string   `json:"sub"`
	Name         string   `json:"name,omitempty"`
	GivenName    string   `json:"given_name,omitempty"`
	FamilyName   string   `json:"family_name,omitempty"`
	SerialNumber string   `json:"serial_number,omitempty"`
	LoA          string   `json:"loa"`
	LoginMethod  string   `json:"login_method"`
	Scopes       []string `json:"scopes,omitempty"`
	// PermittedFlows are the signing flows the current login method may drive
	// (the login-method ↔ signing-flow binding).
	PermittedFlows []string `json:"permitted_flows,omitempty"`
}

// StepUp is the response to a successful step-up: a re-issued, DPoP-bound user
// token reflecting the elevated assurance / new login method.
type StepUp struct {
	Token       Token  `json:"token"`
	LoA         string `json:"loa"`
	LoginMethod string `json:"login_method"`
}
