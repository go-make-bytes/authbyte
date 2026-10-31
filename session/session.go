// Package session holds short-lived auth-flow state (the SPA↔Auth PKCE/state
// and the Auth↔Entrust leg), server-side user sessions and the refresh grants
// that name them, in the application's shared cache (Valkey or Redis).
package session

import (
	"errors"
	"strings"
	"time"
)

// ErrNotFound is returned when a flow or session key is absent or expired.
var ErrNotFound = errors.New("session: not found")

// Flow is the transient state of an in-progress login, keyed by the upstream
// (Auth↔Entrust) state value.
type Flow struct {
	// SPA-side PKCE (the SPA is the client of the Auth service).
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	// RedirectURI the SPA expects the app authorization code returned to.
	AppRedirectURI string `json:"app_redirect_uri"`
	// SPAState echoes the SPA's own state parameter.
	SPAState string `json:"spa_state"`
	// Entrust leg.
	EntrustRedirectURI string `json:"entrust_redirect_uri"`
	// Whether this flow is a step-up (re-auth) and the method requested.
	StepUp         bool   `json:"step_up"`
	RequestedLogin string `json:"requested_login"`
	// RequestedMethods are the login methods an ordinary sign-in's acr_values
	// asked for, in order; empty when it asked for none. The sign-in completes only
	// with one of them.
	RequestedMethods []string `json:"requested_methods,omitempty"`
	// ExistingSession id to update on step-up completion.
	SessionID string `json:"session_id"`
	// ClientID of the public client that initiated the authorization request.
	ClientID string `json:"client_id"`
	// WebEIDNonce is the challenge nonce issued for a Web eID card login (the Auth
	// service owns it; the engine's stateless /auth/validate checks the token
	// against it). Empty for the eParaksts redirect flow.
	WebEIDNonce string `json:"webeid_nonce,omitempty"`
	// Tenant is the organisation the person asked to act under when the login
	// began (`/authorize?tenant=`). Carried to the token issue so that, when the
	// person holds several memberships, the choice is theirs — never guessed.
	Tenant string `json:"tenant,omitempty"`
	// Nonce is the value sent to the upstream provider with the authorize
	// request; the id_token it issues must carry it back, which binds that
	// token to this flow and nothing else. Empty for a card login.
	Nonce string `json:"nonce,omitempty"`
}

// AppCode binds an issued application authorization code (Auth→SPA) to the
// authenticated session, pending the SPA's /token exchange.
type AppCode struct {
	SessionID           string `json:"session_id"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	// ClientID and RedirectURI are echo-checked at /token ([RFC 6749 §4.1.3]).
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	// Tenant is the organisation named when the login began, if any.
	Tenant string `json:"tenant,omitempty"`
}

// Session is the server-side user session.
type Session struct {
	Subject      string `json:"subject"`
	Name         string `json:"name"`
	GivenName    string `json:"given_name"`
	FamilyName   string `json:"family_name"`
	SerialNumber string `json:"serial_number"`
	LoA          string `json:"loa"`
	LoginMethod  string `json:"login_method"`
	// ClientID is the public client the session's tokens are issued to. Its
	// registration says whether the people logging in through it need a
	// membership in the register.
	ClientID string `json:"client_id,omitempty"`
	// Tenant is the membership the session's tokens are minted for — the person's
	// single membership, or the one they chose. Re-resolved at every refresh, so a
	// revoked membership dies with the next token.
	Tenant string `json:"tenant,omitempty"`
	// Thumbprint is the SPA's DPoP key thumbprint the session's tokens bind to.
	Thumbprint string `json:"thumbprint"`
	// Capabilities is the signing-capability catalog captured at login, when
	// the upstream provides one. nil = not captured (the signing-time fallback
	// resolves identities itself).
	Capabilities *Capabilities `json:"capabilities,omitempty"`
	// DirectoryIssuer is the identity provider the session's login came through
	// ("" for a card login). At token issue a person who holds no membership
	// yet is offered to the register's admission door with it: the tenant that
	// attached this issuer as its directory admits them as a member with no
	// grants. DirectoryGuest withholds that — the provider called the person a
	// guest in its directory, and a tenant attached its own people, not its
	// visitors; such a login is refused exactly as any other stranger's.
	DirectoryIssuer string `json:"directory_issuer,omitempty"`
	DirectoryGuest  bool   `json:"directory_guest,omitempty"`
	// ProviderSubject and ProviderIssuer name the credential the session's login
	// used: the provider's handle for the person and the provider ("" for a card
	// login). A step-up of a session without an identity code must come back with
	// the same pair, since nothing else says it is the same person.
	ProviderSubject string `json:"provider_subject,omitempty"`
	ProviderIssuer  string `json:"provider_issuer,omitempty"`
	// ExpiresAt is the end of the session's lifetime, fixed when it is created. A
	// later save keeps it: nothing but a new sign-in gives a person more time.
	ExpiresAt time.Time `json:"expires_at"`
	// RefreshKey is the key the session's refresh token is kept under (a hash of
	// the token; the token itself is never stored). Empty until the first code
	// exchange answers one.
	RefreshKey string `json:"refresh_key,omitempty"`
}

// Expired reports whether the session's lifetime has run out at now. A session
// with no end recorded is treated as ended.
func (s *Session) Expired(now time.Time) bool {
	return s.ExpiresAt.IsZero() || !now.Before(s.ExpiresAt)
}

// RefreshGrant is what a refresh token stands for: the session it renews and the
// client it was issued to. It is kept under the token's hash.
type RefreshGrant struct {
	SessionID string `json:"session_id"`
	ClientID  string `json:"client_id"`
}

// DisplayName is the name a register shows for the person: the full name the
// login carried, else the given and family names, else the subject itself —
// never empty, because a membership row needs one.
func (s *Session) DisplayName() string {
	if s.Name != "" {
		return s.Name
	}
	if n := strings.TrimSpace(s.GivenName + " " + s.FamilyName); n != "" {
		return n
	}

	return s.Subject
}

// Capabilities is the signing capability set derived at login from the
// identity provider's sign-identity profile: which signing identity this
// session's login method uses, its certificate, the paired authentication
// certificate, and the organisation seals the person may sign with. Derived
// data only — no upstream token is ever stored. The certificates carry
// personal data: they are never logged and they die with the session. Every
// field is optional; a signing act uses what is present and falls back to
// resolving the rest itself.
type Capabilities struct {
	SignIdentityID     string `json:"sign_identity_id,omitempty"`
	SigningCertificate string `json:"signing_certificate,omitempty"`
	AuthCertificate    string `json:"auth_certificate,omitempty"`
	Seals              []Seal `json:"seals,omitempty"`
	// SealsKnown marks that the seal catalog was actually read on this login
	// path — an empty Seals list then means the person verifiably holds no
	// seals, as opposed to seal availability being unknown (e.g. a login path
	// that never sees the provider's profile).
	SealsKnown bool `json:"seals_known,omitempty"`
}

// Seal is one organisation seal the person may sign with: the sign-identity id
// a signing act selects it by, the display name a picker shows (from the
// seal's CN label), and its certificate.
type Seal struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Certificate string `json:"certificate,omitempty"`
}
