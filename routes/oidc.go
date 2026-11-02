package routes

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session"
)

const (
	scopeOpenID = "openid"
	// maxNonceLen bounds the nonce a client may make authbyte keep for it. The
	// standard states no bound; this one is far beyond any random value's need.
	maxNonceLen = 512
	// authTimeSkew is the leeway allowed when a provider's authentication time
	// is held against a client's max_age.
	authTimeSkew = 30 * time.Second
)

// errAuthenticationTooOld is a sign-in whose provider says the person
// authenticated longer ago than the client's max_age allows.
var errAuthenticationTooOld = errors.New("the authentication is older than the client allows")

// cardAMR are the means of a card sign-in [RFC 8176 §2]: the card's key (a
// hardware-secured key on a smart card), unlocked by its PIN — two factors.
var cardAMR = []string{"hwk", "mfa", "pin", "sc"}

// registeredAMRValues are the means of authentication [RFC 8176 §2] registers.
var registeredAMRValues = []string{
	"face", "fpt", "geo", "hwk", "iris", "kba", "mca", "mfa", "otp", "pin",
	"pwd", "rba", "retina", "sc", "sms", "swk", "tel", "user", "vbm", "wia",
}

// authError is a refusal of an authorization request, answered at the
// client's own address: its code and description.
type authError struct {
	code, description string
}

// idTokenAsk is what a request asks of an ID token: whether it wants one
// (openid in its scope [OIDC Core §3.1.2.1]) and the nonce it must carry.
type idTokenAsk struct {
	openID bool
	nonce  string
}

// readIDTokenAsk reads scope and nonce. Other scope values are not this
// server's to read and are ignored; the nonce is kept exactly as sent, and only
// bounded.
func readIDTokenAsk(p authParams) (idTokenAsk, *authError) {
	var ask idTokenAsk
	if s := p.opt("scope"); s != nil {
		ask.openID = slices.Contains(strings.Fields(*s), scopeOpenID)
	}
	if n := p.opt("nonce"); n != nil {
		if len(*n) > maxNonceLen {
			return ask, &authError{"invalid_request", "nonce is longer than " + strconv.Itoa(maxNonceLen) + " characters"}
		}
		ask.nonce = *n
	}

	return ask, nil
}

// signInAsk is what an authorization request asks of the sign-in itself.
type signInAsk struct {
	// forcedLogin asks the provider to sign the person in again: prompt=login,
	// or any max_age. A request that reaches the provider was not answered from
	// the browser's shared session, and authbyte cannot read how old the
	// provider's own session is.
	forcedLogin bool
	// login is prompt=login: the person signs in again whatever the browser's
	// shared session holds. none is prompt=none: no page may be shown, so the
	// request is answered from the shared session or refused.
	login, none bool
	// selectAccount passes prompt=select_account on: the accounts are the
	// provider's.
	selectAccount bool
	// maxAge is the client's max_age in seconds, when it named one.
	maxAge *int64
	// uiLocales passes on as they came.
	uiLocales string
}

// readSignInAsk reads what an authorization request asks beyond OAuth and
// refuses, as [OIDC Core §3.1.2.6] codes, what can never be met here. Every
// refusal is decided before anything is stored.
func readSignInAsk(p authParams) (signInAsk, *authError) {
	var ask signInAsk

	// What this server does not support is refused, not ignored.
	if p.opt("request") != nil {
		return ask, &authError{"request_not_supported", "request objects are not supported"}
	}
	if p.opt("request_uri") != nil {
		return ask, &authError{"request_uri_not_supported", "request objects are not supported"}
	}
	// A hint names the person the client expects; until a sign-in can be held
	// to it, a hint is refused, since ignoring it could answer for another
	// person.
	if p.opt("id_token_hint") != nil {
		return ask, &authError{"invalid_request", "id_token_hint is not supported"}
	}

	if v := p.opt("max_age"); v != nil {
		age, err := strconv.ParseInt(*v, 10, 64)
		if err != nil || age < 0 {
			return ask, &authError{"invalid_request", "max_age must be a whole number of seconds"}
		}
		ask.maxAge = &age
		ask.forcedLogin = true
	}

	if p := p.opt("prompt"); p != nil {
		values := strings.Fields(*p)
		if slices.Contains(values, "none") {
			if len(values) > 1 {
				return ask, &authError{"invalid_request", "prompt none cannot be combined with another value"}
			}
			// Answered from the browser's shared session, or refused where it
			// cannot be: never a page.
			ask.none = true
		}
		if slices.Contains(values, "consent") {
			return ask, &authError{"consent_required", "this server shows no consent page"}
		}
		if slices.Contains(values, "login") {
			ask.forcedLogin = true
			ask.login = true
		}
		ask.selectAccount = slices.Contains(values, "select_account")
		// A value outside the set is ignored [OIDC Core §3.1.2.1].
	}

	if l := p.opt("ui_locales"); l != nil {
		ask.uiLocales = *l
	}

	return ask, nil
}

// upstreamPrompt is the prompt the provider is sent for the ask.
func (a signInAsk) upstreamPrompt() string {
	switch {
	case a.forcedLogin:
		return "login"
	case a.selectAccount:
		return "select_account"
	default:
		return ""
	}
}

// upstreamACR is what the provider is sent as acr_values for the methods a
// request named: each method's own code at that provider (acrFor), in the order
// named. A method the provider forces by no code of
// its own (a generic provider's sign-in, the card) adds nothing.
func upstreamACR(acrFor func(method string) string, methods []string) string {
	codes := make([]string, 0, len(methods))
	for _, m := range methods {
		if c := acrFor(m); c != "" {
			codes = append(codes, c)
		}
	}

	return strings.Join(codes, " ")
}

// signInMoment is when the person proved who they are at a provider's sign-in,
// in Unix seconds: the provider's own time when its verified token states it;
// the completion's moment when the provider was made to sign them in again;
// otherwise 0, unknown. A provider's time from before a request that made it
// sign the person in again, or one older than the client's max_age, refuses
// the sign-in: the provider answered from its own session.
func signInMoment(info identity.UserInfo, flow *session.Flow, now time.Time) (int64, error) {
	var at int64
	switch {
	case info.AuthTime > 0:
		at = info.AuthTime
	case flow.ForcedLogin:
		at = now.Unix()
	}

	skew := int64(authTimeSkew / time.Second)
	if flow.ForcedLogin && info.AuthTime > 0 && info.AuthTime < flow.Started-skew {
		return 0, errAuthenticationTooOld
	}
	if flow.MaxAge != nil && at > 0 && now.Unix()-at-skew > *flow.MaxAge {
		return 0, errAuthenticationTooOld
	}

	return at, nil
}

// registeredAMR keeps the means a provider stated that [RFC 8176 §2]
// registers, in its order; nothing else is passed on as a means.
func registeredAMR(amr []string) []string {
	var out []string
	for _, v := range amr {
		if slices.Contains(registeredAMRValues, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}

	return out
}

// stampSignIn records on a new session what its ID tokens will state: when the
// person authenticated, how, and the session's public name.
func stampSignIn(sess *session.Session, authTime int64, amr []string) {
	sess.AuthTime = authTime
	sess.AMR = amr
	sess.SID = randomToken(24)
}

// issuerID is this server's issuer identifier as discovery states it: the iss
// of every answer to the browser and of every token.
func (r *router) issuerID() string {
	return strings.TrimSuffix(r.Config().IssuerURL, "/")
}
