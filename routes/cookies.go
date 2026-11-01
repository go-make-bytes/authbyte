package routes

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"azugo.io/azugo"
)

// The cookies the sign-in page sets on this service's own host.
const (
	// signInCookie ties every sign-in to the browser that started it: a random
	// value, the same for every sign-in that browser starts while it lives, so two
	// sign-ins in two tabs both finish. Each flow keeps its hash.
	signInCookie = "authbyte_signin"
	// noticeCookie carries one message to the next showing of the sign-in page,
	// after the provider sent the person back: read once, then cleared.
	noticeCookie = "authbyte_notice"
	// languageCookie keeps the language the person chose on the page.
	languageCookie = "authbyte_lang"

	hostPrefix     = "__Host-"
	bindingBytes   = 32
	noticeLifetime = time.Minute
	langLifetime   = 365 * 24 * time.Hour
)

// The messages a provider's answer leaves for the page.
const (
	noticeCancelled = "cancelled"
	noticeProvider  = "provider"
)

// secureCookies reports whether this request's cookies are Secure, and so named
// with hostPrefix: over TLS (as the trusted proxy reports it), and in every
// environment but development, so a deployment whose proxy is not trusted still
// names them so. Only a development server reached over plain HTTP uses the plain
// names. This is azugo's CookieDefaultSecurity rule; that option is not used
// itself because it reads a cookie by any of its prefixed names.
func secureCookies(ctx *azugo.Context) bool {
	return ctx.IsTLS() || !ctx.Env().IsDevelopment()
}

// cookieName is the name the cookie named name is set and read under on this
// request.
func cookieName(ctx *azugo.Context, name string) string {
	if secureCookies(ctx) {
		return hostPrefix + name
	}

	return name
}

// readCookie is the value of the cookie this service set as name, read by its
// exact name. Never ctx.Cookie.Get: given a plain name it answers a __Host- or
// __Secure- copy before the plain one, and either can be planted by another host.
func readCookie(ctx *azugo.Context, name string) string {
	return string(ctx.Request().Header.Cookie(cookieName(ctx, name)))
}

// setCookie writes a cookie http-only, SameSite=Lax (Strict would drop it on the
// provider's cross-site return), for the whole host.
func setCookie(ctx *azugo.Context, name, value string, lifetime time.Duration) {
	ctx.Cookie.Set(cookieName(ctx, name), value,
		azugo.CookieHTTPOnly(true),
		azugo.CookieSecure(secureCookies(ctx)),
		azugo.CookieSameSiteLax,
		azugo.CookiePath("/"),
		azugo.CookieMaxAge(lifetime),
	)
}

// clearCookie expires a cookie this service set. The expiring cookie carries
// Secure as the one it replaces did: a browser ignores a host-prefixed cookie
// without it, an expiring one included.
func clearCookie(ctx *azugo.Context, name string) {
	ctx.Cookie.Clear(cookieName(ctx, name), azugo.CookiePath("/"), azugo.CookieSecure(secureCookies(ctx)))
}

// browserBinding is the binding the browser sent, or "" when it sent none or one
// this service could not have set.
func browserBinding(ctx *azugo.Context) string {
	v := readCookie(ctx, signInCookie)
	if len(v) != base64.RawURLEncoding.EncodedLen(bindingBytes) {
		return ""
	}
	if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
		return ""
	}

	return v
}

// bindBrowser keeps the browser's binding, or gives it one, for as long as a
// sign-in may take from now. It is never cleared, only left to expire, so a
// sign-in started in another tab still finishes.
func bindBrowser(ctx *azugo.Context) string {
	binding := browserBinding(ctx)
	if binding == "" {
		binding = randomToken(bindingBytes)
	}
	setCookie(ctx, signInCookie, binding, flowTTL)

	return binding
}

// bindingHash is what a flow keeps of the binding: the cookie's value never
// leaves the browser and this request.
func bindingHash(binding string) string {
	sum := sha256.Sum256([]byte("authbyte sign-in binding\x00" + binding))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// boundHere reports whether this request comes from the browser a flow was
// bound to.
func boundHere(ctx *azugo.Context, flowBinding string) bool {
	b := browserBinding(ctx)

	return b != "" && subtle.ConstantTimeCompare([]byte(bindingHash(b)), []byte(flowBinding)) == 1
}

// choiceToken is the page's anti-forgery token: derived one way from the
// browser's binding, so nothing is stored per page shown, and no page that cannot
// read the cookie can write it.
func choiceToken(binding string) string {
	sum := sha256.Sum256([]byte("authbyte sign-in choice\x00" + binding))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// takeNotice reads the page's one message and clears it.
func takeNotice(ctx *azugo.Context) string {
	n := readCookie(ctx, noticeCookie)
	if n == "" {
		return ""
	}
	clearCookie(ctx, noticeCookie)
	if n != noticeCancelled && n != noticeProvider {
		return ""
	}

	return n
}
