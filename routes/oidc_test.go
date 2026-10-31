package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session"
	"github.com/go-make-bytes/authbyte/session/sessiontest"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

// testIssuer is the issuer the test app names (AUTH_ISSUER_URL).
const testIssuer = "http://localhost:8080"

// authorizeWith sends a browser to /authorize for the every-way client of the
// methods registry with the extra parameters, and answers where it was sent.
func authorizeWith(t *testing.T, app *azugo.TestApp, extra url.Values) *url.URL {
	t.Helper()

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "every-way")
	q.Set("redirect_uri", everyReturn)
	q.Set("state", "spa-state")
	q.Set("code_challenge", "challenge-of-forty-three-characters-long-aaaa")
	q.Set("code_challenge_method", "S256")
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}

	resp, err := app.TestClient().Get("/authorize?" + q.Encode())
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound), qt.Commentf("%s", resp.Body()))
	loc, err := url.Parse(string(resp.Header.Peek("Location")))
	qt.Assert(t, qt.IsNil(err))

	return loc
}

// checkAnsweredAtTheClient checks a refusal reached the client's own address with
// the error, its state and the issuer, and that no flow was stored for it.
func checkAnsweredAtTheClient(t *testing.T, mem *sessiontest.Memory, loc *url.URL, code string) {
	t.Helper()

	qt.Check(t, qt.Equals(loc.Host, "every.example"), qt.Commentf("sent to %s", loc))
	qt.Check(t, qt.Equals(loc.Query().Get("error"), code), qt.Commentf("sent to %s", loc))
	qt.Check(t, qt.Equals(loc.Query().Get("state"), "spa-state"))
	qt.Check(t, qt.Equals(loc.Query().Get("iss"), testIssuer))
	qt.Check(t, qt.Equals(flowCount(mem), 0))
}

// checkSentUpstream checks the browser went on to the provider and answers the
// flow that was stored for it.
func checkSentUpstream(t *testing.T, mem *sessiontest.Memory, loc *url.URL) *session.Flow {
	t.Helper()

	qt.Assert(t, qt.Equals(loc.Host, "localhost:9999"), qt.Commentf("sent to %s", loc))
	flow, err := mem.ConsumeFlow(context.Background(), loc.Query().Get("state"))
	qt.Assert(t, qt.IsNil(err))

	return flow
}

// prompt=none can never be answered without a page while authbyte holds no
// browser session: login_required at the client's address, nothing stored,
// nobody sent to the provider. none beside another value is malformed; consent
// cannot be obtained without a consent page.
func TestPromptNoneAndConsentAreAnsweredAtTheClient(t *testing.T) {
	for _, tc := range []struct{ prompt, code string }{
		{"none", "login_required"},
		{"none login", "invalid_request"},
		{"none select_account", "invalid_request"},
		{"consent", "consent_required"},
	} {
		t.Run(tc.prompt, func(t *testing.T) {
			app, mem := methodsApp(t)
			checkAnsweredAtTheClient(t, mem, authorizeWith(t, app, url.Values{"prompt": {tc.prompt}}), tc.code)
		})
	}
}

// prompt=login, and any max_age, ask the provider for a fresh sign-in, since
// authbyte cannot tell how old the provider's own session is; max_age=0 is
// prompt=login. select_account is the provider's to show. A value outside the
// set is ignored. ui_locales and display never cause an error, and the locales
// reach the provider.
func TestPromptAndMaxAgeReachTheProvider(t *testing.T) {
	for _, tc := range []struct {
		name               string
		extra              url.Values
		wantPrompt, maxAge string
		forced             bool
	}{
		{name: "login", extra: url.Values{"prompt": {"login"}}, wantPrompt: "login", forced: true},
		{name: "max_age=0", extra: url.Values{"max_age": {"0"}}, wantPrompt: "login", maxAge: "0", forced: true},
		{name: "max_age=3600", extra: url.Values{"max_age": {"3600"}}, wantPrompt: "login", maxAge: "3600", forced: true},
		{name: "max_age=43200", extra: url.Values{"max_age": {"43200"}}, wantPrompt: "login", maxAge: "43200", forced: true},
		{name: "select_account", extra: url.Values{"prompt": {"select_account"}}, wantPrompt: "select_account"},
		{name: "a value outside the set", extra: url.Values{"prompt": {"create"}}},
		{name: "display and ui_locales", extra: url.Values{"display": {"popup"}, "ui_locales": {"lv"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, mem := methodsApp(t)
			loc := authorizeWith(t, app, tc.extra)
			q := loc.Query()

			flow := checkSentUpstream(t, mem, loc)
			qt.Check(t, qt.Equals(q.Get("prompt"), tc.wantPrompt))
			qt.Check(t, qt.Equals(q.Get("max_age"), tc.maxAge))
			qt.Check(t, qt.Equals(flow.ForcedLogin, tc.forced))
			qt.Check(t, qt.Equals(q.Get("ui_locales"), tc.extra.Get("ui_locales")))
		})
	}
}

// A max_age that is not a whole number of seconds from 0 up is refused at the
// client's address before anything is stored. (One sent empty is as if omitted,
// [RFC 6749 §3.1].)
func TestABadMaxAgeIsRefused(t *testing.T) {
	for _, v := range []string{"-1", "abc", "1.5", "99999999999999999999"} {
		t.Run(v, func(t *testing.T) {
			app, mem := methodsApp(t)
			checkAnsweredAtTheClient(t, mem, authorizeWith(t, app, url.Values{"max_age": {v}}), "invalid_request")
		})
	}
}

// What authbyte does not support is refused rather than ignored: a request
// object, its address, and an ID token hint, which it cannot yet hold the
// sign-in to (ignoring it could answer for another person).
func TestUnsupportedRequestParametersAreRefused(t *testing.T) {
	for _, tc := range []struct {
		param, code string
	}{
		{"request", "request_not_supported"},
		{"request_uri", "request_uri_not_supported"},
		{"id_token_hint", "invalid_request"},
	} {
		t.Run(tc.param, func(t *testing.T) {
			app, mem := methodsApp(t)
			checkAnsweredAtTheClient(t, mem, authorizeWith(t, app, url.Values{tc.param: {"x.y.z"}}), tc.code)
		})
	}
}

// openid in the scope is what asks for an ID token, beside any other scope
// value; the client's nonce is kept exactly as sent and never sent on to the
// provider, which gets authbyte's own.
func TestTheFlowKeepsTheIDTokenAsk(t *testing.T) {
	const nonce = "n+a/b= c"

	app, mem := methodsApp(t)
	loc := authorizeWith(t, app, url.Values{"scope": {"openid profile"}, "nonce": {nonce}})
	flow := checkSentUpstream(t, mem, loc)
	qt.Check(t, qt.IsTrue(flow.OpenID))
	qt.Check(t, qt.Equals(flow.ClientNonce, nonce))
	qt.Check(t, qt.Not(qt.Equals(loc.Query().Get("nonce"), nonce)))
	qt.Check(t, qt.Equals(loc.Query().Get("nonce"), flow.Nonce))

	for _, scope := range []string{"", "profile"} {
		loc := authorizeWith(t, app, url.Values{"scope": {scope}, "nonce": {nonce}})
		flow := checkSentUpstream(t, mem, loc)
		qt.Check(t, qt.IsFalse(flow.OpenID), qt.Commentf("scope %q", scope))
	}
}

// The nonce authbyte stores for a client is bounded: 512 characters are kept,
// 513 are refused before anything is stored.
func TestTheNonceIsBounded(t *testing.T) {
	app, mem := methodsApp(t)

	flow := checkSentUpstream(t, mem, authorizeWith(t, app, url.Values{"scope": {"openid"}, "nonce": {strings.Repeat("n", 512)}}))
	qt.Check(t, qt.HasLen(flow.ClientNonce, 512))

	checkAnsweredAtTheClient(t, mem, authorizeWith(t, app, url.Values{"scope": {"openid"}, "nonce": {strings.Repeat("n", 513)}}), "invalid_request")
}

// acr_values speaks authbyte's own method names, exactly; the provider is sent
// its own code for each, in the order asked. A provider's code, another
// spelling, or an assurance level names no method.
func TestAcrValuesNameAuthbytesOwnMethods(t *testing.T) {
	for _, tc := range []struct{ acr, upstream string }{
		{identity.LoginEParakstsMobile, "urn:eparaksts:authentication:flow:mobileid"},
		{identity.LoginEIDScan + " " + identity.LoginEParakstsMobile, "urn:eparaksts:authentication:flow:mobile-eid urn:eparaksts:authentication:flow:mobileid"},
	} {
		app, mem := methodsApp(t)
		loc := authorizeWith(t, app, url.Values{"acr_values": {tc.acr}})
		qt.Check(t, qt.Equals(loc.Query().Get("acr_values"), tc.upstream), qt.Commentf("%s", tc.acr))
		checkSentUpstream(t, mem, loc)
	}

	for _, acr := range []string{
		"urn:eparaksts:authentication:flow:mobileid",
		"EparakstsMobile",
		"http://eidas.europa.eu/LoA/high",
	} {
		t.Run(acr, func(t *testing.T) {
			app, mem := methodsApp(t)
			checkAnsweredAtTheClient(t, mem, authorizeWith(t, app, url.Values{"acr_values": {acr}}), "unmet_authentication_requirements")
		})
	}
}

// A provider has an own code only for the methods it forces by one; a sign-in
// through a generic provider, or the card, sends none.
func TestOnlyAProvidersOwnMethodsHaveAnUpstreamCode(t *testing.T) {
	codes := map[string]string{identity.LoginEParakstsMobile: "m", identity.LoginEIDScan: "s"}
	acrFor := func(m string) string { return codes[m] }

	qt.Check(t, qt.Equals(upstreamACR(acrFor, []string{identity.LoginEIDScan, identity.LoginEParakstsMobile}), "s m"))
	qt.Check(t, qt.Equals(upstreamACR(acrFor, []string{"upstream"}), ""))
	qt.Check(t, qt.Equals(upstreamACR(acrFor, nil), ""))
}

// The moment a sign-in proved the person, and how. The provider's own time wins;
// without it the moment is known only when the provider was made to sign the
// person in again; otherwise there is none. An age the provider's time does not
// meet refuses the sign-in. Only registered means pass on.
func TestTheSignInsMomentAndMeans(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	age := func(s int64) *int64 { return &s }

	for _, tc := range []struct {
		name     string
		info     identity.UserInfo
		flow     session.Flow
		want     int64
		tooOld   bool
		wantMean []string
	}{
		{name: "the provider's time", info: identity.UserInfo{AuthTime: now.Unix() - 30}, want: now.Unix() - 30},
		{name: "a fresh sign-in, no time from the provider", flow: session.Flow{ForcedLogin: true}, want: now.Unix()},
		{name: "nothing known", want: 0},
		{name: "an age met", info: identity.UserInfo{AuthTime: now.Unix() - 30}, flow: session.Flow{ForcedLogin: true, MaxAge: age(60)}, want: now.Unix() - 30},
		{name: "an age not met", info: identity.UserInfo{AuthTime: now.Unix() - 120}, flow: session.Flow{ForcedLogin: true, MaxAge: age(60)}, tooOld: true},
		{name: "the largest age", info: identity.UserInfo{AuthTime: now.Unix() - 120}, flow: session.Flow{ForcedLogin: true, MaxAge: age(math.MaxInt64)}, want: now.Unix() - 120},
		{name: "a fresh sign-in the provider answered from its own session", info: identity.UserInfo{AuthTime: now.Unix() - 3*3600}, flow: session.Flow{ForcedLogin: true, Started: now.Unix() - 60}, tooOld: true},
		{name: "a fresh sign-in after the request", info: identity.UserInfo{AuthTime: now.Unix() - 20}, flow: session.Flow{ForcedLogin: true, Started: now.Unix() - 60}, want: now.Unix() - 20},
		{name: "max_age 0 and a time from before the request", info: identity.UserInfo{AuthTime: now.Unix() - 50}, flow: session.Flow{ForcedLogin: true, MaxAge: age(0), Started: now.Unix() - 10}, tooOld: true},
		{name: "registered means pass", info: identity.UserInfo{AMR: []string{"pwd", "mfa", "x-custom", "urn:eparaksts:x:methods:mobileid"}}, wantMean: []string{"pwd", "mfa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := signInMoment(tc.info, &tc.flow, now)
			if tc.tooOld {
				qt.Check(t, qt.ErrorIs(err, errAuthenticationTooOld))

				return
			}
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(got, tc.want))
			qt.Check(t, qt.DeepEquals(registeredAMR(tc.info.AMR), tc.wantMean))
		})
	}

	qt.Check(t, qt.DeepEquals(cardAMR, []string{"hwk", "mfa", "pin", "sc"}))
}

// openIDSignIn stores a completed sign-in that asked for an ID token with nonce.
func openIDSignIn(t *testing.T, mem *sessiontest.Memory, nonce string, openID bool) signIn {
	t.Helper()

	in := signIn{sid: randomToken(24), code: randomToken(24), verifier: randomToken(32)}
	sum := sha256.Sum256([]byte(in.verifier))

	ctx := context.Background()
	qt.Assert(t, qt.IsNil(mem.CreateSession(ctx, in.sid, &session.Session{
		Subject:      testPersonSub(5),
		Name:         "Ann Berzina",
		GivenName:    "Ann",
		FamilyName:   "Berzina",
		SerialNumber: "PNOLV-" + strings.Repeat("3", 11),
		LoA:          "high",
		LoginMethod:  identity.LoginWebEID,
		AuthTime:     1_800_000_000,
		AMR:          cardAMR,
		SID:          "public-sid-1",
	}, sessionLifetime)))
	qt.Assert(t, qt.IsNil(mem.SaveAppCode(ctx, in.code, &session.AppCode{
		SessionID:           in.sid,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(sum[:]),
		CodeChallengeMethod: "S256",
		ClientID:            "portal-spa",
		RedirectURI:         portalRedirect,
		OpenID:              openID,
		Nonce:               nonce,
	}, time.Minute)))

	return in
}

// tokenHeader decodes a token's JOSE header without verifying it.
func tokenHeader(t *testing.T, token string) map[string]any {
	t.Helper()

	tok, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	qt.Assert(t, qt.IsNil(err))

	return tok.Header
}

// A sign-in that asked for an ID token gets one at its code exchange: from this
// issuer, for the client alone, naming the person, the nonce, the moment, the
// method met and its means, and the public session id; nothing personal beyond
// the subject. The access token is typed as one; the ID token is not.
func TestAnIDTokenNamesTheSignIn(t *testing.T) {
	const nonce = "n+a/b= c"

	app, mem := signInApp(t)
	e := newEdge(t, app)

	in := openIDSignIn(t, mem, nonce, true)
	status, body := e.exchange(in, "portal-spa", portalRedirect)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	qt.Check(t, qt.Equals(e.cacheControl, "no-store"))
	qt.Check(t, qt.Equals(e.pragma, "no-cache"))

	raw, _ := body["id_token"].(string)
	qt.Assert(t, qt.Not(qt.Equals(raw, "")))
	c := tokenClaims(t, raw)
	access := tokenClaims(t, body["access_token"].(string))

	qt.Check(t, qt.Equals(c["iss"], any(testIssuer)))
	qt.Check(t, qt.Equals(c["sub"], access["sub"]))
	qt.Check(t, qt.Equals(c["aud"], any("portal-spa")))
	qt.Check(t, qt.Equals(c["nonce"], any(nonce)))
	qt.Check(t, qt.Equals(c["auth_time"], any(float64(1_800_000_000))))
	qt.Check(t, qt.Equals(c["acr"], any(identity.LoginWebEID)))
	qt.Check(t, qt.DeepEquals(c["amr"], any([]any{"hwk", "mfa", "pin", "sc"})))
	qt.Check(t, qt.Equals(c["sid"], any("public-sid-1")))
	qt.Check(t, qt.IsTrue(c["exp"].(float64) > c["iat"].(float64)))
	for _, absent := range []string{"azp", "name", "given_name", "family_name", "serial_number", "loa", "scope", "cnf"} {
		_, has := c[absent]
		qt.Check(t, qt.IsFalse(has), qt.Commentf("the ID token carries %q", absent))
	}

	qt.Check(t, qt.Equals(tokenHeader(t, raw)["typ"], any("JWT")))
	qt.Check(t, qt.Equals(tokenHeader(t, body["access_token"].(string))["typ"], any("at+jwt")))

	// The refresh mints a new access token and no ID token.
	status, body = e.refresh(body["refresh_token"].(string), "portal-spa")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	_, has := body["id_token"]
	qt.Check(t, qt.IsFalse(has))
	qt.Check(t, qt.Equals(e.cacheControl, "no-store"))
}

// A sign-in that did not ask, and one that asked with no nonce: none, and one
// without a nonce claim.
func TestAnIDTokenOnlyWhenAsked(t *testing.T) {
	app, mem := signInApp(t)

	status, body := newEdge(t, app).exchange(openIDSignIn(t, mem, "", false), "portal-spa", portalRedirect)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	_, has := body["id_token"]
	qt.Check(t, qt.IsFalse(has))

	status, body = newEdge(t, app).exchange(openIDSignIn(t, mem, "", true), "portal-spa", portalRedirect)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body["_raw"]))
	_, has = tokenClaims(t, body["id_token"].(string))["nonce"]
	qt.Check(t, qt.IsFalse(has))
}

// The discovery document says what this server answers.
func TestDiscoveryNamesTheIDTokenAndTheIssuerParameter(t *testing.T) {
	doc := discoveryDocument(t)

	qt.Check(t, qt.Equals(doc["issuer"], any(testIssuer)))
	qt.Check(t, qt.DeepEquals(doc["subject_types_supported"], any([]any{"public"})))
	qt.Check(t, qt.DeepEquals(doc["id_token_signing_alg_values_supported"], any([]any{"ES256"})))
	qt.Check(t, qt.DeepEquals(doc["scopes_supported"], any([]any{"openid"})))
	qt.Check(t, qt.Equals(doc["authorization_response_iss_parameter_supported"], any(true)))
	qt.Check(t, qt.Equals(doc["request_uri_parameter_supported"], any(false)))
	qt.Check(t, qt.DeepEquals(doc["response_types_supported"], any([]any{"code"})))

	claims, _ := json.Marshal(doc["claims_supported"])
	for _, name := range []string{"sub", "auth_time", "nonce", "acr", "amr", "sid", "serial_number"} {
		qt.Check(t, qt.StringContains(string(claims), `"`+name+`"`))
	}
	acrs, _ := json.Marshal(doc["acr_values_supported"])
	qt.Check(t, qt.StringContains(string(acrs), `"`+identity.LoginEParakstsMobile+`"`))
}
