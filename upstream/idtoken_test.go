package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

// stubIDP is a provider that publishes a key set: its discovery document names
// an issuer and a jwks_uri, its token endpoint answers an id_token signed with
// the key it publishes, and its userinfo answers whatever the test puts there.
// It is the shape of every mainstream provider (a work-account directory, a
// Keycloak realm), as opposed to the userinfo-only shape the eParaksts profile
// has always been tested against.
type stubIDP struct {
	t        *testing.T
	key      *rsa.PrivateKey
	kid      string
	url      string
	srv      *httptest.Server
	noJWKS   bool   // the discovery document names no key set
	userinfo string // the JSON body userinfo answers
	idToken  string // the id_token the token endpoint answers ("" = none)
}

func newStubIDP(t *testing.T, noJWKS bool) *stubIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))
	s := &stubIDP{t: t, key: key, kid: "k1", noJWKS: noJWKS}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                 s.url,
			"authorization_endpoint": s.url + "/authz",
			"token_endpoint":         s.url + "/tok",
			"userinfo_endpoint":      s.url + "/ui",
		}
		if !s.noJWKS {
			doc["jwks_uri"] = s.url + "/jwks"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/tok", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 600}
		if s.idToken != "" {
			resp["id_token"] = s.idToken
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/ui", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(s.userinfo))
	})
	s.srv = httptest.NewServer(mux)
	s.url = s.srv.URL
	t.Cleanup(s.srv.Close)

	return s
}

// claims is a well-formed id_token claim set for this provider: the flow's
// nonce, a durable directory identifier, a member's account status.
func (s *stubIDP) claims(nonce string) jwt.MapClaims {
	now := time.Now()

	return jwt.MapClaims{
		"iss":         s.url,
		"aud":         "cid",
		"sub":         "pairwise-sub-1",
		"exp":         jwt.NewNumericDate(now.Add(5 * time.Minute)),
		"iat":         jwt.NewNumericDate(now),
		"nonce":       nonce,
		"name":        "Anna Example",
		"given_name":  "Anna",
		"family_name": "Example",
		"oid":         "9f3c2a10-0000-4000-8000-000000000001",
		"acct":        0,
	}
}

// sign issues an id_token with the published key.
func (s *stubIDP) sign(claims jwt.MapClaims) string {
	s.t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.kid
	str, err := tok.SignedString(s.key)
	qt.Assert(s.t, qt.IsNil(err))

	return str
}

// provider constructs the connector against the stub with the claim maps a
// work-account directory needs.
func (s *stubIDP) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(context.Background(), Config{
		AuthorityURL:       s.url,
		ClientID:           "cid",
		ClientSecret:       "secret",
		MethodDefault:      "upstream",
		ClaimDirectoryID:   "oid",
		ClaimAccountStatus: "acct",
	}, nil)
	qt.Assert(t, qt.IsNil(err))

	return p
}

const memberUserinfo = `{"sub":"pairwise-sub-1","name":"Anna Example (userinfo)","given_name":"Anna","family_name":"Example","acr":"urn:x:low"}`

// Discovery captures the issuer and the key set, which is what turns the
// id_token path on; the authorize request carries the nonce; the token
// endpoint's id_token comes back with the access token.
func TestDiscoveryCapturesIssuerAndKeySet(t *testing.T) {
	s := newStubIDP(t, false)
	p := s.provider(t)

	qt.Assert(t, qt.IsTrue(p.IDTokenVerified()))
	qt.Assert(t, qt.Equals(p.Issuer(), s.url))

	auth := p.AuthorizeURL(AuthorizeParams{State: "s", RedirectURI: "https://cb", Nonce: "n-123"})
	qt.Assert(t, qt.StringContains(auth, "nonce=n-123"))

	s.idToken = s.sign(s.claims("n-123"))
	tokens, err := p.Exchange(context.Background(), "code", "https://cb")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(tokens.AccessToken, "tok"))
	qt.Assert(t, qt.Equals(tokens.IDToken, s.idToken))
}

// A verified id_token's claims win over userinfo's; the durable directory
// identifier and the member status are read from it; the authentication
// contexts it names join the amr list so the vocabularies can map them.
func TestClaimsVerifiesTheIDTokenAndMergesItFirst(t *testing.T) {
	s := newStubIDP(t, false)
	p := s.provider(t)
	s.userinfo = memberUserinfo
	c := s.claims("n-1")
	c["amr"] = []string{"pwd", "mfa"}
	c["acrs"] = []string{"c1"}
	s.idToken = s.sign(c)

	info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.idToken}, "n-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(info.Name, "Anna Example"), qt.Commentf("the id_token's name wins over userinfo's"))
	qt.Assert(t, qt.Equals(info.Subject, "pairwise-sub-1"))
	qt.Assert(t, qt.Equals(info.DirectoryID, "9f3c2a10-0000-4000-8000-000000000001"))
	qt.Assert(t, qt.IsFalse(info.DirectoryGuest))
	qt.Assert(t, qt.Equals(info.Issuer, s.url))
	qt.Assert(t, qt.Equals(info.ACR, "urn:x:low"), qt.Commentf("userinfo's acr stands when the id_token carries none"))
	qt.Assert(t, qt.DeepEquals(info.AMR, []string{"pwd", "mfa", "c1"}))
	// No identity code from a directory — the code stays empty, refused nowhere here.
	qt.Assert(t, qt.Equals(info.SerialNumber, ""))
}

// The account status tells a member from a guest, as a number or as text.
func TestClaimsReadsTheGuestFlag(t *testing.T) {
	s := newStubIDP(t, false)
	p := s.provider(t)
	s.userinfo = memberUserinfo

	for _, acct := range []any{1, "1"} {
		c := s.claims("n-2")
		c["acct"] = acct
		info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.sign(c)}, "n-2")
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(info.DirectoryGuest), qt.Commentf("acct=%v", acct))
	}

	// A member: 0, and a token that says nothing about it.
	c := s.claims("n-2")
	delete(c, "acct")
	info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.sign(c)}, "n-2")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(info.DirectoryGuest))
}

// Every way an id_token can fail refuses the login with ErrIDToken — and a
// provider that publishes a key set must send one at all.
func TestClaimsRefusesABadIDToken(t *testing.T) {
	s := newStubIDP(t, false)
	p := s.provider(t)
	s.userinfo = memberUserinfo
	ctx := context.Background()

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	past := s.claims("n-3")
	past["exp"] = jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))
	past["iat"] = jwt.NewNumericDate(time.Now().Add(-15 * time.Minute))
	wrongIss := s.claims("n-3")
	wrongIss["iss"] = s.url + "/other"
	wrongAud := s.claims("n-3")
	wrongAud["aud"] = "somebody-else"
	otherSub := s.claims("n-3")
	otherSub["sub"] = "pairwise-sub-2"

	none := jwt.NewWithClaims(jwt.SigningMethodNone, s.claims("n-3"))
	noneStr, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	qt.Assert(t, qt.IsNil(err))

	hmac := jwt.NewWithClaims(jwt.SigningMethodHS256, s.claims("n-3"))
	hmacStr, err := hmac.SignedString([]byte("secret"))
	qt.Assert(t, qt.IsNil(err))

	foreign := jwt.NewWithClaims(jwt.SigningMethodRS256, s.claims("n-3"))
	foreign.Header["kid"] = s.kid
	foreignStr, err := foreign.SignedString(other)
	qt.Assert(t, qt.IsNil(err))

	unknownKid := jwt.NewWithClaims(jwt.SigningMethodRS256, s.claims("n-3"))
	unknownKid.Header["kid"] = "k-unknown"
	unknownKidStr, err := unknownKid.SignedString(s.key)
	qt.Assert(t, qt.IsNil(err))

	cases := map[string]struct {
		idToken string
		nonce   string
	}{
		"missing id_token":              {"", "n-3"},
		"expired":                       {s.sign(past), "n-3"},
		"wrong issuer":                  {s.sign(wrongIss), "n-3"},
		"wrong audience":                {s.sign(wrongAud), "n-3"},
		"wrong nonce":                   {s.sign(s.claims("n-3")), "n-other"},
		"subject differs from userinfo": {s.sign(otherSub), "n-3"},
		"alg none":                      {noneStr, "n-3"},
		"hmac with the client secret":   {hmacStr, "n-3"},
		"signed by another key":         {foreignStr, "n-3"},
		"unknown kid":                   {unknownKidStr, "n-3"},
		"not a token":                   {"not.a.token", "n-3"},
	}
	for name, tc := range cases {
		_, err := p.Claims(ctx, Tokens{AccessToken: "tok", IDToken: tc.idToken}, tc.nonce)
		qt.Assert(t, qt.ErrorIs(err, ErrIDToken), qt.Commentf("%s: %v", name, err))
		// The refusal never carries a claim value.
		qt.Assert(t, qt.IsFalse(strings.Contains(err.Error(), "pairwise-sub")), qt.Commentf("%s: %v", name, err))
	}

	// The control: the same provider, a good token, accepted.
	s.idToken = s.sign(s.claims("n-3"))
	_, err = p.Claims(ctx, Tokens{AccessToken: "tok", IDToken: s.idToken}, "n-3")
	qt.Assert(t, qt.IsNil(err))
}

// A provider that publishes no key set is userinfo-only, exactly as before this
// path existed: the id_token is not read, and the credential handle is the
// userinfo subject.
func TestClaimsWithoutAKeySetIsUserinfoOnly(t *testing.T) {
	s := newStubIDP(t, true)
	p, err := New(context.Background(), Config{AuthorityURL: s.url, ClientID: "cid", MethodDefault: "upstream"}, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(p.IDTokenVerified()))
	s.userinfo = memberUserinfo

	info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: "garbage.that.is.never.read"}, "n-4")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(info.Name, "Anna Example (userinfo)"))
	qt.Assert(t, qt.Equals(info.DirectoryID, "pairwise-sub-1"))
	qt.Assert(t, qt.IsFalse(info.DirectoryGuest))
	qt.Assert(t, qt.Equals(info.Issuer, s.url))
}

// A key set without an issuer cannot be verified against: refused at startup.
func TestKeySetWithoutIssuerRefusesToStart(t *testing.T) {
	_, err := New(context.Background(), Config{
		AuthorizeURL: "https://idp.example/authz", TokenURL: "https://idp.example/tok",
		UserInfoURL: "https://idp.example/ui", JWKSURL: "https://idp.example/jwks",
		ClientID: "cid",
	}, nil)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.StringContains(err.Error(), "no issuer"))
}

// The eParaksts profile publishes no key set — its logins stay userinfo-only,
// byte-identical to what those deployments have always run.
func TestEParakstsProfileHasNoKeySet(t *testing.T) {
	p := eparakstsProvider(t, "http://localhost:9999/", "", nil)
	qt.Assert(t, qt.IsFalse(p.IDTokenVerified()))
}

// errors.Is through the sentinel, for the callback's switch.
func TestErrIDTokenWraps(t *testing.T) {
	err := errorsJoin()
	qt.Assert(t, qt.ErrorIs(err, ErrIDToken))
}

func errorsJoin() error { return errors.Join(ErrIDToken, errors.New("detail")) }
