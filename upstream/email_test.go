package upstream

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-quicktest/qt"
)

// emailProvider builds the connector against the stub with the given email
// claim name ("" = the default).
func emailProvider(t *testing.T, s *stubIDP, claim string) *Provider {
	t.Helper()

	p, err := New(context.Background(), Config{
		AuthorityURL:     s.url,
		ClientID:         "cid",
		ClientSecret:     "secret",
		MethodDefault:    "upstream",
		ClaimDirectoryID: "oid",
		ClaimEmail:       claim,
	}, nil)
	qt.Assert(t, qt.IsNil(err))

	return p
}

// The address the directory sends in userinfo is kept, trimmed, under the
// default claim name.
func TestClaimsKeepsTheUserinfoEmail(t *testing.T) {
	s := newStubIDP(t, false)
	p := emailProvider(t, s, "")
	s.userinfo = `{"sub":"pairwise-sub-1","email":"  anna@example.test  "}`
	s.idToken = s.sign(s.claims("n-1"))

	info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.idToken}, "n-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, "anna@example.test"))
}

// Where the verified id_token carries the address, it wins over userinfo's, as
// the names do.
func TestClaimsEmailFromTheIDTokenWins(t *testing.T) {
	s := newStubIDP(t, false)
	p := emailProvider(t, s, "")
	s.userinfo = `{"sub":"pairwise-sub-1","email":"old@example.test"}`
	c := s.claims("n-2")
	c["email"] = " new@example.test "

	info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.sign(c)}, "n-2")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, "new@example.test"))
}

// An id_token that carries no address leaves userinfo's in place.
func TestClaimsEmailFallsBackToUserinfo(t *testing.T) {
	s := newStubIDP(t, false)
	p := emailProvider(t, s, "")
	s.userinfo = `{"sub":"pairwise-sub-1","email":"only@example.test"}`

	info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.sign(s.claims("n-3"))}, "n-3")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, "only@example.test"))
}

// The claim name is configurable: another name is read, and the default name is
// then ignored.
func TestClaimsEmailClaimNameIsConfigurable(t *testing.T) {
	s := newStubIDP(t, false)
	p := emailProvider(t, s, "mail")
	s.userinfo = `{"sub":"pairwise-sub-1","email":"default@example.test","mail":"named@example.test"}`

	info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.sign(s.claims("n-4"))}, "n-4")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, "named@example.test"))

	c := s.claims("n-5")
	c["mail"] = "token@example.test"
	c["email"] = "ignored@example.test"
	info, err = p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.sign(c)}, "n-5")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, "token@example.test"))
}

// An address carrying a control character or an invisible formatting one (a NUL,
// a line break, a direction override, a zero-width space) is no address to show:
// it is dropped, from userinfo and from the id_token alike, and the sign-in goes on.
func TestClaimsDropsAnEmailWithHiddenCharacters(t *testing.T) {
	for name, email := range map[string]string{
		"a NUL":                "anna\u0000@example.test",
		"a line break":         "anna@exam\nple.test",
		"a C1 control":         "anna\u0085@example.test",
		"a direction override": "\u202eanna@example.test",
		"a zero-width space":   "an\u200bna@example.test",
		"a word joiner":        "anna@example\u2060.test",
		"a line separator":     "anna@exa\u2028mple.test",
	} {
		s := newStubIDP(t, false)
		p := emailProvider(t, s, "")
		body, err := json.Marshal(map[string]string{"sub": "pairwise-sub-1", "email": email})
		qt.Assert(t, qt.IsNil(err))
		s.userinfo = string(body)

		info, err := p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.sign(s.claims("n-6"))}, "n-6")
		qt.Assert(t, qt.IsNil(err), qt.Commentf("%s: the sign-in goes on", name))
		qt.Check(t, qt.Equals(info.Email, ""), qt.Commentf("%s from userinfo", name))

		c := s.claims("n-7")
		c["email"] = email
		info, err = p.Claims(context.Background(), Tokens{AccessToken: "tok", IDToken: s.sign(c)}, "n-7")
		qt.Assert(t, qt.IsNil(err), qt.Commentf("%s: the sign-in goes on", name))
		qt.Check(t, qt.Equals(info.Email, ""), qt.Commentf("%s from the id_token", name))
	}
}

// A provider that sends no address leaves it empty; the userinfo-only path
// (no key set) reads it too.
func TestUserInfoEmail(t *testing.T) {
	s := newStubIDP(t, true)
	p := emailProvider(t, s, "")

	s.userinfo = `{"sub":"pairwise-sub-1"}`
	info, err := p.UserInfo(context.Background(), "tok")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, ""))

	s.userinfo = `{"sub":"pairwise-sub-1","email":" a@example.test"}`
	info, err = p.UserInfo(context.Background(), "tok")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Email, "a@example.test"))
}
