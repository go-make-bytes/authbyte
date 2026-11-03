package upstream

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/go-make-bytes/authbyte/identity"

	"github.com/go-quicktest/qt"
)

// fixedProvider is a provider with fixed endpoints (no discovery, no network),
// the given issuer, and the given methods.
func fixedProvider(t *testing.T, issuer string, methods ...string) *Provider {
	t.Helper()

	cfg := Config{
		AuthorizeURL: "https://idp.example/a", TokenURL: "https://idp.example/t", UserInfoURL: "https://idp.example/u",
		ClientID: "cid", Issuer: issuer, MethodsAllowed: methods,
	}
	if len(methods) > 0 {
		cfg.MethodDefault = methods[0]
	}
	p, err := New(context.Background(), cfg, nil)
	qt.Assert(t, qt.IsNil(err))

	return p
}

// twoLanes is eParaksts beside a directory provider that holds the stored
// sign-ins, each on its own return path.
func twoLanes(t *testing.T) []Entry {
	t.Helper()

	eparaksts := EParakstsProfile("https://eparaksts.example", "")
	eparaksts.ClientID = "e-cid"
	ep, err := New(context.Background(), eparaksts, nil)
	qt.Assert(t, qt.IsNil(err))

	return []Entry{
		{
			Name: "eparaksts", Provider: ep, ReturnPath: "/auth/eparaksts/callback",
			ACR: map[string]string{identity.LoginEParakstsMobile: "urn:mobile", identity.LoginEIDScan: "urn:scan"},
		},
		{
			Name: "entra", Provider: fixedProvider(t, "https://login.example/tenant/v2.0", "upstream"),
			ReturnPath: "/Auth/Complete", DisplayName: "Microsoft Entra", HoldsStored: true,
		},
	}
}

// Calls 1 and 3: each method names the entry that offers it, and the set
// offers every entry's methods, entry by entry.
func TestASetFindsTheEntryOfEachMethod(t *testing.T) {
	set, err := NewSet(twoLanes(t)...)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(set.ByMethod(identity.LoginEParakstsMobile).Name, "eparaksts"))
	qt.Check(t, qt.Equals(set.ByMethod(identity.LoginEIDScan).Name, "eparaksts"))
	qt.Check(t, qt.Equals(set.ByMethod("upstream").Name, "entra"))
	qt.Check(t, qt.IsNil(set.ByMethod(identity.LoginWebEID)))
	qt.Check(t, qt.IsNil(set.ByMethod("google")))
	qt.Check(t, qt.DeepEquals(set.Methods(), []string{identity.LoginEIDScan, identity.LoginEParakstsMobile, "upstream"}))
	qt.Check(t, qt.HasLen(set.Entries(), 2))

	e := set.ByMethod(identity.LoginEParakstsMobile)
	qt.Check(t, qt.Equals(e.ACRFor(identity.LoginEParakstsMobile), "urn:mobile"))
	qt.Check(t, qt.Equals(e.ACRFor("upstream"), ""))
	qt.Check(t, qt.IsNotNil(e.Resolver()))
}

// Cases 2-4, at the seam: a set that could not tell its entries apart, or an
// entry that could never complete a sign-in, refuses to be made, naming what is
// wrong.
func TestASetRefusesWhatItCannotTellApart(t *testing.T) {
	for _, c := range []struct {
		name  string
		edit  func([]Entry) []Entry
		names string
	}{
		{"no entry", func([]Entry) []Entry { return nil }, "no upstream"},
		{"an entry with no name", func(e []Entry) []Entry { e[0].Name = ""; return e }, "name"},
		{"two entries with one name", func(e []Entry) []Entry { e[1].Name = "eparaksts"; return e }, "eparaksts"},
		{"an entry with no provider", func(e []Entry) []Entry { e[1].Provider = nil; return e }, "entra"},
		{"a return path that is not a path", func(e []Entry) []Entry { e[1].ReturnPath = "Auth/Complete"; return e }, "Auth/Complete"},
		{"two entries on one return path", func(e []Entry) []Entry { e[1].ReturnPath = "/auth/eparaksts/callback"; return e }, "/auth/eparaksts/callback"},
		{"two entries claiming one method", func(e []Entry) []Entry {
			e[1].Provider = fixedProvider(t, "https://login.example/tenant/v2.0", "upstream", identity.LoginEIDScan)
			return e
		}, identity.LoginEIDScan},
		{"an entry claiming the card's method", func(e []Entry) []Entry {
			e[1].Provider = fixedProvider(t, "https://login.example/tenant/v2.0", identity.LoginWebEID)
			return e
		}, identity.LoginWebEID},
		{"an entry with no method", func(e []Entry) []Entry {
			e[1].Provider = fixedProvider(t, "https://login.example/tenant/v2.0")
			return e
		}, "entra"},
		{"no entry holding the stored sign-ins", func(e []Entry) []Entry { e[1].HoldsStored = false; return e }, "stored sign-ins"},
		{"two entries holding them", func(e []Entry) []Entry { e[0].HoldsStored = true; return e }, "stored sign-ins"},
		{"an entry with nothing to key its people by", func(e []Entry) []Entry {
			e[1].HoldsStored, e[0].HoldsStored = false, true
			e[1].Provider = fixedProvider(t, "", "upstream")
			return e
		}, "entra"},
		// The card's sign-ins are kept under a provider of their own, which no
		// upstream may name as its issuer, holder or not.
		{"an entry naming the card's provider as its issuer", func(e []Entry) []Entry {
			e[1].Provider = fixedProvider(t, identity.ProviderWebEID, "upstream")
			return e
		}, identity.ProviderWebEID},
		{"the holder naming the card's provider as its issuer", func(e []Entry) []Entry {
			e[1].HoldsStored, e[0].HoldsStored = false, true
			e[0].Provider = fixedProvider(t, identity.ProviderWebEID, identity.LoginEParakstsMobile, identity.LoginEIDScan)
			return e
		}, identity.ProviderWebEID},
	} {
		_, err := NewSet(c.edit(twoLanes(t))...)
		if err == nil || !strings.Contains(err.Error(), c.names) {
			t.Errorf("%s: err = %v, want a refusal naming %q", c.name, err, c.names)
		}
	}
}

// R15 A (call 6): a credential is keyed by its provider. The entry holding the
// stored sign-ins keys its people by the empty provider, as they were stored;
// any other entry by its provider's issuer, or its authority where it has none;
// and an entry of the holder's own provider shares the holder's key, since one
// provider's handles name one person whichever entry they arrive through.
func TestEachEntryKeysItsPeopleByItsProvider(t *testing.T) {
	entries := twoLanes(t)
	entries = append(entries,
		Entry{Name: "google", Provider: fixedProvider(t, "https://accounts.example", "google"), ReturnPath: "/auth/google"},
		Entry{Name: "entra-again", Provider: fixedProvider(t, "https://login.example/tenant/v2.0", "entraAgain"), ReturnPath: "/auth/entra-again"})
	set, err := NewSet(entries...)
	qt.Assert(t, qt.IsNil(err))

	got := map[string]string{}
	for _, e := range set.Entries() {
		got[e.Name] = e.CredentialProvider()
	}
	qt.Check(t, qt.DeepEquals(got, map[string]string{
		"entra":       "",
		"eparaksts":   "https://eparaksts.example",
		"google":      "https://accounts.example",
		"entra-again": "",
	}))
}

// The set keeps the entries it was given, in their order, and is not changed by
// a later edit of the caller's slice.
func TestASetKeepsItsOwnEntries(t *testing.T) {
	entries := twoLanes(t)
	set, err := NewSet(entries...)
	qt.Assert(t, qt.IsNil(err))
	entries[0].Name = "changed"

	names := []string{}
	for _, e := range set.Entries() {
		names = append(names, e.Name)
	}
	qt.Check(t, qt.IsTrue(slices.Equal(names, []string{"eparaksts", "entra"})))
}
