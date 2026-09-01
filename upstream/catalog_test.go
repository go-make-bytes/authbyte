package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-quicktest/qt"
)

// catalogPayload is a userinfo response shaped like the provider's real
// profile answer: standard claims plus the sign-identity catalog.
const catalogPayload = `{
  "sub": "u1",
  "name": "TEST PERSON",
  "sign_identities": [
    {
      "id": "id-serverid-sign",
      "description": "eparaksts:serverid:sign",
      "status": {"value": "enabled"},
      "labels": ["serverid", "x509:keyUsage:contentCommitment"],
      "access": [{"user_id": "u1", "permissions": ["sign"]}]
    },
    {
      "id": "id-seal-1",
      "description": "eparaksts:qsealc:sign",
      "status": {"value": "enabled"},
      "labels": ["qsealc", "CN:ORG ONE SIA : eZimogs", "x509:keyUsage:contentCommitment"],
      "access": [{"user_id": "u1", "permissions": ["sign"]}]
    }
  ]
}`

func newCatalogProvider(t *testing.T, userinfo http.HandlerFunc, signIdentityURL string) *Provider {
	t.Helper()
	srv := httptest.NewServer(userinfo)
	t.Cleanup(srv.Close)

	p, err := New(context.Background(), Config{
		AuthorizeURL: srv.URL + "/a", TokenURL: srv.URL + "/t", UserInfoURL: srv.URL,
		SignIdentityURL: signIdentityURL,
		ClientID:        "cid", MethodDefault: "upstream",
	}, nil)
	qt.Assert(t, qt.IsNil(err))

	return p
}

func TestUserInfoParsesSignIdentityCatalog(t *testing.T) {
	p := newCatalogProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(catalogPayload))
	}, "")

	info, err := p.UserInfo(t.Context(), "tok")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(info.SignIdentities, 2))
	qt.Check(t, qt.Equals(info.SignIdentities[0].ID, "id-serverid-sign"))
	qt.Check(t, qt.Equals(info.SignIdentities[0].Status, "enabled"))
	qt.Check(t, qt.DeepEquals(info.SignIdentities[0].Permissions, []string{"sign"}))
	qt.Check(t, qt.DeepEquals(info.SignIdentities[1].Labels,
		[]string{"qsealc", "CN:ORG ONE SIA : eZimogs", "x509:keyUsage:contentCommitment"}))
}

func TestUserInfoCatalogAbsentVsEmpty(t *testing.T) {
	// No sign_identities key: the catalog is UNKNOWN — nil, so a caller can
	// tell it apart from a person who verifiably has no identities.
	p := newCatalogProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"u1"}`))
	}, "")
	info, err := p.UserInfo(t.Context(), "tok")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(info.SignIdentities))

	// An empty array: the catalog was read and holds nothing — empty non-nil.
	p2 := newCatalogProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"u1","sign_identities":[]}`))
	}, "")
	info2, err := p2.UserInfo(t.Context(), "tok")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(info2.SignIdentities))
	qt.Check(t, qt.HasLen(info2.SignIdentities, 0))
}

func TestSignIdentityCertFetch(t *testing.T) {
	certSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qt.Check(t, qt.Equals(r.Header.Get("Authorization"), "Bearer tok"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ids/id-serverid-sign":
			_, _ = w.Write([]byte(`{"identity":{"details":{"certificate":"Q0VSVA=="}}}`))
		case "/ids/id-empty":
			_, _ = w.Write([]byte(`{"identity":{"details":{}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer certSrv.Close()

	p := newCatalogProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}, certSrv.URL+"/ids/")

	cert, err := p.SignIdentityCert(t.Context(), "tok", "id-serverid-sign")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cert, "Q0VSVA=="))

	_, err = p.SignIdentityCert(t.Context(), "tok", "id-unknown")
	qt.Check(t, qt.IsNotNil(err))

	// A response without a certificate is an error, not an empty capability.
	_, err = p.SignIdentityCert(t.Context(), "tok", "id-empty")
	qt.Check(t, qt.IsNotNil(err))
}

func TestIdentityCatalogEnabled(t *testing.T) {
	// Enabled needs BOTH the profile scope and the certificate endpoint.
	off := newCatalogProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}, "")
	qt.Check(t, qt.IsFalse(off.IdentityCatalogEnabled()))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	on, err := New(context.Background(), Config{
		AuthorizeURL: srv.URL + "/a", TokenURL: srv.URL + "/t", UserInfoURL: srv.URL,
		SignIdentityURL: srv.URL + "/ids/",
		Scopes:          []string{EParakstsDefaultScope, ScopeSignIdentityProfile},
		ClientID:        "cid", MethodDefault: "upstream",
	}, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(on.IdentityCatalogEnabled()))

	// The eParaksts profile ships with capture on by default.
	prof := EParakstsProfile("https://provider.example", "")
	qt.Check(t, qt.Equals(prof.SignIdentityURL,
		"https://provider.example/trustedx-resources/esigp/v1/sign_identities/"))
	found := false
	for _, s := range prof.Scopes {
		if s == ScopeSignIdentityProfile {
			found = true
		}
	}
	qt.Check(t, qt.IsTrue(found))
}
