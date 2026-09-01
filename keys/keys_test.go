package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/go-quicktest/qt"
)

func genPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	der, err := x509.MarshalECPrivateKey(key)
	qt.Assert(t, qt.IsNil(err))

	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// TestMaybeRotate proves F-8: rotation is a real, idempotent operation —
// re-loading the SAME key is a no-op (so a polling reloader doesn't churn), and
// loading a DIFFERENT key rotates while retaining the old key in the JWKS for
// overlapping validation.
func TestMaybeRotate(t *testing.T) {
	pem1 := genPEM(t)
	pem2 := genPEM(t)

	m, err := New(pem1)
	qt.Assert(t, qt.IsNil(err))
	first := m.ActiveKID()

	// Same key → no rotation.
	rotated, err := m.MaybeRotate(pem1)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(rotated))
	qt.Check(t, qt.Equals(m.ActiveKID(), first))

	// Different key → rotates; new active kid differs.
	rotated, err = m.MaybeRotate(pem2)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(rotated))
	qt.Check(t, qt.Not(qt.Equals(m.ActiveKID(), first)))

	// JWKS retains both keys (old kid still validates until tokens expire).
	doc, err := m.JWKS()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(doc), first))
	qt.Check(t, qt.StringContains(string(doc), m.ActiveKID()))
}
