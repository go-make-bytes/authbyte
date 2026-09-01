package routes

import (
	"testing"

	"github.com/go-make-bytes/authbyte/session"

	"github.com/go-quicktest/qt"
)

func TestCapabilitiesResponseMapsSession(t *testing.T) {
	// nil in, nil out: absent capabilities stay absent on the wire.
	qt.Check(t, qt.IsNil(capabilitiesResponse(nil)))

	got := capabilitiesResponse(&session.Capabilities{
		SignIdentityID:     "id-serverid-sign",
		SigningCertificate: "U0lHTg==",
		AuthCertificate:    "QVVUSA==",
		SealsKnown:         true,
		Seals: []session.Seal{
			{ID: "id-seal-1", Label: "ORG ONE SIA : eZimogs", Certificate: "U0VBTA=="},
		},
	})
	qt.Assert(t, qt.IsNotNil(got))
	qt.Check(t, qt.Equals(got.SignIdentityID, "id-serverid-sign"))
	qt.Check(t, qt.Equals(got.SigningCertificate, "U0lHTg=="))
	qt.Check(t, qt.Equals(got.AuthCertificate, "QVVUSA=="))
	qt.Check(t, qt.IsTrue(got.SealsKnown))
	qt.Assert(t, qt.HasLen(got.Seals, 1))
	qt.Check(t, qt.Equals(got.Seals[0].Label, "ORG ONE SIA : eZimogs"))
	qt.Check(t, qt.Equals(got.Seals[0].Certificate, "U0VBTA=="))

	// A read-but-empty catalog keeps its meaning: seals known, none held.
	empty := capabilitiesResponse(&session.Capabilities{SealsKnown: true})
	qt.Assert(t, qt.IsNotNil(empty))
	qt.Check(t, qt.IsTrue(empty.SealsKnown))
	qt.Check(t, qt.HasLen(empty.Seals, 0))
}
