package rolebyte

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// The register's answer is taken only when it names the subject asked about.
// Another person's answer, or an answer that names nobody, is refused before any
// of its memberships can be minted.
func TestAnsweredForAcceptsOnlyTheSubjectAskedAbout(t *testing.T) {
	answer := func(subject string) resolveResponse {
		return resolveResponse{SubjectKey: subject, Memberships: []membership{
			{TenantID: "tenant-1", Scopes: []string{"projects:read", "projects:log"}},
		}}
	}

	got, err := answeredFor("sub:asked", answer("sub:asked"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(got, []Membership{{TenantID: "tenant-1", Scopes: []string{"projects:read", "projects:log"}}}))

	for name, subject := range map[string]string{"another person": "sub:someone-else", "nobody": ""} {
		got, err := answeredFor("sub:asked", answer(subject))
		qt.Check(t, qt.ErrorIs(err, errAnswerForAnotherSubject), qt.Commentf("%s", name))
		qt.Check(t, qt.IsNil(got), qt.Commentf("%s: nothing may be minted from it", name))
	}

	// An empty answer about the right person is a stranger, not a refusal.
	got, err = answeredFor("sub:asked", resolveResponse{SubjectKey: "sub:asked"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(got, 0))
}
