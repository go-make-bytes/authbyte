package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// TestStepUpMethodMatches pins the step-up binding rule: the method actually
// achieved must equal the method requested, so a session cannot be "elevated"
// by re-authenticating with a different (or the legacy) method. webEid — the
// Web eID step-up target — is exercised alongside the Entrust-federated methods.
func TestStepUpMethodMatches(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		achieved  string
		want      bool
	}{
		{"webEid satisfied by webEid", "webEid", "webEid", true},
		{"mobile satisfied by mobile", "eparakstsMobile", "eparakstsMobile", true},
		{"eidScan satisfied by eidScan", "eidScan", "eidScan", true},

		{"webEid not satisfied by mobile", "webEid", "eparakstsMobile", false},
		{"mobile not satisfied by webEid", "eparakstsMobile", "webEid", false},
		{"webEid not satisfied by legacy eid", "webEid", "eid", false},

		// Exact match only — same vocabulary on both sides, so case must agree.
		{"case-sensitive", "webEid", "WEBEID", false},

		// No requested method (e.g. a normal, non-step-up login) imposes no
		// constraint — the step-up rule only applies when a method was requested.
		{"empty requested imposes no constraint", "", "webEid", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			qt.Check(t, qt.Equals(stepUpMethodMatches(c.requested, c.achieved), c.want))
		})
	}
}
