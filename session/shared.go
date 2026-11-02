package session

import (
	"slices"
	"time"
)

// Shared is a browser's shared session: the person signed in in that browser and
// each way they proved who they are, so that a second app of the deployment can
// sign the same person in without showing a page. It names no tenant: the
// organisation is chosen per app session, at its token issue.
//
// The browser holds its id and a secret; the record keeps only the secret's
// hash, which is replaced at every sign-in, so a value the browser held before a
// sign-in names nothing after it.
type Shared struct {
	SecretHash string `json:"secret_hash"`

	Subject         string `json:"subject"`
	Name            string `json:"name,omitempty"`
	GivenName       string `json:"given_name,omitempty"`
	FamilyName      string `json:"family_name,omitempty"`
	SerialNumber    string `json:"serial_number,omitempty"`
	DirectoryIssuer string `json:"directory_issuer,omitempty"`
	DirectoryGuest  bool   `json:"directory_guest,omitempty"`

	// Ways are the ways the person signed in in this browser, the most recent
	// last; a way signed in again replaces its earlier entry.
	Ways []Way `json:"ways"`
	// ExpiresAt is when the last of the ways ends.
	ExpiresAt time.Time `json:"expires_at"`
}

// Way is one sign-in kept by a shared session: the method, the level it
// proved, when the person authenticated and by what means (what an ID token
// states), and its end, a whole session lifetime after the sign-in completed.
// Nothing renews it.
type Way struct {
	Method   string    `json:"method"`
	LoA      string    `json:"loa,omitempty"`
	AuthTime int64     `json:"auth_time,omitempty"`
	AMR      []string  `json:"amr,omitempty"`
	SignedIn time.Time `json:"signed_in"`
	Ends     time.Time `json:"ends"`
}

// Expired reports whether every way of the shared session has ended at now. A
// shared session with no end recorded is treated as ended.
func (s *Shared) Expired(now time.Time) bool {
	return s.ExpiresAt.IsZero() || !now.Before(s.ExpiresAt)
}

// Keep records w as the most recent way, in place of an earlier sign-in by the
// same method, and moves the shared session's end to the last way's.
func (s *Shared) Keep(w Way) {
	s.Ways = slices.DeleteFunc(s.Ways, func(o Way) bool { return o.Method == w.Method })
	s.Ways = append(s.Ways, w)
	for _, o := range s.Ways {
		if o.Ends.After(s.ExpiresAt) {
			s.ExpiresAt = o.Ends
		}
	}
}
