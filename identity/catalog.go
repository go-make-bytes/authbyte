package identity

import "strings"

// The sign-identity catalog: the identity provider's profile endpoint lists,
// per person, the signing identities they hold — the personal signing identity
// per authentication method, the paired authentication identity, and any
// organisation seals. Selection is label-driven (the labels carry the key
// usage and the method a key pairs with); an identity is usable when its
// status is enabled and the person's access grants "sign".
//
// The vocabulary below mirrors the provider's own label/description scheme so
// a captured catalog selects the same identities the signing service would
// select for itself at signing time.

// Label / description fragments used for sign-identity selection.
const (
	labelServerID          = "serverid"
	labelEID               = "eid"
	labelMobileID          = "mobileid"
	labelQSealC            = "qsealc"
	labelESealC            = "esealc" // official guidance lists this in one place — match defensively
	labelContentCommitment = "x509:keyUsage:contentCommitment"
	labelDigitalSignature  = "x509:keyUsage:digitalSignature"

	descEIDSign      = "eparaksts:eid:sign"
	descEIDAuth      = "eparaksts:eid:auth"
	descMobileIDAuth = "eparaksts:mobileid:auth"

	statusEnabled = "enabled"
)

// SignIdentity is one entry of the provider's sign-identity catalog.
type SignIdentity struct {
	ID          string
	Description string
	Status      string
	Labels      []string
	// Permissions are the authenticated person's own access permissions on
	// this identity, flattened (the profile endpoint lists the person's
	// identities, so every access entry is theirs).
	Permissions []string
}

// Enabled reports whether the identity's status allows use.
func (s SignIdentity) Enabled() bool {
	return strings.EqualFold(s.Status, statusEnabled)
}

// hasPermission reports whether the person's access grants the permission. A
// missing permissions list is treated permissively (some responses omit it) —
// the provider enforces the grant on the actual sign call regardless.
func (s SignIdentity) hasPermission(p string) bool {
	if len(s.Permissions) == 0 {
		return true
	}
	for _, have := range s.Permissions {
		if strings.EqualFold(have, p) {
			return true
		}
	}

	return false
}

// hasLabels reports whether the identity carries all wanted labels
// (case-insensitive).
func (s SignIdentity) hasLabels(want ...string) bool {
	set := make(map[string]struct{}, len(s.Labels))
	for _, l := range s.Labels {
		set[strings.ToLower(l)] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[strings.ToLower(w)]; !ok {
			return false
		}
	}

	return true
}

// SealCandidate is a seal identity offered to a seal picker: its id and the
// human-readable name from the seal's dynamic CN label.
type SealCandidate struct {
	ID    string
	Label string
}

// SelectSigning returns the signing identity a login method's signing flow
// uses: eParaksts Mobile signs with the serverid identity, eID Scan with the
// eid signing identity. False when the person holds none — a person without a
// signing certificate is a valid state, not an error.
func SelectSigning(catalog []SignIdentity, loginMethod string) (SignIdentity, bool) {
	switch loginMethod {
	case LoginEParakstsMobile:
		for _, id := range catalog {
			if id.hasLabels(labelServerID, labelContentCommitment) &&
				id.Enabled() && id.hasPermission("sign") {
				return id, true
			}
		}
	case LoginEIDScan:
		for _, id := range catalog {
			if strings.EqualFold(id.Description, descEIDSign) ||
				(id.hasLabels(labelEID, labelContentCommitment) && id.Enabled()) {
				return id, true
			}
		}
	}

	return SignIdentity{}, false
}

// SelectAuth returns the authentication identity paired with a login method
// (its certificate accompanies a signing act's finalization). eParaksts Mobile
// pairs with the mobileid auth identity, eID Scan with the eid auth identity;
// a missing primary falls back to whichever auth identity is present, since
// finalization tolerates either.
func SelectAuth(catalog []SignIdentity, loginMethod string) (SignIdentity, bool) {
	primaryDesc, primaryLabel := descMobileIDAuth, labelMobileID
	if loginMethod == LoginEIDScan {
		primaryDesc, primaryLabel = descEIDAuth, labelEID
	}
	for _, id := range catalog {
		if strings.EqualFold(id.Description, primaryDesc) ||
			id.hasLabels(primaryLabel, labelDigitalSignature) {
			return id, true
		}
	}
	for _, id := range catalog {
		if strings.EqualFold(id.Description, descMobileIDAuth) ||
			strings.EqualFold(id.Description, descEIDAuth) ||
			id.hasLabels(labelDigitalSignature) {
			return id, true
		}
	}

	return SignIdentity{}, false
}

// Seals returns every enabled seal identity the person may sign with, in
// catalog order, each with the display name from its CN label. An empty result
// from a read catalog means the person verifiably has no seals.
func Seals(catalog []SignIdentity) []SealCandidate {
	var out []SealCandidate
	for _, id := range catalog {
		if (id.hasLabels(labelQSealC) || id.hasLabels(labelESealC)) &&
			id.Enabled() && id.hasPermission("sign") {
			out = append(out, SealCandidate{ID: id.ID, Label: cnLabel(id.Labels)})
		}
	}

	return out
}

// cnLabel returns the seal's dynamic "CN:<name>" label with the prefix
// stripped, or the joined labels when no CN label is present.
func cnLabel(labels []string) string {
	for _, l := range labels {
		if len(l) > 3 && strings.EqualFold(l[:3], "CN:") {
			return strings.TrimSpace(l[3:])
		}
	}

	return strings.Join(labels, ",")
}
