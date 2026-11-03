package upstream

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/go-make-bytes/authbyte/identity"
)

// Entry is one upstream provider of a deployment's set: the connector, the path
// on this service its answers come back to, and what the sign-in page and the
// identity store need to know about it.
type Entry struct {
	// Name names the entry in a refusal at start and in the sign-in flows it
	// starts. Unique in the set.
	Name string
	// Provider is the entry's connector, built with New. The methods it allows
	// are the entry's methods, and a method names exactly one entry of the set.
	Provider *Provider
	// ReturnPath is the path on this service the provider answers on, with a
	// leading slash. Unique in the set, so an answer arriving on it can only be
	// for a sign-in sent to this entry [RFC 9700 §4.4.2.2].
	ReturnPath string
	// DisplayName names the entry's ways on the sign-in page where the page has
	// no name of its own for the method; empty, the page names them as the
	// person's organisation's sign-in.
	DisplayName string
	// ACR is the provider's own words for each of its methods, sent as
	// acr_values when a sign-in asks for that method. A method with none is
	// asked for without.
	ACR map[string]string
	// HoldsStored marks the entry whose people the stored sign-ins of the
	// deployment's first provider belong to: they were kept before providers
	// were told apart, under the empty provider. Exactly one entry of a set
	// holds them.
	HoldsStored bool

	key      string
	resolver *identity.Resolver
}

// CredentialProvider is the provider this entry's people's credentials are kept
// under: a handle is unique only at the provider that issued it, and only the
// provider with the handle names a person [OIDC Core §5.7]. The holder of the
// stored sign-ins, and any entry of the holder's own provider, keep the empty
// provider those were stored under; any other entry its provider's identifier.
func (e *Entry) CredentialProvider() string { return e.key }

// Resolver is the identity resolver carrying this entry's acr/amr vocabularies.
func (e *Entry) Resolver() *identity.Resolver { return e.resolver }

// ACRFor is the provider's own words for method, or "".
func (e *Entry) ACRFor(method string) string { return e.ACR[method] }

// Set is a deployment's upstream providers. The open build runs a set of one,
// made from its settings; a program embedding this service may pass its own.
type Set struct {
	entries  []*Entry
	byMethod map[string]*Entry
}

// NewSet makes a set of entries, refusing one whose entries cannot be told
// apart or could never complete a sign-in: no entry; an entry with no name, no
// provider, no method, or a return path that is not a path; a name, a return
// path or a method two entries claim; the card's method, which the card's own
// door completes; not exactly one entry holding the stored sign-ins; an entry
// with no identifier to keep its people under; or one whose identifier is the
// provider the card's sign-ins are kept under.
func NewSet(entries ...Entry) (*Set, error) {
	if len(entries) == 0 {
		return nil, errors.New("no upstream identity provider in the set")
	}

	s := &Set{byMethod: map[string]*Entry{}}
	names, paths := map[string]bool{}, map[string]string{}
	var holder *Entry
	for i := range entries {
		e := entries[i]
		e.ACR = maps.Clone(e.ACR)
		switch {
		case e.Name == "":
			return nil, fmt.Errorf("upstream entry %d has no name", i+1)
		case names[e.Name]:
			return nil, fmt.Errorf("two upstream entries are named %s", e.Name)
		case e.Provider == nil:
			return nil, fmt.Errorf("upstream %s has no provider", e.Name)
		case !strings.HasPrefix(e.ReturnPath, "/"):
			return nil, fmt.Errorf("upstream %s: return path %q does not start with /", e.Name, e.ReturnPath)
		case paths[e.ReturnPath] != "":
			return nil, fmt.Errorf("upstreams %s and %s both return on %s", paths[e.ReturnPath], e.Name, e.ReturnPath)
		case len(e.Provider.Methods()) == 0:
			return nil, fmt.Errorf("upstream %s allows no sign-in method", e.Name)
		}
		names[e.Name], paths[e.ReturnPath] = true, e.Name

		for _, m := range e.Provider.Methods() {
			if m == identity.LoginWebEID {
				return nil, fmt.Errorf("upstream %s claims the method %s, which the card's own door completes", e.Name, m)
			}
			if other := s.byMethod[m]; other != nil {
				return nil, fmt.Errorf("upstreams %s and %s both claim the method %s", other.Name, e.Name, m)
			}
			s.byMethod[m] = &e
		}
		if e.HoldsStored {
			if holder != nil {
				return nil, fmt.Errorf("upstreams %s and %s both say they hold the stored sign-ins; exactly one does", holder.Name, e.Name)
			}
			holder = &e
		}
		e.resolver = e.Provider.Resolver()
		s.entries = append(s.entries, &e)
	}
	if holder == nil {
		return nil, errors.New("no upstream holds the stored sign-ins; exactly one does")
	}

	for _, e := range s.entries {
		id := e.Provider.Identifier()
		switch {
		case id == identity.ProviderWebEID:
			return nil, fmt.Errorf("upstream %s names its issuer %s, the provider the card's sign-ins are kept under", e.Name, id)
		case e == holder || (id != "" && id == holder.Provider.Identifier()):
			e.key = ""
		case id == "":
			return nil, fmt.Errorf("upstream %s has no issuer or authority to keep its people under", e.Name)
		default:
			e.key = id
		}
	}

	return s, nil
}

// Entries are the set's entries, in the order they were given.
func (s *Set) Entries() []*Entry { return slices.Clone(s.entries) }

// ByMethod is the entry that offers method, or nil.
func (s *Set) ByMethod(method string) *Entry { return s.byMethod[method] }

// Methods are every entry's methods, entry by entry, each entry's sorted.
func (s *Set) Methods() []string {
	var out []string
	for _, e := range s.entries {
		out = append(out, e.Provider.Methods()...)
	}

	return out
}
