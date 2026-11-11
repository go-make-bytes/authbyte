package registry

import (
	"fmt"
	"strings"
	"testing"
)

// signInWith is one sign-in client with the given extra lines.
func signInWith(extra string) string {
	return `
sign_in_clients:
  - client_id: admin-app
    enabled: true
    type: public
    audience: admin-portal
    redirect_uris: [https://admin.example/callback]
` + extra
}

// The scope group the register alone gives out can be named by no registry
// entry: not a grant's scopes, not its assistant_levels, not a baseline.
func TestLoadRefusesAScopeOfTheReservedGroup(t *testing.T) {
	for name, tc := range map[string]struct {
		doc  string
		want []string
	}{
		"a grant's scopes": {
			grantDoc("[membership:people, deployment:admin]", ""),
			[]string{`"svc:product-api"`, `"svc:register"`, `"deployment:admin"`},
		},
		"a grant's scopes, another level of the group": {
			grantDoc("[deployment:read]", ""),
			[]string{`"svc:product-api"`, `"deployment:read"`},
		},
		"a grant's assistant_levels": {
			grantDoc("[membership:people]", "[deployment:admin]"),
			[]string{`"svc:product-api"`, `"deployment:admin"`},
		},
		"a sign-in client's baseline": {
			signInWith("    membership_required: false\n    baseline_scopes: [records:read, deployment:admin]\n"),
			[]string{`"admin-app"`, `"deployment:admin"`},
		},
		"a sign-in client's baseline, another level": {
			signInWith("    membership_required: false\n    baseline_scopes: [deployment:read]\n"),
			[]string{`"admin-app"`, `"deployment:read"`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(tc.doc), nil)
			if err == nil {
				t.Fatal("the registry loaded")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error %q does not name %s", err, want)
				}
			}
		})
	}
}

// The same documents with another group load, and a name that only starts like
// the reserved group is not in it.
func TestLoadAcceptsTheSameShapesOfAnotherGroup(t *testing.T) {
	for name, doc := range map[string]string{
		"a grant's scopes":           grantDoc("[membership:people, workspace:admin]", ""),
		"a grant's assistant_levels": grantDoc("[workspace:admin]", "[workspace:admin]"),
		"a baseline":                 signInWith("    membership_required: false\n    baseline_scopes: [workspace:admin]\n"),
		"a longer group name":        grantDoc("[deployments:admin, deployment-x:admin]", ""),
		"a box of that service":      grantDoc("[deployment/feature:view]", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(doc), nil); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
}

// A baseline scope is a box or a level, like a grant's, or the start stops with
// the client and the scope named.
func TestLoadRefusesABaselineScopeOfNoShape(t *testing.T) {
	for _, scope := range []string{"admin", "a:b:c", "a:b c:d", "a:b c:d", ":read", "projects/task:"} {
		_, err := Load([]byte(signInWith("    membership_required: false\n    baseline_scopes: ['"+scope+"']\n")), nil)
		if err == nil {
			t.Errorf("the baseline scope %q loaded", scope)

			continue
		}
		for _, want := range []string{`"admin-app"`, fmt.Sprintf("%q", scope)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: the error %q does not name %s", scope, err, want)
			}
		}
	}
}

// high_scopes is off unless set, and meaningless where the register is not asked.
func TestHighScopesSettingOffByDefaultAndRefusedWhereItCouldNotApply(t *testing.T) {
	r, err := Load([]byte(signInWith("    high_scopes: true\n")), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c, _ := r.SignInClient("admin-app"); !c.HighScopes {
		t.Error("high_scopes: true was not kept")
	}

	r, err = Load([]byte(signInWith("")), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c, _ := r.SignInClient("admin-app"); c.HighScopes {
		t.Error("high_scopes is on without being set")
	}

	_, err = Load([]byte(signInWith("    membership_required: false\n    high_scopes: true\n")), nil)
	if err == nil || !strings.Contains(err.Error(), "high_scopes") || !strings.Contains(err.Error(), `"admin-app"`) {
		t.Errorf("a client that asks no membership took high_scopes: %v", err)
	}
}

// White space outside ASCII is white space: a scope holding any of these is
// neither a box nor a level, so it cannot be split into two where it is read.
func TestShapeTestsCatchNonASCIISpace(t *testing.T) {
	for name, sp := range map[string]string{
		"U+00A0 no-break space":        " ",
		"U+0085 next line":             "\u0085",
		"U+2007 figure space":          " ",
		"U+202F narrow no-break space": " ",
		"ASCII space":                  " ",
	} {
		if IsLevel("a:b" + sp + "c") {
			t.Errorf("%s: IsLevel accepted a scope holding it", name)
		}
		if IsBox("a/b:c" + sp + "d") {
			t.Errorf("%s: IsBox accepted a scope holding it", name)
		}
	}
}
