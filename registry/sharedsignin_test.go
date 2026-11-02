package registry

import (
	"strings"
	"testing"
)

func noSecret(string, string) (string, error) { return "", nil }

// A client may be answered from the browser's shared session only when its row
// says so.
func TestSingleSignOnIsOnlyWhereTheRowSaysSo(t *testing.T) {
	r, err := Load([]byte(`
sign_in_clients:
  - client_id: shared-app
    enabled: true
    type: public
    audience: shared-api
    single_sign_on: true
    redirect_uris: [https://shared.example/cb]
  - client_id: own-app
    enabled: true
    type: public
    audience: own-api
    redirect_uris: [https://own.example/cb]
`), noSecret)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c, _ := r.SignInClient("shared-app"); !c.SingleSignOn {
		t.Error("shared-app: single_sign_on not read")
	}
	if c, _ := r.SignInClient("own-app"); c.SingleSignOn {
		t.Error("own-app: single sign-on without the setting")
	}
}

// A signing client cannot be single sign-on, and the setting takes a yes or no
// only; a misspelled key stops the start.
func TestSingleSignOnRefusals(t *testing.T) {
	row := `
sign_in_clients:
  - client_id: the-app
    enabled: true
    type: public
    audience: the-api
    redirect_uris: [https://the.example/cb]
`
	for _, c := range []struct {
		name, extra, want string
	}{
		{"signing", "    signing: true\n    single_sign_on: true\n", `"the-app" signs, so it cannot be single_sign_on`},
		{"not a yes or no", "    single_sign_on: maybe\n", "maybe"},
		{"misspelled", "    single_signon: true\n", "single_signon"},
	} {
		_, err := Load([]byte(row+c.extra), noSecret)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", c.name, err, c.want)
		}
	}
}
