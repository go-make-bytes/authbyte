package signin

import (
	"bytes"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

// Every word of the page exists in every language, and the lines the page shares
// with the products' own sign-in pages are theirs word for word.
func TestEveryWordInEveryLanguage(t *testing.T) {
	for _, lang := range Languages {
		v := reflect.ValueOf(For(lang))
		for i := range v.NumField() {
			qt.Check(t, qt.Not(qt.Equals(v.Field(i).String(), "")), qt.Commentf("%s %s", lang, v.Type().Field(i).Name))
		}
	}

	qt.Check(t, qt.Equals(For("en").Cancelled, "The sign-in was cancelled. Nothing happened — you can try again."))
	qt.Check(t, qt.Equals(For("lv").Expired, "Šī pieslēgšanās ilga par ilgu un ir beigusies. Sāciet jaunu."))
	qt.Check(t, qt.Equals(For("de"), For("en")))
}

// The person's own choice first, then the application's word, then the browser's
// by weight, then English.
func TestChoose(t *testing.T) {
	for _, c := range []struct {
		name, chosen, ui, accept, want string
	}{
		{"nothing said", "", "", "", "en"},
		{"the browser's lv", "", "", "lv", "lv"},
		{"a region subtag", "", "", "lv-LV", "lv"},
		{"weight before order", "", "", "de, lv;q=0.5", "lv"},
		{"higher weight wins", "", "", "en;q=0.4, lv;q=0.8", "lv"},
		{"nothing supported", "", "", "de", "en"},
		{"a refused range", "", "", "lv;q=0, en;q=0.1", "en"},
		{"the application before the browser", "", "lv", "en", "lv"},
		{"an application language not spoken here", "", "de", "", "en"},
		{"the person's choice before the application", "en", "lv", "lv", "en"},
		{"a choice not spoken here is no choice", "xx", "", "lv", "lv"},
	} {
		qt.Check(t, qt.Equals(Choose(c.chosen, c.ui, c.accept), c.want), qt.Commentf("%s", c.name))
	}
}

// The policy allows script from this host's own files only, nothing inline, and
// forbids framing and a base address; it lets a form go to this host and the
// provider only.
func TestHeaders(t *testing.T) {
	h := Headers("https://idp.example")
	csp := h["Content-Security-Policy"]
	for _, want := range []string{"default-src 'none'", "script-src 'self';", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self' https://idp.example;"} {
		qt.Check(t, qt.StringContains(csp, want))
	}
	qt.Check(t, qt.Not(qt.StringContains(csp, "unsafe")))
	qt.Check(t, qt.Not(qt.StringContains(csp, "connect-src")))
	qt.Check(t, qt.Equals(h["X-Frame-Options"], "DENY"))
	qt.Check(t, qt.StringContains(Headers("")["Content-Security-Policy"], "form-action 'self';"))
}

// luminance is a colour's relative luminance [WCAG 2.2] (its glossary).
func luminance(hex string) float64 {
	channel := func(s string) float64 {
		v, _ := strconv.ParseUint(s, 16, 8)
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}

		return math.Pow((c+0.055)/1.055, 2.4)
	}
	hex = strings.TrimPrefix(hex, "#")

	return 0.2126*channel(hex[0:2]) + 0.7152*channel(hex[2:4]) + 0.0722*channel(hex[4:6])
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}

	return (la + 0.05) / (lb + 0.05)
}

// Every text the page draws stands at 4.5:1 or more against what it sits on
// [WCAG 2.2 §1.4.3], read from the stylesheet the page ships.
func TestEveryTextPairContrasts(t *testing.T) {
	css, _, ok := Asset("style.css")
	qt.Assert(t, qt.IsTrue(ok))
	vars := map[string]string{}
	for _, m := range regexp.MustCompile(`--([a-z-]+):\s*(#[0-9a-f]{6});`).FindAllStringSubmatch(string(css), -1) {
		vars[m[1]] = m[2]
	}
	vars["white"] = "#ffffff"

	for _, pair := range [][2]string{
		{"ink", "paper"},             // title, the language button
		{"ink", "surface"},           // a way's button
		{"white", "ink"},             // the main way's button
		{"muted-strong", "paper"},    // the lead
		{"muted-strong", "paper"},    // the hints, the foot line (muted is 4.45:1)
		{"late-fg", "late-bg"},       // a refusal, a cancel
		{"blocked-fg", "blocked-bg"}, // no way set up
		{"white", "ontrack-fg"},      // the mark
		{"ink", "surface"},           // the language menu
	} {
		fg, bg := vars[pair[0]], vars[pair[1]]
		qt.Assert(t, qt.Not(qt.Equals(fg, "")), qt.Commentf("%s", pair[0]))
		qt.Assert(t, qt.Not(qt.Equals(bg, "")), qt.Commentf("%s", pair[1]))
		qt.Check(t, qt.IsTrue(contrast(fg, bg) >= 4.5), qt.Commentf("%s on %s: %.2f", pair[0], pair[1], contrast(fg, bg)))
	}
}

// Case 53, the look: the language button as the approved mock draws it, a globe,
// the language's name and an arrow, the two marks drawn rather than left to a
// font (a system with no font for ▾ shows an empty box: measured in Chrome and
// Firefox on a headless Linux, 2026-11-01).
func TestTheLanguageButtonDrawsItsMarks(t *testing.T) {
	var buf bytes.Buffer
	p := Page{Lang: "en", Words: For("en"), Title: "Sign in to Acme", Languages: []Language{{Code: "en", Name: "English", Href: "/x", Current: true}}}
	qt.Assert(t, qt.IsNil(Render(&buf, p)))

	summary := regexp.MustCompile(`(?s)<summary[^>]*>(.*?)</summary>`).FindStringSubmatch(buf.String())
	qt.Assert(t, qt.HasLen(summary, 2))
	qt.Check(t, qt.Equals(strings.Count(summary[1], `<svg class="globe"`), 1), qt.Commentf("%s", summary[1]))
	qt.Check(t, qt.Equals(strings.Count(summary[1], `<svg class="car"`), 1), qt.Commentf("%s", summary[1]))
	qt.Check(t, qt.StringContains(summary[1], "English"))
	qt.Check(t, qt.Not(qt.StringContains(summary[1], "▾")))
	qt.Check(t, qt.Equals(strings.Count(summary[1], `aria-hidden="true"`), 2))
}

// The page never loads anything from another origin.
func TestThePageLoadsOnlyFromThisHost(t *testing.T) {
	css, _, _ := Asset("style.css")
	for _, b := range [][]byte{css} {
		qt.Check(t, qt.Not(qt.Matches(string(b), `(?s).*https?://.*`)))
	}
	tmpl, err := assets.ReadFile("assets/page.html")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Matches(string(tmpl), `(?s).*(src|href)="https?://.*`)))
	// One script, this host's own file; nothing inline.
	qt.Check(t, qt.Equals(strings.Count(string(tmpl), "<script"), 1))
	qt.Check(t, qt.StringContains(string(tmpl), `<script type="module" src="/signin/card.js"></script>`))
	card, _, ok := Asset("card.js")
	qt.Check(t, qt.IsTrue(ok))
	qt.Check(t, qt.Not(qt.Matches(string(card), `(?s).*https?://.*`)))
	// The library names one address, an explanation it links to in an error
	// message; it loads nothing.
	lib, _, ok := Asset("web-eid.js")
	qt.Check(t, qt.IsTrue(ok))
	qt.Check(t, qt.DeepEquals(regexp.MustCompile(`https?://[^"'\s]+`).FindAllString(string(lib), -1),
		[]string{"https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts"}))
}
