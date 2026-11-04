// Package signin draws this service's own sign-in page: the ways in an
// application may use, listed when its request names none, and the messages a
// person meets on the way. It holds the page's words, its language choice, its
// headers and its assets; the routes decide what the page says.
package signin

import (
	"bytes"
	"embed"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"
)

//go:embed assets
var assets embed.FS

var page = template.Must(template.ParseFS(assets, "assets/page.html"))

// Asset is one file the page loads from this host, by its name under /signin/.
func Asset(name string) ([]byte, string, bool) {
	types := map[string]string{
		"style.css":                    "text/css; charset=utf-8",
		"HankenGrotesk-Variable.woff2": "font/woff2",
		"HankenGrotesk-OFL.txt":        "text/plain; charset=utf-8",
		// The card's script, and the Web eID library it loads to reach the card
		// (2.1.0, its licence in its own header).
		"card.js":    "text/javascript; charset=utf-8",
		"web-eid.js": "text/javascript; charset=utf-8",
	}
	ct, ok := types[name]
	if !ok {
		return nil, "", false
	}
	b, err := assets.ReadFile("assets/" + name)
	if err != nil {
		return nil, "", false
	}

	return b, ct, true
}

// Words are the page's words in one language. {app}, {name} and {operator} are
// filled in where they appear.
type Words struct {
	Self, Language                     string
	Title, Lead                        string
	Cancelled, ProviderError, Expired  string
	NoWays                             string
	Operator                           string
	BadTitle, BadLead                  string
	Organisation                       string
	HintRedirect, HintMobile, HintScan string
	// The card read on the page: its hint, the wait, the failure, the missing
	// software (a title, a lead and the link's words), and the line for a
	// browser that runs no script.
	HintCard, Waiting, CardFailed            string
	MissingTitle, MissingLead, MissingAction string
	NoScript                                 string
	// The page after an AI app's sign-in, where the person chooses which of
	// their assistants the app works as: its title and lead, the hint under the
	// choices, and the refusal for a person with none.
	AssistantTitle, AssistantLead, AssistantHint string
	NoAssistant                                  string
}

// CardSoftwareURL is where a person gets the card software and its browser
// extension.
const CardSoftwareURL = "https://www.id.ee/en/article/install-id-software/"

// Languages are the page's languages, in the order its menu lists them.
var Languages = []string{"en", "lv"}

var words = map[string]Words{
	"en": {
		Self:           "English",
		Language:       "Language",
		Title:          "Sign in to {app}",
		Lead:           "Choose how to sign in. You come back to {app} once you are in.",
		Cancelled:      "The sign-in was cancelled. Nothing happened — you can try again.",
		ProviderError:  "The identity provider could not complete the sign-in. Try again; if it keeps failing, it is on their side rather than yours.",
		Expired:        "That sign-in took too long and has expired. Start a fresh one.",
		NoWays:         "No way to sign in is set up here. Tell whoever runs this deployment.",
		Operator:       "Sign-in run by {operator} for {app}",
		BadTitle:       "This sign-in cannot start",
		BadLead:        "The link that brought you here is not one this sign-in knows. Go back to the app you came from and start again.",
		Organisation:   "Your organisation’s sign-in",
		HintRedirect:   "{name} opens your company’s own sign-in page.",
		HintMobile:     "{name} asks you to approve in its app on your phone.",
		HintScan:       "{name} has you scan your ID card with your phone.",
		HintCard:       "{name} is your ID card, read by the card software on this computer; it asks for your PIN.",
		Waiting:        "Waiting for the card…",
		CardFailed:     "That did not complete. Check the card is in the reader and try again.",
		MissingTitle:   "The card software is not running",
		MissingLead:    "Signing in with a card needs the ID-software and its browser extension on this computer. Install it, then try again — nothing here has to be redone.",
		MissingAction:  "Get the ID software",
		NoScript:       "Signing in with a card needs JavaScript turned on in this browser.",
		AssistantTitle: "Connect {app}",
		AssistantLead:  "Choose which of your assistants {app} works as. It does only what you and that assistant may both do.",
		AssistantHint:  "You can sign {app} out at any time.",
		NoAssistant:    "You have no assistant in any workspace. An administrator makes one for you in People & access.",
	},
	"lv": {
		Self:           "Latviešu",
		Language:       "Valoda",
		Title:          "Pieslēgšanās lietotnei {app}",
		Lead:           "Izvēlieties, kā pieslēgties. Pēc pieslēgšanās jūs atgriezīsieties lietotnē {app}.",
		Cancelled:      "Pieslēgšanās tika atcelta. Nekas nenotika — varat mēģināt vēlreiz.",
		ProviderError:  "Identitātes pakalpojums nevarēja pabeigt pieslēgšanos. Mēģiniet vēlreiz; ja neizdodas atkārtoti, vaina ir viņu pusē.",
		Expired:        "Šī pieslēgšanās ilga par ilgu un ir beigusies. Sāciet jaunu.",
		NoWays:         "Šeit nav iestatīta neviena pieslēgšanās iespēja. Pasakiet to tam, kas uztur šo izvietojumu.",
		Operator:       "Pieslēgšanos lietotnei {app} nodrošina {operator}",
		BadTitle:       "Šo pieslēgšanos nevar sākt",
		BadLead:        "Saite, kas jūs šeit atveda, šai pieslēgšanai nav zināma. Atgriezieties lietotnē, no kuras nācāt, un sāciet vēlreiz.",
		Organisation:   "Jūsu organizācijas pieslēgšanās",
		HintRedirect:   "{name} atver jūsu uzņēmuma pieslēgšanās lapu.",
		HintMobile:     "{name} lūgs apstiprināt pieslēgšanos lietotnē jūsu tālrunī.",
		HintScan:       "Ar {name} jūs noskenējat savu ID karti ar tālruni.",
		HintCard:       "{name} ir jūsu ID karte, ko nolasa šī datora ID programmatūra; tā prasīs PIN.",
		Waiting:        "Gaida karti…",
		CardFailed:     "Neizdevās pabeigt. Pārbaudiet, vai karte ir lasītājā, un mēģiniet vēlreiz.",
		MissingTitle:   "ID programmatūra nedarbojas",
		MissingLead:    "Pieslēgšanai ar karti nepieciešama ID programmatūra un tās pārlūka paplašinājums šajā datorā. Uzinstalējiet to un mēģiniet vēlreiz — neko no jauna sākt nevajag.",
		MissingAction:  "Iegūt ID programmatūru",
		NoScript:       "Pieslēgšanai ar karti šajā pārlūkā jābūt ieslēgtam JavaScript.",
		AssistantTitle: "Pievienot {app}",
		AssistantLead:  "Izvēlieties, kurš no jūsu asistentiem būs {app}. Tas darīs tikai to, ko drīkstat gan jūs, gan šis asistents.",
		AssistantHint:  "{app} varat atslēgt jebkurā brīdī.",
		NoAssistant:    "Jums nav neviena asistenta nevienā darbvietā. Administrators to izveido jums sadaļā Cilvēki un piekļuve.",
	},
}

// For is the page's words in lang; English for a language the page lacks.
func For(lang string) Words {
	if w, ok := words[lang]; ok {
		return w
	}

	return words["en"]
}

// Fill puts values into a line's {placeholders}.
func Fill(line string, values map[string]string) string {
	for k, v := range values {
		line = strings.ReplaceAll(line, "{"+k+"}", v)
	}

	return line
}

// Choose picks the page's language: the person's own choice kept in their
// browser, then the language the application asked for (ui_locales, in its
// order), then the browser's Accept-Language by weight, then English.
func Choose(chosen, uiLocales, acceptLanguage string) string {
	if supported(chosen) {
		return chosen
	}
	for _, tag := range strings.Fields(uiLocales) {
		if l := primary(tag); supported(l) {
			return l
		}
	}
	for _, tag := range byWeight(acceptLanguage) {
		if l := primary(tag); supported(l) {
			return l
		}
	}

	return "en"
}

func supported(lang string) bool {
	_, ok := words[lang]

	return ok
}

// primary is a language tag's primary subtag, lower case: "lv-LV" is "lv".
func primary(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexByte(tag, '-'); i >= 0 {
		tag = tag[:i]
	}

	return tag
}

// byWeight is an Accept-Language value's ranges, highest weight first, the
// header's own order kept among equal weights; a range weighted 0 is refused.
func byWeight(header string) []string {
	type ranged struct {
		tag string
		q   float64
		at  int
	}
	var all []ranged
	for i, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		tag := strings.TrimSpace(fields[0])
		if tag == "" {
			continue
		}
		q := 1.0
		for _, f := range fields[1:] {
			if v, ok := strings.CutPrefix(strings.TrimSpace(f), "q="); ok {
				if w, err := strconv.ParseFloat(v, 64); err == nil {
					q = w
				}
			}
		}
		if q > 0 {
			all = append(all, ranged{tag, q, i})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].q > all[j].q })
	out := make([]string, len(all))
	for i, r := range all {
		out[i] = r.tag
	}

	return out
}

// Way is one button: the method's code, its exact name and its hint.
type Way struct{ Code, Name, Hint string }

// Language is one entry of the language menu.
type Language struct {
	Code, Name, Href string
	Current          bool
}

// Notice is the one message above the ways; Amber for a state of this
// deployment rather than of this sign-in.
type Notice struct {
	Text  string
	Amber bool
}

// Card is the card read on this showing of the page: where its answer is posted,
// the challenge the card signs, and the state that names it.
type Card struct {
	Action, Nonce, State string
}

// Page is everything one showing of the page says.
type Page struct {
	Lang         string
	Words        Words
	Title, Lead  string
	Notice       *Notice
	Ways         []Way
	Action       string
	Token        string
	Card         *Card
	SoftwareURL  string
	Operator     string
	OperatorMark bool
	Languages    []Language
}

// Render writes the page.
func Render(w io.Writer, p Page) error {
	var buf bytes.Buffer
	if err := page.Execute(&buf, p); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())

	return err
}

// Headers are what every showing of the page is answered with: no framing, no
// script but this host's own files, nothing inline [CSP3 §6.1.10], no stored
// copy [RFC 9700 §4.16], and the page's address, which carries
// the client's request, sent to no other host. Not no-referrer: under it a
// browser sends Origin: null on the page's own form post, which the choice must
// refuse (measured in Chrome and Firefox, 2026-11-01). A form may be sent to this
// host and on to each of formTargets, the origins a form's answer redirects to:
// the provider's authorization endpoint, where the choice is sent on, and the
// client's own address, where the card's answer returns, since Chromium and WebKit
// refuse a post's redirect to an origin form-action does not name (measured
// 2026-11-01); frame-ancestors, form-action and base-uri are named because none
// falls back to default-src [CSP3 §6.4.2] [CSP3 §6.1.3]. A window that opened the
// page loses its hold on it [HTML §7.1.3.1]: the card's library takes its answer
// from any message the page receives, and the opener could otherwise post a
// forged one (measured in Chrome, Firefox and WebKit, 2026-11-02).
func Headers(formTargets ...string) map[string]string {
	formAction := "'self'"
	for _, o := range formTargets {
		if o != "" {
			formAction += " " + o
		}
	}

	return map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; form-action " +
			formAction + "; frame-ancestors 'none'; base-uri 'none'",
		"X-Frame-Options":            "DENY",
		"Cross-Origin-Opener-Policy": "same-origin",
		"Cache-Control":              "no-store",
		"Pragma":                     "no-cache",
		"Referrer-Policy":            "same-origin",
		"X-Content-Type-Options":     "nosniff",
	}
}
