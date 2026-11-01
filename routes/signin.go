package routes

import (
	"bytes"
	"crypto/subtle"
	"net/url"
	"slices"
	"strings"

	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/registry"
	"github.com/go-make-bytes/authbyte/signin"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
	"github.com/valyala/fasthttp"
)

// noticeExpired is the page's message when the browser's binding ran out before
// the person chose; it is decided on the request itself, never carried over.
const noticeExpired = "expired"

// pickable are the methods the page may offer a client: those its registration
// lists, in that order, that this deployment's provider can start. The card is
// read on the client's own page until it moves onto this one.
func (r *router) pickable(client registry.SignInClient) []string {
	var out []string
	for _, m := range client.Methods {
		if r.Upstream().MethodAllowed(m) && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}

	return out
}

// wayName is a method's exact name on the page and its one-line hint.
func (r *router) wayName(method string, w signin.Words) (name, hint string) {
	switch method {
	case identity.LoginEParakstsMobile:
		return "eParaksts Mobile", w.HintMobile
	case identity.LoginEIDScan:
		return "eID Scan", w.HintScan
	default:
		// The generic provider's way, named as the deployment names it.
		if n := r.Config().OIDCUpstreamDisplayName; n != "" {
			return n, w.HintRedirect
		}

		return w.Organisation, w.HintRedirect
	}
}

// appName is the client as the page names it: its registered name, else its id.
func appName(client registry.SignInClient) string {
	if client.ClientName != "" {
		return client.ClientName
	}

	return client.ClientID
}

// pageLanguage is the language the page is shown in.
func pageLanguage(ctx *azugo.Context, uiLocales string) string {
	return signin.Choose(readCookie(ctx, languageCookie), uiLocales, ctx.Header.Get("Accept-Language"))
}

// languageMenu links each language to the address the page was shown at.
func languageMenu(lang, next string) []signin.Language {
	menu := make([]signin.Language, 0, len(signin.Languages))
	for _, code := range signin.Languages {
		menu = append(menu, signin.Language{
			Code:    code,
			Name:    signin.For(code).Self,
			Href:    "/signin/language?" + url.Values{"lang": {code}, "next": {next}}.Encode(),
			Current: code == lang,
		})
	}

	return menu
}

// operatorLine is the page's foot: who runs this sign-in, when the deployment
// says so.
func (r *router) operatorLine(w signin.Words, app string) string {
	op := r.Config().SignInOperatorName
	if op == "" {
		return ""
	}

	return signin.Fill(w.Operator, map[string]string{"operator": op, "app": app})
}

// showPage answers a request that names no way with this service's sign-in page.
func (r *router) showPage(ctx *azugo.Context, req *authorizeRequest, binding, notice string) {
	lang := pageLanguage(ctx, req.signAsk.uiLocales)
	w := signin.For(lang)
	app := appName(req.client)
	request := "/authorize?" + req.params.encode()

	p := signin.Page{
		Lang:         lang,
		Words:        w,
		Title:        signin.Fill(w.Title, map[string]string{"app": app}),
		Operator:     r.operatorLine(w, app),
		OperatorMark: r.operatorMark != nil,
		Languages:    languageMenu(lang, request),
	}
	for _, m := range r.pickable(req.client) {
		name, hint := r.wayName(m, w)
		p.Ways = append(p.Ways, signin.Way{Code: m, Name: name, Hint: signin.Fill(hint, map[string]string{"name": name})})
	}

	if len(p.Ways) == 0 {
		p.Notice = &signin.Notice{Text: w.NoWays, Amber: true}
	} else {
		p.Lead = signin.Fill(w.Lead, map[string]string{"app": app})
		p.Action = "/authorize/choice?" + req.params.encode()
		p.Token = choiceToken(binding)
		switch notice {
		case noticeCancelled:
			p.Notice = &signin.Notice{Text: w.Cancelled}
		case noticeProvider:
			p.Notice = &signin.Notice{Text: w.ProviderError}
		case noticeExpired:
			p.Notice = &signin.Notice{Text: w.Expired}
		}
	}

	r.renderPage(ctx, fasthttp.StatusOK, p)
}

// cannotStart answers a request this service cannot place. A browser gets the
// page that says so, naming no client, since none can be trusted from the
// request; any other caller gets err. Never a redirect: the address the request
// names is not one this service knows [RFC 6749 §4.1.2.1]. next is the address
// to show the page at again in another language, or "" for none.
func (r *router) cannotStart(ctx *azugo.Context, status int, err error, next string) {
	if !ctx.AcceptsExplicit("text/html") {
		ctx.Error(err)

		return
	}

	lang := pageLanguage(ctx, "")
	w := signin.For(lang)
	p := signin.Page{Lang: lang, Words: w, Title: w.BadTitle, Lead: w.BadLead}
	if next != "" {
		p.Languages = languageMenu(lang, next)
	}
	r.renderPage(ctx, status, p)
}

// renderPage writes a page with the headers every showing of it carries.
func (r *router) renderPage(ctx *azugo.Context, status int, p signin.Page) {
	var buf bytes.Buffer
	if err := signin.Render(&buf, p); err != nil {
		ctx.Error(err)

		return
	}
	for k, v := range signin.Headers(r.Upstream().AuthorizationOrigin()) {
		ctx.Header.Set(k, v)
	}
	ctx.StatusCode(status)
	ctx.ContentType("text/html", "utf-8")
	ctx.Raw(buf.Bytes())
}

// selfOrigin is this service's own origin, as browsers name it in Origin.
func (r *router) selfOrigin() string {
	return originOf(r.Config().BaseURL)
}

// originOf is the origin of an address, as browsers name it in Origin: without
// the scheme's default port, which browsers leave out.
func originOf(address string) string {
	u, err := url.Parse(address)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Host)
	if p := u.Port(); (u.Scheme == "https" && p == "443") || (u.Scheme == "http" && p == "80") {
		host = strings.TrimSuffix(host, ":"+p)
	}

	return u.Scheme + "://" + host
}

// choose answers the page: the person picked a way. The request it answers is
// the client's, carried on the form's address and checked again exactly as
// /authorize checks it; the choice itself comes from this service's own page
// in the browser the page was shown in, with the page's token, and names a way
// the page offered.
//
// @route /authorize/choice [post].
func (r *router) choose(ctx *azugo.Context) {
	if origin := ctx.Header.Get("Origin"); origin == "" || !strings.EqualFold(origin, r.selfOrigin()) {
		r.Audit().LoginFailure(ctx, "sign-in choice sent from another origin")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	req, ok := r.readAuthorize(ctx, queryParams(ctx))
	if !ok {
		return
	}
	// The page is shown only for a request that names no way.
	if len(req.named) > 0 {
		r.cannotStart(ctx, fasthttp.StatusBadRequest, azugo.ParamInvalidError{Name: "acr_values", Tag: "absent"}, "")

		return
	}

	binding := browserBinding(ctx)
	if binding == "" {
		// The binding outlived its ten minutes, or this is not the browser the
		// page was shown in: the page again, to start afresh.
		r.showPage(ctx, req, bindBrowser(ctx), noticeExpired)

		return
	}

	form := ctx.Request().PostArgs()
	if subtle.ConstantTimeCompare(form.Peek("csrf"), []byte(choiceToken(binding))) != 1 {
		r.Audit().LoginFailure(ctx, "sign-in choice without the page's token")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	way := string(form.Peek("way"))
	if !slices.Contains(r.pickable(req.client), way) {
		r.Audit().LoginFailure(ctx, "sign-in choice names a way the page did not offer")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	bindBrowser(ctx)
	r.startProvider(ctx, req, []string{way}, binding, pageLanguage(ctx, req.signAsk.uiLocales))
}

// chooseLanguage keeps the language the person picked and shows the page again.
// It sends the browser only to this service's own authorization endpoint, with
// the request rebuilt from its parsed query, so no byte of the address as it came
// reaches the answer.
//
// @route /signin/language [get].
func (r *router) chooseLanguage(ctx *azugo.Context) {
	if l := ctx.Query.StringOptional("lang"); l != nil && slices.Contains(signin.Languages, *l) {
		setCookie(ctx, languageCookie, *l, langLifetime)
	}
	next := "/authorize"
	if n := ctx.Query.StringOptional("next"); n != nil {
		if query, ok := strings.CutPrefix(*n, "/authorize?"); ok {
			if q, err := url.ParseQuery(query); err == nil {
				next = "/authorize?" + q.Encode()
			}
		}
	}
	ctx.StatusCode(fasthttp.StatusSeeOther)
	ctx.Redirect(next)
}

// signinAsset serves the page's own files, and the operator's mark when the
// deployment names one.
//
// @route /signin/{name} [get].
func (r *router) signinAsset(ctx *azugo.Context) {
	ctx.Header.Set("X-Content-Type-Options", "nosniff")

	name := ctx.Params.String("name")
	if name == "operator.svg" && r.operatorMark != nil {
		// Shown as an image; opened on its own it may run nothing.
		ctx.Header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
		ctx.ContentType("image/svg+xml")
		ctx.Raw(r.operatorMark)

		return
	}
	b, ct, ok := signin.Asset(name)
	if !ok {
		ctx.NotFound()

		return
	}
	ctx.Header.Set("Cache-Control", "public, max-age=86400")
	ctx.ContentType(ct)
	ctx.Raw(b)
}
