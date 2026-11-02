package routes

import (
	"bytes"
	"crypto/subtle"
	"errors"
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

// The page's messages decided on the request itself, never carried over: the
// browser's binding ran out before the person chose; the card's button posted
// the page's choice because this browser runs no script; the card's answer
// signed no one in.
const (
	noticeExpired    = "expired"
	noticeNoScript   = "noscript"
	noticeCardFailed = "cardfailed"
)

// offered are the methods the page may offer a client: those its registration
// lists, in that order, that this deployment can start.
func (r *router) offered(client registry.SignInClient) []string {
	var out []string
	for _, m := range client.Methods {
		if r.canStart(m) && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}

	return out
}

// canStart reports whether this deployment can start a sign-in with method:
// a way one of its providers offers, or the card where it reads cards.
func (r *router) canStart(method string) bool {
	return r.Upstreams().ByMethod(method) != nil || (method == identity.LoginWebEID && r.WebEID() != nil)
}

// pageWays are the ways the page shows a request, and whether it is shown at
// all: every way offered when the request names none; the ways it names when
// the card is among them, since the card is read on this page, or when they
// are ways of more than one provider, which the person picks between; none, and
// no page, when it names only one provider's ways, which go straight there.
func (r *router) pageWays(req *authorizeRequest, offered []string) ([]string, bool) {
	switch {
	case len(req.named) == 0:
		return offered, true
	case slices.Contains(req.named, identity.LoginWebEID), r.providerOf(req.named) == nil:
		return req.named, true
	default:
		return nil, false
	}
}

// wayName is a method's exact name on the page and its one-line hint.
func (r *router) wayName(method string, w signin.Words) (name, hint string) {
	switch method {
	case identity.LoginEParakstsMobile:
		return "eParaksts Mobile", w.HintMobile
	case identity.LoginEIDScan:
		return "eID Scan", w.HintScan
	case identity.LoginWebEID:
		return "eID", w.HintCard
	default:
		// A generic provider's way, named as the deployment names it.
		if e := r.Upstreams().ByMethod(method); e != nil && e.DisplayName != "" {
			return e.DisplayName, w.HintRedirect
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

// showPage answers a request with this service's sign-in page.
func (r *router) showPage(ctx *azugo.Context, req *authorizeRequest, binding, notice string) {
	r.showPageWith(ctx, fasthttp.StatusOK, req, binding, notice)
}

// showPageWith answers with the page under status: the ways pageWays gives the
// request, and the card's challenge when the card is among them.
func (r *router) showPageWith(ctx *azugo.Context, status int, req *authorizeRequest, binding, notice string) {
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
	ways, _ := r.pageWays(req, r.offered(req.client))
	for _, m := range ways {
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
		case noticeNoScript:
			p.Notice = &signin.Notice{Text: w.NoScript}
		case noticeCardFailed:
			p.Notice = &signin.Notice{Text: w.CardFailed}
		}
	}

	// The card's answer returns to the client with a redirect, which the page's
	// form must be allowed to send the browser to.
	var back string
	if slices.Contains(ways, identity.LoginWebEID) {
		card, err := r.startCard(ctx, req, binding)
		if err != nil {
			ctx.Error(err)

			return
		}
		p.Card = card
		p.SoftwareURL = signin.CardSoftwareURL
		back = webOrigin(req.redirectURI)
	}

	r.renderPage(ctx, status, p, back)
}

// webOrigin is the origin of an http or https address, as a policy names it; ""
// for any other address.
func webOrigin(address string) string {
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}

	return originOf(address)
}

// startCard makes the challenge the card signs on this showing of the page: a
// flow tied to this browser that keeps the client's request, as a flow sent to
// the provider from the page does.
func (r *router) startCard(ctx *azugo.Context, req *authorizeRequest, binding string) (*signin.Card, error) {
	nonce, err := webeidNonce()
	if err != nil {
		return nil, err
	}

	state := randomToken(24)
	flow := newFlow(req, []string{identity.LoginWebEID}, binding, true)
	flow.WebEIDNonce = nonce
	if err := r.Session().SaveFlow(ctx, state, flow, flowTTL); err != nil {
		return nil, err
	}

	return &signin.Card{Action: "/authorize/card?" + req.params.encode(), Nonce: nonce, State: state}, nil
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

// renderPage writes a page with the headers every showing of it carries; its forms
// may also be answered with a redirect to each of formTargets.
func (r *router) renderPage(ctx *azugo.Context, status int, p signin.Page, formTargets ...string) {
	var buf bytes.Buffer
	if err := signin.Render(&buf, p); err != nil {
		ctx.Error(err)

		return
	}
	var targets []string
	for _, e := range r.Upstreams().Entries() {
		targets = append(targets, e.Provider.AuthorizationOrigin())
	}
	for k, v := range signin.Headers(append(targets, formTargets...)...) {
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
	if !r.fromOwnPage(ctx) {
		r.Audit().LoginFailure(ctx, "sign-in choice sent from another origin")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	req, ok := r.readAuthorize(ctx, queryParams(ctx))
	if !ok {
		return
	}
	// A request that may show no page was never shown one.
	if req.signAsk.none {
		r.refuseAtClient(ctx, req, "login_required", "the person must sign in")

		return
	}
	// The page is shown only for a request that names no way, or names the card.
	ways, page := r.pageWays(req, r.offered(req.client))
	if !page {
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
	if !slices.Contains(ways, way) {
		r.Audit().LoginFailure(ctx, "sign-in choice names a way the page did not offer")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}
	if way == identity.LoginWebEID {
		// The card's button posted the page's choice: its script, which reads the
		// card, did not run in this browser.
		r.showPage(ctx, req, bindBrowser(ctx), noticeNoScript)

		return
	}

	bindBrowser(ctx)
	r.startProvider(ctx, req, []string{way}, binding, pageLanguage(ctx, req.signAsk.uiLocales), true)
}

// fromOwnPage reports whether a post comes from this service's own page: its
// Origin is this service's own. One without it, or "null", is refused
// [RFC 6454 §7.3].
func (r *router) fromOwnPage(ctx *azugo.Context) bool {
	origin := ctx.Header.Get("Origin")

	return origin != "" && strings.EqualFold(origin, r.selfOrigin())
}

// cardAnswer completes a card sign-in begun on this page: the card signed the
// challenge the page was shown with, and the page's script posts its answer.
// Like the choice, the post comes from this service's own page in the browser
// the page was shown in, with the page's token; the challenge must be one that
// browser was given for this client's request. The browser goes back to the
// client with a code, or to the page saying why it did not.
//
// @route /authorize/card [post].
func (r *router) cardAnswer(ctx *azugo.Context) {
	if !r.fromOwnPage(ctx) {
		r.Audit().LoginFailure(ctx, "card answer sent from another origin")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	req, ok := r.readAuthorize(ctx, queryParams(ctx))
	if !ok {
		return
	}
	if req.signAsk.none {
		r.refuseAtClient(ctx, req, "login_required", "the person must sign in")

		return
	}
	if ways, page := r.pageWays(req, r.offered(req.client)); !page || !slices.Contains(ways, identity.LoginWebEID) {
		r.Audit().LoginFailure(ctx, "card answer for a request the card is not offered to")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	binding := browserBinding(ctx)
	if binding == "" {
		r.showPage(ctx, req, bindBrowser(ctx), noticeExpired)

		return
	}

	form := ctx.Request().PostArgs()
	if subtle.ConstantTimeCompare(form.Peek("csrf"), []byte(choiceToken(binding))) != 1 {
		r.Audit().LoginFailure(ctx, "card answer without the page's token")
		r.cannotStart(ctx, fasthttp.StatusForbidden, corehttp.ForbiddenError{}, "")

		return
	}

	flow, err := r.Session().ConsumeFlow(ctx, string(form.Peek("state")))
	if err != nil || flow.WebEIDNonce == "" || flow.Binding == "" || flow.ClientID != req.clientID {
		// Used, expired, or never this page's (a flow bound to no browser is a
		// step-up saved before the step-up was removed): the page again, with a
		// fresh challenge.
		r.showPage(ctx, req, bindBrowser(ctx), noticeExpired)

		return
	}
	if !boundHere(ctx, flow.Binding) {
		r.Audit().LoginFailure(ctx, "card answer in a browser the sign-in did not start in")
		r.cannotStart(ctx, fasthttp.StatusUnauthorized, corehttp.UnauthorizedError{}, "")

		return
	}

	bindBrowser(ctx)
	appCode, err := r.completeCard(ctx, flow, append([]byte(nil), form.Peek("token")...))
	switch {
	case errors.Is(err, errCardAnswered):
		return
	case errors.Is(err, errCardRefused):
		r.showPageWith(ctx, fasthttp.StatusUnauthorized, req, binding, noticeCardFailed)

		return
	case err != nil:
		ctx.Error(err)

		return
	}

	// The client's own redirect address, validated with its request.
	ctx.StatusCode(fasthttp.StatusSeeOther)
	ctx.RedirectUnsafe(appendCodeState(flow.AppRedirectURI, r.issuerID(), appCode, flow.SPAState))
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
