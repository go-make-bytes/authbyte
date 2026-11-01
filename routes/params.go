package routes

import (
	"net/url"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// authParams are an authorization request's parameters, read from the query of
// a GET or from the form body of a POST [OIDC Core §3.1.2.1], so that both
// methods answer alike.
type authParams url.Values

// queryParams reads the request's query.
func queryParams(ctx *azugo.Context) authParams {
	return argsParams(ctx.Request().URI().QueryArgs())
}

// requestParams reads an authorization request: the form body of a POST, the
// query of anything else.
func requestParams(ctx *azugo.Context) authParams {
	if ctx.Method() == fasthttp.MethodPost {
		return argsParams(ctx.Request().PostArgs())
	}

	return queryParams(ctx)
}

// argsParams copies decoded arguments, which fasthttp reuses after the request.
func argsParams(args *fasthttp.Args) authParams {
	p := authParams{}
	for k, v := range args.All() {
		key := string(k)
		p[key] = append(p[key], string(v))
	}

	return p
}

// opt is the first value of key, or nil when it is absent or empty, as a query
// parameter read on its own is.
func (p authParams) opt(key string) *string {
	v := url.Values(p).Get(key)
	if v == "" {
		return nil
	}

	return &v
}

// get is the first value of key, or "" when it is absent.
func (p authParams) get(key string) string {
	return url.Values(p).Get(key)
}

// encode is the request as a query string, for an address that repeats it.
func (p authParams) encode() string {
	return url.Values(p).Encode()
}
