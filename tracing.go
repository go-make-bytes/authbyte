package authbytecore

import (
	"context"

	"azugo.io/core/cache"
	"azugo.io/opentelemetry"
)

// cacheTracingOptions are the tracing options the service starts with: a cache
// span is named without its key.
func cacheTracingOptions() []opentelemetry.Option {
	return []opentelemetry.Option{opentelemetry.InstrumentationSpanNameFormatter(cacheSpanName)}
}

// cacheSpanName names a cache operation's span by the operation and the cache
// instance alone. The tracing library's own name carries the full key, and this
// service's keys are session ids, refresh-token hashes, application codes, login
// states and proof ids: a trace must never hold them. Every other operation keeps
// the library's name (the empty answer).
func cacheSpanName(_ context.Context, op string, args ...any) string {
	var verb string

	switch op {
	case cache.InstrumentationGet:
		verb = "GET"
	case cache.InstrumentationSet:
		verb = "SET"
	case cache.InstrumentationDelete:
		verb = "DELETE"
	default:
		return ""
	}

	instance, ok := cache.InstrInstance(args...)
	if !ok || instance == "" {
		instance = "cache"
	}

	return verb + " " + instance
}
