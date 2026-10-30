package authbytecore

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-make-bytes/authbyte/session"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"azugo.io/opentelemetry"
	"github.com/go-quicktest/qt"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// A cache span is named by the operation and the instance; the key, which is a
// session id, a refresh-token hash, a code, a login state or a proof id here,
// never reaches the name.
func TestCacheSpansAreNamedWithoutTheKey(t *testing.T) {
	const key = "authbyte:sessions:the-session-id"

	for op, want := range map[string]string{
		cache.InstrumentationGet:    "GET sessions",
		cache.InstrumentationSet:    "SET sessions",
		cache.InstrumentationDelete: "DELETE sessions",
	} {
		name := cacheSpanName(context.Background(), op, key, string(cache.RedisCache), "sessions")

		qt.Check(t, qt.Equals(name, want))
		qt.Check(t, qt.IsFalse(strings.Contains(name, "the-session-id")))
	}
}

// Without an instance name a cache span still never falls back to the key.
func TestACacheSpanWithoutAnInstanceIsNamedCache(t *testing.T) {
	qt.Check(t, qt.Equals(cacheSpanName(context.Background(), cache.InstrumentationGet, "the-key"), "GET cache"))
}

// Every other operation keeps the tracing library's own name.
func TestOtherOperationsKeepTheLibrarysName(t *testing.T) {
	qt.Check(t, qt.Equals(cacheSpanName(context.Background(), "http-request", "GET", "https://example.test/"), ""))
}

// With the service's tracing options, no span the session store's operations
// record carries a key or a stored value in its name or its attributes. Needs
// VALKEY_TEST_URL (for example redis://localhost:6379/15); skipped without,
// because the tracing library records no span for the in-memory cache.
func TestNoSessionStoreSpanCarriesAKey(t *testing.T) {
	url := os.Getenv("VALKEY_TEST_URL")
	if url == "" {
		t.Skip("VALKEY_TEST_URL is not set")
	}

	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	app := azugo.New()
	_, err := opentelemetry.Use(app, &opentelemetry.Configuration{Endpoint: "http://127.0.0.1:1"},
		append(cacheTracingOptions(), opentelemetry.TracerProvider(provider))...)
	qt.Assert(t, qt.IsNil(err))

	c := cache.New(
		cache.RedisCache,
		cache.ConnectionString(url),
		cache.KeyPrefix("authbyte-tracing-test"),
		cache.ClientCache(false),
		cache.Instrumenter(app.Instrumenter()),
	)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	store, err := session.New(c)
	qt.Assert(t, qt.IsNil(err))
	proofs, err := session.NewProofReplay(c)
	qt.Assert(t, qt.IsNil(err))

	const (
		state  = "the-login-state"
		code   = "the-application-code"
		sid    = "the-session-id"
		grant  = "the-refresh-token-hash"
		proof  = "the-proof-id"
		person = "the-person"
	)
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(store.SaveFlow(ctx, state, &session.Flow{SPAState: state}, time.Minute)))
	_, err = store.ConsumeFlow(ctx, state)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(store.SaveAppCode(ctx, code, &session.AppCode{SessionID: sid}, time.Minute)))
	_, err = store.ConsumeAppCode(ctx, code)
	qt.Assert(t, qt.IsNil(err))
	sess := &session.Session{Subject: person}
	qt.Assert(t, qt.IsNil(store.CreateSession(ctx, sid, sess, time.Minute)))
	qt.Assert(t, qt.IsNil(store.ReplaceSession(ctx, sid, sess)))
	_, err = store.LoadSession(ctx, sid)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(store.SaveRefresh(ctx, grant, &session.RefreshGrant{SessionID: sid}, time.Now().Add(time.Minute))))
	_, err = store.LoadRefresh(ctx, grant)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(store.DeleteRefresh(ctx, grant)))
	qt.Assert(t, qt.IsNil(store.DeleteSession(ctx, sid)))
	_, err = proofs.CheckAndSet(ctx, proof, time.Minute)
	qt.Assert(t, qt.IsNil(err))

	spans := exporter.GetSpans()
	// A guard on the guard: with no spans recorded the check below passes over
	// nothing.
	qt.Assert(t, qt.IsTrue(len(spans) >= 10), qt.Commentf("%d spans recorded", len(spans)))

	for _, s := range spans {
		texts := []string{s.Name}
		for _, a := range s.Attributes {
			texts = append(texts, string(a.Key), a.Value.String())
		}
		for _, ev := range s.Events {
			texts = append(texts, ev.Name)
			for _, a := range ev.Attributes {
				texts = append(texts, a.Value.String())
			}
		}
		texts = append(texts, s.Status.Description)

		for _, text := range texts {
			for _, secret := range []string{state, code, sid, grant, proof, person} {
				qt.Check(t, qt.IsFalse(strings.Contains(text, secret)),
					qt.Commentf("span %q carries %q in %q", s.Name, secret, text))
			}
		}
	}
}
