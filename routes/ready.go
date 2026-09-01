package routes

import (
	"context"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// readinessTimeout bounds each dependency check on the readiness path.
const readinessTimeout = 2 * time.Second

// serviceUnavailableError is a 503 used when a backing store is unreachable, so
// Kubernetes readiness probes pull the pod from rotation (NFR-AVA-1).
type serviceUnavailableError struct{}

func (serviceUnavailableError) Error() string   { return "service unavailable" }
func (serviceUnavailableError) StatusCode() int { return fasthttp.StatusServiceUnavailable }

// readyz is a dependency-aware readiness probe: unlike /healthz (liveness), it
// fails when Redis or PostgreSQL is unreachable, so a pod with a dead backing
// store reports NOT ready instead of silently failing logins.
//
// @route /readyz [get].
func (r *router) readyz(ctx *azugo.Context) {
	ctx.SkipRequestLog() // a readiness probe needs no access line; a failure is still logged via ctx.Error
	c, cancel := context.WithTimeout(r.BackgroundContext(), readinessTimeout)
	defer cancel()

	if err := r.Session().Ping(c); err != nil {
		ctx.Error(serviceUnavailableError{})

		return
	}
	if err := r.Store().Ping(c); err != nil {
		ctx.Error(serviceUnavailableError{})

		return
	}

	ctx.JSON(map[string]string{"status": "ready"})
}
