package routes

import (
	"net/url"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// overLimit is larger than the framework's default request body limit (4 MiB).
const overLimit = 4<<20 + 1024

// A form body over the framework's limit is refused with 413 before any
// grant is looked at.
func TestATokenFormOverTheBodyLimitIsRefusedWith413(t *testing.T) {
	app, _ := signInApp(t)
	e := newEdge(t, app)

	status, _ := e.post("/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {strings.Repeat("a", overLimit)},
	})
	qt.Check(t, qt.Equals(status, fasthttp.StatusRequestEntityTooLarge))
}

// A form body well under the limit is still read as before.
func TestATokenFormUnderTheBodyLimitIsRead(t *testing.T) {
	app, _ := signInApp(t)
	e := newEdge(t, app)

	status, _ := e.post("/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {strings.Repeat("a", 1<<10)},
	})
	qt.Check(t, qt.Not(qt.Equals(status, fasthttp.StatusRequestEntityTooLarge)))
}

// The person-lines read refuses a JSON body over the limit with 413.
func TestPersonLinesBodyOverTheLimitIsRefusedWith413(t *testing.T) {
	app := peopleApp(t, &fakePeople{})

	status, _, _ := send(t, app, linesService, fasthttp.MethodPost, "/testonly/lines",
		`{"subjects":["`+strings.Repeat("a", overLimit)+`"]}`)
	qt.Check(t, qt.Equals(status, fasthttp.StatusRequestEntityTooLarge))
}
