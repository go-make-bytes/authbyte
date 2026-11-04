package routes

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"testing"

	"github.com/gmb-lib/go-authbyte/replay"

	authbytecore "github.com/go-make-bytes/authbyte"
	"github.com/go-make-bytes/authbyte/identity"
	"github.com/go-make-bytes/authbyte/session/sessiontest"
	"github.com/go-make-bytes/authbyte/upstream"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The eID card read on eParaksts' page by eParaksts' own browser plugin
// (legacyEid) is a method of the eParaksts provider. A deployment turns it on by
// naming it among the provider's methods; the profile's own methods leave it
// out, so it is off unless named.
const legacyRegistry = `
sign_in_clients:
  - client_id: plugin-card
    type: public
    audience: plugin-api
    enabled: true
    redirect_uris: [https://plugin.example/cb]
    methods: [legacyEid, eparakstsMobile, webEid]
    signing: true
`

const (
	pluginReturn = "https://plugin.example/cb"
	// The words eParaksts is asked for the card through its plugin in.
	pluginACR = "urn:eparaksts:authentication:flow:sc_plugin"
)

// offeredInDiscovery is what the discovery document says acr_values may name.
func offeredInDiscovery(t *testing.T, app *azugo.TestApp) []string {
	t.Helper()

	resp, err := app.TestClient().Get("/.well-known/openid-configuration")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	var doc struct {
		ACR []string `json:"acr_values_supported"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &doc)))

	return doc.ACR
}

// Case 7: with the open build's settings naming no methods, the deployment does
// not offer the card through the plugin. Discovery leaves it out, and a request
// naming it is answered at the client's address before any flow is stored.
func TestTheCardThroughThePluginIsOffUnlessTheSettingsNameIt(t *testing.T) {
	app, mem := registryApp(t, legacyRegistry)

	qt.Check(t, qt.IsFalse(slices.Contains(offeredInDiscovery(t, app), identity.LoginLegacyEID)))

	loc := authorizeAs(t, app, "plugin-card", pluginReturn, identity.LoginLegacyEID)
	checkUnmet(t, loc, "plugin.example")
	qt.Check(t, qt.Equals(flowCount(mem), 0))
}

// Case 8 (asking): named in the open build's methods setting, the card through
// the plugin is offered in discovery and a request naming it goes to eParaksts
// asking for its plugin flow, beside the profile's own methods.
func TestTheSettingsTurnTheCardThroughThePluginOn(t *testing.T) {
	t.Setenv("OIDC_UPSTREAM_METHODS_ALLOWED", "eparakstsMobile,eidScan,legacyEid")
	app, mem := registryApp(t, legacyRegistry)

	offered := offeredInDiscovery(t, app)
	for _, m := range []string{identity.LoginLegacyEID, identity.LoginEParakstsMobile, identity.LoginEIDScan} {
		qt.Check(t, qt.IsTrue(slices.Contains(offered, m)), qt.Commentf("%s in %v", m, offered))
	}

	loc := authorizeAs(t, app, "plugin-card", pluginReturn, identity.LoginLegacyEID)
	qt.Check(t, qt.Equals(loc.Host, "localhost:9999"), qt.Commentf("%s", loc))
	qt.Check(t, qt.Equals(loc.Query().Get("acr_values"), pluginACR))
	qt.Check(t, qt.Equals(flowCount(mem), 1))
}

// pluginDeployment is one eParaksts provider whose methods name the card through
// the plugin, as a deployment's settings or list make it.
type pluginDeployment struct {
	app       *azugo.TestApp
	mem       *sessiontest.Memory
	eparaksts *standIn
	people    *byProvider
	events    *eventLog
}

func pluginApp(t *testing.T) *pluginDeployment {
	t.Helper()

	d := &pluginDeployment{eparaksts: newStandIn(t, false), people: &byProvider{}, events: &eventLog{}, mem: sessiontest.NewMemory()}
	cfg := upstream.EParakstsProfile(d.eparaksts.url, "")
	cfg.ClientID = "eparaksts-client"
	cfg.MethodsAllowed = []string{identity.LoginEParakstsMobile, identity.LoginEIDScan, identity.LoginLegacyEID}
	p, err := upstream.New(context.Background(), cfg, nil)
	qt.Assert(t, qt.IsNil(err))

	t.Setenv("WEBEID_ENGINE_URL", "http://localhost:9998")
	t.Setenv("SERVICE_CLIENT_REGISTRY", legacyRegistry)
	app := authbytecore.TestApp(t, authbytecore.WithUpstreams(upstream.Entry{
		Name: "eparaksts", Provider: p, ReturnPath: eparakstsPath, HoldsStored: true,
		ACR: map[string]string{
			identity.LoginEParakstsMobile: "urn:eparaksts:authentication:flow:mobileid",
			identity.LoginLegacyEID:       pluginACR,
		},
	}))
	app.SetSessionStore(d.mem)
	app.SetReplay(replay.NewMemory())
	app.SetWebEID(whoseCard{})
	app.SetIdentities(d.people)
	recordingAudit(d.events)(app)
	qt.Assert(t, qt.IsNil(Init(app)))

	d.app = azugo.NewTestApp(app.App)
	d.app.Start(t)
	t.Cleanup(d.app.Stop)

	return d
}

// start begins a sign-in for the plugin-card client asking for method, answering
// where the browser was sent and the flow's state.
func (d *pluginDeployment) start(t *testing.T, tc *azugo.TestClient, method string) (*url.URL, string) {
	t.Helper()

	return sentTo(t, authorizeIn(t, tc, "plugin-card", pluginReturn, url.Values{"acr_values": {method}}))
}

// Case 8 (answering): eParaksts answering with its plugin flow signs the person in
// with the method legacyEid, at a card's assurance, found by their code under the
// eParaksts provider rather than the card engine's.
func TestAnAnswerByThePluginSignsInWithLegacyEID(t *testing.T) {
	d := pluginApp(t)
	tc := d.app.TestClient()

	sent, state := d.start(t, tc, identity.LoginLegacyEID)
	qt.Check(t, qt.Equals(sent.Query().Get("acr_values"), pluginACR))
	d.eparaksts.answer(eParakstsPerson(pluginACR))

	code := codeAt(t, complete(t, tc, eparakstsPath, state), pluginReturn)
	qt.Assert(t, qt.Not(qt.Equals(code, "")))
	_, sess := sessionOf(t, d.mem, code)
	qt.Check(t, qt.Equals(sess.LoginMethod, identity.LoginLegacyEID))
	qt.Check(t, qt.Equals(sess.LoA, identity.LoAHigh))

	last := d.people.last()
	qt.Check(t, qt.Equals(last.profile.SerialNumber, annasCode))
	qt.Check(t, qt.Equals(last.profile.LoginMethod, identity.LoginLegacyEID))
	qt.Check(t, qt.Not(qt.Equals(last.profile.Provider, identity.ProviderWebEID)))
}

// Case 9: a sign-in completes only with the method it asked for. Asked for the
// card through the plugin, an answer by eParaksts Mobile is refused at the
// client's address, and so is the reverse; neither reaches the identity store.
func TestTheCardThroughThePluginAndAnotherMethodDoNotStandInForEachOther(t *testing.T) {
	d := pluginApp(t)

	for _, c := range []struct{ asked, answeredACR string }{
		{identity.LoginLegacyEID, "urn:eparaksts:authentication:flow:mobileid"},
		{identity.LoginEParakstsMobile, pluginACR},
	} {
		tc := d.app.TestClient()
		_, state := d.start(t, tc, c.asked)
		d.eparaksts.answer(eParakstsPerson(c.answeredACR))

		a := complete(t, tc, eparakstsPath, state)
		loc, err := url.Parse(a.location)
		qt.Assert(t, qt.IsNil(err), qt.Commentf("%d %s", a.status, a.body))
		checkUnmet(t, loc, "plugin.example")
		qt.Check(t, qt.Equals(loc.Query().Get("code"), ""), qt.Commentf("asked %s", c.asked))
	}
	qt.Check(t, qt.Equals(d.people.count(), 0))
	qt.Check(t, qt.HasLen(d.mem.Keys("code:"), 0))
}

// The sign-in page names the way as eParaksts' card tool and says where the card
// is read, when the client may use it and the deployment offers it.
func TestThePageNamesTheCardThroughThePlugin(t *testing.T) {
	d := pluginApp(t)

	p := showPage(t, d.app.TestClient(), pageQuery("plugin-card", pluginReturn))
	qt.Assert(t, qt.Equals(p.status, fasthttp.StatusOK), qt.Commentf("%s", p.body))
	qt.Check(t, qt.IsTrue(slices.Contains(ways(p.body), identity.LoginLegacyEID)), qt.Commentf("%v", ways(p.body)))
	qt.Check(t, qt.StringContains(p.body, "eParaksts eID"))
	qt.Check(t, qt.StringContains(p.body, "where you sign in with the ID card in your card reader"))
	qt.Check(t, qt.Not(qt.StringContains(p.body, "eParakstītājs")))
}
