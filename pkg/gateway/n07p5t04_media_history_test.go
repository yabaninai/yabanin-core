package cli

// N07-P05-T04: media-history accounting — pricing/usage verified paths and
// the I62 logging default.
//
// Owner decision I62 refines I26 for media files: request history retains
// only metadata and references for input and generated media — inline
// media bytes, base64/data URLs and multipart file contents must never be
// retained indirectly in JSON payload logs or persistent history buffers.
// The media rule is profile-independent: it holds under the legacy
// full-content default (which keeps TEXT and tool-call content, I26) and
// under metadata-only alike.
//
// The wire pins lock that boundary on the media surfaces of the five
// agreed capabilities (I61): image input (vision), PDF input, image
// generation, speech recognition, speech synthesis — plus the
// expired-link negative (a data[].url reference is never dereferenced and
// never promises a reproducible file).

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// t04DataURL is a well-formed image data URL whose base64 span must never
// reach a persistent event capture.
var t04DataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(testTinyPNG)

// t04B64 is the raw base64 span of t04DataURL.
var t04B64 = base64.StdEncoding.EncodeToString(testTinyPNG)

// T04/I62: a data URL hidden inside a plain TEXT message part is still
// inline media — it must not land in the persistent payload buffer, while
// the surrounding text content survives verbatim (I26 legacy keeps text).
func TestN07P5T04_HiddenDataURLInTextPart_NeverPersists(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "openai"},
	})
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" {
			ev = e
		}
	})
	defer restore()

	body := `{"model":"m1","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"pasted screenshot ` + t04DataURL + ` describe it"}]}]}`
	rec := t02ChatRequest(t, gw, body, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, ev, "no request.completed event")
	require.EqualValues(t, 1, calls.Load(), "exactly one upstream call")

	assert.NotContains(t, ev.Payload, t04B64, "inline media bytes must not persist (I62)")
	assert.Contains(t, ev.Payload, "pasted screenshot", "surrounding text content survives (I26)")
	assert.Contains(t, ev.Payload, "describe it", "text after the stripped span survives")
	assert.Contains(t, ev.Payload, "media stripped", "the strip is explicit, not silent")
	assert.Contains(t, ev.Payload, "data:image/png;base64,", "the media reference (mime) is retained as metadata")
}

// T04/I62: an image_url data-URL part on the chat path keeps its text
// parts and the media reference in the payload; the base64 bytes never
// persist. This flips the T02 legacy pin — I62 refines I26 for media.
func TestN07P5T04_ChatImagePartPayload_StripsMediaKeepsText(t *testing.T) {
	srv, _, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "openai"},
	})
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" {
			ev = e
		}
	})
	defer restore()

	body := `{"model":"m1","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"` + t04DataURL + `"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, ev, "no request.completed event")

	assert.NotContains(t, ev.Payload, t04B64, "inline media bytes must not persist (I62)")
	assert.Contains(t, ev.Payload, `"describe"`, "text content keeps the I26 legacy retention")
	assert.Contains(t, ev.Payload, "data:image/png;base64,", "media reference metadata retained")
	assert.Contains(t, ev.Payload, "media stripped", "explicit strip marker in the capture")
}

// T04/I62: the images pipeline passes the request through verbatim to the
// upstream (including an edits-style `image` data-URL field), but the event
// payload carries only the stripped reference — and the generated
// b64_json response still reaches the CLIENT byte-for-byte (delivery is
// never degraded; only the history capture is hygienic).
func TestN07P5T04_ImagesRequestImageFieldDataURL_Stripped(t *testing.T) {
	var sent atomic.Pointer[string]
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s := string(raw)
		sent.Store(&s)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1790000000,"data":[{"b64_json":"` + t04B64 + `"}]}`))
	}))
	defer up.Close()

	info := resolver.ModelInfo{ModelName: "img-canon", Provider: "openai", UpstreamURL: up.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := imagesTestGateway(t, info, up.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"a cat","image":"`+t04DataURL+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Upstream still receives the full body (passthrough unchanged).
	require.NotNil(t, sent.Load(), "upstream never called")
	assert.Contains(t, *sent.Load(), t04DataURL, "upstream gets the verbatim request body")
	// The client still receives the full generated payload.
	assert.Contains(t, rec.Body.String(), t04B64, "generated media still delivered to the client")
	// The history capture is metadata-only.
	require.NotNil(t, ev, "no request.completed event")
	assert.NotContains(t, ev.Payload, t04B64, "request media bytes must not persist (I62)")
	assert.Contains(t, ev.Payload, "media stripped", "explicit strip marker")
}

// T04 negative (expired link): the gateway passes data[].url references
// through without dereferencing them — it never promises a reproducible
// file, never fetches the reference, and persists no media bytes.
func TestN07P5T04_ImagesUrlReferencePassthrough_NoFetch(t *testing.T) {
	var fetches atomic.Int64
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write([]byte("expired"))
	}))
	defer remote.Close()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1790000000,"data":[{"url":"` + remote.URL + `/expired.png"}]}`))
	}))
	defer up.Close()

	info := resolver.ModelInfo{ModelName: "img-canon", Provider: "openai", UpstreamURL: up.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := imagesTestGateway(t, info, up.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"a cat"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	assert.EqualValues(t, 0, fetches.Load(), "the gateway must never dereference a data[].url reference")
	assert.Contains(t, rec.Body.String(), remote.URL+"/expired.png", "reference passes through verbatim")
	require.NotNil(t, ev)
	assert.Empty(t, ev.UpstreamResponse, "generated response payloads are never captured into history")
}

// T04: the publish funnel applies the same media hygiene to post-build
// capture setters (audit surfaces that stamp raw params onto built
// events), while the caller's event object stays untouched — the same
// non-mutation contract the content-profile sanitizer pins.
func TestN07P5T04_PublishFunnel_MediaHygienicNoCallerMutation(t *testing.T) {
	var observed atomic.Pointer[eventpub.Event]
	restore := observeEvent(func(e *eventpub.Event) { observed.Store(e) })
	defer restore()

	raw := `{"tool":"render","args":"` + t04DataURL + `"}`
	caller := &eventpub.Event{EventType: "request.completed", Payload: raw}
	publishEvent(nil, testLogger(), caller)

	seen := observed.Load()
	require.NotNil(t, seen, "observer saw no event")
	assert.NotContains(t, seen.Payload, t04B64, "the funnel never forwards inline media")
	assert.Contains(t, seen.Payload, "media stripped", "the strip is explicit at the funnel")
	assert.Equal(t, raw, caller.Payload, "the caller's event object is never mutated")
}
