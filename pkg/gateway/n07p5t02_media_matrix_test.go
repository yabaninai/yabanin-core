package cli

// N07-P05-T02: media-capability matrix wire behavior.
//
// Capability rejections (image parts / unmapped content-part types on
// adapters without the mapping — bedrock, vertex) must surface as an
// explicit 400 unsupported_feature answer carrying the adapter's exact
// reason text — JSON on the chat path, a structured SSE error frame on the
// stream path — never as the opaque upstream_outcome_unknown 502, and
// never after any upstream byte was sent. The rejection is chain-terminal
// (the fallback executor's 4xx/unknown policy), pinned here.
//
// The persistence pins (I26/I62) lock the media history boundary: generated
// image bytes and transcription audio never enter analytics events, and
// since N07-P05-T04 the I62 media rule is profile-independent — inline
// base64/data-URL spans are stripped at the event boundary (media
// references and TEXT/tool-call content kept under the legacy default;
// metadata-only stripping of the remainder is the consumer's job).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
)

const t02ImagePartMessage = `{"type":"text","text":"what is in this picture"},{"type":"image_url","image_url":{"url":"https://example.invalid/y.png"}}`

// t02JSONUpstream answers every request with a minimal OpenAI-style chat
// completion (JSON or SSE per the request), recording path/model/calls.
func t02JSONUpstream(t *testing.T) (*httptest.Server, *atomic.Int64, func() ([]string, []string)) {
	t.Helper()
	var (
		mu     sync.Mutex
		paths  []string
		models []string
		calls  atomic.Int64
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw := make([]byte, 0, 512)
		buf := make([]byte, 512)
		for {
			n, err := r.Body.Read(buf)
			raw = append(raw, buf[:n]...)
			if err != nil {
				break
			}
		}
		var body struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		paths = append(paths, r.URL.Path)
		models = append(models, body.Model)
		mu.Unlock()
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
				"data: [DONE]\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, func() ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...), append([]string(nil), models...)
	}
}

// t02Registry wires a real resolver over an in-memory registry: one row per
// (name, provider) with an optional failover chain.
func t02Registry(t *testing.T, gw *gateway, upstreamURL string, rows map[string]resolver.ModelInfo) {
	t.Helper()
	dbRows := make(map[string][]any, len(rows))
	for name, info := range rows {
		row := []any{name, name + " display", "standard", upstreamURL, "", info.Provider, info.FailoverModels, true, int64(0), "EU"}
		dbRows[name] = row
	}
	gw.log = slog.New(slog.DiscardHandler)
	gw.res = resolver.NewResolver(&rt06ModelDB{rows: dbRows}, "fb", time.Minute, slog.New(slog.DiscardHandler))
}

func t02ChatRequest(t *testing.T, gw *gateway, body string, stream bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	r.Header.Set("X-Session-Id", "sess-1")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

// T02 wire contract: an image part on a bedrock-bound model is an explicit
// client format error (400 with the adapter's reason), raised before any
// upstream byte — not an opaque 502. The stable unsupported_feature code
// rides the envelope (N07-RECON restore of the N07-P05-T02 semantics; the
// capability_not_supported code stays reserved for the adapter's
// streaming/tools refusals).
func TestN07P5T02_ChatImagePartOnBedrock_Explicit400UnsupportedFeature(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "bedrock"},
	})

	body := `{"model":"m1","messages":[{"role":"user","content":[` + t02ImagePartMessage + `]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"code":"unsupported_feature"`)
	assert.Contains(t, rec.Body.String(), `"type":"invalid_request_error"`)
	assert.Contains(t, rec.Body.String(), "image inputs are not supported")
	assert.Zero(t, calls.Load(), "a pre-flight capability rejection must not reach any upstream")
}

// T01 finding F1 fixed on the wire: an unmapped content-part type on bedrock
// must fail closed with an explicit rejection — never a silently-dropped
// part answered as a text-only success.
func TestN07P5T02_ChatUnknownContentPartOnBedrock_FailsClosed(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "bedrock"},
	})

	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"code":"unsupported_feature"`)
	// The message embeds the part type; JSON-escaped quotes inside the body.
	assert.Contains(t, rec.Body.String(), "content part type")
	assert.Contains(t, rec.Body.String(), "input_audio")
	assert.Zero(t, calls.Load(), "the unmapped part must never reach the upstream")
}

// T02 decision pin, restored (N07-RECON): the image-part rejection is a
// typed unsupported-feature refusal with proof the request never left the
// process, so the fallback chain ADVANCES to a media-capable candidate
// (provider.UnsupportedFeatureError doc) — the client's image request is
// served in full instead of refused. The refusal renders 400
// unsupported_feature only when no media-capable fallback exists (the
// single-candidate pin above).
func TestN07P5T02_ChatImagePartRefusal_AdvancesToMediaCapableFallback(t *testing.T) {
	srv, calls, getModels := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "bedrock", FailoverModels: []string{"m2"}},
		"m2": {Provider: "openai"},
	})

	body := `{"model":"m1","messages":[{"role":"user","content":[` + t02ImagePartMessage + `]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"content":"ok"`)
	assert.Equal(t, int64(1), calls.Load(), "exactly the media-capable fallback serves the request")
	_, calledModels := getModels()
	assert.NotContains(t, strings.Join(calledModels, ","), "m1",
		"the bedrock primary refusal is pre-flight: the primary is never dialed")
	assert.Contains(t, strings.Join(calledModels, ","), "m2",
		"the media-capable fallback candidate is called with the full image-bearing body")
}

// The stream path answers the same capability rejection with the structured
// SSE error frame (type invalid_request_error, adapter reason) and status
// 400 — not the upstream_outcome_unknown frame.
func TestN07P5T02_StreamImagePartOnBedrock_Explicit400SSEFrame(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "bedrock"},
	})

	body := `{"model":"m1","stream":true,"messages":[{"role":"user","content":[` + t02ImagePartMessage + `]}]}`
	rec := t02ChatRequest(t, gw, body, true)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"type":"invalid_request_error"`)
	assert.Contains(t, rec.Body.String(), `"code":"unsupported_feature"`,
		"CONTRACT §1: an error code present on the JSON envelope rides the same code field on the SSE frame")
	assert.Contains(t, rec.Body.String(), "image inputs are not supported")
	assert.NotContains(t, rec.Body.String(), "upstream outcome unknown")
	assert.Zero(t, calls.Load(), "a pre-flight capability rejection must not reach any upstream")
}

// Persistence pin (I62): generated-image bytes stay out of the analytics
// event even though the client receives them — no upstream payload/response
// retention on the images path.
func TestN07P5T02_ImagesEvent_NeverPersistsMediaBytes(t *testing.T) {
	upstreamBody := `{"created":1790000000,"data":[{"b64_json":"` +
		base64.StdEncoding.EncodeToString(testTinyPNG) + `"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer srv.Close()

	info := resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: srv.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := imagesTestGateway(t, info, srv.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"a single red cube","n":1,"size":"1024x1024"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "iVBORw0KGgo", "the client must receive the image bytes")
	require.NotNil(t, ev, "no request.completed event")
	assert.Empty(t, ev.UpstreamPayload, "media bytes must never persist in events")
	assert.Empty(t, ev.UpstreamResponse, "media bytes must never persist in events")
	assert.NotContains(t, ev.Payload, base64.StdEncoding.EncodeToString(testTinyPNG))
}

// Persistence pin (I62): the transcription event payload is metadata only —
// the uploaded audio never enters the event.
func TestN07P5T02_TranscriptionPayload_MetadataOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"hello world"}`))
	}))
	defer srv.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(srv.URL))
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	wav := audioFixtureBytes(t, "hello.wav")
	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
	rec := postAudioTranscriptions(t, gw, body, contentType)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, ev, "no request.completed event")

	assert.NotContains(t, ev.Payload, "RIFF", "audio bytes must never persist in events")
	assert.NotContains(t, ev.Payload, base64.StdEncoding.EncodeToString(wav))
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(ev.Payload), &payload), "payload must stay metadata JSON: %q", ev.Payload)
}

// Persistence pin (I26 legacy, refined for media by I62 / N07-P05-T04):
// the legacy default keeps the guarded request payload's TEXT and
// tool-call content, but media is profile-independent — a data-URL image
// part is stripped to its media reference at the event boundary; only the
// base64 span is removed (metadata-only stripping is the consumer's job
// for the rest).
func TestN07P5T02_ChatLegacyProfile_MediaStripped_I62(t *testing.T) {
	srv, _, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "openai"},
	})
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	const dataURL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="
	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"` + dataURL + `"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, ev, "no request.completed event")
	assert.Equal(t, "chat.completions", ev.Endpoint)
	assert.NotContains(t, ev.Payload, dataURL,
		"I62 (supersedes the T02 legacy data-URL retention): media bytes are profile-independent — never persist")
	assert.Contains(t, ev.Payload, "data:image/png;base64,", "the media reference (mime) is retained as metadata")
	assert.Contains(t, ev.Payload, "media stripped", "the strip is explicit")
	assert.Contains(t, ev.Payload, "describe", "I26 legacy still keeps text content")
}
