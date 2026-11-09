package cli

// N07-P05-T05: negative scenarios must be reproducible without a false
// success status.
//
// Three negatives are pinned on the wire:
//
//  1. An expired/unfetchable image URL is never answered with a success:
//     the gateway forwards the reference to the provider, the provider-side
//     fetch failure maps to an explicit error answer, and the analytics
//     stream carries a request.failed event — never a request.completed.
//  2. An inline data URL stays out of the persistent payload buffer on the
//     negative paths too (error answers carry no media bytes).
//  3. No OCR surface exists: the /v1 route table mounts no OCR/analysis
//     endpoint, and unknown /v1 paths answer 404 — the capability is not
//     advertised as implemented anywhere on the wire.
//
// Plus the false-success defect this card fixes: the anthropic adapter used
// to silently skip unmappable content parts (unknown part types, nil/empty
// or unmappable image URLs). A client that sent such a part got a text-only
// answer pretending the part never existed. Like bedrock/vertex (T02), the
// anthropic adapter now fails closed with the typed unsupported_feature
// answer before any upstream byte.

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// t05AnthropicModel wires the shared t02 harness for an anthropic-bound
// model with the standard failover-free chain.
func t05AnthropicModel(t *testing.T, srv *httptest.Server) (*gateway, *atomic.Int64) {
	t.Helper()
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "anthropic"},
	})
	return gw, nil
}

// Negative 1 (expired link): a vision request whose image URL the provider
// cannot fetch must surface as an explicit error with a request.failed
// event — never a 200 answer or a request.completed event pretending the
// image was seen.
func TestN07P5T05_VisionExpiredURL_NoFalseSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Provider-side image fetch failure (the URL is expired/unreachable
		// from the provider's network). OpenAI-shaped error body.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"Failed to download image from https://example.invalid/expired.png","type":"invalid_request_error"}}`))
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "openai"},
	})
	var completed, failed *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		switch e.EventType {
		case "request.completed":
			completed = e
		case "request.failed":
			failed = e
		}
	})
	defer restore()

	body := `{"model":"m1","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"https://example.invalid/expired.png"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalid_request_error", "the provider failure reason surfaces to the client")
	assert.Nil(t, completed, "an expired image link must never produce a request.completed success event")
	require.NotNil(t, failed, "the failure must be observable in the analytics stream")
	assert.EqualValues(t, http.StatusBadRequest, failed.StatusCode)
}

// Negative 1b (expired link, delivery hygiene): the failure answers carry
// the URL reference only — no fetched media bytes persist anywhere.
func TestN07P5T05_VisionExpiredURL_EventCarriesReferenceOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"download failed","type":"invalid_request_error"}}`))
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "openai"},
	})
	var failed *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.failed" {
			failed = e
		}
	})
	defer restore()

	const b64 = "iVBORw0KGgoAAAANSUhEUg=="
	body := `{"model":"m1","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"data:image/png;base64,` + b64 + `"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)
	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	require.NotNil(t, failed, "no request.failed event")

	assert.NotContains(t, failed.Payload, b64, "inline media bytes must not persist in failure events (I62)")
	assert.Contains(t, failed.Payload, "media stripped", "the strip is explicit on the failure path too")
	assert.Contains(t, failed.Payload, "data:image/png;base64,", "the media reference (mime) survives as metadata")
}

// Negative 3 (OCR): no OCR/protective-analysis surface is mounted anywhere
// under /v1, and an unknown analysis path answers 404 — the capability is
// never advertised as implemented (I66).
func TestN07P5T05_NoOCRSurfaceMounted(t *testing.T) {
	srv, _, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)

	r := chi.NewRouter()
	gw.routes(r)

	var paths []string
	require.NoError(t, chi.Walk(r, func(_, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		paths = append(paths, route)
		return nil
	}), "route walk failed")
	joined := strings.Join(paths, " ")
	for _, banned := range []string{"ocr", "vision-analysis", "image-analysis", "protect"} {
		assert.NotContains(t, strings.ToLower(joined), banned,
			"no OCR/analysis surface may be advertised on the route table (I66)")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/ocr", strings.NewReader(`{"image":"x"}`))
	req.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code, "an OCR request must not find an endpoint (capability not implemented)")
}

// False-success defect (fixed by this card): an unmapped content-part type
// on an anthropic-bound model used to be silently skipped — the client got
// a text-only answer pretending the audio part never existed. It now fails
// closed with the typed unsupported_feature answer before any upstream byte.
func TestN07P5T05_AnthropicUnknownPart_FailsClosed(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw, _ := t05AnthropicModel(t, srv)

	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"code":"unsupported_feature"`)
	assert.Contains(t, rec.Body.String(), `"type":"invalid_request_error"`)
	assert.Contains(t, rec.Body.String(), "content part type")
	assert.Contains(t, rec.Body.String(), "input_audio")
	assert.Zero(t, calls.Load(), "the unmapped part must never reach the upstream")
}

// The stream path answers the same rejection with the structured SSE error
// frame, not a text-only delta stream pretending success.
func TestN07P5T05_AnthropicUnknownPart_StreamFailsClosed(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw, _ := t05AnthropicModel(t, srv)

	body := `{"model":"m1","stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`
	rec := t02ChatRequest(t, gw, body, true)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"type":"invalid_request_error"`)
	assert.NotContains(t, rec.Body.String(), "upstream outcome unknown")
	assert.Zero(t, calls.Load(), "the unmapped part must never reach the upstream")
}

// An image_url part whose URL the anthropic mapping cannot represent
// (neither data: nor http(s)://) used to be silently dropped. It now fails
// closed before any upstream byte.
func TestN07P5T05_AnthropicUnmappableImageScheme_FailsClosed(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw, _ := t05AnthropicModel(t, srv)

	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"ftp://example.invalid/y.png"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"code":"unsupported_feature"`)
	assert.Contains(t, rec.Body.String(), "image URL scheme")
	assert.Zero(t, calls.Load(), "the unmappable image part must never reach the upstream")
}

// A data: URL that is not a base64 image payload cannot map to an anthropic
// image block — it must be rejected, not silently dropped.
func TestN07P5T05_AnthropicNonBase64DataURL_FailsClosed(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw, _ := t05AnthropicModel(t, srv)

	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png,not-base64-payload"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"code":"unsupported_feature"`)
	assert.Zero(t, calls.Load(), "the unmappable image part must never reach the upstream")
}

// Positive control: the anthropic mapping itself is untouched — a well-formed
// base64 data URL still maps to an image block and the request succeeds.
func TestN07P5T05_AnthropicValidDataURL_StillMaps(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw, _ := t05AnthropicModel(t, srv)

	b64 := base64.StdEncoding.EncodeToString(testTinyPNG)
	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"data:image/png;base64,` + b64 + `"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.EqualValues(t, 1, calls.Load(), "exactly one upstream call")
}

// Positive control: https:// image references still map (provider-side
// fetch semantics unchanged — the gateway never dereferences them itself).
func TestN07P5T05_AnthropicHTTPSImage_StillMaps(t *testing.T) {
	srv, calls, sent := t02JSONUpstream(t)
	gw, _ := t05AnthropicModel(t, srv)

	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/y.png"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.EqualValues(t, 1, calls.Load(), "exactly one upstream call")
	paths, _ := sent()
	require.Len(t, paths, 1)
	assert.Equal(t, "/v1/messages", paths[0], "the anthropic adapter still answers the Messages upstream path")
}

// The capability rejection settles locally without an analytics event
// (T02 parity: finalizeNoEvent, escrow closes with no spend) — so the
// analytics stream carries neither a success nor a media-bearing failure
// event, and the client answer is a structured 400 (never a fake 200).
func TestN07P5T05_AnthropicReject_NoEventNoMediaLeak(t *testing.T) {
	srv, _, _ := t02JSONUpstream(t)
	gw, _ := t05AnthropicModel(t, srv)
	var failed, completed *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		switch e.EventType {
		case "request.failed":
			failed = e
		case "request.completed":
			completed = e
		}
	})
	defer restore()

	const b64 = "iVBORw0KGgoAAAANSUhEUg=="
	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"ftp://example.invalid/y.png"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)
	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())

	assert.Nil(t, completed, "a rejected request must never answer with a success event")
	assert.Nil(t, failed, "the capability rejection settles locally — no analytics event (T02 parity)")
	assert.NotContains(t, rec.Body.String(), b64, "no media bytes anywhere in the answer")
}
