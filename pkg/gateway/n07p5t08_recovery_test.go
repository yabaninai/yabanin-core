package cli

// images recovery boundary: the two upstream-failure shapes the images
// endpoint can hit that were not yet pinned at wire level. Both pin the
// same honesty contract — a broken or retried attempt must never read as
// success (no request.completed event, escrow settled locally), no partial
// upstream payload may reach the client, and the gateway itself never
// auto-retries a charged generation (one upstream call per attempt).
// Client-driven retry after a surfaced failure is safe and bills exactly
// once for the one attempt that actually succeeded.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
)

func imagesUsageBodyT08() string {
	return `{"created":1790000000,"data":[{"b64_json":"` +
		base64.StdEncoding.EncodeToString(testTinyPNG) +
		`"}],"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444,` +
		`"input_tokens_details":{"cached_tokens":0}}}`
}

// upstream sends headers and a partial payload, then aborts the connection
// mid-body (speech pipeline pins the same shape live). The gateway must
// answer 502 with a clean envelope — never a truncated 200 payload, no
// echo of the partial upstream bytes, and no completion event.
func TestN07P5T08_ImagesUpstreamBreakMidBody_NoFalseSuccess(t *testing.T) {
	partial := `{"created":1790000000,"data":[{"b64_json":"` +
		base64.StdEncoding.EncodeToString(testTinyPNG)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, partial)
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer upstream.Close()

	info := resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}
	gw := imagesTestGateway(t, info, upstream.URL)
	var events []*eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { events = append(events, e) }

	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if got := errorTypeT08(t, rec); got != "api_error" {
		t.Fatalf("error type %q, want api_error: %s", got, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString(testTinyPNG)) {
		t.Fatalf("error envelope echoes partial upstream payload: %s", rec.Body.String())
	}
	if len(events) != 0 {
		t.Fatalf("broken upstream published %+v — must never read as success", events)
	}
}

// first attempt hits an upstream 500 (surfaced, one upstream call, no
// event); the client retries and the second attempt passes end to end with
// exactly one completion event across both attempts.
func TestN07P5T08_ImagesRetryAfterUpstreamFailure_BilledOnce(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":{"message":"transient upstream failure"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, imagesUsageBodyT08())
	}))
	defer upstream.Close()

	info := resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}
	gw := imagesTestGateway(t, info, upstream.URL)
	var events []*eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { events = append(events, e) }

	body := `{"model":"m","prompt":"x","n":1,"size":"1024x1024"}`
	first := postImages(t, gw, body)
	if first.Code != http.StatusBadGateway {
		t.Fatalf("first attempt status %d, want 502: %s", first.Code, first.Body.String())
	}
	if len(events) != 0 {
		t.Fatalf("failed attempt published %+v — must never read as success", events)
	}
	if calls.Load() != 1 {
		t.Fatalf("gateway auto-retried the failed generation: %d upstream calls", calls.Load())
	}

	second := postImages(t, gw, body)
	if second.Code != http.StatusOK {
		t.Fatalf("retry status %d, want 200: %s", second.Code, second.Body.String())
	}
	if second.Body.String() != imagesUsageBodyT08() {
		t.Fatalf("retry body is not a verbatim passthrough: %s", second.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls = %d, want 2 (one per attempt)", calls.Load())
	}
	if len(events) != 1 || events[0].EventType != "request.completed" {
		t.Fatalf("events = %+v, want exactly one request.completed for the successful attempt", events)
	}
	if events[0].TokensIn != 20 || events[0].TokensOut != 1424 || events[0].UsageSource != "provider" {
		t.Fatalf("completed event accounting = %+v", events[0])
	}
}

func errorTypeT08(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("envelope: %v (%s)", err, rec.Body.String())
	}
	return env.Error.Type
}
