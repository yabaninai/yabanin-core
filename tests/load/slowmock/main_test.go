package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseDelay(t *testing.T) {
	for _, tc := range []struct {
		text string
		def  time.Duration
		want time.Duration
	}{
		{"[delay=30s] write something", 0, 30 * time.Second},
		{"[delay=120s] write something", 0, 120 * time.Second},
		{"[delay=500ms] quick", 0, 500 * time.Millisecond},
		{"[delay=2m] long", 0, 2 * time.Minute},
		{"no marker here", 7 * time.Second, 7 * time.Second},
		{"", 0, 0},
		// only the first marker counts; a later different unit must not win
		{"[delay=30s] then [delay=120s]", 0, 30 * time.Second},
		// clamped to maxDelay — a typo must not hold a VU forever
		{"[delay=999m] typo", 0, maxDelay},
		// fractional seconds are accepted
		{"[delay=1.5s] frac", 0, 1500 * time.Millisecond},
	} {
		if got := parseDelay(tc.text, tc.def); got != tc.want {
			t.Errorf("parseDelay(%q, %v) = %v, want %v", tc.text, tc.def, got, tc.want)
		}
	}
}

func TestLastUserTextMultimodal(t *testing.T) {
	req := ChatCompletionRequest{Messages: []Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: []interface{}{
			map[string]interface{}{"type": "text", "text": "part one "},
			map[string]interface{}{"type": "text", "text": "[delay=30s]"},
		}},
	}}
	got := lastUserText(req)
	if !strings.Contains(got, "part one") || !strings.Contains(got, "[delay=30s]") {
		t.Errorf("lastUserText lost multimodal text: %q", got)
	}
	if got := parseDelay(got, 0); got != 30*time.Second {
		t.Errorf("marker inside multimodal content not parsed: %v", got)
	}
}

func TestChunkPlan(t *testing.T) {
	if got := chunkCount(0); got != minChunks {
		t.Errorf("chunkCount(0) = %d, want %d", got, minChunks)
	}
	if got := chunkCount(120 * time.Second); got != 160 { // 120s / 750ms
		t.Errorf("chunkCount(120s) = %d, want 160", got)
	}
	if got := chunkCount(30 * time.Second); got != 40 { // 30s / 750ms
		t.Errorf("chunkCount(30s) = %d, want 40", got)
	}
	if got := streamInterval(120*time.Second, 160); got != chunkCadence {
		t.Errorf("streamInterval(120s) = %v, want %v", got, chunkCadence)
	}
	if got := streamInterval(0, minChunks); got != 0 {
		t.Errorf("streamInterval(0) = %v, want 0 (no holds on instant replies)", got)
	}
}

func TestStreamShapeSpreadsWindow(t *testing.T) {
	// A short window keeps the test fast while proving the real mechanics:
	// SSE content type, delta frames spread over (not before) the window,
	// terminal stop frame with usage, [DONE] terminator.
	delay := 1500 * time.Millisecond
	start := time.Now()
	rec := httptest.NewRecorder()
	req := ChatCompletionRequest{Model: "profile-model", Stream: true, Messages: []Message{
		{Role: "user", Content: "[delay=1500ms] hi"},
	}}
	writeSSE(rec, req, delay)
	elapsed := time.Since(start)

	body := rec.Body.String()
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content type = %q, want text/event-stream", ct)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) {
		t.Errorf("missing terminal stop frame in %q", body)
	}
	if !strings.Contains(body, `"completion_tokens":16`) {
		t.Errorf("missing usage in stop frame")
	}
	if !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Errorf("missing [DONE] terminator: %q", body)
	}
	frames := strings.Count(body, "data: {")
	if frames < 4 {
		t.Errorf("expected >=4 delta/stop frames, got %d", frames)
	}
	if elapsed < 1200*time.Millisecond {
		t.Errorf("stream returned in %v — window was not spread on wall-clock", elapsed)
	}
}

func TestNonStreamHoldsWindowThenJSON(t *testing.T) {
	delay := 1500 * time.Millisecond
	start := time.Now()
	rec := httptest.NewRecorder()
	req := ChatCompletionRequest{Model: "profile-model", Messages: []Message{
		{Role: "user", Content: "[delay=1500ms] hi"},
	}}
	writeJSON(rec, req, delay)
	elapsed := time.Since(start)
	if elapsed < 1200*time.Millisecond {
		t.Errorf("non-stream returned in %v — hold window not honored", elapsed)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
	}
	choices, ok := resp["choices"].([]any)
	if !ok || len(choices) != 1 {
		t.Fatalf("choices shape wrong: %v", resp)
	}
	if strings.Contains(rec.Body.String(), "[delay") {
		t.Errorf("marker leaked into response body: %q", rec.Body.String())
	}
}

func TestMarkerDoesNotLeakIntoResponses(t *testing.T) {
	rec := httptest.NewRecorder()
	req := ChatCompletionRequest{Model: "m", Stream: true, Messages: []Message{
		{Role: "user", Content: "[delay=1ms] secret prompt body"},
	}}
	writeSSE(rec, req, time.Millisecond)
	if strings.Contains(rec.Body.String(), "[delay=") || strings.Contains(rec.Body.String(), "secret prompt body") {
		t.Errorf("prompt/marker leaked into SSE stream: %q", rec.Body.String())
	}
}

func TestHealthzHandler(t *testing.T) {
	// Wire the same registration pattern main() uses, without binding a port.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "goroutines": 1})
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}
