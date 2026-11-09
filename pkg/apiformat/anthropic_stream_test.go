package apiformat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func anthOpts() AnthropicOptions {
	return AnthropicOptions{
		IDGen:     func(prefix string) string { return prefix + "fixed" },
		Now:       func() time.Time { return time.Unix(1700000000, 0) },
		KeepAlive: -1,
	}
}

func runAnthropicStream(t *testing.T, sse []byte, meta AnthropicMeta, opts AnthropicOptions, chunks int) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	w := NewAnthropicWriter(rec, meta, opts)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if chunks <= 1 {
		_, _ = w.Write(sse)
	} else {
		for i := 0; i < len(sse); i += chunks {
			end := i + chunks
			if end > len(sse) {
				end = len(sse)
			}
			_, _ = w.Write(sse[i:end])
		}
	}
	w.Finish()
	return rec
}

func TestAnthropicStream_Fixtures(t *testing.T) {
	text, err := os.ReadFile("testdata/stream_chat_text.sse")
	if err != nil {
		t.Fatal(err)
	}
	tools, err := os.ReadFile("testdata/stream_chat_tools.sse")
	if err != nil {
		t.Fatal(err)
	}
	bad, err := os.ReadFile("testdata/stream_chat_error.sse")
	if err != nil {
		t.Fatal(err)
	}
	meta := AnthropicMeta{RequestedModel: "claude", Stream: true}

	t.Run("text", func(t *testing.T) {
		rec := runAnthropicStream(t, text, meta, anthOpts(), 1)
		events := ParseSSE(rec.Body.Bytes())
		if err := ValidateAnthropicStream(events); err != nil {
			t.Fatalf("%v\n%s", err, rec.Body.String())
		}
		expectSSE(t, "testdata/stream_anthropic_text.sse", rec.Body.Bytes())
	})
	t.Run("text chunks", func(t *testing.T) {
		one := runAnthropicStream(t, text, meta, anthOpts(), 1)
		chunked := runAnthropicStream(t, text, meta, anthOpts(), 3)
		if one.Body.String() != chunked.Body.String() {
			t.Fatalf("chunked output differs\n%s\n%s", one.Body.String(), chunked.Body.String())
		}
	})
	t.Run("tools", func(t *testing.T) {
		rec := runAnthropicStream(t, tools, meta, anthOpts(), 1)
		events := ParseSSE(rec.Body.Bytes())
		if err := ValidateAnthropicStream(events); err != nil {
			t.Fatalf("%v\n%s", err, rec.Body.String())
		}
		var deltas int
		var partials []string
		for _, ev := range events {
			if eventName(ev) != "content_block_delta" {
				continue
			}
			_, kind, partial, err := anthropicBlockDelta(ev.Data)
			if err != nil {
				t.Fatal(err)
			}
			if kind != "input_json_delta" {
				continue
			}
			deltas++
			partials = append(partials, partial)
			var obj map[string]any
			if err := json.Unmarshal([]byte(partial), &obj); err != nil {
				t.Fatalf("partial %s: %v", partial, err)
			}
		}
		if deltas != 2 || partials[0] != `{"path":"a"}` || partials[1] != `{"input":"d"}` {
			t.Fatalf("deltas %d %#v\n%s", deltas, partials, rec.Body.String())
		}
		expectSSE(t, "testdata/stream_anthropic_tools.sse", rec.Body.Bytes())
	})
	t.Run("error", func(t *testing.T) {
		rec := runAnthropicStream(t, bad, meta, anthOpts(), 1)
		events := ParseSSE(rec.Body.Bytes())
		if err := ValidateAnthropicStream(events); err != nil {
			t.Fatalf("%v\n%s", err, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, "message_stop") {
			t.Fatalf("error stream must not message_stop:\n%s", body)
		}
		if events[len(events)-1].Event != "error" {
			t.Fatalf("last %s", events[len(events)-1].Event)
		}
		expectSSE(t, "testdata/stream_anthropic_error.sse", rec.Body.Bytes())
	})
}

func TestAnthropicStream_ErrorClosesOpenTextBlock(t *testing.T) {
	const sse = "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"par\"}}]}\n\n" +
		"data: {\"error\":{\"message\":\"boom\",\"type\":\"server_error\"}}\n\n"
	rec := runAnthropicStream(t, []byte(sse), AnthropicMeta{RequestedModel: "claude", Stream: true}, anthOpts(), 3)
	events := ParseSSE(rec.Body.Bytes())
	if err := ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	var names []string
	for _, ev := range events {
		names = append(names, eventName(ev))
	}
	want := []string{"message_start", "content_block_start", "content_block_delta", "content_block_stop", "error"}
	if len(names) != len(want) {
		t.Fatalf("events %v\n%s", names, rec.Body.String())
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("events %v, want %v\n%s", names, want, rec.Body.String())
		}
	}
	body := rec.Body.String()
	if strings.Contains(body, "message_delta") || strings.Contains(body, "message_stop") {
		t.Fatalf("error stream must not terminate the message:\n%s", body)
	}
}

func TestAnthropicStream_ErrorDropsBufferedToolCalls(t *testing.T) {
	const sse = "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"read\",\"arguments\":\"{\\\"p\\\"\"}}]}}]}\n\n" +
		"data: {\"error\":{\"message\":\"boom\",\"type\":\"server_error\"}}\n\n"
	rec := runAnthropicStream(t, []byte(sse), AnthropicMeta{RequestedModel: "claude", Stream: true}, anthOpts(), 1)
	events := ParseSSE(rec.Body.Bytes())
	if err := ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	if events[len(events)-1].Event != "error" {
		t.Fatalf("last %s", events[len(events)-1].Event)
	}
	if strings.Contains(rec.Body.String(), "content_block") {
		t.Fatalf("never-announced tool calls must stay dropped:\n%s", rec.Body.String())
	}
}

func TestAnthropicStream_KeepaliveAndRace(t *testing.T) {
	rec := httptest.NewRecorder()
	opts := anthOpts()
	opts.KeepAlive = 20 * time.Millisecond
	w := NewAnthropicWriter(rec, AnthropicMeta{Stream: true, RequestedModel: "claude"}, opts)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	time.Sleep(80 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(2)
	payload := []byte("data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ab\"}}]}\n\n")
	go func() {
		defer wg.Done()
		for i := 0; i < len(payload); i += 5 {
			end := i + 5
			if end > len(payload) {
				end = len(payload)
			}
			_, _ = w.Write(payload[i:end])
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(30 * time.Millisecond)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))
	}()
	wg.Wait()
	w.Finish()
	body := rec.Body.String()
	if !strings.Contains(body, "event: ping") {
		t.Fatalf("missing ping:\n%s", body)
	}
	events := ParseSSE(rec.Body.Bytes())
	if err := ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
}

func TestAnthropicStream_JSONAndHTTPError(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewAnthropicWriter(rec, AnthropicMeta{RequestedModel: "claude"}, anthOpts())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}`))
	w.Finish()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"text":"Hi"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}

	errRec := httptest.NewRecorder()
	ew := NewAnthropicWriter(errRec, AnthropicMeta{RequestedModel: "claude"}, anthOpts())
	ew.WriteHeader(http.StatusForbidden)
	_, _ = ew.Write([]byte(`{"error":{"message":"no","type":"permission_denied_error","code":"guard_denied"}}`))
	ew.Finish()
	if errRec.Code != http.StatusForbidden || !strings.Contains(errRec.Body.String(), `"type":"error"`) {
		t.Fatalf("%d %s", errRec.Code, errRec.Body.String())
	}
	if errRec.Header().Get("x-should-retry") != "false" {
		t.Fatalf("retry %q", errRec.Header().Get("x-should-retry"))
	}
}

// N07-P01-T02 (INCLUDE, owner decision 2026-10-30): the inner chat pipeline
// sets http.TrailerPrefix entries on the wrapper's Header() AFTER the SSE
// stream opened — the prompt-cache outcome (pkg/gateway.setPromptCacheTrailer,
// value of pkg/gateway.PromptCacheHeader) rides the trailing usage chunk.
// startStreamLocked copies only the pre-commit allowlist and commits the 200,
// so Finish must forward the late entries or the adapted /v1/messages SSE
// loses the trailer the native relay delivers. The literal mirrors
// pkg/gateway.PromptCacheHeader; importing pkg/gateway here would cycle.
const anthPromptCacheTrailerKey = http.TrailerPrefix + "X-Yabanin-Prompt-Cache"

const anthChatSSEWithUsage = "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\n" +
	"data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\n" +
	"data: [DONE]\n\n"

func TestAnthropicStream_TrailerForwardedAfterStreamStart(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewAnthropicWriter(rec, AnthropicMeta{RequestedModel: "claude", Stream: true}, anthOpts())
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(anthChatSSEWithUsage))
	// The chat pipeline's late writer (setPromptCacheTrailer in
	// finishSuccess, pkg/gateway/stream.go) runs after the stream committed.
	w.Header().Set(anthPromptCacheTrailerKey, "hit")
	w.Finish()

	if got := rec.Header().Get(anthPromptCacheTrailerKey); got != "hit" {
		t.Fatalf("trailer lost on the adapted stream, got %q\n%s", got, rec.Body.String())
	}
	events := ParseSSE(rec.Body.Bytes())
	if err := ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	if !strings.HasSuffix(rec.Body.String(), "data: {\"type\":\"message_stop\"}\n\n") {
		t.Fatalf("stream shape changed:\n%s", rec.Body.String())
	}
}

func TestAnthropicStream_TrailerAbsentWithoutOutcome(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewAnthropicWriter(rec, AnthropicMeta{RequestedModel: "claude", Stream: true}, anthOpts())
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(anthChatSSEWithUsage))
	// No usage-derived outcome → the pipeline never sets the trailer key;
	// the writer must not fabricate one.
	w.Finish()

	if got := rec.Header().Get(anthPromptCacheTrailerKey); got != "" {
		t.Fatalf("trailer fabricated without a pipeline outcome: %q", got)
	}
}

// The drain-failure branch (finishDrainFailure, pkg/gateway/stream.go) sets
// the trailer from the partial usage BEFORE writing the in-band error frame:
// a failed adapted stream still reports the outcome.
func TestAnthropicStream_TrailerForwardedOnErrorStream(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewAnthropicWriter(rec, AnthropicMeta{RequestedModel: "claude", Stream: true}, anthOpts())
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"par\"}}]}\n\n"))
	w.Header().Set(anthPromptCacheTrailerKey, "miss")
	_, _ = w.Write([]byte("data: {\"error\":{\"message\":\"stream interrupted\",\"type\":\"api_error\"}}\n\n"))
	w.Finish()

	if got := rec.Header().Get(anthPromptCacheTrailerKey); got != "miss" {
		t.Fatalf("trailer lost on the error stream, got %q\n%s", got, rec.Body.String())
	}
	events := ParseSSE(rec.Body.Bytes())
	if err := ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	if events[len(events)-1].Event != "error" {
		t.Fatalf("terminal event must be error:\n%s", rec.Body.String())
	}
}

// forwardTrailersLocked must not duplicate allowlist keys already delivered
// at stream start, and late passthrough keys must still land once.
func TestAnthropicStream_LatePassthroughHeadersCopiedOnce(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewAnthropicWriter(rec, AnthropicMeta{RequestedModel: "claude", Stream: true}, anthOpts())
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Cache", "HIT") // pre-start: copied by startStreamLocked
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(anthChatSSEWithUsage))
	w.Header().Set("X-Yabanin-Dropped", "top_k") // late entry after commit
	w.Finish()

	if got := rec.Header().Values("X-Cache"); len(got) != 1 || got[0] != "HIT" {
		t.Fatalf("pre-start X-Cache must be delivered exactly once, got %v", got)
	}
	if got := rec.Header().Values("X-Yabanin-Dropped"); len(got) != 1 || got[0] != "top_k" {
		t.Fatalf("late X-Yabanin-Dropped must be delivered exactly once, got %v", got)
	}
}
