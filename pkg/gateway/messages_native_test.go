package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

func TestMessagesNative_StreamPassthrough(t *testing.T) {
	const sse = "event: ping\ndata: {\"type\":\"ping\"}\n\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":0}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":2,\"output_tokens\":1,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	clientBody := []byte(`{"model":"claude-3-5-sonnet","max_tokens":8,"system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	var gotBody []byte
	var gotBeta, gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotBeta = r.Header.Get("anthropic-beta")
		gotKey = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", strings.NewReader(string(clientBody)))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "claude-code-20250219")
	req.Header.Set("x-claude-code-session-id", "cc-session-1")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != sse {
		t.Fatalf("sse mismatch\ngot %q", rec.Body.String())
	}
	if gotBeta != "claude-code-20250219" {
		t.Fatalf("beta %q", gotBeta)
	}
	if gotKey != "upstream-key" {
		t.Fatalf("x-api-key %q", gotKey)
	}
	assertNativeModelAndSystem(t, clientBody, gotBody)
	if ev == nil || ev.Endpoint != "messages" || ev.SessionID != "cc-session-1" {
		t.Fatalf("event %+v", ev)
	}
	if ev.TokensIn != 7 || ev.TokensOut != 1 || ev.CacheReadTokens != 4 || ev.CacheCreationTokens != 1 {
		t.Fatalf("usage in=%d out=%d read=%d create=%d", ev.TokensIn, ev.TokensOut, ev.CacheReadTokens, ev.CacheCreationTokens)
	}
}

func TestMessagesNative_RateLimitPassthrough(t *testing.T) {
	const errBody = `{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}`
	var gotBeta string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBeta = r.Header.Get("anthropic-beta")
		w.Header().Set("Retry-After", "3")
		w.Header().Set("Anthropic-Ratelimit-Unified-Reset", "10")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, errBody)
	}))
	defer server.Close()
	gw := nativeMessagesGateway(t, server.URL)
	var failed bool
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.failed" && e.Endpoint == "messages" {
			failed = true
		}
	})
	t.Cleanup(restore)

	body := `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`
	rec := postMessages(t, gw, body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != errBody {
		t.Fatalf("body %s", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "3" || rec.Header().Get("Anthropic-Ratelimit-Unified-Reset") != "10" {
		t.Fatalf("headers %#v", rec.Header())
	}
	if gotBeta != "" {
		t.Fatalf("beta should be cleared, got %q", gotBeta)
	}
	if !failed {
		t.Fatal("missing request.failed")
	}
}

// TestMessagesNative_ToolRoundtrip is the packet criterion end to end: tools
// in, streamed tool_use out, then the tool_result replay round-trips through
// the gateway untouched.
func TestMessagesNative_ToolRoundtrip(t *testing.T) {
	const toolSSE = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"input_tokens\":12,\"output_tokens\":9}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	const finalSSE = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":21,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"a.go\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":21,\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	var calls atomic.Int32
	var firstBody, secondBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if calls.Add(1) == 1 {
			firstBody = body
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, toolSSE)
			return
		}
		secondBody = body
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, finalSSE)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var completed []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" && e.Endpoint == "messages" {
			completed = append(completed, e)
		}
	})
	t.Cleanup(restore)

	turn1 := `{"model":"claude-3-5-sonnet","max_tokens":100,"messages":[{"role":"user","content":"List files"}],"tools":[{"name":"bash","description":"Run","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}}],"stream":true}`
	rec1 := postMessages(t, gw, turn1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec1.Code, rec1.Body.String())
	}
	if rec1.Body.String() != toolSSE {
		t.Fatalf("tool stream mismatch\ngot %q", rec1.Body.String())
	}
	if !strings.Contains(string(firstBody), `"input_schema"`) || !strings.Contains(string(firstBody), `"cmd"`) {
		t.Fatalf("tools dropped on the way up: %s", firstBody)
	}
	if len(completed) != 1 || completed[0].TokensIn != 12 || completed[0].TokensOut != 9 {
		t.Fatalf("turn1 events %+v", completed)
	}

	turn2 := `{"model":"claude-3-5-sonnet","max_tokens":100,"system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"List files"},{"role":"assistant","content":[{"type":"text","text":"Calling"},{"type":"tool_use","id":"toolu_1","name":"bash","input":{"cmd":"ls"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"a.go"},{"type":"text","text":"Thanks"}]}],"tools":[{"name":"bash","description":"Run","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}}],"stream":true}`
	rec2 := postMessages(t, gw, turn2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec2.Code, rec2.Body.String())
	}
	if rec2.Body.String() != finalSSE {
		t.Fatalf("final stream mismatch\ngot %q", rec2.Body.String())
	}
	if !strings.Contains(string(secondBody), `"tool_result"`) || !strings.Contains(string(secondBody), `"toolu_1"`) || !strings.Contains(string(secondBody), `"tool_use_id":"toolu_1"`) {
		t.Fatalf("tool_result replay mangled: %s", secondBody)
	}
	assertNativeModelAndSystem(t, []byte(turn2), secondBody)
	if len(completed) != 2 || completed[1].TokensIn != 21 || completed[1].TokensOut != 3 {
		t.Fatalf("turn2 events %+v", completed)
	}
}

// TestMessagesNative_StreamClientCancel pins the negative scenario (content
// blocks and token accounting on cancel): the relayed stream is cut wherever
// it was, partial usage from the seen events is billed, and the finish event
// stays request.completed with termination client_cancel (D1 canon).
func TestMessagesNative_StreamClientCancel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n")
		flusher.Flush()
		for i := 0; ; i++ {
			time.Sleep(50 * time.Millisecond)
			if _, err := fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"%d,\"}}\n\n", i); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(e *eventpub.Event) { evCh <- e })
	t.Cleanup(restore)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gwServer.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := gwServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var partial bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		partial.Write(buf[:n])
		if strings.Contains(partial.String(), "content_block_start") {
			cancel()
		}
		if rerr != nil {
			break
		}
	}
	_ = resp.Body.Close()

	var ev *eventpub.Event
	select {
	case ev = <-evCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for the finish event\npartial:\n%s", partial.String())
	}
	if ev.EventType != "request.completed" {
		t.Fatalf("native cancel must stay request.completed (D1 canon), got %s", ev.EventType)
	}
	if ev.Endpoint != "messages" {
		t.Fatalf("endpoint %q", ev.Endpoint)
	}
	if ev.TokensIn != 7 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
	// Termination stamping needs the reservation harness (integration build);
	// pin the §5.3 classifier the finisher uses for this dead context.
	if got := completionTermination(ctx); got != budget.TerminationClientCancel {
		t.Fatalf("termination classification %q", got)
	}
	if !strings.Contains(partial.String(), "content_block_start") || strings.Contains(partial.String(), "message_stop") {
		t.Fatalf("cancel must cut the stream mid-block:\n%s", partial.String())
	}
}

// TestMessagesNative_EventAsymmetry_CutStream pins the D1 owner decision
// (DECISIONS.md 2026-10-14): the same client-visible mid-stream cut records
// request.completed with billed partial usage on the native path, but
// request.failed on the adapted path.
func TestMessagesNative_EventAsymmetry_CutStream(t *testing.T) {
	t.Run("native completed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
			flusher.Flush()
			panic(http.ErrAbortHandler)
		}))
		defer server.Close()

		gw := nativeMessagesGateway(t, server.URL)
		var ev *eventpub.Event
		restore := observeEvent(func(e *eventpub.Event) {
			if e.Endpoint == "messages" {
				ev = e
			}
		})
		t.Cleanup(restore)

		rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
		if ev == nil {
			t.Fatalf("missing finish event\nbody:\n%s", rec.Body.String())
		}
		if ev.EventType != "request.completed" {
			t.Fatalf("native break must stay request.completed (D1 canon), got %s (%s)", ev.EventType, ev.Error)
		}
		if ev.TokensIn != 5 || ev.TokensOut != 0 {
			t.Fatalf("fallback usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
		}
		if got := completionTermination(context.Background()); got != budget.TerminationCompleted {
			t.Fatalf("termination classification %q", got)
		}
		if strings.Contains(rec.Body.String(), "message_stop") {
			t.Fatalf("cut stream must not fabricate message_stop:\n%s", rec.Body.String())
		}
	})

	t.Run("adapted failed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			_, _ = io.WriteString(w, "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"par\"}}]}\n\n")
			flusher.Flush()
			panic(http.ErrAbortHandler)
		}))
		defer server.Close()

		gw := responsesTestGateway(t, server.URL)
		var ev *eventpub.Event
		restore := observeEvent(func(e *eventpub.Event) {
			if e.Endpoint == "messages" {
				ev = e
			}
		})
		t.Cleanup(restore)

		rec := postMessages(t, gw, `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
		if ev == nil {
			t.Fatalf("missing finish event\nbody:\n%s", rec.Body.String())
		}
		if ev.EventType != "request.failed" {
			t.Fatalf("adapted break must be request.failed (D1 canon), got %s (%s)", ev.EventType, ev.Error)
		}
		// Termination stamping needs the reservation harness (integration
		// build) and the adapted drain classifies inline in stream.go; the
		// D1 pin here is the request.failed event type itself.
		events := apiformat.ParseSSE(rec.Body.Bytes())
		if err := apiformat.ValidateAnthropicStream(events); err != nil {
			t.Fatalf("%v\n%s", err, rec.Body.String())
		}
		if events[len(events)-1].Event != "error" {
			t.Fatalf("last event %s", events[len(events)-1].Event)
		}
		// D- through the full adapted pipeline: the text block open
		// when the cut lands must be closed (content_block_stop) before the
		// terminal error, so Claude Code renders the partial text. The unit
		// anchor is TestAnthropicStream_ErrorClosesOpenTextBlock; the
		// validator alone tolerates an open block before the error.
		var names []string
		for _, e := range events {
			names = append(names, e.Event)
		}
		want := []string{"message_start", "content_block_start", "content_block_delta", "content_block_stop", "error"}
		if len(names) != len(want) {
			t.Fatalf("adapted stream events %v\n%s", names, rec.Body.String())
		}
		for i := range want {
			if names[i] != want[i] {
				t.Fatalf("adapted stream events %v, want %v (D2: open block must close before the error)\n%s", names, want, rec.Body.String())
			}
		}
	})
}

// TestMessages_AdaptedStreamClientCancel completes the negative-scenario
// duality through the same /v1/messages boundary: a real client hanging up
// mid-stream on the ADAPTED path (non-anthropic model) bills the partial
// usage and records request.failed (D1 canon) — the native twin
// TestMessagesNative_StreamClientCancel stays request.completed.
func TestMessages_AdaptedStreamClientCancel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		// Leading usage-only chunk: parsed for accounting (RM-03) but
		// suppressed from the client bytes, so the billed usage is fixed
		// before the first client-visible delta regardless of cancel timing.
		_, _ = io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n")
		flusher.Flush()
		for i := 0; ; i++ {
			time.Sleep(50 * time.Millisecond)
			if _, err := fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"%d,\"}}]}\n\n", i); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(e *eventpub.Event) { evCh <- e })
	t.Cleanup(restore)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gwServer.URL+"/v1/messages",
		strings.NewReader(`{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := gwServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var partial bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		partial.Write(buf[:n])
		if strings.Contains(partial.String(), "content_block_delta") {
			cancel()
		}
		if rerr != nil {
			break
		}
	}
	_ = resp.Body.Close()

	var ev *eventpub.Event
	select {
	case ev = <-evCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for the finish event\npartial:\n%s", partial.String())
	}
	if ev.EventType != "request.failed" {
		t.Fatalf("adapted cancel must be request.failed (D1 canon), got %s", ev.EventType)
	}
	if ev.Endpoint != "messages" {
		t.Fatalf("endpoint %q", ev.Endpoint)
	}
	if ev.TokensIn != 3 || ev.TokensOut != 2 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
	if !strings.Contains(ev.Error, "stream drain failed") {
		t.Fatalf("error %q", ev.Error)
	}
	if !strings.Contains(partial.String(), "content_block_delta") || strings.Contains(partial.String(), "message_stop") {
		t.Fatalf("cancel must cut the stream mid-block:\n%s", partial.String())
	}
}

func nativeMessagesGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	gw := responsesTestGateway(t, upstreamURL)
	gw.res = stubModelResolver{
		"claude-3-5-sonnet": {
			ModelName:      "claude-upstream",
			Provider:       "anthropic",
			UpstreamURL:    upstreamURL,
			UpstreamAPIKey: "upstream-key",
			Enabled:        true,
		},
	}
	return gw
}

func assertNativeModelAndSystem(t *testing.T, clientBody, upstreamBody []byte) {
	t.Helper()
	var client, upstream struct {
		Model  string          `json:"model"`
		System json.RawMessage `json:"system"`
	}
	if err := json.Unmarshal(clientBody, &client); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(upstreamBody, &upstream); err != nil {
		t.Fatal(err)
	}
	if upstream.Model != "claude-upstream" {
		t.Fatalf("model %q", upstream.Model)
	}
	if !rawJSONEq(client.System, upstream.System) {
		t.Fatalf("system\nclient %s\nupstream %s", client.System, upstream.System)
	}
	if !strings.Contains(string(upstream.System), "cache_control") {
		t.Fatalf("cache_control dropped: %s", upstream.System)
	}
}

func rawJSONEq(a, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	lb, errL := json.Marshal(left)
	rb, errR := json.Marshal(right)
	return errL == nil && errR == nil && string(lb) == string(rb)
}

// W-TIMEOUT stream-survival variants shared by the native/completions
// stream-timeout regression tests.
//
//   - "short" (runs everywhere): a live stream must outlive the configured
//     UpstreamTimeout — 6 chunks paced 60ms apart stream for ~360ms, well past
//     the 200ms UpstreamTimeout, which used to kill the whole stream.
//   - "long90s" (local/nightly only): reproduces the original defect at
//     production scale — 180 chunks at 500ms stream for ~90s and used to be
//     cut at the hardcoded 60s whole-stream ceiling. It is gated behind
//     YABANIN_LONG_STREAM_TESTS=1 (and skipped under -short) purely for CI
//     speed; run it locally with:
//     YABANIN_LONG_STREAM_TESTS=1 go test ./pkg/gateway/ -run StreamOutlivesTimeout -count=1 -timeout 15m
type nativeStreamSurvivalVariant struct {
	name            string
	chunks          int
	chunkInterval   time.Duration
	upstreamTimeout time.Duration
}

func nativeStreamSurvivalVariants() []nativeStreamSurvivalVariant {
	variants := []nativeStreamSurvivalVariant{{
		name:            "short",
		chunks:          6,
		chunkInterval:   60 * time.Millisecond,
		upstreamTimeout: 200 * time.Millisecond,
	}}
	if os.Getenv("YABANIN_LONG_STREAM_TESTS") == "1" && !testing.Short() {
		variants = append(variants, nativeStreamSurvivalVariant{
			name:            "long90s",
			chunks:          180,
			chunkInterval:   500 * time.Millisecond,
			upstreamTimeout: 0,
		})
	}
	return variants
}

func TestMessagesNative_StreamOutlivesTimeout(t *testing.T) {
	for _, tc := range nativeStreamSurvivalVariants() {
		t.Run(tc.name, func(t *testing.T) {
			var want strings.Builder
			for i := 0; i < tc.chunks; i++ {
				fmt.Fprintf(&want, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"text\":\"chunk-%d\"}}\n\n", i)
			}
			want.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				flusher := w.(http.Flusher)
				for i := 0; i < tc.chunks; i++ {
					_, _ = fmt.Fprintf(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"text\":\"chunk-%d\"}}\n\n", i)
					flusher.Flush()
					time.Sleep(tc.chunkInterval)
				}
				_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
			}))
			defer server.Close()

			gw := responsesTestGateway(t, server.URL)
			gw.res = stubModelResolver{"claude-3-5-sonnet": {
				ModelName:       "claude-upstream",
				Provider:        "anthropic",
				UpstreamURL:     server.URL,
				UpstreamAPIKey:  "upstream-key",
				UpstreamTimeout: tc.upstreamTimeout,
				Enabled:         true,
			}}

			body := `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`
			rec := postMessages(t, gw, body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != want.String() {
				t.Fatalf("stream truncated: got %d bytes, want %d; tail %q", len(got), want.Len(), got[max(0, len(got)-200):])
			}
		})
	}
}

func TestMessagesNative_NonStreamUpstreamTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"late"}]}`)
	}))
	defer server.Close()

	gw := responsesTestGateway(t, server.URL)
	gw.res = stubModelResolver{"claude-3-5-sonnet": {
		ModelName:       "claude-upstream",
		Provider:        "anthropic",
		UpstreamURL:     server.URL,
		UpstreamAPIKey:  "upstream-key",
		UpstreamTimeout: time.Second,
		Enabled:         true,
	}}

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upstream request failed") {
		t.Fatalf("body %s", rec.Body.String())
	}
}
