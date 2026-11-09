package cli

// Reasoning (thinking) tool-use relay pins for the native /v1/messages
// branch: thinking blocks and their deltas relay byte-identically alongside
// tool_use blocks; partial usage from message_start plus message_delta is
// billed exactly once with cumulative-merge semantics (the last cumulative
// value wins, never a sum of the deltas); a cut that lands inside an open
// thinking block, or after a closed thinking block but inside a half-written
// tool_use JSON, closes the still-open blocks before the terminal error.
//
// ValidateAnthropicStream is deliberately NOT used on the complete thinking
// streams: its delta-matching table knows text and tool_use only, so a
// compliant thinking_delta on a thinking block would be rejected there. The
// assertions below check the frames manually instead.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

const reasoningToolSSE = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"check the dir listing first\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig0\"}}\n\n" +
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"ls\\\"}\"}}\n\n" +
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n" +
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":2}}\n\n" +
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"input_tokens\":10,\"output_tokens\":9}}\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

// TestMessagesNative_ReasoningToolUseStreamPassthrough: a complete stream
// with an interleaved thinking block and a tool_use block relays
// byte-identically, and the billing merge takes the last cumulative usage
// (output 9 from the final message_delta) instead of summing the deltas
// (1 from message_start, then 2, then 9 would double-count as 12).
func TestMessagesNative_ReasoningToolUseStreamPassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(reasoningToolSSE))
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var completes int
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "messages" && e.EventType == "request.completed" {
			completes++
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":64,"messages":[{"role":"user","content":"List files"}],"stream":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != reasoningToolSSE {
		t.Fatalf("thinking + tool_use stream must relay byte-identically\ngot %q", rec.Body.String())
	}
	if completes != 1 {
		t.Fatalf("request.completed count %d, want exactly 1", completes)
	}
	if ev == nil {
		t.Fatal("missing finish event")
	}
	if ev.TokensIn != 10 || ev.TokensOut != 9 {
		t.Fatalf("cumulative usage in=%d out=%d, want in=10 out=9 (last value, not the sum)", ev.TokensIn, ev.TokensOut)
	}
}

// TestMessagesNative_ReasoningCutMidThinkingClosesOpenBlocks: the upstream
// dies while a thinking block is open. The client gets the byte-identical
// prefix, the synthesized content_block_stop for the thinking index, and the
// canonical terminal error; the partial usage from message_start is billed
// once; message_stop is never fabricated.
func TestMessagesNative_ReasoningCutMidThinkingClosesOpenBlocks(t *testing.T) {
	const passthrough = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"par\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte(passthrough))
		flusher.Flush()
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "messages" && e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	body := rec.Body.String()
	if !strings.HasPrefix(body, passthrough) {
		t.Fatalf("passthrough prefix must stay byte-identical:\n%s", body)
	}
	if strings.Contains(body, "message_stop") {
		t.Fatalf("cut stream must not fabricate message_stop:\n%s", body)
	}
	if !strings.Contains(body, `{"type":"content_block_stop","index":0}`) {
		t.Fatalf("open thinking block must close before the terminal error:\n%s", body)
	}
	if !strings.Contains(body, nativeCutTerminalError) {
		t.Fatalf("terminal error missing:\n%s", body)
	}
	if ev == nil {
		t.Fatal("missing request.completed (partial usage must be billed once)")
	}
	if ev.TokensIn != 4 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
}

// TestMessagesNative_ReasoningCutMidToolAfterClosedThinking: the thinking
// block is already stopped by the upstream when the cut lands inside the
// open tool_use JSON. The client stream ends with the relayed upstream stop
// for index 0, the synthesized stop for the still-open index 1 — the closed
// thinking index is never stopped twice — followed by the terminal error.
func TestMessagesNative_ReasoningCutMidToolAfterClosedThinking(t *testing.T) {
	const passthrough = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"plan\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte(passthrough))
		flusher.Flush()
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "messages" && e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	body := rec.Body.String()
	if !strings.HasPrefix(body, passthrough) {
		t.Fatalf("passthrough prefix must stay byte-identical:\n%s", body)
	}
	var stops []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: {\"type\":\"content_block_stop\"") {
			stops = append(stops, strings.TrimPrefix(line, "data: "))
		}
	}
	if len(stops) != 2 || stops[0] != `{"type":"content_block_stop","index":0}` || stops[1] != `{"type":"content_block_stop","index":1}` {
		t.Fatalf("stops %v, want [upstream index 0, then synthesized index 1] (the closed thinking index is never stopped twice):\n%s", stops, body)
	}
	if !strings.Contains(body, nativeCutTerminalError) {
		t.Fatalf("terminal error missing:\n%s", body)
	}
	if strings.Contains(body, "message_stop") {
		t.Fatalf("cut stream must not fabricate message_stop:\n%s", body)
	}
	if ev == nil {
		t.Fatal("missing request.completed (partial usage must be billed once)")
	}
	if ev.TokensIn != 2 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d (no double billing)", ev.TokensIn, ev.TokensOut)
	}
}

// TestMessagesNative_NonStreamReasoningUsageBilledOnce: the non-stream
// native branch relays the thinking response body byte-identically and bills
// the provider usage parsed from it exactly once.
func TestMessagesNative_NonStreamReasoningUsageBilledOnce(t *testing.T) {
	const body = `{"type":"message","id":"msg_1","content":[{"type":"thinking","thinking":"plan","signature":"sig0"},{"type":"tool_use","id":"toolu_1","name":"bash","input":{"cmd":"ls"}}],"stop_reason":"tool_use","usage":{"input_tokens":21,"output_tokens":13,"cache_read_input_tokens":5,"cache_creation_input_tokens":2}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var completes int
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "messages" && e.EventType == "request.completed" {
			completes++
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":64,"messages":[{"role":"user","content":"List files"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != body {
		t.Fatalf("thinking response body must relay byte-identically\ngot %s", rec.Body.String())
	}
	if completes != 1 {
		t.Fatalf("request.completed count %d, want exactly 1", completes)
	}
	if ev == nil {
		t.Fatal("missing finish event")
	}
	// TokensIn follows the accounting canon: input + cache_read +
	// cache_creation (21+5+2), the same merge the streaming pin uses.
	if ev.TokensIn != 28 || ev.TokensOut != 13 || ev.CacheReadTokens != 5 || ev.CacheCreationTokens != 2 {
		t.Fatalf("usage in=%d out=%d read=%d create=%d", ev.TokensIn, ev.TokensOut, ev.CacheReadTokens, ev.CacheCreationTokens)
	}
}
