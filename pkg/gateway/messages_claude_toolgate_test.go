package cli

// TOOL-02 native-surface controls (CP-C02-02): the SSE enforcement twin of
// TestMessagesNative_ToolPolicyEnforced plus the edge-case contract — args
// guard, all-denied stop repair, byte-identical passthrough when the policy
// does not apply, malformed/truncated streams failing closed, unknown
// compatible events not bypassing a denial, and org isolation. All ride a
// real toolpolicy engine over an in-memory loader and a mock anthropic
// upstream, and observe the ledger through observeEvent.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// ccCaptureNativeLedger funnels the messages-endpoint analytics events: the
// latest terminal (request.completed/failed) and the total event count.
func ccCaptureNativeLedger(t *testing.T) (terminal func() *eventpub.Event, events func() int) {
	t.Helper()
	var ev *eventpub.Event
	var count int
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		count++
		if e.EventType == "request.completed" || e.EventType == "request.failed" {
			ev = e
		}
	})
	t.Cleanup(restore)
	return func() *eventpub.Event { return ev }, func() int { return count }
}

// ccNativeContentBlocks decodes the content array of a native reply.
func ccNativeContentBlocks(t *testing.T, body string) []map[string]any {
	t.Helper()
	var doc struct {
		Content []map[string]any `json:"content"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode native body: %v", err)
	}
	return doc.Content
}

// ccNativeStopReason decodes the top-level stop_reason of a native reply.
func ccNativeStopReason(t *testing.T, body string) string {
	t.Helper()
	var doc struct {
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode native body: %v", err)
	}
	return doc.StopReason
}

// ccFrame renders one native SSE frame.
func ccFrame(event, data string) string { return "event: " + event + "\ndata: " + data + "\n\n" }

// ccNativeSSEUpstream serves one fixed native SSE frame sequence (frames
// carry their own separators), flushing after each.
func ccNativeSSEUpstream(t *testing.T, frames []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for _, f := range frames {
			_, _ = io.WriteString(w, f)
			flusher.Flush()
		}
	}))
}

// ccNativeFrames splits a client-visible SSE stream into parsed frames.
// Data that does not parse (deliberately malformed controls) leaves Data
// nil but the Event name is still recovered.
func ccNativeFrames(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(body), "\n\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var datas []string
		for _, line := range strings.Split(raw, "\n") {
			if d, ok := strings.CutPrefix(line, "data: "); ok {
				datas = append(datas, d)
			}
		}
		if len(datas) == 0 {
			t.Fatalf("frame without data payload: %q", raw)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(strings.Join(datas, "\n")), &doc); err != nil {
			continue // malformed control frames stay in the raw assertions
		}
		out = append(out, doc)
	}
	return out
}

// ccCountType counts the parsed frames of one native event type.
func ccCountType(frames []map[string]any, typ string) int {
	n := 0
	for _, f := range frames {
		if v, _ := f["type"].(string); v == typ {
			n++
		}
	}
	return n
}

// ccBlockByName returns the first content_block_start frame whose block
// declares the named tool.
func ccBlockByName(t *testing.T, frames []map[string]any, name string) map[string]any {
	t.Helper()
	for _, f := range frames {
		if v, _ := f["type"].(string); v != "content_block_start" {
			continue
		}
		block, _ := f["content_block"].(map[string]any)
		if block != nil && block["name"] == name {
			return f
		}
	}
	t.Fatalf("no content_block_start for %q in %d frames", name, len(frames))
	return nil
}

// ccStopReasonFromDelta extracts the message_delta stop_reason.
func ccStopReasonFromDelta(t *testing.T, frames []map[string]any) string {
	t.Helper()
	for _, f := range frames {
		if v, _ := f["type"].(string); v != "message_delta" {
			continue
		}
		delta, _ := f["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		if reason, _ := delta["stop_reason"].(string); reason != "" {
			return reason
		}
	}
	t.Fatalf("no message_delta stop_reason found")
	return ""
}

// Fixed wire frames for the streaming controls: message_start (usage 5/0),
// a text block, a bash tool_use block and a calculator tool_use block, the
// message_delta finish and the message_stop terminal.
var (
	ccMsgStartFrame  = ccFrame("message_start", `{"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":0}}}`)
	ccTextStartFrame = ccFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
	ccTextDeltaFrame = ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`)
	ccTextStopFrame  = ccFrame("content_block_stop", `{"type":"content_block_stop","index":0}`)
	ccBashStartFrame = ccFrame("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}`)
	ccBashDeltaFrame = ccFrame("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls\"}"}}`)
	ccBashStopFrame  = ccFrame("content_block_stop", `{"type":"content_block_stop","index":1}`)
	ccCalcStartFrame = ccFrame("content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_2","name":"calculator","input":{}},"vendor_hint":{"keep":true}}`)
	ccCalcDeltaFrame = ccFrame("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"expr\":\"2+2\"}"}}`)
	ccCalcStopFrame  = ccFrame("content_block_stop", `{"type":"content_block_stop","index":2}`)
	ccDeltaFrame     = ccFrame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":2}}`)
	ccStopFrame      = ccFrame("message_stop", `{"type":"message_stop"}`)
)

// ccSSEBody posts a streaming native request and returns the client stream.
func ccSSEBody(t *testing.T, gw *gateway, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// TestMessagesNative_ToolPolicyAllDenied pins the stop repair: when every
// declared tool_use was denied, the "tool_use" stop_reason rewrites to
// "end_turn" so the client tool loop is never stranded, and the reply
// carries exactly the surviving (non-tool) content.
func TestMessagesNative_ToolPolicyAllDenied(t *testing.T) {
	const reply = `{"id":"msg_3","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"working"},{"type":"tool_use","id":"toolu_1","name":"bash","input":{"cmd":"ls"}}],"stop_reason":"tool_use","usage":{"input_tokens":3,"output_tokens":4}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "bash") {
		t.Fatalf("denied tool_use must not reach the client: %s", rec.Body.String())
	}
	blocks := ccNativeContentBlocks(t, rec.Body.String())
	if len(blocks) != 1 || blocks[0]["type"] != "text" {
		t.Fatalf("only the text block must survive: %s", rec.Body.String())
	}
	if reason := ccNativeStopReason(t, rec.Body.String()); reason != "end_turn" {
		t.Fatalf("an all-denied finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolPolicyArgsGuard pins the declared-args guard on
// the native surface: a calculator ALLOW row with an args deny_regex drops
// the call whose input matches — the args row activates the gate by
// itself (HasResponseGates: no deny row is required).
func TestMessagesNative_ToolPolicyArgsGuard(t *testing.T) {
	const reply = `{"id":"msg_4","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"tool_use","id":"toolu_9","name":"calculator","input":{"expr":"SECRET-TOKEN-123 + 1"}}],"stop_reason":"tool_use","usage":{"input_tokens":2,"output_tokens":2}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		sseArgsDenyRow("calculator", "SECRET-TOKEN"),
	}}, time.Minute)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "calculator") || strings.Contains(rec.Body.String(), "SECRET-TOKEN") {
		t.Fatalf("args-denied tool_use must not reach the client: %s", rec.Body.String())
	}
	if reason := ccNativeStopReason(t, rec.Body.String()); reason != "end_turn" {
		t.Fatalf("an all-denied finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolPolicyNoDenyByteIdentity pins the zero-cost
// posture: an unrelated deny row must not touch the reply at all.
func TestMessagesNative_ToolPolicyNoDenyByteIdentity(t *testing.T) {
	const reply = `{"id":"msg_5","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"tool_use","id":"toolu_1","name":"bash","input":{"cmd":"ls"}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("shell")}}, time.Minute)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != reply {
		t.Fatalf("an unrelated deny row must keep byte identity, got %s", rec.Body.String())
	}
}

// ---- shared enforcement assertions ----

// ccAssertNativeGated asserts one gated native JSON reply: status 200, the
// denied tool never appears, the surviving blocks and the tool_use finish
// are intact.
func ccAssertNativeGated(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("native status %d %s", rec.Code, rec.Body.String())
	}
	ccAssertNativeDeniedGone(t, rec.Body.String())
	ccAssertNativeSurvivors(t, rec.Body.String())
	if reason := ccNativeStopReason(t, rec.Body.String()); reason != "tool_use" {
		t.Fatalf("a surviving call keeps stop_reason tool_use, got %q", reason)
	}
}

// ccAssertNativeDeniedGone asserts the denied tool (bash/toolu_1) appears
// nowhere in a client-visible body.
func ccAssertNativeDeniedGone(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, "bash") || strings.Contains(body, "toolu_1") {
		t.Fatalf("denied tool_use must not reach the client: %s", body)
	}
}

// ccAssertNativeSurvivors asserts the surviving native content shape: the
// text block and the allowed calculator with its id and input.
func ccAssertNativeSurvivors(t *testing.T, body string) {
	t.Helper()
	blocks := ccNativeContentBlocks(t, body)
	if len(blocks) != 2 {
		t.Fatalf("content must keep the text and calculator blocks: %s", body)
	}
	if blocks[0]["type"] != "text" || blocks[0]["text"] != "working" {
		t.Fatalf("text block must survive intact: %v", blocks[0])
	}
	if blocks[1]["type"] != "tool_use" || blocks[1]["name"] != "calculator" || blocks[1]["id"] != "toolu_2" {
		t.Fatalf("allowed tool_use must survive intact: %v", blocks[1])
	}
	input, _ := blocks[1]["input"].(map[string]any)
	if input == nil || input["expr"] != "2+2" {
		t.Fatalf("allowed tool input must survive intact: %v", blocks[1]["input"])
	}
}

// ccAssertNativeLedger asserts the single messages ledger event: a
// request.completed on the messages endpoint billing the original usage
// exactly once.
func ccAssertNativeLedger(t *testing.T, ev *eventpub.Event, eventCount int, tokensIn, tokensOut int64) {
	t.Helper()
	if ev == nil || ev.EventType != "request.completed" || ev.Endpoint != "messages" {
		t.Fatalf("ledger terminal %+v", ev)
	}
	if ev.TokensIn != tokensIn || ev.TokensOut != tokensOut {
		t.Fatalf("ledger must bill the original usage, got in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
	if eventCount != 1 {
		t.Fatalf("exactly one messages event expected, got %d", eventCount)
	}
}

// ccAssertAdaptedGate asserts the translated-route contrast: the same
// engine strips the denied call and keeps the allowed one.
func ccAssertAdaptedGate(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("adapted status %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"bash"`) {
		t.Fatalf("denied tool_call must be stripped on the translated route: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"calculator"`) {
		t.Fatalf("allowed tool_call must survive the gate: %s", rec.Body.String())
	}
}

// ccAssertSSESingleFinish asserts the stream carries exactly one finish
// and one terminal frame.
func ccAssertSSESingleFinish(t *testing.T, frames []map[string]any) {
	t.Helper()
	if ccCountType(frames, "message_stop") != 1 {
		t.Fatalf("exactly one message_stop expected, got %d", ccCountType(frames, "message_stop"))
	}
	if ccCountType(frames, "message_delta") != 1 {
		t.Fatalf("exactly one message_delta expected, got %d", ccCountType(frames, "message_delta"))
	}
}

// ccAssertSSECalcAtIndex asserts the calculator block streams at the
// expected (shifted) content_block index.
func ccAssertSSECalcAtIndex(t *testing.T, frames []map[string]any, want float64) {
	t.Helper()
	if got := ccBlockByName(t, frames, "calculator")["index"]; got != want {
		t.Fatalf("calculator must shift to the contiguous index %v, got %v", want, got)
	}
}

// ccAssertSSEStopReason asserts the message_delta finish reason.
func ccAssertSSEStopReason(t *testing.T, frames []map[string]any, want string) {
	t.Helper()
	if reason := ccStopReasonFromDelta(t, frames); reason != want {
		t.Fatalf("stop_reason must be %q, got %q", want, reason)
	}
}

// TestMessagesNative_ToolPolicyEnforcedSSE pins the streaming enforcement:
// the denied bash block is suppressed whole (never one byte), the visible
// indices stay contiguous (calculator shifts 2→1), the message_delta keeps
// tool_use (a survivor), and the ledger bills the original usage once.
func TestMessagesNative_ToolPolicyEnforcedSSE(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame, ccTextStartFrame, ccTextDeltaFrame, ccTextStopFrame,
		ccBashStartFrame, ccBashDeltaFrame, ccBashStopFrame,
		ccCalcStartFrame, ccCalcDeltaFrame, ccCalcStopFrame,
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	terminal, events := ccCaptureNativeLedger(t)
	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)

	ccAssertNativeDeniedGone(t, body)
	frames := ccNativeFrames(t, body)
	ccAssertSSESingleFinish(t, frames)
	ccAssertSSECalcAtIndex(t, frames, 1)
	ccAssertSSEStopReason(t, frames, "tool_use")
	ccAssertNativeLedger(t, terminal(), events(), 5, 2)
}

// TestMessagesNative_ToolPolicySSEAllDenied pins the streaming stop
// repair: with every declared call denied, no tool frames reach the client
// and the message_delta stop_reason rewrites to end_turn.
func TestMessagesNative_ToolPolicySSEAllDenied(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame, ccTextStartFrame, ccTextDeltaFrame, ccTextStopFrame,
		ccBashStartFrame, ccBashDeltaFrame, ccBashStopFrame,
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "bash") || strings.Contains(body, "toolu_1") || strings.Contains(body, "input_json_delta") {
		t.Fatalf("denied tool_use frames must not reach the stream:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	ccAssertSSESingleFinish(t, frames)
	if reason := ccStopReasonFromDelta(t, frames); reason != "end_turn" {
		t.Fatalf("an all-denied finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolPolicySSEArgsGuard pins the streaming args guard:
// the calculator's accumulated input runs through GuardDeclaredArgs at its
// content_block_stop and the denied call drops before the client ever saw
// a fragment. The args ALLOW row activates the gate by itself
// (HasResponseGates: no deny row is required).
func TestMessagesNative_ToolPolicySSEArgsGuard(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame,
		ccFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_9","name":"calculator","input":{}}}`),
		ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"expr\":\"SECRET-TOKEN-123\"}"}}`),
		ccFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		sseArgsDenyRow("calculator", "SECRET-TOKEN"),
	}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "calculator") || strings.Contains(body, "SECRET-TOKEN") || strings.Contains(body, "input_json_delta") {
		t.Fatalf("args-denied tool_use must not reach the stream:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	ccAssertSSESingleFinish(t, frames)
	if reason := ccStopReasonFromDelta(t, frames); reason != "end_turn" {
		t.Fatalf("an all-denied finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolPolicySSENoDenyByteIdentity pins the passthrough
// posture: with an active engine whose rows never match the stream, every
// byte reaches the client unchanged.
func TestMessagesNative_ToolPolicySSENoDenyByteIdentity(t *testing.T) {
	frames := []string{
		ccMsgStartFrame, ccTextStartFrame, ccTextDeltaFrame, ccTextStopFrame,
		ccBashStartFrame, ccBashDeltaFrame, ccBashStopFrame,
		ccCalcStartFrame, ccCalcDeltaFrame, ccCalcStopFrame,
		ccDeltaFrame, ccStopFrame,
	}
	server := ccNativeSSEUpstream(t, frames)
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("shell")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if want := strings.Join(frames, ""); body != want {
		t.Fatalf("an unrelated deny row must keep byte identity\ngot:\n%s\nwant:\n%s", body, want)
	}
}

// TestMessagesNative_ToolPolicySSEMalformedMidRun pins the fail-closed
// malformed contract: a frame that does not parse inside an open tool_use
// run DISCARDS the run (never releases unchecked, never converts into an
// allowed call), while a later allowed block still streams with its index
// shifted to the contiguous position.
func TestMessagesNative_ToolPolicySSEMalformedMidRun(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame, ccTextStartFrame, ccTextDeltaFrame, ccTextStopFrame,
		ccBashStartFrame, ccBashDeltaFrame,
		ccFrame("content_block_stop", `{broken`),
		ccCalcStartFrame, ccCalcDeltaFrame,
		ccFrame("content_block_stop", `{"type":"content_block_stop","index":2}`),
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "bash") || strings.Contains(body, "toolu_1") {
		t.Fatalf("a discarded run must release nothing:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	calc := ccBlockByName(t, frames, "calculator")
	if calc["index"] != float64(1) {
		t.Fatalf("the post-discard calculator must shift to the contiguous index 1, got %v", calc["index"])
	}
	if reason := ccStopReasonFromDelta(t, frames); reason != "tool_use" {
		t.Fatalf("the surviving calculator keeps tool_use, got %q", reason)
	}
	ccAssertSSESingleFinish(t, frames)
}

// TestMessagesNative_ToolPolicySSETruncatedMidRun pins the truncation
// contract: an upstream cut inside an open tool_use run discards the run
// fail-closed (no partial arguments ever stream), the relay still closes
// the client stream with its single synthesized terminal, and the ledger
// bills the partial usage exactly once (native D1 cut canon).
func TestMessagesNative_ToolPolicySSETruncatedMidRun(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame, ccBashStartFrame, ccBashDeltaFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	terminal, events := ccCaptureNativeLedger(t)
	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "bash") || strings.Contains(body, "toolu_1") || strings.Contains(body, `"cmd"`) {
		t.Fatalf("a truncated run must release nothing:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	if n := ccCountType(frames, "message_stop") + ccCountType(frames, "error"); n != 1 {
		t.Fatalf("exactly one synthesized terminal expected, got %d:\n%s", n, body)
	}
	ev := terminal()
	if ev == nil || ev.EventType != "request.completed" {
		t.Fatalf("a cut bills per the D1 canon, got %+v", ev)
	}
	if ev.TokensIn != 5 {
		t.Fatalf("partial usage in=%d", ev.TokensIn)
	}
	if events() != 1 {
		t.Fatalf("exactly one messages event expected, got %d", events())
	}
}

// TestMessagesNative_ToolPolicySSEUnknownEvent pins the unknown-compatible
// contract: an unrecognized event type carrying a content_block index is
// renumbered with the same shift (no stale indices after a removal), and
// unknown members on a content_block_start do not bypass the decision —
// the denied bash stays dropped, the calculator streams at its shifted
// index.
func TestMessagesNative_ToolPolicySSEUnknownEvent(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame,
		ccBashStartFrame, ccBashDeltaFrame, ccBashStopFrame,
		ccFrame("vendor_ping", `{"type":"vendor_ping","index":2,"note":"x"}`),
		ccCalcStartFrame, ccCalcDeltaFrame, ccCalcStopFrame,
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "bash") || strings.Contains(body, "toolu_1") {
		t.Fatalf("denied tool_use must not reach the stream:\n%s", body)
	}
	if !strings.Contains(body, `"index":1,"note":"x"`) && !strings.Contains(body, `{"type":"vendor_ping","index":1`) {
		t.Fatalf("the unknown event's index must shift with the removals:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	if ccBlockByName(t, frames, "calculator")["index"] != float64(1) {
		t.Fatalf("calculator must shift to the contiguous index 1:\n%s", body)
	}
	ccAssertSSESingleFinish(t, frames)
}

// orgLoader is a policy loader keyed by org (memLoader ignores the org), so
// controls can prove the engine keys its decisions on the request's org.
type orgLoader struct {
	byOrg map[string][]toolpolicy.Policy
}

func (m *orgLoader) ListEnabled(_ context.Context, org string) ([]toolpolicy.Policy, error) {
	return m.byOrg[org], nil
}

// TestMessagesNative_ToolPolicyOrgIsolated pins the tenant boundary: a deny
// row scoped to org-1 gates org-1's native replies and leaves org-2's
// untouched, on one shared engine.
func TestMessagesNative_ToolPolicyOrgIsolated(t *testing.T) {
	const reply = `{"id":"msg_6","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"tool_use","id":"toolu_1","name":"bash","input":{"cmd":"ls"}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&orgLoader{byOrg: map[string][]toolpolicy.Policy{
		"org-1": {denyTool("bash")},
	}}, time.Minute)

	const body = `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`
	scoped := postMessagesForOrg(t, gw, body, "org-1")
	if scoped.Code != http.StatusOK || strings.Contains(scoped.Body.String(), "bash") {
		t.Fatalf("org-1 must be gated: %d %s", scoped.Code, scoped.Body.String())
	}
	other := postMessagesForOrg(t, gw, body, "org-2")
	if other.Code != http.StatusOK {
		t.Fatalf("org-2 status %d %s", other.Code, other.Body.String())
	}
	blocks := ccNativeContentBlocks(t, other.Body.String())
	if len(blocks) != 1 || blocks[0]["name"] != "bash" {
		t.Fatalf("org-2 has no policy rows and must see the reply untouched: %s", other.Body.String())
	}
	again := postMessagesForOrg(t, gw, body, "org-1")
	if again.Code != http.StatusOK || strings.Contains(again.Body.String(), "bash") {
		t.Fatalf("org-1 must stay gated after the org-2 request: %d %s", again.Code, again.Body.String())
	}
}

// ---- review regressions (CP-C02-02 rework) ----

// ccRawSSEUpstream serves raw byte chunks verbatim (frame shapes, terminal
// styles and cut positions are under the test's control), flushing each.
func ccRawSSEUpstream(t *testing.T, chunks []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for _, chunk := range chunks {
			_, _ = io.WriteString(w, chunk)
			flusher.Flush()
		}
	}))
}

// ccReadGateUntil drains the gate reader until want appears in the output.
func ccReadGateUntil(t *testing.T, g io.Reader, want string) string {
	t.Helper()
	var acc []byte
	buf := make([]byte, 4096)
	for !strings.Contains(string(acc), want) {
		n, err := g.Read(buf)
		acc = append(acc, buf[:n]...)
		if err != nil {
			t.Fatalf("gate ended before %q: %v\noutput so far:\n%s", want, err, acc)
		}
	}
	return string(acc)
}

// ccMutLoader is an org loader whose rows a test swaps mid-stream.
type ccMutLoader struct {
	mu  sync.Mutex
	pos []toolpolicy.Policy
}

func (l *ccMutLoader) ListEnabled(context.Context, string) ([]toolpolicy.Policy, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pos, nil
}

func (l *ccMutLoader) set(policies []toolpolicy.Policy) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pos = policies
}

// ccChanReader hands one chunk per Read: the test drives the upstream byte
// stream deterministically (write → drain → mutate → write).
type ccChanReader chan []byte

func (r ccChanReader) Read(p []byte) (int, error) {
	chunk, ok := <-r
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, chunk)
	if n < len(chunk) {
		rest := chunk[n:]
		go func() { r <- rest }()
	}
	return n, nil
}

// TestMessagesNative_ToolPolicySSEDataOnlyFrames pins the decode-parity
// regression: frames that carry NO event line (data-only, the payload's
// type member names the event) route exactly like event-line frames —
// the denied bash is suppressed whole and the calculator shifts forward.
func TestMessagesNative_ToolPolicySSEDataOnlyFrames(t *testing.T) {
	chunks := []string{
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n",
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n",
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}\n\n",
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"calculator\",\"input\":{}}}\n\n",
		"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"expr\\\":\\\"2+2\\\"}\"}}\n\n",
		"data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":2}}\n\n",
		"data: {\"type\":\"message_stop\"}\n\n",
	}
	server := ccRawSSEUpstream(t, chunks)
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	ccAssertNativeDeniedGone(t, body)
	if strings.Contains(body, `\"cmd\":"`) || strings.Contains(body, `\"cmd\"`) {
		t.Fatalf("denied run deltas must not reach the stream:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	ccAssertSSESingleFinish(t, frames)
	ccAssertSSECalcAtIndex(t, frames, 0)
	ccAssertSSEStopReason(t, frames, "tool_use")
}

// TestMessagesNative_ToolPolicySSECRTerminators pins the terminator
// parity: a CR-only upstream (lone-CR line and frame terminators, no LF
// anywhere) decodes like an LF one — the denial holds, the survivor's
// index shifts, and the forwarded frames keep the CR byte style.
func TestMessagesNative_ToolPolicySSECRTerminators(t *testing.T) {
	ccCR := func(event, data string) string {
		return "event: " + event + "\rdata: " + data + "\r\r"
	}
	chunks := []string{strings.Join([]string{
		ccCR("message_start", `{"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":0}}}`),
		ccCR("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}`),
		ccCR("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls\"}"}}`),
		ccCR("content_block_stop", `{"type":"content_block_stop","index":1}`),
		ccCR("content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_2","name":"calculator","input":{}}}`),
		ccCR("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"expr\":\"2+2\"}"}}`),
		ccCR("content_block_stop", `{"type":"content_block_stop","index":2}`),
		ccCR("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":2}}`),
		ccCR("message_stop", `{"type":"message_stop"}`),
	}, "")}
	server := ccRawSSEUpstream(t, chunks)
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "bash") || strings.Contains(body, "toolu_1") || strings.Contains(body, `"cmd"`) {
		t.Fatalf("denied tool_use must not reach the CR stream:\n%s", body)
	}
	if !strings.Contains(body, `"name":"calculator"`) || !strings.Contains(body, `\"expr\":\"2+2\"`) {
		t.Fatalf("the allowed tool must survive the CR stream:\n%s", body)
	}
	if !strings.Contains(body, `"index":1`) {
		t.Fatalf("the calculator must shift to the contiguous index 1:\n%s", body)
	}
	if !strings.Contains(body, `"stop_reason":"tool_use"`) {
		t.Fatalf("a survivor keeps tool_use:\n%s", body)
	}
	if !strings.Contains(body, "\r") || strings.Contains(body, "\n") {
		t.Fatalf("forwarded frames must keep the lone-CR byte style (no LF anywhere):\n%s", body)
	}
}

// TestMessagesNative_ToolPolicySSESalvageTail pins the tail parity: an
// upstream cut that lands exactly after a denied start frame's data line
// (complete event, missing only its separator) routes through the gate
// like the relay's own salvage would — the denied run delivers nothing
// and the relay closes with its single synthesized terminal.
func TestMessagesNative_ToolPolicySSESalvageTail(t *testing.T) {
	server := ccRawSSEUpstream(t, []string{
		ccMsgStartFrame,
		`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}` + "\n",
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	terminal, events := ccCaptureNativeLedger(t)
	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "bash") || strings.Contains(body, "toolu_1") {
		t.Fatalf("a salvaged denied frame must deliver nothing:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	if n := ccCountType(frames, "message_stop") + ccCountType(frames, "error"); n != 1 {
		t.Fatalf("exactly one synthesized terminal expected, got %d:\n%s", n, body)
	}
	ev := terminal()
	if ev == nil || ev.EventType != "request.completed" || ev.TokensIn != 5 {
		t.Fatalf("the cut bills the partial usage once, got %+v", ev)
	}
	if events() != 1 {
		t.Fatalf("exactly one messages event expected, got %d", events())
	}
}

// TestMessagesNative_ToolGateReaderCancelTailFailOpen pins D-15 at the
// tail: an idle-watchdog or client-side cancellation mid-hold releases
// the held ALLOWED run through the shifted path — the surface fails open
// (the chat SSE gate's canon) without exposing a raw wire index when an
// earlier block was already removed.
func TestMessagesNative_ToolGateReaderCancelTailFailOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)
	src := make(ccChanReader, 4)
	g := newNativeToolGateReader(ctx, src, engine, "org-1", "*")

	src <- []byte(ccMsgStartFrame)
	src <- []byte(ccBashStartFrame)                   // denied at declaration: shift 1
	src <- []byte(ccCalcStartFrame)                   // allowed: held
	src <- []byte(ccFrame("ping", `{"type":"ping"}`)) // observable: every earlier frame is settled
	first := ccReadGateUntil(t, g, `"type":"ping"`)
	if strings.Contains(first, "bash") || strings.Contains(first, "toolu_1") {
		t.Fatalf("the denied run must deliver nothing:\n%s", first)
	}

	cancel() // the idle-watchdog path: the client is still attached
	close(src)
	out, err := io.ReadAll(g)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(out), "calculator") {
		t.Fatalf("a cancelled context must release the held allowed run:\n%s", out)
	}
	if strings.Contains(string(out), `"index":2`) {
		t.Fatalf("a release after a removal must map the held run's index (raw 2 -> visible 1):\n%s", out)
	}
	if !strings.Contains(string(out), `"index":1`) {
		t.Fatalf("the released start must carry the mapped visible index:\n%s", out)
	}
}

// TestMessagesNative_ToolGateReaderMismatchDeltaSwallowed pins the
// violating-frame rule: a delta aimed at the held run's own index whose
// type the run does not accept is the frame that CAUSES the fail-closed
// discard — its own content must swallow with the run, never surface
// headless under an index another block will own.
func TestMessagesNative_ToolGateReaderMismatchDeltaSwallowed(t *testing.T) {
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		sseArgsDenyRow("calculator", "NEVER-MATCHES-QQ7"),
	}}, time.Minute)
	violation := ccFrame("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"VIOLFRAME-MARKER"}}`)
	g := newNativeToolGateReader(context.Background(), strings.NewReader(
		ccMsgStartFrame+ccCalcStartFrame+violation+
			ccFrame("content_block_stop", `{"type":"content_block_stop","index":2}`)+
			ccDeltaFrame+ccStopFrame), engine, "org-1", "*")
	out, err := io.ReadAll(g)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(out), "VIOLFRAME-MARKER") {
		t.Fatalf("the frame that caused the discard must not surface:\n%s", out)
	}
	if strings.Contains(string(out), "calculator") || strings.Contains(string(out), "input_json_delta") {
		t.Fatalf("the discarded run must release nothing:\n%s", out)
	}
	if !strings.Contains(string(out), `"stop_reason":"end_turn"`) {
		t.Fatalf("a fail-closed discard must strand no tool loop (end_turn rewrite):\n%s", out)
	}
}

// TestMessagesNative_ToolGateReaderCommentParity pins keepalive comment
// parity with the relay: ':' lines ride no event and forward immediately
// — byte-identically around a resolved run, and alive even when a
// trailing comment is all that follows an unresolved (discarded) run.
func TestMessagesNative_ToolGateReaderCommentParity(t *testing.T) {
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	t.Run("byte identity", func(t *testing.T) {
		input := ": opening\n\n" + ccMsgStartFrame + ccCalcStartFrame + ccCalcDeltaFrame + ccCalcStopFrame + ": done\n"
		g := newNativeToolGateReader(context.Background(), strings.NewReader(input), engine, "org-1", "*")
		out, err := io.ReadAll(g)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(out) != input {
			t.Fatalf("comments must forward immediately and byte-identically\ngot:\n%q\nwant:\n%q", out, input)
		}
	})

	t.Run("trailing comment survives unresolved run", func(t *testing.T) {
		input := ccMsgStartFrame + ccCalcStartFrame + ": done\n"
		g := newNativeToolGateReader(context.Background(), strings.NewReader(input), engine, "org-1", "*")
		out, err := io.ReadAll(g)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !strings.Contains(string(out), ": done") {
			t.Fatalf("a trailing comment must not die in the frame buffer:\n%q", out)
		}
		if strings.Contains(string(out), "calculator") {
			t.Fatalf("the unresolved run still discards fail-closed:\n%s", out)
		}
	})
}

// TestMessagesNative_ToolPolicySSEPingMidRun pins the ping contract: a
// ping inside an open allowed run is a keepalive, not a protocol event —
// the hold survives and the run still resolves at its stop with its
// accumulated input intact.
func TestMessagesNative_ToolPolicySSEPingMidRun(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame,
		ccFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_2","name":"calculator","input":{}}}`),
		ccFrame("ping", `{"type":"ping"}`),
		ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"expr\":\"2+2\"}"}}`),
		ccFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("shell")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	frames := ccNativeFrames(t, body)
	calc := ccBlockByName(t, frames, "calculator")
	input, _ := calc["content_block"].(map[string]any)
	if input == nil {
		t.Fatalf("the held run must survive the ping:\n%s", body)
	}
	if !strings.Contains(body, `\"expr\":\"2+2\"`) {
		t.Fatalf("the ping must not orphan the hold: the guarded input must release:\n%s", body)
	}
	ccAssertSSEStopReason(t, frames, "tool_use")
	ccAssertSSESingleFinish(t, frames)
}

// TestMessagesNative_ToolPolicySSEPingMidDeny pins the quarantine: a ping
// between a decided denial's delta and its stop cannot bypass the denial —
// the run's remaining frames stay swallowed and the finish repairs.
func TestMessagesNative_ToolPolicySSEPingMidDeny(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame,
		ccBashStartFrame,
		ccFrame("ping", `{"type":"ping"}`),
		ccBashDeltaFrame, ccBashStopFrame,
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "bash") || strings.Contains(body, "toolu_1") || strings.Contains(body, `"cmd"`) || strings.Contains(body, "input_json_delta") {
		t.Fatalf("a mid-deny ping must not bypass the denial:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	ccAssertSSESingleFinish(t, frames)
	if reason := ccStopReasonFromDelta(t, frames); reason != "end_turn" {
		t.Fatalf("an all-denied finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolPolicySSEStartInputGuard pins the start-frame
// args guard: a tool_use declared with a complete input member and NO
// deltas faces GuardDeclaredArgs at the declaration itself — the payload
// rides the start frame, so guarding only the delta accumulation would
// release it unchecked.
func TestMessagesNative_ToolPolicySSEStartInputGuard(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame,
		ccFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_9","name":"calculator","input":{"expr":"SECRET-TOKEN-9"}}}`),
		ccFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		sseArgsDenyRow("calculator", "SECRET-TOKEN"),
	}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "calculator") || strings.Contains(body, "SECRET-TOKEN") || strings.Contains(body, "input_json_delta") {
		t.Fatalf("a guarded start input must drop the run:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	ccAssertSSESingleFinish(t, frames)
	if reason := ccStopReasonFromDelta(t, frames); reason != "end_turn" {
		t.Fatalf("an all-denied finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolGateReaderRecheckPerDeclaration pins live
// activation: the gate re-queries the org's response gates on EVERY
// tool_use declaration, so a policy that lands mid-stream (admin CRUD →
// Invalidate) gates the second declaration without a new request.
func TestMessagesNative_ToolGateReaderRecheckPerDeclaration(t *testing.T) {
	loader := &ccMutLoader{}
	engine := toolpolicy.NewEngine(loader, time.Minute)
	src := make(ccChanReader, 4)
	g := newNativeToolGateReader(context.Background(), src, engine, "org-1", "*")

	src <- []byte(ccBashStartFrame)
	first := ccReadGateUntil(t, g, "bash") // no gates: verbatim

	loader.set([]toolpolicy.Policy{denyTool("bash")})
	engine.Invalidate("org-1")

	src <- []byte(ccBashStopFrame) // close the first (allowed) run cleanly
	src <- []byte(ccBashStartFrame)
	src <- []byte(ccDeltaFrame) // the finish must see the delivered first call
	src <- []byte(ccStopFrame)
	out := ccReadGateUntil(t, g, "message_stop")

	if !strings.Contains(first, "bash") {
		t.Fatalf("the ungated declaration must pass verbatim:\n%s", first)
	}
	if strings.Count(out, "bash") != 0 {
		t.Fatalf("the second declaration must gate under the new policy:\nfirst:\n%s\nrest:\n%s", first, out)
	}
	if !strings.Contains(out, "message_stop") {
		t.Fatalf("the stream must close normally:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"tool_use"`) || strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Fatalf("the pre-activation delivered call must keep the tool loop alive:\n%s", out)
	}
}

// TestMessagesNative_ToolPolicyJSONNamelessStopRepair pins the JSON stop
// repair for dropped nameless declarations: a nameless tool_use fails
// closed and drops, and with nothing left alive the "tool_use" finish
// rewrites to end_turn even though no NAMED denial was counted.
func TestMessagesNative_ToolPolicyJSONNamelessStopRepair(t *testing.T) {
	const reply = `{"id":"msg_7","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"tool_use","id":"toolu_x"}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("shell")}}, time.Minute)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "toolu_x") {
		t.Fatalf("a nameless tool_use must drop:\n%s", rec.Body.String())
	}
	if blocks := ccNativeContentBlocks(t, rec.Body.String()); len(blocks) != 0 {
		t.Fatalf("nothing survives a lone nameless block: %s", rec.Body.String())
	}
	if reason := ccNativeStopReason(t, rec.Body.String()); reason != "end_turn" {
		t.Fatalf("a dropped-declaration finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolPolicySSENamelessStopRepair pins the SSE twin:
// a nameless tool_use run is denied at its declaration (nothing streams)
// and the message_delta stop_reason rewrites to end_turn.
func TestMessagesNative_ToolPolicySSENamelessStopRepair(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame,
		ccFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_x"}}`),
		ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"k\":1}"}}`),
		ccFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("shell")}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if strings.Contains(body, "toolu_x") || strings.Contains(body, "input_json_delta") {
		t.Fatalf("a nameless run must deliver nothing:\n%s", body)
	}
	frames := ccNativeFrames(t, body)
	ccAssertSSESingleFinish(t, frames)
	if reason := ccStopReasonFromDelta(t, frames); reason != "end_turn" {
		t.Fatalf("a dropped-declaration finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolGateReaderHoldCaps pins the bounded hold: an
// allowed run whose delta accumulation crosses the frame-count or total
// bytes cap discards fail-closed — nothing of the run releases and the
// gateway never buffers it without limit.
// ccHoldCapRun streams a capped-run body through a fresh gate and pins
// the fail-closed contract every bounded-hold cap shares: nothing of the
// held run may release and the finish must rewrite to end_turn (a cap
// discard is a removal).
func ccHoldCapRun(t *testing.T, engine *toolpolicy.Engine, body string) {
	t.Helper()
	g := newNativeToolGateReader(context.Background(), strings.NewReader(body), engine, "org-1", "*")
	out, err := io.ReadAll(g)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(out), "calculator") || strings.Contains(string(out), "input_json_delta") {
		t.Fatalf("a run over a bounded-hold cap must release nothing:\n%s", out)
	}
	if !strings.Contains(string(out), `"stop_reason":"end_turn"`) {
		t.Fatalf("a cap discard must count as a removal and rewrite the finish:\n%s", out)
	}
}

func TestMessagesNative_ToolGateReaderHoldCaps(t *testing.T) {
	ccCalcDelta := func(partial string) string {
		return ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"`+partial+`"}}`)
	}
	ccStream := func(deltas []string) string {
		frames := []string{
			ccMsgStartFrame,
			ccFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_2","name":"calculator","input":{}}}`),
		}
		frames = append(frames, deltas...)
		frames = append(frames,
			ccFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
			ccDeltaFrame, ccStopFrame,
		)
		return strings.Join(frames, "")
	}
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("shell")}}, time.Minute)

	t.Run("frame count cap", func(t *testing.T) {
		deltas := make([]string, 0, 4096)
		for i := 0; i < 4096; i++ {
			deltas = append(deltas, ccCalcDelta(`{\"n\":`+strconv.Itoa(i)+`}`))
		}
		ccHoldCapRun(t, engine, ccStream(deltas))
	})

	t.Run("args bytes cap", func(t *testing.T) {
		big := strings.Repeat("a", 5<<20) // two of these cross the 8 MiB args cap
		ccHoldCapRun(t, engine, ccStream([]string{ccCalcDelta(big), ccCalcDelta(big)}))
	})

	t.Run("frame bytes cap", func(t *testing.T) {
		// ~100 KiB of padding per delta with ~10-byte args fragments:
		// the buffered frame bytes alone cross the 16 MiB frames cap
		// while total args stay far under the 8 MiB args cap and the
		// frame count under its own cap — only the frames dimension
		// trips.
		pad := strings.Repeat("p", 100<<10)
		deltas := make([]string, 0, 200)
		for i := 0; i < 200; i++ {
			deltas = append(deltas, ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"z":"`+pad+`","delta":{"type":"input_json_delta","partial_json":"{\"n\":`+strconv.Itoa(i)+`}"}}`))
		}
		ccHoldCapRun(t, engine, ccStream(deltas))
	})
}

// TestMessagesNative_ToolPolicySSERewritePreservesEnvelope pins the
// surgical rewrite: a shifted or repaired frame keeps its envelope record
// lines (id:, retry:) byte-verbatim and its unknown members' number
// precision exact — a map[string]any round-trip would corrupt
// 9007199254740993 into 9007199254740992.
func TestMessagesNative_ToolPolicySSERewritePreservesEnvelope(t *testing.T) {
	t.Run("shift rewrite", func(t *testing.T) {
		server := ccNativeSSEUpstream(t, []string{
			ccMsgStartFrame,
			ccBashStartFrame, ccBashDeltaFrame, ccBashStopFrame,
			"id: evt_2\nretry: 100\n" + ccFrame("content_block_start", `{"type":"content_block_start","index":2,"big":9007199254740993,"content_block":{"type":"tool_use","id":"toolu_2","name":"calculator","input":{}}}`),
			ccCalcDeltaFrame,
			ccFrame("content_block_stop", `{"type":"content_block_stop","index":2}`),
			ccDeltaFrame, ccStopFrame,
		})
		defer server.Close()

		gw := nativeMessagesGateway(t, server.URL)
		gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

		body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
		for _, want := range []string{"9007199254740993", `"index":1`, "id: evt_2", "retry: 100", `\"expr\":\"2+2\"`} {
			if !strings.Contains(body, want) {
				t.Fatalf("the shifted frame must keep %s verbatim:\n%s", want, body)
			}
		}
		if strings.Contains(body, "9007199254740992") {
			t.Fatalf("the rewrite must not lose integer precision:\n%s", body)
		}
		ccAssertSSEStopReason(t, ccNativeFrames(t, body), "tool_use")
	})

	t.Run("stop rewrite", func(t *testing.T) {
		server := ccNativeSSEUpstream(t, []string{
			ccMsgStartFrame,
			ccBashStartFrame, ccBashDeltaFrame, ccBashStopFrame,
			"id: evt_9\nretry: 5\n" + ccFrame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9007199254740993}}`),
			ccStopFrame,
		})
		defer server.Close()

		gw := nativeMessagesGateway(t, server.URL)
		gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("bash")}}, time.Minute)

		body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
		for _, want := range []string{"9007199254740993", `"stop_reason":"end_turn"`, "id: evt_9", "retry: 5"} {
			if !strings.Contains(body, want) {
				t.Fatalf("the repaired finish must keep %s verbatim:\n%s", want, body)
			}
		}
		if strings.Contains(body, "9007199254740992") {
			t.Fatalf("the rewrite must not lose integer precision:\n%s", body)
		}
	})
}

// TestMessagesNative_ToolPolicySSEArgsFragmentOracle pins the fragment
// oracle: the deny_regex runs over the CONCATENATION of partial_json
// deltas, so a secret split across fragments (invisible to any single
// frame) still denies the run.
func TestMessagesNative_ToolPolicySSEArgsFragmentOracle(t *testing.T) {
	server := ccNativeSSEUpstream(t, []string{
		ccMsgStartFrame,
		ccFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_9","name":"calculator","input":{}}}`),
		ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"expr\":\"SUPERSE"}}`),
		ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"CRET"}}`),
		ccFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"FRAG + 1\"}"}}`),
		ccFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
		ccDeltaFrame, ccStopFrame,
	})
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		sseArgsDenyRow("calculator", "SUPERSECRETFRAG"),
	}}, time.Minute)

	body := ccSSEBody(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	for _, marker := range []string{"SUPERSE", "CRET", "FRAG + 1", "calculator", "input_json_delta"} {
		if strings.Contains(body, marker) {
			t.Fatalf("the fragment-denied run must not reach the stream (%q found):\n%s", marker, body)
		}
	}
	frames := ccNativeFrames(t, body)
	ccAssertSSESingleFinish(t, frames)
	if reason := ccStopReasonFromDelta(t, frames); reason != "end_turn" {
		t.Fatalf("an all-denied finish must rewrite to end_turn, got %q", reason)
	}
}

// TestMessagesNative_ToolGateReaderSubjectAddressing pins the subject
// boundary on the stream gate: one engine, one org — the deny row scoped
// to subject "agent-a" gates that agent's run while another agent's
// identical run survives untouched.
func TestMessagesNative_ToolGateReaderSubjectAddressing(t *testing.T) {
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{{
		OrgID: "org-1", Name: "deny-bash-agent-a", Subject: "agent-a", Tool: "bash", Action: toolpolicy.ActionDeny, Enabled: true,
	}}}, time.Minute)

	scoped := newNativeToolGateReader(context.Background(),
		strings.NewReader(ccBashStartFrame+ccBashStopFrame), engine, "org-1", "agent-a")
	out, err := io.ReadAll(scoped)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(out), "bash") || strings.Contains(string(out), "toolu_1") {
		t.Fatalf("agent-a's deny row must drop the run:\n%s", out)
	}

	other := newNativeToolGateReader(context.Background(),
		strings.NewReader(ccBashStartFrame+ccBashStopFrame), engine, "org-1", "agent-b")
	out, err = io.ReadAll(other)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(out), "bash") || !strings.Contains(string(out), "toolu_1") {
		t.Fatalf("agent-b has no matching row and must see the run verbatim:\n%s", out)
	}
}
