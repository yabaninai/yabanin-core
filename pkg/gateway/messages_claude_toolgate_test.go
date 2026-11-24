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
	"strings"
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
// the native surface: a calculator allow row with an args deny_regex drops
// the call whose input matches (the org also carries a deny row so the
// gate activates — deny rows drive activation on every surface).
func TestMessagesNative_ToolPolicyArgsGuard(t *testing.T) {
	const reply = `{"id":"msg_4","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"tool_use","id":"toolu_9","name":"calculator","input":{"expr":"SECRET-TOKEN-123 + 1"}}],"stop_reason":"tool_use","usage":{"input_tokens":2,"output_tokens":2}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		denyTool("shell"),
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
// a fragment.
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
		denyTool("shell"),
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
