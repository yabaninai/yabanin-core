package cli

// Claude Code-shaped multi-step task loop through the real /v1/messages
// boundary. Mockup distinction (card requires it explicit): the provider
// upstream is a local httptest fixture and the tool executor is a
// hermetic map — the real Claude Code binary is not exercised; every byte
// the CLIENT speaks and parses here is the real Anthropic SSE contract,
// while the provider side is explicitly mock. A recorded real-binary run
// would replace the fixture without changing the loop.
//
// Loop = what the real client does per task step: stream the round, collect
// text / tool_use blocks, execute the tools, append the assistant turn plus
// tool_result, repeat until end_turn. Each round is a separate billed
// request.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

type ccBlock struct {
	Index   int
	Type    string
	Text    string
	ToolID  string
	Tool    string
	Input   map[string]any
	jsonBuf strings.Builder
}

// ccParseRound parses one client-side SSE round the way the real client
// does: text deltas accumulate, tool_use input accumulates from
// input_json_delta fragments and is parsed at content_block_stop, the
// terminal stop_reason and any in-band error are captured.
func ccParseRound(t *testing.T, body string) (blocks []*ccBlock, stop string) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m); err != nil {
			continue
		}
		switch m["type"] {
		case "content_block_start":
			idx := int(m["index"].(float64))
			cb := m["content_block"].(map[string]any)
			for len(blocks) <= idx {
				blocks = append(blocks, &ccBlock{})
			}
			blocks[idx].Index = idx
			blocks[idx].Type = cb["type"].(string)
			blocks[idx].ToolID, _ = cb["id"].(string)
			blocks[idx].Tool, _ = cb["name"].(string)
		case "content_block_delta":
			idx := int(m["index"].(float64))
			d := m["delta"].(map[string]any)
			switch d["type"] {
			case "text_delta":
				blocks[idx].Text += d["text"].(string)
			case "input_json_delta":
				blocks[idx].jsonBuf.WriteString(d["partial_json"].(string))
			}
		case "content_block_stop":
			idx := int(m["index"].(float64))
			if blocks[idx].Type == "tool_use" {
				if err := json.Unmarshal([]byte(blocks[idx].jsonBuf.String()), &blocks[idx].Input); err != nil {
					t.Fatalf("tool_use input did not parse at content_block_stop: %v (%q)", err, blocks[idx].jsonBuf.String())
				}
			}
		case "message_delta":
			d := m["delta"].(map[string]any)
			if sr, ok := d["stop_reason"].(string); ok {
				stop = sr
			}
		case "error":
			t.Fatalf("client stream carried an in-band error event: %v", m)
		}
	}
	return blocks, stop
}

// ccMockExec is the hermetic tool executor (the mock half of the mockup
// distinction): no real process execution, just a fixed cmd map.
func ccMockExec(t *testing.T, cmd string) string {
	t.Helper()
	switch cmd {
	case "echo hello":
		return "hello"
	case "cat report.txt":
		return "42"
	default:
		t.Fatalf("mock executor has no fixture for cmd %q", cmd)
		return ""
	}
}

const (
	// Native upstream rounds: Anthropic SSE with one tool_use per tool
	// round, then the final text round.
	ccNativeRound1 = `event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":7,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\": \"echo hello\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":5}}

event: message_stop
data: {"type":"message_stop"}
`
	ccNativeRound2 = `event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":7,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_2","name":"bash","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\": \"cat report.txt\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":6}}

event: message_stop
data: {"type":"message_stop"}
`
	ccNativeRound3 = `event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":7,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Task done: hello 42"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9}}

event: message_stop
data: {"type":"message_stop"}
`
	// Adapted upstream rounds: the same task spoken in OpenAI chat shape.
	ccAdaptedRound1 = `data: {"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":""}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"cmd\": \"echo hello\"}"}}]}}]}

data: {"choices":[{"index":0,"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":5,"total_tokens":12}}

data: [DONE]
`
	ccAdaptedRound2 = `data: {"model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_2","type":"function","function":{"name":"bash","arguments":""}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"cmd\": \"cat report.txt\"}"}}]}}]}

data: {"choices":[{"index":0,"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":6,"total_tokens":13}}

data: [DONE]
`
	ccAdaptedRound3 = `data: {"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"Task done: hello 42"}}]}

data: {"choices":[{"index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":9,"total_tokens":16}}

data: [DONE]
`
)

// ccUpstream records request bodies and serves the round fixture matching
// how many tool_result blocks the client has appended so far.
type ccUpstream struct {
	mu     sync.Mutex
	bodies []string
}

func (u *ccUpstream) bodiesSnapshot() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.bodies...)
}

// TestClaudeCodeLoopNativeMultiStepTaskMockUpstream: two tool round-trips
// then the final answer, native branch. The client loop speaks only the
// real Anthropic SSE contract; the provider side is the explicitly mock
// fixture (see the file header for the mockup distinction).
func TestClaudeCodeLoopNativeMultiStepTaskMockUpstream(t *testing.T) {
	up := &ccUpstream{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		up.mu.Lock()
		up.bodies = append(up.bodies, body)
		up.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		switch strings.Count(body, `"type":"tool_result"`) {
		case 0:
			_, _ = w.Write([]byte(ccNativeRound1))
		case 1:
			_, _ = w.Write([]byte(ccNativeRound2))
		default:
			_, _ = w.Write([]byte(ccNativeRound3))
		}
	}))
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 8)
	var evs []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		evs = append(evs, e)
		evCh <- e
	})
	t.Cleanup(restore)

	messages := []map[string]any{{"role": "user", "content": "Run the task"}}
	finalText := ""
	rounds := 0
	for {
		if rounds > 8 {
			t.Fatal("loop did not terminate within 8 rounds")
		}
		reqBody, err := json.Marshal(map[string]any{
			"model":      "claude-3-5-sonnet",
			"max_tokens": 64,
			"messages":   messages,
			"stream":     true,
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := postMessages(t, gw, string(reqBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("round %d status %d %s", rounds+1, rec.Code, rec.Body.String())
		}
		blocks, stop := ccParseRound(t, rec.Body.String())
		rounds++
		if stop == "end_turn" {
			for _, b := range blocks {
				finalText += b.Text
			}
			break
		}
		if stop != "tool_use" {
			t.Fatalf("round %d stop_reason %q, want tool_use or end_turn", rounds, stop)
		}
		var toolUses []*ccBlock
		for _, b := range blocks {
			if b.Type == "tool_use" {
				toolUses = append(toolUses, b)
			}
		}
		if len(toolUses) == 0 {
			t.Fatalf("round %d ended with tool_use but carried no tool_use block", rounds)
		}
		assistant := []map[string]any{}
		for _, tu := range toolUses {
			assistant = append(assistant, map[string]any{
				"type": "tool_use", "id": tu.ToolID, "name": tu.Tool, "input": tu.Input,
			})
		}
		messages = append(messages, map[string]any{"role": "assistant", "content": assistant})
		for _, tu := range toolUses {
			out := ccMockExec(t, tu.Input["cmd"].(string))
			messages = append(messages, map[string]any{"role": "user", "content": []map[string]any{{
				"type": "tool_result", "tool_use_id": tu.ToolID, "content": out,
			}}})
		}
	}

	if rounds != 3 || finalText != "Task done: hello 42" {
		t.Fatalf("rounds=%d finalText=%q, want 3 rounds ending in the mock answer", rounds, finalText)
	}
	bodies := up.bodiesSnapshot()
	if len(bodies) != 3 {
		t.Fatalf("upstream saw %d requests, want 3", len(bodies))
	}
	if !strings.Contains(bodies[1], `"type":"tool_result"`) || !strings.Contains(bodies[1], `"tool_use_id":"toolu_1"`) {
		t.Fatalf("round 2 request must carry the tool_result for toolu_1:\n%s", bodies[1])
	}
	if strings.Count(bodies[2], `"tool_use_id":"toolu_2"`) != 1 {
		t.Fatalf("round 3 request must carry the tool_result for toolu_2:\n%s", bodies[2])
	}
	// Each round is billed separately and completely.
	deadline := time.After(5 * time.Second)
	for len(evs) < 3 {
		select {
		case <-evCh:
		case <-deadline:
			t.Fatalf("timed out waiting for 3 billed rounds, got %d", len(evs))
		}
	}
	wantOut := []int64{5, 6, 9}
	for i, ev := range evs {
		if ev.EventType != "request.completed" {
			t.Fatalf("round %d event %s", i+1, ev.EventType)
		}
		if ev.TokensIn != 7 || ev.TokensOut != wantOut[i] {
			t.Fatalf("round %d usage in=%d out=%d, want in=7 out=%d", i+1, ev.TokensIn, ev.TokensOut, wantOut[i])
		}
	}
	if len(evs) != 3 {
		t.Fatalf("%d analytics events, want exactly one per round (3)", len(evs))
	}
}

// TestClaudeCodeLoopAdaptedMultiStepTaskMockUpstream: the same client loop
// through the adapted (translation) branch — the client still speaks
// Anthropic SSE, the mock provider receives OpenAI chat shape with
// role:"tool" tool rounds, and every round bills once.
func TestClaudeCodeLoopAdaptedMultiStepTaskMockUpstream(t *testing.T) {
	up := &ccUpstream{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		up.mu.Lock()
		up.bodies = append(up.bodies, body)
		up.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		switch strings.Count(body, `"role":"tool"`) {
		case 0:
			_, _ = w.Write([]byte(ccAdaptedRound1))
		case 1:
			_, _ = w.Write([]byte(ccAdaptedRound2))
		default:
			_, _ = w.Write([]byte(ccAdaptedRound3))
		}
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 8)
	var evs []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		evs = append(evs, e)
		evCh <- e
	})
	t.Cleanup(restore)

	messages := []map[string]any{{"role": "user", "content": "Run the task"}}
	finalText := ""
	rounds := 0
	for {
		if rounds > 8 {
			t.Fatal("loop did not terminate within 8 rounds")
		}
		reqBody, err := json.Marshal(map[string]any{
			"model":      "m",
			"max_tokens": 64,
			"messages":   messages,
			"stream":     true,
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := postMessages(t, gw, string(reqBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("round %d status %d %s", rounds+1, rec.Code, rec.Body.String())
		}
		blocks, stop := ccParseRound(t, rec.Body.String())
		rounds++
		if stop == "end_turn" {
			for _, b := range blocks {
				finalText += b.Text
			}
			break
		}
		if stop != "tool_use" {
			t.Fatalf("round %d stop_reason %q, want tool_use or end_turn", rounds, stop)
		}
		var toolUses []*ccBlock
		for _, b := range blocks {
			if b.Type == "tool_use" {
				toolUses = append(toolUses, b)
			}
		}
		if len(toolUses) == 0 {
			t.Fatalf("round %d ended with tool_use but carried no tool_use block", rounds)
		}
		assistant := []map[string]any{}
		for _, tu := range toolUses {
			assistant = append(assistant, map[string]any{
				"type": "tool_use", "id": tu.ToolID, "name": tu.Tool, "input": tu.Input,
			})
		}
		messages = append(messages, map[string]any{"role": "assistant", "content": assistant})
		for _, tu := range toolUses {
			out := ccMockExec(t, tu.Input["cmd"].(string))
			messages = append(messages, map[string]any{"role": "user", "content": []map[string]any{{
				"type": "tool_result", "tool_use_id": tu.ToolID, "content": out,
			}}})
		}
	}

	if rounds != 3 || finalText != "Task done: hello 42" {
		t.Fatalf("rounds=%d finalText=%q, want 3 rounds ending in the mock answer", rounds, finalText)
	}
	bodies := up.bodiesSnapshot()
	if len(bodies) != 3 {
		t.Fatalf("upstream saw %d requests, want 3", len(bodies))
	}
	if !strings.Contains(bodies[1], `"role":"tool"`) || !strings.Contains(bodies[1], `"tool_call_id":"call_1"`) {
		t.Fatalf("adapted round 2 request must translate the tool_result to role:tool with the preserved id:\n%s", bodies[1])
	}
	deadline := time.After(5 * time.Second)
	for len(evs) < 3 {
		select {
		case <-evCh:
		case <-deadline:
			t.Fatalf("timed out waiting for 3 billed rounds, got %d", len(evs))
		}
	}
	wantOut := []int64{5, 6, 9}
	for i, ev := range evs {
		if ev.EventType != "request.completed" {
			t.Fatalf("round %d event %s", i+1, ev.EventType)
		}
		if ev.TokensIn != 7 || ev.TokensOut != wantOut[i] {
			t.Fatalf("round %d usage in=%d out=%d, want in=7 out=%d", i+1, ev.TokensIn, ev.TokensOut, wantOut[i])
		}
	}
}
