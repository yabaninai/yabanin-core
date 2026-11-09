package streaming

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// aggFrame renders a chat.completion.chunk data payload.
func aggFrame(t *testing.T, body map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(append([]byte("data: "), b...), '\n', '\n')
}

func TestFinalAggregate_DocumentParity(t *testing.T) {
	// The W-STCACHE parity: content concatenated from deltas, the first
	// role wins, the last finish_reason and the final usage frame carry.
	fa := NewFinalAggregate()
	fa.AddFrame(aggFrame(t, map[string]any{
		"id": "c1", "object": "chat.completion.chunk", "created": int64(7), "model": "m1",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": "Hello "}}},
	}))
	fa.AddFrame(aggFrame(t, map[string]any{
		"id": "c1", "model": "m1",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": "world"}}},
	}))
	fa.AddFrame(aggFrame(t, map[string]any{
		"id": "c1", "model": "m1",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
	}))
	fa.AddFrame(aggFrame(t, map[string]any{
		"id": "c1", "model": "m1",
		"choices": []any{},
		"usage":   map[string]any{"prompt_tokens": 3, "completion_tokens": 2},
	}))
	fa.AddFrame([]byte("data: [DONE]\n\n"))

	doc := fa.Document()
	if doc == nil {
		t.Fatal("document is nil")
	}
	var got struct {
		Object  string `json:"object"`
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatalf("document is not valid JSON: %v (%s)", err, doc)
	}
	if got.Object != "chat.completion" || got.ID != "c1" || got.Created != 7 || got.Model != "m1" {
		t.Fatalf("document header = %+v", got)
	}
	if len(got.Choices) != 1 || got.Choices[0].Message.Role != "assistant" ||
		got.Choices[0].Message.Content != "Hello world" || got.Choices[0].FinishReason != "stop" {
		t.Fatalf("document choice = %+v", got.Choices)
	}
	if got.Usage.PromptTokens != 3 || got.Usage.CompletionTokens != 2 {
		t.Fatalf("usage = %+v", got.Usage)
	}
}

// TestFinalAggregate_ReasoningAccumulated pins the reasoning facet of
// N03-P01-T03 at the aggregate layer: reasoning deltas concatenate in
// arrival order into message.reasoning_content, multi-byte text rides the
// JSON string contract (a rune cannot be torn), and content accumulates
// independently alongside.
func TestFinalAggregate_ReasoningAccumulated(t *testing.T) {
	fa := NewFinalAggregate()
	fa.AddFrame(aggFrame(t, map[string]any{
		"id": "c1", "model": "m1",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "reasoning_content": "шаг 1: "}}},
	}))
	fa.AddFrame(aggFrame(t, map[string]any{
		"id": "c1", "model": "m1",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"reasoning_content": "шаг 2 🚀"}}},
	}))
	fa.AddFrame(aggFrame(t, map[string]any{
		"id": "c1", "model": "m1",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": "готово"}, "finish_reason": "stop"}},
	}))

	doc := fa.Document()
	if doc == nil {
		t.Fatal("document is nil")
	}
	var got struct {
		Choices []struct {
			Message struct {
				Content   string  `json:"content"`
				Reasoning *string `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatalf("document is not valid JSON: %v (%s)", err, doc)
	}
	if len(got.Choices) != 1 {
		t.Fatalf("choices = %+v", got.Choices)
	}
	msg := got.Choices[0].Message
	if msg.Content != "готово" {
		t.Fatalf("content = %q", msg.Content)
	}
	if msg.Reasoning == nil || *msg.Reasoning != "шаг 1: шаг 2 🚀" {
		t.Fatalf("reasoning_content = %v", msg.Reasoning)
	}
}

func TestFinalAggregate_ToolCallsMergedByIndex(t *testing.T) {
	fa := NewFinalAggregate()
	fa.AddChunk([]byte(`{"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"get_weather","arguments":""}}]}}]}`))
	fa.AddChunk([]byte(`{"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]}}]}`))
	fa.AddChunk([]byte(`{"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Moscow\"}"}}]}}]}`))

	doc := fa.Document()
	if doc == nil {
		t.Fatal("document is nil")
	}
	var got struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatalf("document is not valid JSON: %v", err)
	}
	calls := got.Choices[0].Message.ToolCalls
	if len(calls) != 1 {
		t.Fatalf("tool calls = %+v, want one merged call", calls)
	}
	c := calls[0]
	if c.ID != "call_1" || c.Type != "function" || c.Function.Name != "get_weather" ||
		c.Function.Arguments != `{"city":"Moscow"}` {
		t.Fatalf("merged call = %+v", c)
	}
}

func TestFinalAggregate_EmptyAndRoleOnly(t *testing.T) {
	if NewFinalAggregate().Document() != nil {
		t.Fatal("empty aggregate produced a document")
	}
	fa := NewFinalAggregate()
	fa.AddChunk([]byte(`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`))
	if fa.Document() != nil {
		t.Fatal("role-only aggregate produced a document (would serve an empty answer)")
	}
	// Noise tolerance: unparseable frames are ignored, not fatal.
	fa.AddFrame([]byte("data: oops\n\n"))
	fa.AddFrame([]byte(": comment\n\n"))
	if fa.Document() != nil {
		t.Fatal("noise turned into a document")
	}
}

func TestFinalCheck_DenyAfterIssuanceDegradesToFlag(t *testing.T) {
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, finalDenyPolicy)
	fa := NewFinalAggregate()
	fa.AddFrame(chunkFrame(t, "c1", "nice answer with "+testInjectionTrigger))
	out := FinalCheck(context.Background(), EngineRunner(eng, []pipeline.Compiled{pol}), fa, nil, "chat")
	if out.Err != nil {
		t.Fatalf("unexpected infra error: %v", out.Err)
	}
	if out.Result == nil || out.Result.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %+v, want deny", out.Result)
	}
	if out.Effective != pipeline.ActionFlag {
		t.Fatalf("effective = %q, want flag (deny after issuance cannot unsend)", out.Effective)
	}
	if len(out.Result.Findings) == 0 {
		t.Fatal("flag outcome lost the findings for the decision-log")
	}
	if !strings.Contains(string(out.Document), "nice answer") {
		t.Fatalf("document = %s", out.Document)
	}
}

func TestFinalCheck_MaskVerdictKeepsMutation(t *testing.T) {
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, finalMaskPolicy)
	fa := NewFinalAggregate()
	fa.AddFrame(chunkFrame(t, "c1", "value "+testSecretTrigger))
	out := FinalCheck(context.Background(), EngineRunner(eng, []pipeline.Compiled{pol}), fa, nil, "chat")
	if out.Err != nil {
		t.Fatalf("unexpected infra error: %v", out.Err)
	}
	if out.Effective != pipeline.ActionMask {
		t.Fatalf("effective = %q, want mask", out.Effective)
	}
	if out.Result == nil || out.Result.Mutated == nil {
		t.Fatalf("mask outcome lost the mutated document: %+v", out.Result)
	}
	if strings.Contains(string(out.Result.Mutated.Body), testSecretTrigger) {
		t.Fatal("mutated document still contains the secret")
	}
}

func TestFinalCheck_AllowAndEmptySkip(t *testing.T) {
	eng := newTestEngine(t)
	pol := mustCompile(t, eng, finalDenyPolicy)
	runner := EngineRunner(eng, []pipeline.Compiled{pol})

	clean := NewFinalAggregate()
	clean.AddFrame(chunkFrame(t, "c1", "perfectly fine answer"))
	out := FinalCheck(context.Background(), runner, clean, nil, "chat")
	if out.Effective != pipeline.ActionAllow || out.Result == nil {
		t.Fatalf("clean check = %+v, want allow", out)
	}

	empty := NewFinalAggregate()
	out = FinalCheck(context.Background(), runner, empty, nil, "chat")
	if out.Effective != pipeline.ActionAllow || out.Result != nil || out.Document != nil {
		t.Fatalf("empty aggregate = %+v, want a skip", out)
	}

	out = FinalCheck(context.Background(), runner, nil, nil, "chat")
	if out.Effective != pipeline.ActionAllow {
		t.Fatalf("nil aggregate = %+v", out)
	}
}

func TestFinalCheck_CancelledContextDegradesToFlag(t *testing.T) {
	fa := NewFinalAggregate()
	fa.AddFrame(chunkFrame(t, "c1", "content"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := FinalCheck(ctx, nil, fa, nil, "chat")
	if out.Effective != pipeline.ActionFlag || out.Err == nil {
		t.Fatalf("cancelled check = %+v, want a flagged infra failure", out)
	}
	if out.Result != nil {
		t.Fatal("policies ran on a cancelled context")
	}
}

func TestFinalCheck_NilRunnerFlagged(t *testing.T) {
	fa := NewFinalAggregate()
	fa.AddFrame(chunkFrame(t, "c1", "content"))
	out := FinalCheck(context.Background(), nil, fa, nil, "chat")
	if out.Effective != pipeline.ActionFlag || out.Err == nil {
		t.Fatalf("nil runner = %+v, want a flagged infra failure", out)
	}
}
