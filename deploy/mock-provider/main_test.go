package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func lastUserMsg(s string) []Message {
	return []Message{{Role: "user", Content: s}}
}

func TestPlainRequestGetsCannedContent(t *testing.T) {
	resp := buildResponse(ChatCompletionRequest{Model: "gpt-4o", Messages: lastUserMsg("hello")})
	msg := resp.Choices[0].Message
	if msg.Content != "Mock response to: hello" || len(msg.ToolCalls) != 0 {
		t.Fatalf("unexpected plain reply: %+v", msg)
	}
	if resp.Choices[0].FinishReason != "stop" {
		t.Fatalf("finish_reason = %q, want stop", resp.Choices[0].FinishReason)
	}
}

func TestToolTaskGetsDeterministicToolCalls(t *testing.T) {
	resp := buildResponse(ChatCompletionRequest{Model: "gpt-4o", Messages: lastUserMsg("[tool-task] refactor the retry loop")})
	choice := resp.Choices[0]
	if choice.FinishReason != "tool_calls" {
		t.Fatalf("finish_reason = %q, want tool_calls", choice.FinishReason)
	}
	if choice.Message.Content != "" {
		t.Fatalf("content = %q, want empty for tool branch", choice.Message.Content)
	}
	var names []string
	for _, c := range choice.Message.ToolCalls {
		if c.Type != "function" || c.ID == "" || c.Function.Name == "" {
			t.Fatalf("malformed tool call: %+v", c)
		}
		names = append(names, c.Function.Name)
	}
	if strings.Join(names, ",") != "bash,read,edit" {
		t.Fatalf("refactor plan = %v, want [bash read edit]", names)
	}
	// The wire form must carry tool_calls where loggerd looks for them.
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"tool_calls"`) || !strings.Contains(string(raw), `"finish_reason":"tool_calls"`) {
		t.Fatalf("wire form missing tool_calls markers: %s", raw)
	}
}

func TestToolPlansByKeywords(t *testing.T) {
	search := buildResponse(ChatCompletionRequest{Messages: lastUserMsg("[tool-task] find all usages of the cache")})
	if got := len(search.Choices[0].Message.ToolCalls); got != 2 {
		t.Fatalf("search plan length = %d, want 2", got)
	}
	def := buildResponse(ChatCompletionRequest{Messages: lastUserMsg("[tool-task] deploy the service")})
	if got := len(def.Choices[0].Message.ToolCalls); got != 2 {
		t.Fatalf("default plan length = %d, want 2", got)
	}
}

func TestMarkerNotAtStartStaysPlain(t *testing.T) {
	resp := buildResponse(ChatCompletionRequest{Messages: lastUserMsg("please use [tool-task] inside a sentence")})
	if len(resp.Choices[0].Message.ToolCalls) != 0 {
		t.Fatal("marker not at start must stay in the plain branch")
	}
}

func TestStreamFrames_PlainRequest(t *testing.T) {
	frames := streamFrames(ChatCompletionRequest{Model: "mock-model", Stream: true, Messages: lastUserMsg("hello")})
	if len(frames) < 4 {
		t.Fatalf("frame count = %d, want >= 4 (role, deltas, finish, DONE)", len(frames))
	}
	if got := frames[len(frames)-1]; got != "data: [DONE]\n\n" {
		t.Fatalf("last frame = %q, want data: [DONE]", got)
	}
	for i, f := range frames[:len(frames)-1] {
		if !strings.HasPrefix(f, "data: {") || !strings.HasSuffix(f, "\n\n") {
			t.Fatalf("frame %d is not a complete SSE event: %q", i, f)
		}
		var chunk struct {
			Object  string `json:"object"`
			Choices []struct {
				Delta struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				TotalTokens int `json:"total_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(f[len("data: "):]), &chunk); err != nil {
			t.Fatalf("frame %d is not JSON: %v (%q)", i, err, f)
		}
		if chunk.Object != "chat.completion.chunk" {
			t.Fatalf("frame %d object = %q", i, chunk.Object)
		}
	}
	first := frames[0]
	if !strings.Contains(first, `"role":"assistant"`) {
		t.Fatalf("first frame must carry the role delta: %q", first)
	}
	last := frames[len(frames)-2]
	if !strings.Contains(last, `"finish_reason":"stop"`) || !strings.Contains(last, `"total_tokens":20`) {
		t.Fatalf("finish frame must carry finish_reason stop and usage: %q", last)
	}
	var content strings.Builder
	for _, f := range frames[1 : len(frames)-2] {
		content.WriteString(extractDeltaContent(t, f))
	}
	if content.String() != "Mock response to: hello" {
		t.Fatalf("reassembled content = %q", content.String())
	}
}

func extractDeltaContent(t *testing.T, frame string) string {
	t.Helper()
	var chunk struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(frame[len("data: "):]), &chunk); err != nil {
		t.Fatalf("frame not JSON: %v", err)
	}
	if len(chunk.Choices) != 1 {
		t.Fatalf("frame must have exactly one choice: %q", frame)
	}
	return chunk.Choices[0].Delta.Content
}

func TestStreamFrames_ToolTask(t *testing.T) {
	frames := streamFrames(ChatCompletionRequest{Model: "mock-model", Stream: true,
		Messages: lastUserMsg("[tool-task] refactor the retry loop")})
	joined := strings.Join(frames, "")
	if !strings.Contains(joined, `"tool_calls"`) {
		t.Fatalf("tool stream must carry tool_calls deltas: %s", joined)
	}
	last := frames[len(frames)-2]
	if !strings.Contains(last, `"finish_reason":"tool_calls"`) {
		t.Fatalf("tool stream must finish with tool_calls: %q", last)
	}
	if frames[len(frames)-1] != "data: [DONE]\n\n" {
		t.Fatal("tool stream must end with the [DONE] terminator")
	}
}
