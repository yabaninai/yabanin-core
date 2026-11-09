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
