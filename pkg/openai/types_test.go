package openai

import (
	"encoding/json"
	"testing"
)

func TestChatMessage_UnmarshalJSON_StringContent(t *testing.T) {
	var m ChatMessage
	if err := json.Unmarshal([]byte(`{"role":"user","content":"hi"}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Role != "user" || m.Content != "hi" {
		t.Fatalf("got %+v", m)
	}
}

func TestChatMessage_UnmarshalJSON_NullContent(t *testing.T) {
	var m ChatMessage
	if err := json.Unmarshal([]byte(`{"role":"assistant","content":null,"tool_calls":[{"id":"1"}]}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Role != "assistant" || m.Content != "" {
		t.Fatalf("got %+v", m)
	}
}

func TestChatMessage_UnmarshalJSON_TextParts(t *testing.T) {
	var m ChatMessage
	in := `{"role":"user","content":[{"type":"text","text":"read "},{"type":"text","text":"file.go"}]}`
	if err := json.Unmarshal([]byte(in), &m); err != nil {
		t.Fatal(err)
	}
	if m.Content != "read file.go" {
		t.Fatalf("content=%q", m.Content)
	}
}

func TestChatCompletionRequest_OpenCodeToolLoop(t *testing.T) {
	body := []byte(`{
		"model":"glm-5.3",
		"messages":[
			{"role":"system","content":"You are a coding agent."},
			{"role":"user","content":[{"type":"text","text":"fix the test"}]},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read","arguments":"{\"path\":\"a.go\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"package a"}
		],
		"tools":[{"type":"function","function":{"name":"read"}}],
		"stream":true,
		"max_tokens":32768
	}`)
	var req ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("OpenCode tool-loop body must parse: %v", err)
	}
	if req.Model != "glm-5.3" || !req.Stream {
		t.Fatalf("got model=%q stream=%v", req.Model, req.Stream)
	}
	if req.MaxTokens == nil || *req.MaxTokens != 32768 {
		t.Fatalf("max_tokens=%v", req.MaxTokens)
	}
	if len(req.Messages) != 4 {
		t.Fatalf("messages=%d", len(req.Messages))
	}
	if req.Messages[1].Content != "fix the test" {
		t.Fatalf("user content=%q", req.Messages[1].Content)
	}
	if req.Messages[2].Role != "assistant" || req.Messages[2].Content != "" {
		t.Fatalf("assistant=%+v", req.Messages[2])
	}
	if req.Messages[3].Role != "tool" || req.Messages[3].Content != "package a" {
		t.Fatalf("tool=%+v", req.Messages[3])
	}
}
