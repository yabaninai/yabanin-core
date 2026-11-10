package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// ChatCompletionRequest matches OpenAI's /v1/chat/completions.
type ChatCompletionRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream,omitempty"`
}

// ContentPart represents a single content part in multimodal OpenAI format.
type ContentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Message is a single chat message. Content can be a plain string or an
// array of content parts (OpenAI multimodal format).
type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

// StringContent extracts the text from Content regardless of whether it
// arrived as a string or an array of content parts.
func (m Message) StringContent() string {
	switch v := m.Content.(type) {
	case string:
		return v
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				if t, ok := m["type"].(string); ok && t == "text" {
					if text, ok := m["text"].(string); ok {
						return text
					}
				}
			}
		}
	}
	return ""
}

// Choice is a single choice in the response.
type Choice struct {
	Index        int         `json:"index"`
	Message      ResponseMsg `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// ResponseMsg is the assistant message.
type ResponseMsg struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// ToolFunction is the function part of an OpenAI tool call.
type ToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolCall is a single OpenAI tool_calls entry.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// toolTaskMarker switches the demo stand into the agent branch: requests
// whose last user message starts with it receive a deterministic
// tool_calls response, so the gateway's tool-call extraction pipeline
// (loggerd -> tool_calls table -> admin request detail -> dashboard) has
// data to show. Ordinary requests keep the plain canned reply.
const toolTaskMarker = "[tool-task]"

// toolCallsFor maps a marked task to a deterministic tool-call plan. The
// names mirror the repo's own agent tooling (bash/read/edit/grep).
func toolCallsFor(task string) []ToolCall {
	mk := func(i int, name, args string) ToolCall {
		return ToolCall{
			ID:       fmt.Sprintf("call_demo_%d", i),
			Type:     "function",
			Function: ToolFunction{Name: name, Arguments: args},
		}
	}
	switch {
	case strings.Contains(task, "refactor"):
		return []ToolCall{
			mk(1, "bash", `{"command":"go build ./..."}`),
			mk(2, "read", `{"path":"pkg/retry/retry.go"}`),
			mk(3, "edit", `{"path":"pkg/retry/retry.go"}`),
		}
	case strings.Contains(task, "search") || strings.Contains(task, "find"):
		return []ToolCall{
			mk(1, "grep", `{"pattern":"tool_calls","path":"services/loggerd"}`),
			mk(2, "read", `{"path":"docs/demo.md"}`),
		}
	default:
		return []ToolCall{
			mk(1, "bash", `{"command":"git status --short"}`),
			mk(2, "read", `{"path":"README.md"}`),
		}
	}
}

// ChatCompletionResponse matches OpenAI's response.
type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Usage contains token usage information.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// buildResponse produces the deterministic canned reply. Plain requests
// get "Mock response to: <last user message>"; [tool-task] requests get a
// deterministic tool_calls plan with finish_reason "tool_calls".
func buildResponse(req ChatCompletionRequest) ChatCompletionResponse {
	var lastUser string
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" || req.Messages[i].Role == "assistant" {
			lastUser = req.Messages[i].StringContent()
			break
		}
	}

	content := fmt.Sprintf("Mock response to: %s", lastUser)
	finish := "stop"
	var calls []ToolCall
	if strings.HasPrefix(lastUser, toolTaskMarker) {
		content = ""
		finish = "tool_calls"
		calls = toolCallsFor(lastUser)
	}

	return ChatCompletionResponse{
		ID:      fmt.Sprintf("chatcmpl-%d", len(lastUser)),
		Object:  "chat.completion",
		Created: 1720000000,
		Model:   req.Model,
		Choices: []Choice{{
			Index:        0,
			Message:      ResponseMsg{Role: "assistant", Content: content, ToolCalls: calls},
			FinishReason: finish,
		}},
		Usage: Usage{PromptTokens: len(lastUser), CompletionTokens: 15, TotalTokens: len(lastUser) + 15},
	}
}

// ChunkDelta is the streaming delta of one chat.completion.chunk frame.
// It reuses ResponseMsg: role first, then content and/or tool_calls pieces.
type chunkChoice struct {
	Index        int         `json:"index"`
	Delta        ResponseMsg `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

type chatChunk struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []chunkChoice `json:"choices"`
	Usage   *Usage        `json:"usage,omitempty"`
}

// streamFrames renders the full SSE payload for a streaming request: OpenAI
// chat.completion.chunk frames ending with a terminal data: [DONE] event.
// The gateway's drain (pkg/provider/stream.go) requires the [DONE]
// terminator — a plain JSON body is not a stream, and the request used to be
// recorded as failed with an injected client-facing error frame.
func streamFrames(req ChatCompletionRequest) []string {
	resp := buildResponse(req)
	choice := resp.Choices[0]
	id := "chatcmpl-stream-" + resp.ID[9:] // strip "chatcmpl-" prefix reuse
	mk := func(delta ResponseMsg, finish *string, usage *Usage) string {
		payload, err := json.Marshal(chatChunk{
			ID: id, Object: "chat.completion.chunk", Created: resp.Created, Model: resp.Model,
			Choices: []chunkChoice{{Index: 0, Delta: delta, FinishReason: finish}},
			Usage:   usage,
		})
		if err != nil {
			return "data: {}\n\n" // unreachable: the structs always marshal
		}
		return "data: " + string(payload) + "\n\n"
	}

	frames := []string{mk(ResponseMsg{Role: "assistant"}, nil, nil)}
	if choice.FinishReason == "tool_calls" {
		for _, call := range choice.Message.ToolCalls {
			frames = append(frames, mk(ResponseMsg{ToolCalls: []ToolCall{call}}, nil, nil))
		}
	} else {
		// Split the canned content into two deltas so consumers see a real
		// incremental stream, not one bulk frame.
		content := choice.Message.Content
		half := len(content) / 2
		frames = append(frames,
			mk(ResponseMsg{Content: content[:half]}, nil, nil),
			mk(ResponseMsg{Content: content[half:]}, nil, nil),
		)
	}
	finish := choice.FinishReason
	frames = append(frames, mk(ResponseMsg{}, &finish, &resp.Usage))
	frames = append(frames, "data: [DONE]\n\n")
	return frames
}

func main() {
	port := os.Getenv("MOCK_PROVIDER_PORT")
	if port == "" {
		port = "8081"
	}

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ChatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			for _, frame := range streamFrames(req) {
				if _, err := fmt.Fprintf(w, "%s", frame); err != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(buildResponse(req))
	})

	addr := ":" + port
	log.Printf("mock-provider listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
