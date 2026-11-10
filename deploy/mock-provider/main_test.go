package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestStreamingHTTPResponse(t *testing.T) {
	for _, prompt := range []string{"hello", "[tool-task] refactor the retry loop"} {
		t.Run(prompt, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(chatCompletions))
			defer server.Close()
			body, err := json.Marshal(ChatCompletionRequest{Model: "mock-model", Stream: true, Messages: lastUserMsg(prompt)})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, strings.NewReader(string(body)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
				t.Fatalf("unexpected response: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
			}
			events := strings.Split(strings.TrimSuffix(string(raw), "\n\n"), "\n\n")
			if len(events) != 4 || events[3] != "data: [DONE]" {
				t.Fatalf("incomplete SSE response: %s", raw)
			}
			for i, event := range events[:3] {
				var chunk struct {
					Object  string `json:"object"`
					Choices []struct {
						Delta struct {
							Content   string `json:"content"`
							ToolCalls []struct {
								Index int `json:"index"`
								ToolCall
							} `json:"tool_calls"`
						} `json:"delta"`
						FinishReason *string `json:"finish_reason"`
					} `json:"choices"`
					Usage *Usage `json:"usage"`
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(event, "data: ")), &chunk); err != nil {
					t.Fatal(err)
				}
				if chunk.Object != "chat.completion.chunk" {
					t.Fatal("not a chat stream chunk")
				}
				if i == 0 {
					if len(chunk.Choices) != 1 || chunk.Choices[0].FinishReason != nil {
						t.Fatal("invalid initial delta")
					}
					if prompt == "hello" && chunk.Choices[0].Delta.Content != "Mock response to: hello" {
						t.Fatal("content missing")
					}
					if strings.HasPrefix(prompt, toolTaskMarker) {
						calls := chunk.Choices[0].Delta.ToolCalls
						if len(calls) != 3 {
							t.Fatal("tool calls missing")
						}
						for j, call := range calls {
							if call.Index != j || call.ID == "" || call.Function.Name == "" {
								t.Fatal("invalid indexed tool call")
							}
						}
					}
				}
				if i == 1 {
					want := "stop"
					if strings.HasPrefix(prompt, toolTaskMarker) {
						want = "tool_calls"
					}
					if len(chunk.Choices) != 1 || chunk.Choices[0].FinishReason == nil || *chunk.Choices[0].FinishReason != want {
						t.Fatal("incorrect finish reason")
					}
				}
				if i == 2 && (len(chunk.Choices) != 0 || chunk.Usage == nil || chunk.Usage.TotalTokens != len(prompt)+15) {
					t.Fatal("final usage missing")
				}
			}
		})
	}
}
