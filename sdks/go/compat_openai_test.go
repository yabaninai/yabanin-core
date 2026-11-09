package yabanin

// N07-P01-T02 — OpenAI JSON/SSE errors contract, consumer side.
//
// The gateway-side contract is machine-checked in the gateway module
// (contracts/api-contract.json schema_version 1, pkg/gateway/api_contract_test.go,
// TestGoldenWire_SSEErrorFrame_ExactBytes). This file proves the CONSUMER
// side of the same contract with the pinned third-party OpenAI client
// (github.com/sashabaranov/go-openai v1.41.2 — the exact pin declared in
// go.mod): a real client build must decode the gateway's error envelopes and
// the SSE error frame without rewrapping or field loss.
//
// The fixtures below are the canonical contract bytes, copied verbatim:
//   - error_401 / error_upstream fixtures of contracts/api-contract.json;
//   - the sse_error_event fixture: data: {"error":{message,type}}\n\ndata: [DONE]\n\n.
//
// Decision pinned by the packet (2026-10-30): the SSE error frame stays
// message+type only — code/param ride the JSON envelope and are dropped on
// the SSE surface — so the contract keeps schema_version 1 and this test
// changes nothing about the wire.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	openai "github.com/sashabaranov/go-openai"
)

// openaiContractClient returns the pinned client aimed at a test double that
// replies with the given gateway bytes.
func openaiContractClient(t *testing.T, status int, contentType, body string) *openai.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	cfg := openai.DefaultConfig("test-key")
	cfg.BaseURL = srv.URL
	return openai.NewClientWithConfig(cfg)
}

func contractChatRequest() openai.ChatCompletionRequest {
	return openai.ChatCompletionRequest{
		Model:    "gpt-4o-mini",
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "hi"}},
	}
}

// TestOpenAICompat_JSONErrorEnvelopeDecodes pins the JSON half: the gateway's
// non-2xx envelope decodes into the client's APIError with message and type
// preserved, param/code absent when the gateway omits them, and the optional
// code preserved when present (error_upstream fixture).
func TestOpenAICompat_JSONErrorEnvelopeDecodes(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantType   string
		wantMsg    string
		wantCode   string
		wantCodeOK bool
	}{
		{
			name:     "error_401 fixture: no param/code keys",
			status:   http.StatusUnauthorized,
			body:     `{"error":{"message":"invalid api key","type":"invalid_request_error"}}`,
			wantType: "invalid_request_error",
			wantMsg:  "invalid api key",
		},
		{
			name:       "error_upstream fixture: code preserved",
			status:     http.StatusServiceUnavailable,
			body:       `{"error":{"message":"upstream provider unavailable","type":"api_error","code":"service_unavailable"}}`,
			wantType:   "api_error",
			wantMsg:    "upstream provider unavailable",
			wantCode:   "service_unavailable",
			wantCodeOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := openaiContractClient(t, tc.status, "application/json", tc.body)
			_, err := client.CreateChatCompletion(context.Background(), contractChatRequest())
			if err == nil {
				t.Fatal("gateway error body must surface as an error, not a completion")
			}
			var apiErr *openai.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error must decode as *openai.APIError, got %T: %v", err, err)
			}
			if apiErr.Message != tc.wantMsg || apiErr.Type != tc.wantType {
				t.Fatalf("message/type lost: got %q/%q want %q/%q", apiErr.Message, apiErr.Type, tc.wantMsg, tc.wantType)
			}
			if tc.wantCodeOK {
				if code, _ := apiErr.Code.(string); code != tc.wantCode {
					t.Fatalf("code lost: got %#v want %q", apiErr.Code, tc.wantCode)
				}
			} else if apiErr.Code != nil {
				t.Fatalf("absent code must stay absent, got %#v", apiErr.Code)
			}
			if apiErr.HTTPStatusCode != tc.status {
				t.Fatalf("HTTP status lost: got %d want %d", apiErr.HTTPStatusCode, tc.status)
			}
		})
	}
}

// TestOpenAICompat_SSEErrorFrameDecodes pins the SSE half: the canonical
// gateway error frame (message+type, then [DONE]) is surfaced by the pinned
// client as an *APIError carrying the same message and type — the frame the
// golden wire test pins byte-exactly on the gateway side.
func TestOpenAICompat_SSEErrorFrameDecodes(t *testing.T) {
	const sseErrorFrame = "data: {\"error\":{\"message\":\"boom\",\"type\":\"upstream_error\"}}\n\n" +
		"data: [DONE]\n\n"
	client := openaiContractClient(t, http.StatusOK, "text/event-stream", sseErrorFrame)

	stream, err := client.CreateChatCompletionStream(context.Background(), contractChatRequest())
	if err != nil {
		t.Fatalf("stream open must succeed before the error frame: %v", err)
	}
	defer func() { _ = stream.Close() }()

	_, err = stream.Recv()
	if err == nil {
		t.Fatal("the error frame must surface as a Recv error, not a chunk")
	}
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("SSE error frame must decode as *openai.APIError, got %T: %v", err, err)
	}
	if apiErr.Message != "boom" || apiErr.Type != "upstream_error" {
		t.Fatalf("SSE frame message/type lost: got %q/%q", apiErr.Message, apiErr.Type)
	}
}

// ---------------------------------------------------------------------------
// N07-P01-T03 — tools / parallel calls / refusal consumer proofs.
//
// Acceptance "Совместимость доказана pinned SDK versions": every fixture
// below is the exact byte payload the gateway's chat path produces (copied
// verbatim from the gateway-side goldens and live handler output), decoded
// through the pinned go-openai v1.41.2 client the way a real consumer runs.
// A pinned client must recover parallel tool calls (by index), the refusal
// shape, and the cache-replay twins without field loss.
// ---------------------------------------------------------------------------

// TestOpenAICompat_ParallelToolCallsResponseDecodes pins the non-streaming
// tools contract: the translated parallel tool-call completion — exact bytes
// of pkg/provider/testdata/anthropic_down_tools.out.json — decodes into two
// ordered tool calls with ids, names and arguments preserved.
func TestOpenAICompat_ParallelToolCallsResponseDecodes(t *testing.T) {
	const body = `{"id":"msg_1","object":"chat.completion","created":1700000000,"model":"claude","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":"ok","tool_calls":[{"id":"toolu_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}},{"id":"toolu_2","type":"function","function":{"name":"get_time","arguments":"{\"tz\":\"UTC\"}"}}]}}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`
	client := openaiContractClient(t, http.StatusOK, "application/json", body)

	resp, err := client.CreateChatCompletion(context.Background(), contractChatRequest())
	if err != nil {
		t.Fatalf("parallel tool-call completion must decode, got error: %v", err)
	}
	choice := resp.Choices[0]
	if choice.FinishReason != openai.FinishReasonToolCalls {
		t.Fatalf("finish_reason lost: got %q want tool_calls", choice.FinishReason)
	}
	calls := choice.Message.ToolCalls
	if len(calls) != 2 {
		t.Fatalf("parallel tool calls lost: got %d want 2", len(calls))
	}
	want := []struct{ id, name, args string }{
		{"toolu_1", "get_weather", `{"city":"Paris"}`},
		{"toolu_2", "get_time", `{"tz":"UTC"}`},
	}
	for i, w := range want {
		if calls[i].ID != w.id || calls[i].Function.Name != w.name || calls[i].Function.Arguments != w.args {
			t.Fatalf("tool call %d lost: got %q/%q/%q want %q/%q/%q", i, calls[i].ID, calls[i].Function.Name, calls[i].Function.Arguments, w.id, w.name, w.args)
		}
	}
	if choice.Message.Content != "ok" {
		t.Fatalf("content lost alongside tool calls: got %q", choice.Message.Content)
	}
}

// TestOpenAICompat_RefusalResponseDecodes pins the refusal contract: the
// translated refusal — exact bytes of
// pkg/provider/testdata/anthropic_down_refusal.out.json — surfaces through
// the pinned client as message.refusal with content_filter finish, the
// programmatic refusal signal go-openai consumers branch on.
func TestOpenAICompat_RefusalResponseDecodes(t *testing.T) {
	const body = `{"id":"msg_refusal","object":"chat.completion","created":1700000000,"model":"claude","choices":[{"index":0,"finish_reason":"content_filter","message":{"role":"assistant","content":null,"refusal":"I can't help with that request."}}],"usage":{"prompt_tokens":5,"completion_tokens":9,"total_tokens":14}}`
	client := openaiContractClient(t, http.StatusOK, "application/json", body)

	resp, err := client.CreateChatCompletion(context.Background(), contractChatRequest())
	if err != nil {
		t.Fatalf("refusal completion must decode, got error: %v", err)
	}
	choice := resp.Choices[0]
	if choice.FinishReason != openai.FinishReasonContentFilter {
		t.Fatalf("finish_reason lost: got %q want content_filter", choice.FinishReason)
	}
	if choice.Message.Refusal != "I can't help with that request." {
		t.Fatalf("refusal text lost: got %q", choice.Message.Refusal)
	}
	if choice.Message.Content != "" {
		t.Fatalf("refusal must not carry content, got %q", choice.Message.Content)
	}
}

// refuseReceivingStream consumes a pinned-client chat stream, merging
// tool-call fragments by index (the canonical SDK consumer pattern) and
// returning the last finish_reason, accumulated arguments, tool names and
// the refusal wording.
func refuseReceivingStream(t *testing.T, client *openai.Client) (finish openai.FinishReason, args map[int]string, names map[int]string, refusal string) {
	t.Helper()
	stream, err := client.CreateChatCompletionStream(context.Background(), contractChatRequest())
	if err != nil {
		t.Fatalf("stream open failed: %v", err)
	}
	defer func() { _ = stream.Close() }()
	args = map[int]string{}
	names = map[int]string{}
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return finish, args, names, refusal
		}
		if err != nil {
			t.Fatalf("stream recv failed: %v", err)
		}
		for _, ch := range chunk.Choices {
			if ch.FinishReason != "" {
				finish = ch.FinishReason
			}
			for _, call := range ch.Delta.ToolCalls {
				idx := 0
				if call.Index != nil {
					idx = *call.Index
				}
				if call.Function.Name != "" {
					names[idx] = call.Function.Name
				}
				args[idx] += call.Function.Arguments
			}
			if ch.Delta.Refusal != "" {
				refusal = ch.Delta.Refusal
			}
		}
	}
}

// TestOpenAICompat_ParallelToolCallStreamAccumulates pins the streaming
// tools contract: the exact chunk frames the gateway's Anthropic stream
// translator emits for two parallel tool_use blocks (live handler output,
// captured verbatim) merge, by index, into two complete tool calls.
func TestOpenAICompat_ParallelToolCallStreamAccumulates(t *testing.T) {
	const frames = "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"\",\"name\":\"get_weather\"},\"id\":\"toolu_a\",\"index\":0,\"type\":\"function\"}]},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{\\\"ci\"},\"index\":0}]},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"ty\\\":\"},\"index\":0}]},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"\\\"Paris\\\"}\"},\"index\":0}]},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"\",\"name\":\"get_time\"},\"id\":\"toolu_b\",\"index\":1,\"type\":\"function\"}]},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{\\\"t\"},\"index\":1}]},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"z\\\":\\\"UT\"},\"index\":1}]},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"C\\\"}\"},\"index\":1}]},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\",\"index\":0}],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[],\"id\":\"chatcmpl-msg_tools\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\",\"usage\":{\"completion_tokens\":8,\"prompt_tokens\":10,\"total_tokens\":18}}\n\n" +
		"data: [DONE]\n\n"
	client := openaiContractClient(t, http.StatusOK, "text/event-stream", frames)

	finish, args, names, _ := refuseReceivingStream(t, client)
	if finish != openai.FinishReasonToolCalls {
		t.Fatalf("finish_reason lost: got %q want tool_calls", finish)
	}
	if len(args) != 2 {
		t.Fatalf("parallel tool call indexes lost: got %d want 2", len(args))
	}
	if names[0] != "get_weather" || args[0] != `{"city":"Paris"}` {
		t.Fatalf("tool call 0 fragment merge failed: name %q args %q", names[0], args[0])
	}
	if names[1] != "get_time" || args[1] != `{"tz":"UTC"}` {
		t.Fatalf("tool call 1 fragment merge failed: name %q args %q", names[1], args[1])
	}
}

// TestOpenAICompat_RefusalStreamFinishReasonSurfaces pins the streaming
// refusal contract: the exact frames the gateway emits for an Anthropic
// refusal (live handler output, captured verbatim) end the stream with
// finish_reason content_filter — the refusal signal — with the refusal text
// in content (documented streaming limitation: delta.refusal is not
// emulated without full-response buffering).
func TestOpenAICompat_RefusalStreamFinishReasonSurfaces(t *testing.T) {
	const frames = "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_ref\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"I can't help with that.\"},\"finish_reason\":null,\"index\":0}],\"id\":\"chatcmpl-msg_ref\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"content_filter\",\"index\":0}],\"id\":\"chatcmpl-msg_ref\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[],\"id\":\"chatcmpl-msg_ref\",\"model\":\"claude\",\"object\":\"chat.completion.chunk\",\"usage\":{\"completion_tokens\":7,\"prompt_tokens\":4,\"total_tokens\":11}}\n\n" +
		"data: [DONE]\n\n"
	client := openaiContractClient(t, http.StatusOK, "text/event-stream", frames)

	finish, _, _, refusal := refuseReceivingStream(t, client)
	if finish != openai.FinishReasonContentFilter {
		t.Fatalf("refusal finish_reason lost: got %q want content_filter", finish)
	}
	if refusal != "" {
		t.Fatalf("no delta.refusal is expected on this surface (documented limitation), got %q", refusal)
	}
}

// TestOpenAICompat_ReplayToolCallFramesDecode pins the cache-replay twin of
// the tools contract: the exact SSE frames sseReplayFrames emits for a
// cached parallel tool-call completion (live output, captured verbatim)
// merge into the same two tool calls a live stream would have delivered.
func TestOpenAICompat_ReplayToolCallFramesDecode(t *testing.T) {
	const frames = "data: {\"id\":\"chatcmpl-cache-tools\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-5.3\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"function\":{\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\",\"name\":\"get_weather\"},\"id\":\"call_0\",\"index\":0,\"type\":\"function\"},{\"function\":{\"arguments\":\"{\\\"tz\\\":\\\"UTC\\\"}\",\"name\":\"get_time\"},\"id\":\"call_1\",\"index\":1,\"type\":\"function\"}]},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-cache-tools\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-5.3\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":4,\"total_tokens\":14}}\n\n" +
		"data: [DONE]\n\n"
	client := openaiContractClient(t, http.StatusOK, "text/event-stream", frames)

	finish, args, names, _ := refuseReceivingStream(t, client)
	if finish != openai.FinishReasonToolCalls {
		t.Fatalf("replay finish_reason lost: got %q want tool_calls", finish)
	}
	if names[0] != "get_weather" || args[0] != `{"city":"Paris"}` {
		t.Fatalf("replayed tool call 0 lost: name %q args %q", names[0], args[0])
	}
	if names[1] != "get_time" || args[1] != `{"tz":"UTC"}` {
		t.Fatalf("replayed tool call 1 lost: name %q args %q", names[1], args[1])
	}
}

// TestOpenAICompat_ReplayRefusalFramesDecode pins the cache-replay twin of
// the refusal contract: the exact SSE frames sseReplayFrames emits for a
// cached refusal carry delta.refusal and the content_filter finish through
// the pinned client without loss.
func TestOpenAICompat_ReplayRefusalFramesDecode(t *testing.T) {
	const frames = "data: {\"id\":\"chatcmpl-cache-refusal\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-5.3\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"refusal\":\"I can't help with that request.\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-cache-refusal\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-5.3\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"content_filter\"}]}\n\n" +
		"data: [DONE]\n\n"
	client := openaiContractClient(t, http.StatusOK, "text/event-stream", frames)

	finish, _, _, refusal := refuseReceivingStream(t, client)
	if finish != openai.FinishReasonContentFilter {
		t.Fatalf("replay finish_reason lost: got %q want content_filter", finish)
	}
	if refusal != "I can't help with that request." {
		t.Fatalf("replayed refusal text lost: got %q", refusal)
	}
}

// TestOpenAICompat_ReasoningEffortRefusalSurfacesExactReason (N07-P01-T05)
// proves the consumer side of the negative criterion with the pinned
// go-openai client: the request models ReasoningEffort, and when a
// translated route cannot express the field, the gateway's 400 envelope
// decodes as a normal *openai.APIError whose message names the field and
// the reason (I51) — no silent default-effort success, no generic 502.
func TestOpenAICompat_ReasoningEffortRefusalSurfacesExactReason(t *testing.T) {
	// Exact envelope shape the gateway renders for a translate-layer
	// refusal (apierrors.Write, invalid_request_error).
	body := `{"error":{"message":"translate request: anthropic: reasoning_effort \"high\" is not mapped (Anthropic thinking uses a different request shape); rejecting instead of silently dropping (I51)","type":"invalid_request_error"}}`
	client := openaiContractClient(t, http.StatusBadRequest, "application/json", body)

	req := contractChatRequest()
	req.ReasoningEffort = "high" // the field the pinned SDK models and sends
	_, err := client.CreateChatCompletion(context.Background(), req)
	if err == nil {
		t.Fatal("the refusal must surface as an error, not a default-effort completion")
	}
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("refusal must decode as *openai.APIError, got %T: %v", err, err)
	}
	if apiErr.Type != "invalid_request_error" {
		t.Fatalf("refusal must be a client-side request error, got type %q", apiErr.Type)
	}
	for _, want := range []string{"reasoning_effort", "rejecting"} {
		if !strings.Contains(apiErr.Message, want) {
			t.Fatalf("refusal message must name the field and the contract: %q missing from %q", want, apiErr.Message)
		}
	}
}
