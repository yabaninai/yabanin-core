package yabanin

// N07-P01-T06 — joint user scenario, SDK consumer leg (MOCK).
//
// Card acceptance: «Совместный пользовательский сценарий пакета выполнен на
// согласованной среде; реальные и mock проверки явно различены» — this file
// is the explicitly-MOCK consumer half: both shipped Go clients run a
// multi-turn session against the canonical gateway bytes recorded from the
// gateway-side legs (pkg/gateway/n07p1t06_joint_scenario_test.go and the
// T05 negative corpus). The REAL leg (production server, real DB/Redis
// auth, real event ledger) is
// services/gateway/integration/n07p1t06_joint_scenario_int_test.go (build
// tag `integration`).
//
// Two clients, two compatibility stories:
//   - the own client (yabanin.go, stdlib only): extensions ride Extra
//     verbatim in both directions (the N07-P01-T04 mechanism), so the
//     session proves provider extensions survive the whole round trip;
//   - the pinned third-party client (github.com/sashabaranov/go-openai
//     v1.41.2 — the exact pin declared in go.mod): the packet's typed
//     fields (reasoning effort, tools, structured output, stream usage)
//     marshal and decode without loss. Provider-extension keys are outside
//     the pinned client's schema and are dropped by ITS decoder — the
//     documented consumer-side gap that motivates the own client's Extra.
//
// Assertions stay on the stdlib testing package — this SDK module
// deliberately carries no test dependencies beyond the pinned client pin.
//
// The session covers the packet's facets from the consumer's seat:
//   - extensions (T04): Extra out, Extra back;
//   - the effort asymmetry (T05): effort is sent on the wire, and the
//     translated-route refusal surfaces the exact reason;
//   - structured outputs/tools (T03): tool calls and the refusal field
//     decode untouched;
//   - the usage-chunk contract (T02/T05 field verdicts): the usage chunk
//     decodes when the client asked for it.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	openai "github.com/sashabaranov/go-openai"
)

// Canonical gateway bytes, copied verbatim from the gateway-side joint
// scenario (pkg/gateway/n07p1t06_joint_scenario_test.go).
const (
	n07t06SDKCompletion = `{"id":"chatcmpl-t06","object":"chat.completion","model":"m","provider_ext":{"trace":"t06"},"choices":[{"index":0,"message":{"role":"assistant","content":"","refusal":"Я не могу помочь с этим.","tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Москва\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10},"x_provider_usage":{"cached":true}}`

	n07t06SDKSSE = "data: {\"id\":\"chatcmpl-t06\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Привет\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-t06\",\"model\":\"m\",\"choices\":[],\"usage\":{\"prompt_tokens\":6,\"completion_tokens\":2,\"total_tokens\":8},\"x_provider_ext\":{\"latency_ms\":42}}\n\n" +
		"data: [DONE]\n\n"

	n07t06SDKRefusal400 = `{"error":{"message":"translate request: anthropic: reasoning_effort \"high\" is not mapped (Anthropic thinking uses a different request shape); rejecting instead of silently dropping (I51)","type":"invalid_request_error"}}`
)

// n07t06SDKGateway is a recording gateway double: it captures every request
// body verbatim and answers each call with the next scripted response.
func n07t06SDKGateway(t *testing.T, responses ...string) (baseURL string, bodies func() []string) {
	t.Helper()
	var mu sync.Mutex
	var reqs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, string(b))
		i := len(reqs) - 1
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(responses[i], "data: ") {
			w.Header().Set("Content-Type", "text/event-stream")
		}
		if strings.HasPrefix(responses[i], `{"error"`) {
			w.WriteHeader(http.StatusBadRequest)
		}
		_, _ = w.Write([]byte(responses[i]))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(reqs))
		copy(out, reqs)
		return out
	}
}

// n07t06AssertContains fails the test unless s contains every want substring.
func n07t06AssertContains(t *testing.T, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("expected %q in %q", w, s)
		}
	}
}

// TestJointSession_OwnSDK walks the own stdlib client through the packet's
// joint scenario: extensions out via Extra (top level, effort as a raw
// field), provider extensions back verbatim, refusal and tool calls decoded
// through the any-typed choice maps, and the refusal envelope surfacing the
// exact T05 reason through the error path.
func TestJointSession_OwnSDK(t *testing.T) {
	base, bodies := n07t06SDKGateway(t, n07t06SDKCompletion, n07t06SDKRefusal400)
	client, err := New(Config{BaseURL: base, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()

	// Turn 1 — extensions + effort out via Extra; the merged body reaches
	// the gateway verbatim (T04 marshal mechanism).
	resp, err := client.Chat(ctx, ChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []Message{{Role: "user", Content: "Погода в Москве?"}},
		Extra: map[string]json.RawMessage{
			"reasoning_effort": json.RawMessage(`"high"`),
			"x_client_ext":     json.RawMessage(`{"trace":"t06"}`),
		},
	})
	if err != nil {
		t.Fatalf("turn 1: %v", err)
	}

	sent := bodies()[0]
	n07t06AssertContains(t, sent, `"reasoning_effort":"high"`, `"x_client_ext":{"trace":"t06"}`)

	// Inbound: provider extensions captured verbatim in Extra (exact bytes);
	// refusal and tool calls ride the any-typed choice maps (T03 facet).
	if got, want := string(resp.Extra["provider_ext"]), `{"trace":"t06"}`; got != want {
		t.Errorf("provider_ext = %q, want %q", got, want)
	}
	if got, want := string(resp.Extra["x_provider_usage"]), `{"cached":true}`; got != want {
		t.Errorf("x_provider_usage = %q, want %q", got, want)
	}
	msg, _ := resp.Choices[0]["message"].(map[string]any)
	if msg == nil {
		t.Fatalf("choice message missing: %v", resp.Choices[0])
	}
	if got, want := msg["refusal"], "Я не могу помочь с этим."; got != want {
		t.Errorf("refusal = %v, want %v", got, want)
	}
	toolCalls, _ := msg["tool_calls"].([]any)
	if len(toolCalls) != 1 {
		t.Fatalf("tool_calls = %v, want exactly one call", toolCalls)
	}
	fn, _ := toolCalls[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "get_weather" {
		t.Errorf("tool name = %v, want get_weather", fn["name"])
	}
	if fn["arguments"] != `{"city":"Москва"}` {
		t.Errorf("tool arguments = %v, want the original JSON bytes", fn["arguments"])
	}
	if resp.Choices[0]["finish_reason"] != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", resp.Choices[0]["finish_reason"])
	}
	if resp.Usage["total_tokens"] != float64(10) {
		t.Errorf("usage total = %v, want 10", resp.Usage["total_tokens"])
	}

	// Turn 2 — the translated-route refusal (T05 negative): the own client
	// surfaces the exact reason through the error path.
	_, err = client.Chat(ctx, ChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []Message{{Role: "user", Content: "hi"}},
		Extra:    map[string]json.RawMessage{"reasoning_effort": json.RawMessage(`"high"`)},
	})
	if err == nil {
		t.Fatalf("turn 2 must fail with the refusal envelope")
	}
	n07t06AssertContains(t, err.Error(), "400", "reasoning_effort", "rejecting instead of silently dropping (I51)")
}

// TestJointSession_PinnedOpenAI walks the pinned third-party client through
// the same scenario with its typed fields: ReasoningEffort, tools and
// stream usage marshal natively; the refusal and tool calls decode through
// the typed response; the translated-route refusal decodes as APIError.
// Provider-extension keys are outside the pinned client's schema and are
// dropped by its decoder — the documented consumer-side gap that motivates
// the own client's Extra (asserted in TestJointSession_OwnSDK).
func TestJointSession_PinnedOpenAI(t *testing.T) {
	base, bodies := n07t06SDKGateway(t, n07t06SDKCompletion, n07t06SDKSSE, n07t06SDKRefusal400)
	cfg := openai.DefaultConfig("test-key")
	cfg.BaseURL = base
	client := openai.NewClientWithConfig(cfg)
	ctx := context.Background()

	// Turn 1 — the packet's typed field set on one request. The pinned SDK
	// (v1.41.2) marshals ReasoningEffort natively; per-message extensions
	// are not expressible in this version (no Extra on
	// ChatCompletionMessage) and stay a top-level mechanism only.
	req := openai.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []openai.ChatCompletionMessage{{
			Role:    openai.ChatMessageRoleUser,
			Content: "Погода в Москве?",
		}},
		ReasoningEffort: "high",
		Tools: []openai.Tool{{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:       "get_weather",
				Parameters: json.RawMessage(`{"type":"object"}`),
			},
		}},
		ToolChoice:     "auto",
		ResponseFormat: &openai.ChatCompletionResponseFormat{Type: openai.ChatCompletionResponseFormatTypeText},
		StreamOptions:  &openai.StreamOptions{IncludeUsage: true},
	}
	resp, err := client.CreateChatCompletion(ctx, req)
	if err != nil {
		t.Fatalf("turn 1: %v", err)
	}

	// Outbound: every packet field reached the gateway on the wire.
	n07t06AssertContains(t, bodies()[0],
		`"reasoning_effort":"high"`, `"tool_choice":"auto"`,
		`"response_format":{"type":"text"}`, `"stream_options":{"include_usage":true}`)

	// Inbound: refusal, tool call and usage decode without loss (facets 2+3;
	// provider_ext/x_provider_usage are silently dropped by this client's
	// schema — the documented gap).
	if got, want := resp.Choices[0].Message.Refusal, "Я не могу помочь с этим."; got != want {
		t.Errorf("refusal = %q, want %q", got, want)
	}
	if len(resp.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("tool_calls = %v, want exactly one call", resp.Choices[0].Message.ToolCalls)
	}
	call := resp.Choices[0].Message.ToolCalls[0]
	if call.Function.Name != "get_weather" {
		t.Errorf("tool name = %q, want get_weather", call.Function.Name)
	}
	if call.Function.Arguments != `{"city":"Москва"}` {
		t.Errorf("tool arguments = %q, want the original JSON bytes", call.Function.Arguments)
	}
	if resp.Usage.TotalTokens != 10 {
		t.Errorf("usage total = %d, want 10", resp.Usage.TotalTokens)
	}

	// Turn 2 — streaming with include_usage: the usage-only chunk decodes
	// through the pinned stream reader (T02 facet; the RM-03 suppression
	// side is pinned gateway-side and never triggers here).
	stream, err := client.CreateChatCompletionStream(ctx, req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer func() { _ = stream.Close() }()

	var sawContent, sawUsage bool
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			sawContent = true
			if got := chunk.Choices[0].Delta.Content; got != "Привет" {
				t.Errorf("content = %q, want Привет", got)
			}
		}
		if chunk.Usage != nil {
			sawUsage = true
			if chunk.Usage.PromptTokens != 6 || chunk.Usage.TotalTokens != 8 {
				t.Errorf("usage chunk = %d/%d, want 6 prompt/8 total",
					chunk.Usage.PromptTokens, chunk.Usage.TotalTokens)
			}
		}
	}
	if !sawContent {
		t.Errorf("content chunk must decode")
	}
	if !sawUsage {
		t.Errorf("usage chunk must decode when the client asked for usage")
	}

	// Turn 3 — the translated-route refusal (T05 negative) decodes as
	// APIError with the exact reason; the session stays fully typed.
	_, err = client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:           "gpt-4o-mini",
		Messages:        []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "hi"}},
		ReasoningEffort: "high",
	})
	if err == nil {
		t.Fatalf("turn 3 must fail with the refusal envelope")
	}
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error must decode as *openai.APIError, got %T: %v", err, err)
	}
	if apiErr.Type != "invalid_request_error" {
		t.Errorf("type = %q, want invalid_request_error", apiErr.Type)
	}
	n07t06AssertContains(t, apiErr.Message, "reasoning_effort", "rejecting instead of silently dropping (I51)")
}
