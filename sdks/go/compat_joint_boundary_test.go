package yabanin

// N07-P01-T07 — boundary corpus, consumer seat (MOCK).
//
// Card action: «Построить boundary corpus для трёх аспектов; проверить
// наблюдаемые ошибки и прежнее поведение» — the consumer half of the
// boundary corpus. The gateway-side legs live in
// pkg/gateway/n07p1t07_boundary_corpus_test.go and
// pkg/provider/n07p1t07_boundary_corpus_test.go; this file pins what the
// shipped clients see at those boundaries:
//   - send boundary (own client): boundary values the typed schema cannot
//     express — an unknown tool_choice, an unmapped reasoning_effort —
//     ride via Extra verbatim, so the consumer can actually send them and
//     the upstream/gateway owns the verdict;
//   - decode boundary (pinned client): the two new T07 tool_choice
//     rejection envelopes decode as *openai.APIError with the exact
//     reason — the pinned client's behavior is unchanged and the observed
//     errors stay readable (the negative criterion's "same pinned SDK").
//
// Assertions stay on the stdlib testing package — the SDK module
// deliberately carries no test dependencies beyond the pinned client.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	openai "github.com/sashabaranov/go-openai"
)

// Canonical boundary envelopes recorded from the gateway legs — the same
// bytes the wire-level corpus asserts, in the T05 envelope shape.
const (
	n07t07SDKToolChoiceUnknown = `{"error":{"message":"translate request: anthropic: unsupported tool_choice \"banana\"; rejecting instead of silently dropping (I51)","type":"invalid_request_error"}}`
	n07t07SDKToolChoiceShape   = `{"error":{"message":"translate request: anthropic: tool_choice must be \"auto\"|\"none\"|\"required\" or {\"type\":\"function\",\"function\":{\"name\":…}}; rejecting instead of silently dropping (I51)","type":"invalid_request_error"}}`
)

// TestJointSessionBoundary_OwnSDKSend: boundary values that no typed field
// expresses go out via Extra verbatim — the consumer's send boundary holds.
func TestJointSessionBoundary_OwnSDKSend(t *testing.T) {
	base, bodies := n07t06SDKGateway(t, n07t06SDKCompletion)
	client, err := New(Config{BaseURL: base, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	_, err = client.Chat(context.Background(), ChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []Message{{Role: "user", Content: "hi"}},
		Extra: map[string]json.RawMessage{
			"tool_choice":      json.RawMessage(`"banana"`),
			"reasoning_effort": json.RawMessage(`"ultra"`),
		},
	})
	if err != nil {
		t.Fatalf("boundary values must reach the gateway for the upstream's verdict: %v", err)
	}
	n07t06AssertContains(t, bodies()[0],
		`"tool_choice":"banana"`, `"reasoning_effort":"ultra"`)
}

// TestJointSessionBoundary_PinnedOpenAIDecode: the new T07 tool_choice
// rejection envelopes decode as *openai.APIError with the exact reason —
// the pinned client's behavior is unchanged (the negative criterion).
func TestJointSessionBoundary_PinnedOpenAIDecode(t *testing.T) {
	base, _ := n07t06SDKGateway(t, n07t07SDKToolChoiceUnknown, n07t07SDKToolChoiceShape)
	cfg := openai.DefaultConfig("test-key")
	cfg.BaseURL = base
	client := openai.NewClientWithConfig(cfg)
	ctx := context.Background()

	want := []string{
		`unsupported tool_choice "banana"`,
		`tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`,
	}
	for i, reason := range want {
		_, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
			Model:    "gpt-4o-mini",
			Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "hi"}},
		})
		if err == nil {
			t.Fatalf("case %d: the boundary rejection must surface as an error", i)
		}
		var apiErr *openai.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("case %d: error must decode as *openai.APIError, got %T: %v", i, err, err)
		}
		if apiErr.Type != "invalid_request_error" {
			t.Errorf("case %d: type = %q, want invalid_request_error", i, apiErr.Type)
		}
		if !strings.Contains(apiErr.Message, reason) {
			t.Errorf("case %d: message %q must contain %q", i, apiErr.Message, reason)
		}
		if !strings.Contains(apiErr.Message, "rejecting instead of silently dropping (I51)") {
			t.Errorf("case %d: message %q must carry the contract phrase", i, apiErr.Message)
		}
	}
}
