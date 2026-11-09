package yabanin

// N07-P01-T08 — retry/recovery corpus, consumer seat (MOCK).
//
// Card action: «Проверить interruption/retry/resume и восстановление
// результатов без дубликатов и потерь» — the consumer half of the recovery
// corpus. The gateway-side legs live in
// pkg/gateway/n07p1t08_retry_recovery_test.go; this file pins what the
// shipped clients see of recovery:
//   - pinned client (pinned go-openai v1.41.2): internal gateway recovery is
//     TRANSPARENT — the consumer sees exactly one canonical completion with
//     typed usage, no duplicate bodies and no retried-away fragments; and
//     recovery EXHAUSTION (every hop refused) surfaces as *openai.APIError
//     with the exact refusal reason, still readable;
//   - own client: the exhaustion envelope arrives as a plain error carrying
//     the exact reason — a consumer on the own SDK can act on it.
//
// The exhaustion envelope bytes are recorded from the wire-level REC-02 leg
// (TestN07P1T08_AllHopsRefuse_TypedTerminal_LedgerSilent render).
//
// Assertions stay on the stdlib testing package — the SDK module
// deliberately carries no test dependencies beyond the pinned client.
//
// Stable IDs: N07P1T08-SDK-01..03.

import (
	"context"
	"errors"
	"strings"
	"testing"

	openai "github.com/sashabaranov/go-openai"
)

// The all-hops-refuse terminal envelope, recorded from the gateway REC-02
// render (translate wrap + exact T07 reason).
const n07t08SDKExhaustion = `{"error":{"message":"translate request: anthropic: reasoning_effort \"high\" is not mapped (Anthropic thinking uses a different request shape); rejecting instead of silently dropping (I51)","type":"invalid_request_error"}}`

// TestJointRecovery_PinnedOpenAIRetryTransparent (SDK-01): the pinned
// client sends one request; behind it the gateway retried a transient 503
// and served the winning completion. The consumer sees exactly one typed
// completion — recovery adds no duplicate bodies, no error, no extra
// choices.
func TestJointRecovery_PinnedOpenAIRetryTransparent(t *testing.T) {
	completion := `{"id":"chatcmpl-t08r","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ок-t08"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`
	base, bodies := n07t06SDKGateway(t, completion)
	cfg := openai.DefaultConfig("test-key")
	cfg.BaseURL = base
	client := openai.NewClientWithConfig(cfg)

	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model:    "m",
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "Привет"}},
	})
	if err != nil {
		t.Fatalf("recovered completion must read as a normal completion: %v", err)
	}
	if resp.ID != "chatcmpl-t08r" || resp.Choices[0].Message.Content != "ок-t08" {
		t.Fatalf("typed content mismatch: %+v", resp.Choices[0].Message)
	}
	if resp.Usage.PromptTokens != 5 || resp.Usage.CompletionTokens != 3 {
		t.Fatalf("typed usage mismatch: %+v", resp.Usage)
	}
	bodies()
}

// TestJointRecovery_PinnedOpenAIExhaustionEnvelope (SDK-02): recovery
// exhaustion (every hop refused) decodes as *openai.APIError with the exact
// refusal reason — the pinned client's behavior is unchanged and the
// terminal negative stays readable for the consumer.
func TestJointRecovery_PinnedOpenAIExhaustionEnvelope(t *testing.T) {
	base, _ := n07t06SDKGateway(t, n07t08SDKExhaustion)
	cfg := openai.DefaultConfig("test-key")
	cfg.BaseURL = base
	client := openai.NewClientWithConfig(cfg)

	_, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model:    "smart-claude",
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("exhaustion must surface as an error")
	}
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *openai.APIError, got %T: %v", err, err)
	}
	if apiErr.Type != "invalid_request_error" {
		t.Fatalf("error type: %q", apiErr.Type)
	}
	want := `reasoning_effort "high" is not mapped (Anthropic thinking uses a different request shape); rejecting instead of silently dropping (I51)`
	if !strings.Contains(apiErr.Message, want) {
		t.Fatalf("exhaustion reason not readable: %q", apiErr.Message)
	}
}

// TestJointRecovery_OwnSDKExhaustionError (SDK-03): the own client surfaces
// the exhaustion envelope as a plain error carrying the exact refusal
// reason — the consumer can act on it (retry policy, user messaging).
func TestJointRecovery_OwnSDKExhaustionError(t *testing.T) {
	base, _ := n07t06SDKGateway(t, n07t08SDKExhaustion)
	client, err := New(Config{BaseURL: base, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	_, err = client.Chat(context.Background(), ChatRequest{
		Model:    "smart-claude",
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("exhaustion must surface as an error")
	}
	// The own client renders the raw envelope (JSON-escaped quotes) — the
	// escaped fragment is exactly what this consumer sees and can match on.
	want := `reasoning_effort \"high\" is not mapped`
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("exhaustion reason not carried: %v", err)
	}
}
