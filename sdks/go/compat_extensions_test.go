package yabanin

// N07-P01-T04 — response extensions decode via SDK mechanisms (facet 3,
// artifacts/internal-delivery-program/N07-P01/T01-scope-2026-10-30.md §4).
//
// Two decode mechanisms are proven side by side:
//
//  1. The pinned third-party OpenAI client (github.com/sashabaranov/go-openai
//     v1.41.2, the exact go.mod pin) must DECODE a completion carrying unknown
//     top-level / choice / message / usage extension keys without error and
//     without losing the typed fields it does model (tolerance proof).
//  2. The own SDK must CAPTURE those unknown top-level keys verbatim in
//     ChatResponse.Extra — the field the packet calls the explicit
//     pass-through mechanism. Extension integers beyond float64's 2^53
//     window must keep their exact literal (RawMessage, not float64).
//
// The request-side counterpart (ChatRequest.Extra) is pinned in
// compat_extensions_request_test.go, added together with the mechanism.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// extensionsCompletionBody is a gateway-style completion carrying provider
// extensions a narrow typed struct would drop: unknown top-level keys, an
// unknown per-message key, an unknown per-choice key, an unknown usage key —
// plus a big integer (2^53+1) that float64 re-encoding would corrupt.
const extensionsCompletionBody = `{"id":"cmpl-ext","object":"chat.completion","created":1760000000,"model":"gpt-4o-mini",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"ok","x_upstream_msg":"msg-ext"},` +
	`"x_upstream_choice":"choice-ext","logprobs":null,"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2,"x_upstream_usage":42},` +
	`"system_fingerprint":"fp-ext","x_provider_ext":{"tier":"gold","rank":9007199254740993},"x_seq":9007199254740993}`

// compactRaw normalizes a RawMessage for byte comparison (captured values
// keep the encoder's exact spacing).
func compactRaw(t *testing.T, v json.RawMessage) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, v); err != nil {
		t.Fatalf("compact extension value: %v", err)
	}
	return buf.String()
}

// ownSDKClient returns the own SDK client aimed at a test double replying
// with body.
func ownSDKClient(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("own SDK client: %v", err)
	}
	return c
}

// TestChatResponse_ExtraCapturesUnknownTopLevelExtensions pins the own-SDK
// capture mechanism: unknown top-level keys land in ChatResponse.Extra
// verbatim (big ints exact), typed fields still decode.
func TestChatResponse_ExtraCapturesUnknownTopLevelExtensions(t *testing.T) {
	c := ownSDKClient(t, extensionsCompletionBody)
	resp, err := c.Chat(context.Background(), ChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("chat with extension-bearing response: %v", err)
	}

	// Typed fields must decode exactly as before.
	if resp.ID != "cmpl-ext" {
		t.Errorf("ID lost: got %q", resp.ID)
	}
	if resp.Model != "gpt-4o-mini" {
		t.Errorf("model lost: got %q", resp.Model)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("choices lost: got %+v", resp.Choices)
	}
	msg, _ := resp.Choices[0]["message"].(map[string]any)
	if msg == nil || msg["content"] != "ok" {
		t.Errorf("choice message content lost: got %+v", resp.Choices[0])
	}

	// The capture mechanism: unknown top-level keys verbatim, unknown keys only
	// (typed keys are not duplicated into Extra).
	if resp.Extra == nil {
		t.Fatalf("Extra must capture unknown top-level extension keys, got nil")
	}
	if got := compactRaw(t, resp.Extra["x_provider_ext"]); got != `{"tier":"gold","rank":9007199254740993}` {
		t.Errorf("nested extension value must keep exact number literals, got %s", got)
	}
	if got := compactRaw(t, resp.Extra["x_seq"]); got != `9007199254740993` {
		t.Errorf("big-int extension scalar must not be re-encoded through float64, got %s", got)
	}
	if got := compactRaw(t, resp.Extra["system_fingerprint"]); got != `"fp-ext"` {
		t.Errorf("system_fingerprint must be captured as unknown key, got %s", got)
	}
	for _, typed := range []string{"id", "choices", "usage"} {
		if _, dup := resp.Extra[typed]; dup {
			t.Errorf("typed key %q must not be duplicated into Extra", typed)
		}
	}
}

// TestOpenAICompat_ResponseExtensionFieldsTolerated pins the pinned-client
// tolerance proof: go-openai v1.41.2 decodes the same extension-bearing
// completion without error and without losing modeled fields (unknown keys
// are ignored, unknown nested values ride in the raw JSON it does not see).
func TestOpenAICompat_ResponseExtensionFieldsTolerated(t *testing.T) {
	client := openaiContractClient(t, http.StatusOK, "application/json", extensionsCompletionBody)
	resp, err := client.CreateChatCompletion(context.Background(), contractChatRequest())
	if err != nil {
		t.Fatalf("extension keys must not break the pinned client's decode: %v", err)
	}

	if resp.ID != "cmpl-ext" || resp.Model != "gpt-4o-mini" {
		t.Errorf("typed top-level fields lost: id=%q model=%q", resp.ID, resp.Model)
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message.Content != "ok" {
		t.Errorf("typed choice fields lost: %+v", resp.Choices)
	}
	if resp.SystemFingerprint != "fp-ext" {
		t.Errorf("system_fingerprint lost: got %q", resp.SystemFingerprint)
	}
	if resp.Usage.TotalTokens != 2 {
		t.Errorf("usage lost: %+v", resp.Usage)
	}
}

// TestOpenAICompat_StreamExtensionChunksTolerated pins the streaming half of
// the tolerance proof: unknown chunk-level and delta-level keys must not
// break the pinned client's SSE decode; modeled fields still accumulate.
func TestOpenAICompat_StreamExtensionChunksTolerated(t *testing.T) {
	const sse = "data: {\"id\":\"c1\",\"x_chunk_ext\":\"chunk-keep\",\"object\":\"chat.completion.chunk\",\"created\":1760000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"he\",\"x_delta_ext\":\"delta-keep\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"c1\",\"x_chunk_ext\":\"chunk-keep2\",\"object\":\"chat.completion.chunk\",\"created\":1760000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"llo\",\"x_delta_ext\":\"delta-keep\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	client := openaiContractClient(t, http.StatusOK, "text/event-stream", sse)

	stream, err := client.CreateChatCompletionStream(context.Background(), contractChatRequest())
	if err != nil {
		t.Fatalf("extension keys must not break the pinned client's stream open: %v", err)
	}
	defer stream.Close() //nolint:errcheck // test double stream

	content := ""
	for {
		chunk, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("extension keys must not break stream recv: %v", rerr)
		}
		for _, ch := range chunk.Choices {
			content += ch.Delta.Content
		}
	}
	if content != "hello" {
		t.Errorf("content must accumulate across extension-bearing frames, got %q", content)
	}
}
