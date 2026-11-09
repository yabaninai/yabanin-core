// Package provider — wire-level tests for the native Bedrock adapter
// (N08-P02-T02). The httptest stub speaks Bedrock-shaped wire contracts
// (Converse REST JSON, binary ConverseStream eventstream frames); the tests
// prove the adapter/boundary plumbing through the SAME provider.Pool and
// stream-handler seams production uses — not AWS attestation (no live
// Converse call is possible offline; recorded as an honest gap).
package provider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	eventstream "github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bedrockModelID = "anthropic.claude-3-5-sonnet-20241022-v2:0"

const bedrockConverseOutput = `{"output":{"message":{"role":"assistant","content":[{"text":"pong"}]}},"stopReason":"end_turn","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15,"cacheReadInputTokens":4,"cacheWriteInputTokens":2}}`

// bedrockEvent is one ConverseStream eventstream frame in the stub script.
type bedrockEvent struct {
	eventType     string // ":event-type" for events, "" for exceptions
	exceptionType string // ":exception-type" when non-empty
	payload       string
}

// encodeEvents serialises frames with the same encoder production decoders
// expect (CRC-checked AWS eventstream framing).
func encodeEvents(t *testing.T, events []bedrockEvent) []byte {
	t.Helper()
	enc := eventstream.NewEncoder()
	var buf bytes.Buffer
	for _, ev := range events {
		if ev.exceptionType != "" {
			hdrs := eventstream.Headers{
				{Name: ":message-type", Value: eventstream.StringValue("exception")},
				{Name: ":exception-type", Value: eventstream.StringValue(ev.exceptionType)},
				{Name: ":content-type", Value: eventstream.StringValue("application/json")},
			}
			require.NoError(t, enc.Encode(&buf, eventstream.Message{Headers: hdrs, Payload: []byte(ev.payload)}))
			continue
		}
		hdrs := eventstream.Headers{
			{Name: ":message-type", Value: eventstream.StringValue("event")},
			{Name: ":event-type", Value: eventstream.StringValue(ev.eventType)},
			{Name: ":content-type", Value: eventstream.StringValue("application/json")},
		}
		require.NoError(t, enc.Encode(&buf, eventstream.Message{Headers: hdrs, Payload: []byte(ev.payload)}))
	}
	return buf.Bytes()
}

func newBedrockPool(t *testing.T, srvURL string) *upstream.Pool {
	t.Helper()
	return upstream.NewPool(upstream.Options{AllowedUpstreams: []string{srvURL}})
}

// bedrockStubEnv pins ambient AWS identity to harmless stub values so the
// DefaultChain resolves from env (no IMDS/SSO probing on dev machines).
// Must NOT run under t.Parallel (process-global env); all wire tests are
// therefore sequential.
func bedrockStubEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDBEDROCKWIRETEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "stub-secret-not-a-real-credential")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestBedrockWire_NonStreamingConverse(t *testing.T) {
	bedrockStubEnv(t)

	var mu sync.Mutex
	var gotPath, gotAuth, gotContentType, gotAPIKey string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.EscapedPath()
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotAPIKey = r.Header.Get("X-Api-Key")
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bedrockConverseOutput))
	}))
	t.Cleanup(srv.Close)

	client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
	require.NoError(t, err)
	require.Equal(t, "bedrock", client.Adapter().Name())

	chat := []byte(`{"model":"ignored-by-override","messages":[{"role":"user","content":"ping"}],"max_tokens":64}`)
	_, respBody, sent, ferr := client.ForwardJSONCapturing(context.Background(), chat, bedrockModelID, "", 2*time.Second)
	require.NoError(t, ferr)

	// Wire: fixed Converse suffix, escaped modelId, SigV4 identity, and no
	// static bearer/api key anywhere (I49: DefaultChain identity).
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse", gotPath)
	assert.True(t, strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256"), "got %q", gotAuth)
	assert.NotContains(t, gotAuth, "Bearer")
	assert.Empty(t, gotAPIKey)
	assert.Equal(t, "application/json", gotContentType)

	// The envelope never reaches the wire: bare Converse payload only, and
	// the modelId appears nowhere in the body (it rides the path).
	assert.NotContains(t, string(gotBody), `"model"`)
	assert.Contains(t, string(gotBody), `"messages"`)

	// Response translated to the OpenAI contract.
	var out struct {
		Object  string `json:"object"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(respBody, &out))
	assert.Equal(t, "chat.completion", out.Object)
	require.Len(t, out.Choices, 1)
	assert.Equal(t, "pong", out.Choices[0].Message.Content)
	assert.Equal(t, "stop", out.Choices[0].FinishReason)
	assert.InDelta(t, float64(16), out.Usage["prompt_tokens"].(float64), 1e-9) // 10 + 4 read + 2 write

	// upstream.Client captures the TRANSLATED envelope (pre-PrepareRequest);
	// the wire body is the unwrapped Converse payload. Together they prove
	// the full chain: TranslateRequest → OverrideModel(registry model into
	// envelope) → PrepareRequest unwrap → bare Converse on the wire.
	require.NotEmpty(t, sent)
	var sentEnv struct {
		Model    string          `json:"model"`
		Converse json.RawMessage `json:"converse"`
	}
	require.NoError(t, json.Unmarshal(sent, &sentEnv))
	assert.Equal(t, bedrockModelID, sentEnv.Model)
	require.NotEmpty(t, sentEnv.Converse)
	assert.JSONEq(t, string(gotBody), string(sentEnv.Converse))

	// Usage through the adapter for billing.
	u := client.Adapter().ParseUsage(respBody)
	assert.Equal(t, provider.UsageSourceProvider, u.Source)
	assert.Equal(t, int64(16), u.PromptTokens)
	assert.Equal(t, int64(5), u.CompletionTokens)
	assert.Equal(t, int64(4), u.CacheReadTokens)
	assert.Equal(t, int64(2), u.CacheCreationTokens)
}

func TestBedrockWire_RefusalPassesThroughUnrewritten(t *testing.T) {
	bedrockStubEnv(t)

	const refusal = `{"message":"User is not authorized to perform: bedrock:InvokeModel on resource: arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0 because no identity-based policy allows the bedrock:InvokeModel action"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(refusal))
	}))
	t.Cleanup(srv.Close)

	client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
	require.NoError(t, err)

	chat := []byte(`{"model":"` + bedrockModelID + `","messages":[{"role":"user","content":"ping"}]}`)
	_, _, ferr := client.ForwardJSONWithHeaders(context.Background(), chat, bedrockModelID, "", 2*time.Second)
	require.Error(t, ferr)

	var upErr *upstream.Error
	require.ErrorAs(t, ferr, &upErr, "want upstream.Error, got %T: %v", ferr, ferr)
	assert.Equal(t, http.StatusForbidden, upErr.Status)
	// I51: precise upstream refusal texts pass through unrewritten.
	assert.JSONEq(t, refusal, upErr.Body)
	assert.Contains(t, ferr.Error(), refusal)
}

func TestBedrockWire_StreamEventstreamToSSE(t *testing.T) {
	bedrockStubEnv(t)

	frames := encodeEvents(t, []bedrockEvent{
		{eventType: "messageStart", payload: `{"role":"assistant"}`},
		{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"He"}}`},
		{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"y"}}`},
		{eventType: "messageStop", payload: `{"stopReason":"end_turn"}`},
		{eventType: "metadata", payload: `{"usage":{"inputTokens":10,"outputTokens":3,"totalTokens":13,"cacheReadInputTokens":4},"metrics":{"latencyMs":42}}`},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write(frames)
	}))
	t.Cleanup(srv.Close)

	client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
	require.NoError(t, err)

	chat := upstream.OverrideModel([]byte(`{"model":"any-alias","messages":[{"role":"user","content":"hi"}],"stream":true}`), bedrockModelID)
	resp, err := client.Stream(context.Background(), chat, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	w, buf := newWireRecorder()
	h := provider.NewStreamHandlerWithOptions("bedrock", bedrockModelID, provider.StreamOptions{})
	usage, derr := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, derr)

	// [DONE]-equivalent end: Bedrock's metadata event terminates the OpenAI
	// stream; the handler must always emit `data: [DONE]` afterwards.
	sseFrames := strings.Split(strings.TrimSpace(buf.String()), "\n\n")
	require.GreaterOrEqual(t, len(sseFrames), 5, "role + 2 deltas + finish + usage chunks expected, got:\n%s", buf.String())
	assert.Equal(t, "data: [DONE]", sseFrames[len(sseFrames)-1])

	var chunks []map[string]any
	for _, f := range sseFrames[:len(sseFrames)-1] {
		require.True(t, strings.HasPrefix(f, "data: "), "frame %q", f)
		var c map[string]any
		require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(f, "data: ")), &c))
		require.Equal(t, "chat.completion.chunk", c["object"])
		assert.Equal(t, bedrockModelID, c["model"])
		chunks = append(chunks, c)
	}

	// role chunk → content chunks → finish chunk → usage-only chunk.
	require.Len(t, chunks, 5)
	first := chunks[0]["choices"].([]any)[0].(map[string]any)
	assert.Equal(t, map[string]any{"role": "assistant"}, first["delta"])

	second := chunks[1]["choices"].([]any)[0].(map[string]any)
	assert.Equal(t, map[string]any{"content": "He"}, second["delta"])
	third := chunks[2]["choices"].([]any)[0].(map[string]any)
	assert.Equal(t, map[string]any{"content": "y"}, third["delta"])

	finish := chunks[3]["choices"].([]any)[0].(map[string]any)
	assert.Equal(t, "stop", finish["finish_reason"])

	usageChunk := chunks[4]
	assert.Equal(t, []any{}, usageChunk["choices"])
	u := usageChunk["usage"].(map[string]any)
	assert.InDelta(t, float64(14), u["prompt_tokens"].(float64), 1e-9) // 10 + 4 cache read
	assert.InDelta(t, float64(3), u["completion_tokens"].(float64), 1e-9)
	assert.InDelta(t, float64(13), u["total_tokens"].(float64), 1e-9)
	assert.InDelta(t, float64(4), u["prompt_tokens_details"].(map[string]any)["cached_tokens"].(float64), 1e-9)

	// Returned Usage mirrors the metadata event (canonical fold).
	assert.Equal(t, provider.UsageSourceProvider, usage.Source)
	assert.Equal(t, int64(14), usage.PromptTokens)
	assert.Equal(t, int64(3), usage.CompletionTokens)
	assert.Equal(t, int64(13), usage.TotalTokens)
	assert.Equal(t, int64(4), usage.CacheReadTokens)
}

func TestBedrockWire_StreamSuppressUsageOnlyChunk(t *testing.T) {
	bedrockStubEnv(t)

	frames := encodeEvents(t, []bedrockEvent{
		{eventType: "messageStart", payload: `{"role":"assistant"}`},
		{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"hi"}}`},
		{eventType: "messageStop", payload: `{"stopReason":"max_tokens"}`},
		{eventType: "metadata", payload: `{"usage":{"inputTokens":2,"outputTokens":1,"totalTokens":3}}`},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(frames)
	}))
	t.Cleanup(srv.Close)

	client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
	require.NoError(t, err)

	chat := []byte(`{"model":"` + bedrockModelID + `","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	resp, err := client.Stream(context.Background(), chat, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	w, buf := newWireRecorder()
	h := provider.NewStreamHandlerWithOptions("bedrock", bedrockModelID, provider.StreamOptions{SuppressUsageOnlyChunk: true})
	usage, derr := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, derr)

	// Usage is still parsed for billing…
	assert.Equal(t, int64(2), usage.PromptTokens)
	assert.Equal(t, int64(1), usage.CompletionTokens)
	// …but the client sees only role/content/finish + [DONE].
	out := buf.String()
	assert.NotContains(t, out, `"usage"`)
	assert.Contains(t, out, `"finish_reason":"length"`)
	assert.True(t, strings.HasSuffix(strings.TrimSpace(out), "data: [DONE]"))
}

func TestBedrockWire_StreamExceptionRefusalVerbatim(t *testing.T) {
	bedrockStubEnv(t)

	frames := encodeEvents(t, []bedrockEvent{
		{eventType: "messageStart", payload: `{"role":"assistant"}`},
		{exceptionType: "ThrottlingException", payload: `{"message":"Rate exceeded for model anthropic.claude-3-5-sonnet-20241022-v2:0"}`},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(frames)
	}))
	t.Cleanup(srv.Close)

	client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
	require.NoError(t, err)

	chat := []byte(`{"model":"` + bedrockModelID + `","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	resp, err := client.Stream(context.Background(), chat, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	w, _ := newWireRecorder()
	h := provider.NewStreamHandlerWithOptions("bedrock", bedrockModelID, provider.StreamOptions{})
	_, derr := h.HandleStream(context.Background(), w, w, resp)
	require.Error(t, derr)
	// I51: the provider's precise refusal text passes through unrewritten.
	assert.Contains(t, derr.Error(), "bedrock stream exception ThrottlingException:")
	assert.Contains(t, derr.Error(), "Rate exceeded for model anthropic.claude-3-5-sonnet-20241022-v2:0")
}

func TestBedrockWire_FactoryAndTemplatePaths(t *testing.T) {
	bedrockStubEnv(t)

	adapter, err := provider.New("bedrock")
	require.NoError(t, err)
	assert.Equal(t, "bedrock", adapter.Name())
	assert.Equal(t, "/model/{model}/converse", adapter.Path(false))
	assert.Equal(t, "/model/{model}/converse-stream", adapter.Path(true))

	// Unknown names keep failing fast at the factory boundary.
	_, err = provider.New("bedrock-stream")
	assert.Error(t, err)
}

// wireRecorder is the external-package twin of the internal recorderFlusher:
// it captures written bytes and satisfies http.Flusher.
type wireRecorder struct {
	*httptest.ResponseRecorder
}

func (wireRecorder) Flush() {}

func newWireRecorder() (*wireRecorder, *bytes.Buffer) {
	var buf bytes.Buffer
	r := httptest.NewRecorder()
	r.Body = &buf
	return &wireRecorder{ResponseRecorder: r}, &buf
}
