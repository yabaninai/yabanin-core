package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bedrockStubCreds is a minimal aws.CredentialsProvider so tests never touch
// the environment DefaultChain (and the credentials package stays indirect).
type bedrockStubCreds struct{}

func (bedrockStubCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "testsecret"}, nil
}

func newBedrockTestAdapter(region string) *Bedrock {
	return NewBedrockWithConfig(aws.Config{Region: region, Credentials: bedrockStubCreds{}})
}

const bedrockOpenaiBody = `{"model":"anthropic.claude-3-5-sonnet-20241022-v2:0","messages":[{"role":"system","content":"Be terse."},{"role":"user","content":"ping"}],"max_completion_tokens":77,"temperature":0.5,"top_p":0.9,"stop":["END"]}`

func TestBedrockTranslateRequest_EnvelopeAndConverse(t *testing.T) {
	t.Parallel()
	b := &Bedrock{}
	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)

	var env bedrockEnvelope
	require.NoError(t, json.Unmarshal(out, &env))
	assert.Equal(t, "anthropic.claude-3-5-sonnet-20241022-v2:0", env.Model)

	var conv bedrockConverseInput
	require.NoError(t, json.Unmarshal(env.Converse, &conv))
	require.Len(t, conv.System, 1)
	assert.Equal(t, "Be terse.", conv.System[0].Text)
	require.Len(t, conv.Messages, 1)
	assert.Equal(t, "user", conv.Messages[0].Role)
	require.Len(t, conv.Messages[0].Content, 1)
	assert.Equal(t, "ping", conv.Messages[0].Content[0].Text)
	require.NotNil(t, conv.InferenceConfig)
	assert.Equal(t, 77, *conv.InferenceConfig.MaxTokens)
	assert.InDelta(t, 0.5, float64(*conv.InferenceConfig.Temperature), 1e-9)
	assert.InDelta(t, 0.9, float64(*conv.InferenceConfig.TopP), 1e-9)
	assert.Equal(t, []string{"END"}, conv.InferenceConfig.StopSequences)
	// The envelope must not leak the converse payload outside: modelId rides
	// the path segment, never a body field.
	assert.NotContains(t, string(env.Converse), `"model"`)
}

func TestBedrockTranslateRequest_ResponseFormatTextAccepted(t *testing.T) {
	// N07-P01-T03: response_format {"type":"text"} (and an absent field) is
	// the no-guarantee default — accepted as a no-op. json_object/json_schema
	// are rejected by the FailClosed table above.
	t.Parallel()
	for _, body := range []string{
		`{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":{"type":"text"}}`,
		`{"model":"m","messages":[{"role":"user","content":"x"}]}`,
	} {
		_, _, err := chatToBedrockConverse([]byte(body))
		require.NoError(t, err)
	}
}

func TestBedrockTranslateRequest_MaxTokensFallback(t *testing.T) {
	t.Parallel()
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"max_tokens":42}`
	out, err := (&Bedrock{}).TranslateRequest([]byte(body))
	require.NoError(t, err)
	var env bedrockEnvelope
	require.NoError(t, json.Unmarshal(out, &env))
	var conv bedrockConverseInput
	require.NoError(t, json.Unmarshal(env.Converse, &conv))
	require.NotNil(t, conv.InferenceConfig.MaxTokens)
	assert.Equal(t, 42, *conv.InferenceConfig.MaxTokens)
}

func TestBedrockTranslateRequest_MultipartAndDeveloper(t *testing.T) {
	t.Parallel()
	body := `{"model":"m","messages":[
		{"role":"system","content":"be nice"},
		{"role":"developer","content":"policy"},
		{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}]}`
	out, err := (&Bedrock{}).TranslateRequest([]byte(body))
	require.NoError(t, err)
	var env bedrockEnvelope
	require.NoError(t, json.Unmarshal(out, &env))
	var conv bedrockConverseInput
	require.NoError(t, json.Unmarshal(env.Converse, &conv))
	// system and developer roles both fold into Converse system blocks,
	// one per message (per text-part within a message).
	require.Len(t, conv.System, 2)
	assert.Equal(t, "be nice", conv.System[0].Text)
	assert.Equal(t, "policy", conv.System[1].Text)
	require.Len(t, conv.Messages, 1)
	require.Len(t, conv.Messages[0].Content, 2)
	assert.Equal(t, "a", conv.Messages[0].Content[0].Text)
	assert.Equal(t, "b", conv.Messages[0].Content[1].Text)
}

func TestBedrockTranslateRequest_FailClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string
	}{
		{"tools", `{"model":"m","messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{"name":"f"}}]}`, "tools/tool_choice are not supported"},
		{"tool_choice", `{"model":"m","messages":[{"role":"user","content":"x"}],"tool_choice":"auto"}`, "tools/tool_choice are not supported"},
		{"tool role", `{"model":"m","messages":[{"role":"tool","content":"r"}]}`, "tools/tool_choice are not supported"},
		{"assistant tool_calls", `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"1"}]}]}`, "tools/tool_choice are not supported"},
		{"image part", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x/y.png"}}]}]}`, "image inputs are not supported"},
		// N07-P05-T02 / F1 (T01 finding): unknown content-part types must be
		// rejected explicitly, never silently dropped from the Converse body.
		{"unknown part input_audio", `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`, `content part type "input_audio" is not mapped`},
		{"unknown part file", `{"model":"m","messages":[{"role":"user","content":[{"type":"file","file":{"file_data":"data:application/pdf;base64,AAAA"}}]}]}`, `content part type "file" is not mapped`},
		{"unknown part input_file", `{"model":"m","messages":[{"role":"user","content":[{"type":"input_file","input_file":{"filename":"x.pdf","file_data":"data:application/pdf;base64,AAAA"}}]}]}`, `content part type "input_file" is not mapped`},
		{"response_format json_object", `{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":{"type":"json_object"}}`, "response_format"},
		{"response_format json_schema", `{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":{"type":"json_schema","json_schema":{"name":"s"}}}`, "response_format"},
		{"response_format non-object", `{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":"bogus"}`, "decode response_format"},
		{"no model", `{"messages":[{"role":"user","content":"x"}]}`, "no model field"},
		{"no messages", `{"model":"m","messages":[]}`, "no user/assistant messages"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := chatToBedrockConverse([]byte(tc.body))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// N07-P05-T02: media-capability rejections are deterministic pre-flight
// client errors, so the adapter must surface them as a typed
// UnsupportedFeatureError — the gateway maps the type to an explicit
// 400 unsupported_feature answer instead of the opaque
// upstream_outcome_unknown 502 (and it must never pay a breaker penalty).
func TestBedrockUnsupportedFeatureErrorsAreTyped(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, body, wantProvider, wantReason string
	}{
		{
			"image part",
			`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x/y.png"}}]}]}`,
			"bedrock", "image inputs are not supported",
		},
		{
			"unknown input_audio part",
			`{"model":"m","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`,
			"bedrock", `content part type "input_audio" is not mapped`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := chatToBedrockConverse([]byte(tc.body))
			require.Error(t, err)
			var ufe *UnsupportedFeatureError
			require.ErrorAs(t, err, &ufe, "media rejection must be typed: %v", err)
			assert.Equal(t, tc.wantProvider, ufe.Provider)
			assert.Contains(t, ufe.Reason, tc.wantReason)
			assert.True(t, IsUnsupportedFeature(err))
			// Wire-compat: the full message keeps the adapter prefix.
			assert.Contains(t, err.Error(), tc.wantProvider+" adapter:")
		})
	}
}

func TestBedrockPathTemplates(t *testing.T) {
	t.Parallel()
	b := &Bedrock{}
	assert.Equal(t, "/model/{model}/converse", b.Path(false))
	assert.Equal(t, "/model/{model}/converse-stream", b.Path(true))
}

func TestBedrockSigv4EscapePath(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "anthropic.claude-3-5-sonnet-20241022-v2%3A0",
		sigv4EscapePath("anthropic.claude-3-5-sonnet-20241022-v2:0"))
	assert.Equal(t, "plain-id-1.0", sigv4EscapePath("plain-id-1.0"))
	assert.Equal(t, "a%20b", sigv4EscapePath("a b"))
}

func TestBedrockPrepareRequest_SignsConversePath(t *testing.T) {
	t.Parallel()
	b := newBedrockTestAdapter("us-east-1")
	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)

	req, err := b.PrepareRequest(context.Background(), "https://bedrock-runtime.us-east-1.amazonaws.com", b.Path(false), out, "ignored-api-key", false)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse", req.URL.EscapedPath())
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	auth := req.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256"), "SigV4 signature expected, got %q", auth)
	assert.Contains(t, auth, "Credential=") // scope carries the region/identity
	assert.NotContains(t, auth, "Bearer")   // never a static bearer key (I49 DefaultChain)
	assert.NotEmpty(t, req.Header.Get("X-Amz-Date"))
	// The apiKey parameter must not leak into any header.
	for k := range req.Header {
		assert.NotEqual(t, "X-Api-Key", k)
	}
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), `"envelope"`)
	assert.NotContains(t, string(body), `"model":`) // bare Converse payload on the wire
	assert.Contains(t, string(body), `"messages"`)
}

func TestBedrockPrepareRequest_StreamAcceptHeader(t *testing.T) {
	t.Parallel()
	b := newBedrockTestAdapter("us-east-1")
	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)

	req, err := b.PrepareRequest(context.Background(), "https://bedrock-runtime.us-east-1.amazonaws.com", b.Path(true), out, "", true)
	require.NoError(t, err)
	assert.Equal(t, "application/vnd.amazon.eventstream", req.Header.Get("Accept"))
	assert.Equal(t, "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse-stream", req.URL.EscapedPath())

	nonStream, err := b.PrepareRequest(context.Background(), "https://bedrock-runtime.us-east-1.amazonaws.com", b.Path(false), out, "", false)
	require.NoError(t, err)
	assert.Empty(t, nonStream.Header.Get("Accept"), "Accept: eventstream is stream-only")
}

func TestBedrockPrepareRequest_MissingRegionFailsClosed(t *testing.T) {
	t.Parallel()
	b := NewBedrockWithConfig(aws.Config{Credentials: bedrockStubCreds{}})
	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)
	_, err = b.PrepareRequest(context.Background(), "https://bedrock.example.com", "", out, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "region is not configured")
}

func TestBedrockPrepareRequest_EnvelopeRequired(t *testing.T) {
	t.Parallel()
	b := newBedrockTestAdapter("us-east-1")
	_, err := b.PrepareRequest(context.Background(), "https://x.example.com", "", []byte(`{"messages":[]}`), "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "envelope has no model")
}

func TestBedrockDefaultChain_EnvResolution(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	t.Setenv("AWS_REGION", "eu-central-1")

	b := NewBedrock() // production constructor: DefaultChain, no injected config
	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)
	req, err := b.PrepareRequest(context.Background(), "https://bedrock-runtime.test.local", "", out, "ignored", false)
	require.NoError(t, err)
	auth := req.Header.Get("Authorization")
	assert.Contains(t, auth, "eu-central-1")
	assert.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256"))
}

func TestBedrockTranslateResponse_RoundTrip(t *testing.T) {
	t.Parallel()
	converse := `{"output":{"message":{"role":"assistant","content":[{"text":"pon"},{"text":"g"}]}},"stopReason":"end_turn","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15,"cacheReadInputTokens":4,"cacheWriteInputTokens":2}}`
	out, err := (&Bedrock{}).TranslateResponse([]byte(converse))
	require.NoError(t, err)

	var resp struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Choices []struct {
			Index        int    `json:"index"`
			Message      any    `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(out, &resp))
	assert.Equal(t, "chat.completion", resp.Object)
	require.Len(t, resp.Choices, 1)
	assert.Equal(t, "stop", resp.Choices[0].FinishReason)
	msg, ok := resp.Choices[0].Message.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "assistant", msg["role"])
	assert.Equal(t, "pong", msg["content"]) // text blocks concatenated without separator
	// Canonical fold: prompt includes cache reads AND writes (anthropic
	// convention; Bedrock passes through per-model semantics).
	assert.InDelta(t, float64(16), resp.Usage["prompt_tokens"].(float64), 1e-9)
	assert.InDelta(t, float64(5), resp.Usage["completion_tokens"].(float64), 1e-9)
	assert.InDelta(t, float64(15), resp.Usage["total_tokens"].(float64), 1e-9)
	details, ok := resp.Usage["prompt_tokens_details"].(map[string]any)
	require.True(t, ok, "cache fields must surface in prompt_tokens_details")
	assert.InDelta(t, float64(4), details["cached_tokens"].(float64), 1e-9)
	assert.InDelta(t, float64(2), details["cache_creation_input_tokens"].(float64), 1e-9)

	// ParseUsage on the TRANSLATED body keeps the same numbers (OpenAI field
	// names path, mirroring the anthropic adapter).
	u := (&Bedrock{}).ParseUsage(out)
	assert.Equal(t, UsageSourceProvider, u.Source)
	assert.Equal(t, int64(16), u.PromptTokens)
	assert.Equal(t, int64(5), u.CompletionTokens)
	assert.Equal(t, int64(15), u.TotalTokens)
	assert.Equal(t, int64(4), u.CacheReadTokens)
	assert.Equal(t, int64(2), u.CacheCreationTokens)
}

func TestBedrockTranslateResponse_NoUsage(t *testing.T) {
	t.Parallel()
	converse := `{"output":{"message":{"role":"assistant","content":[{"text":"x"}]}},"stopReason":"max_tokens"}`
	out, err := (&Bedrock{}).TranslateResponse([]byte(converse))
	require.NoError(t, err)
	u := (&Bedrock{}).ParseUsage(out)
	assert.Equal(t, UsageSourceNone, u.Source)
	assert.Contains(t, string(out), `"finish_reason":"length"`)
}

func TestBedrockTranslateResponse_MissingOutput(t *testing.T) {
	t.Parallel()
	_, err := (&Bedrock{}).TranslateResponse([]byte(`{"stopReason":"end_turn"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no message")
}

func TestBedrockMapStop(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"end_turn":             "stop",
		"stop_sequence":        "stop",
		"":                     "stop",
		"max_tokens":           "length",
		"tool_use":             "tool_calls",
		"content_filtered":     "content_filter",
		"guardrail_intervened": "content_filter",
		"something_new":        "stop", // unknown defaults to stop (anthropic convention)
	}
	for in, want := range cases {
		assert.Equal(t, want, mapBedrockStop(in), "stopReason %q", in)
	}
}

func TestBedrockParseUsageNativeShape(t *testing.T) {
	t.Parallel()
	native := []byte(`{"usage":{"inputTokens":7,"outputTokens":3,"totalTokens":10,"cacheReadInputTokens":5}}`)
	u := bedrockParseUsage(native)
	assert.Equal(t, UsageSourceProvider, u.Source)
	assert.Equal(t, int64(12), u.PromptTokens) // 7 + 5 cache read
	assert.Equal(t, int64(3), u.CompletionTokens)
	assert.Equal(t, int64(10), u.TotalTokens)
	assert.Equal(t, int64(5), u.CacheReadTokens)
	// Not Converse output: falls back to the shared OpenAI parser.
	assert.Equal(t, UsageSourceNone, bedrockParseUsage([]byte(`{"oops":true}`)).Source)
}

func TestBedrockEnvelopeValidation(t *testing.T) {
	t.Parallel()
	_, err := parseBedrockEnvelope([]byte(`not json`))
	require.Error(t, err)
	_, err = parseBedrockEnvelope([]byte(`{"converse":{"messages":[]}}`))
	require.Error(t, err)
	_, err = parseBedrockEnvelope([]byte(`{"model":"m"}`))
	require.Error(t, err)
	env, err := parseBedrockEnvelope([]byte(`{"model":"m","converse":{"messages":[]}}`))
	require.NoError(t, err)
	assert.Equal(t, "m", env.Model)
}

func TestBedrockRandomHex(t *testing.T) {
	t.Parallel()
	a, b := bedrockRandomHex(8), bedrockRandomHex(8)
	assert.Len(t, a, 16)
	assert.NotEqual(t, a, b)
}

// TestBedrockTranslateRequest_ReasoningEffortRejected (N07-P01-T05) pins the
// negative criterion: `reasoning_effort` is a modeled request field with no
// Converse equivalent yet — the adapter refuses loudly with the precise
// reason (I51) instead of silently answering at a default effort.
func TestBedrockTranslateRequest_ReasoningEffortRejected(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"x"}],"reasoning_effort":"high"}`
	_, _, err := chatToBedrockConverse([]byte(body))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reasoning_effort", "the field at fault must be named")
	assert.Contains(t, err.Error(), "refusing", "the refusal must state the loud-reject contract (bedrock house wording)")
}
