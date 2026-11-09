package provider

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChatToAnthropicRequest_Golden(t *testing.T) {
	ins, err := filepath.Glob("testdata/anthropic_up_*.in.json")
	require.NoError(t, err)
	require.NotEmpty(t, ins)
	for _, inPath := range ins {
		t.Run(filepath.Base(inPath), func(t *testing.T) {
			outPath := strings.TrimSuffix(inPath, ".in.json") + ".out.json"
			// Paths come from filepath.Glob("testdata/anthropic_up_*.in.json"), not request input.
			in, err := os.ReadFile(inPath) //nolint:gosec // G304: fixed testdata glob, not user input
			require.NoError(t, err)
			want, err := os.ReadFile(outPath) //nolint:gosec // G304: sibling of the testdata glob match
			require.NoError(t, err)
			got, err := NewAnthropic().TranslateRequest(in)
			require.NoError(t, err)
			assert.JSONEq(t, string(want), string(got))
		})
	}
}

func TestAnthropicToChatResponse_ToolUse(t *testing.T) {
	assertAnthropicDownGolden(t, "anthropic_down_tools")
}

func TestAnthropicToChatResponse_OnlyToolUse(t *testing.T) {
	assertAnthropicDownGolden(t, "anthropic_down_only_tool")
}

func TestAnthropicToChatResponse_Usage(t *testing.T) {
	assertAnthropicDownGolden(t, "anthropic_down_usage")
}

func TestAnthropicToChatResponse_Refusal(t *testing.T) {
	// N07-P01-T03: stop_reason "refusal" must surface as the OpenAI refusal
	// shape (message.refusal carries the text, content null,
	// finish_reason content_filter) — pinned go-openai clients read
	// Message.Refusal / FinishReason to detect refusals programmatically.
	assertAnthropicDownGolden(t, "anthropic_down_refusal")
}

func TestAnthropicToChatResponse_RefusalWithoutText(t *testing.T) {
	// A refusal stop without text blocks still must NOT look like a plain
	// stop: finish_reason stays content_filter, refusal key stays absent.
	prev := anthropicNow
	anthropicNow = func() time.Time { return time.Unix(1700000000, 0) }
	t.Cleanup(func() { anthropicNow = prev })
	in := []byte(`{"id":"msg_r2","model":"claude","stop_reason":"refusal","content":[],"usage":{"input_tokens":1,"output_tokens":1}}`)
	got, err := NewAnthropic().TranslateResponse(in)
	require.NoError(t, err)
	var doc struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Refusal string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal(got, &doc))
	require.Len(t, doc.Choices, 1)
	assert.Equal(t, "content_filter", doc.Choices[0].FinishReason)
	assert.Empty(t, doc.Choices[0].Message.Refusal)
}

func assertAnthropicDownGolden(t *testing.T, name string) {
	t.Helper()
	prev := anthropicNow
	anthropicNow = func() time.Time { return time.Unix(1700000000, 0) }
	t.Cleanup(func() { anthropicNow = prev })
	in, err := os.ReadFile(filepath.Join("testdata", name+".in.json")) //nolint:gosec // G304: fixed testdata name from the test, not user input
	require.NoError(t, err)
	want, err := os.ReadFile(filepath.Join("testdata", name+".out.json")) //nolint:gosec // G304: fixed testdata name from the test, not user input
	require.NoError(t, err)
	got, err := NewAnthropic().TranslateResponse(in)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(got))
}

func TestChatToAnthropicRequest_MaxCompletionTokensAndStopArray(t *testing.T) {
	in := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":77,"stop":["A","B"],"temperature":0.2,"top_p":0.5,"user":"alice"}`)
	got, err := chatToAnthropicRequest(in)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"model":"m",
		"max_tokens":77,
		"temperature":0.2,
		"top_p":0.5,
		"stop_sequences":["A","B"],
		"metadata":{"user_id":"alice"},
		"messages":[{"role":"user","content":"hi"}]
	}`, string(got))
}

func TestChatToAnthropicRequest_ResponseFormatRejected(t *testing.T) {
	// N07-P01-T03 negative criterion: response_format carries a JSON
	// guarantee Anthropic Messages cannot honor — the request must fail
	// loudly (I51), never drop the field and answer free-form text.
	cases := []struct {
		name    string
		rf      string
		wantErr string
		wantOK  bool
	}{
		{"absent", "", "", true},
		{"text", `{"type":"text"}`, "", true},
		{"json_object", `{"type":"json_object"}`, `response_format "json_object"`, false},
		{"json_schema", `{"type":"json_schema","json_schema":{"name":"s"}}`, `response_format "json_schema"`, false},
		{"unknown type", `{"type":"grault"}`, "unsupported response_format type", false},
		// A syntactically broken response_format is impossible within valid
		// JSON (the outer request decode rejects it first); a valid-JSON
		// non-object value is the reachable degenerate shape.
		{"non-object", `"bogus"`, "decode response_format", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"model":"m","messages":[{"role":"user","content":"hi"}]`
			if tc.rf != "" {
				body += `,"response_format":` + tc.rf
			}
			body += `}`
			got, err := chatToAnthropicRequest([]byte(body))
			if tc.wantOK {
				require.NoError(t, err)
				assert.NotContains(t, string(got), "response_format")
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Contains(t, err.Error(), "rejecting")
		})
	}
}

func TestChatToAnthropicRequest_InvalidToolArguments(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	in := []byte(`{"model":"m","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"call_x","type":"function","function":{"name":"get_weather","arguments":"not-json"}}]}]}`)
	got, err := chatToAnthropicRequest(in)
	require.NoError(t, err)
	var doc struct {
		Messages []struct {
			Content []struct {
				Type  string         `json:"type"`
				Input map[string]any `json:"input"`
				Name  string         `json:"name"`
			} `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(got, &doc))
	require.Len(t, doc.Messages, 1)
	require.Len(t, doc.Messages[0].Content, 1)
	assert.Equal(t, "tool_use", doc.Messages[0].Content[0].Type)
	assert.Equal(t, "get_weather", doc.Messages[0].Content[0].Name)
	assert.Empty(t, doc.Messages[0].Content[0].Input)
	assert.Contains(t, buf.String(), "get_weather")
	assert.NotContains(t, buf.String(), "not-json")
}

// TestChatToAnthropicRequest_ReasoningEffortRejected (N07-P01-T05) pins the
// negative criterion: `reasoning_effort` is a modeled request field
// (apiformat.ChatRequest) with no Anthropic Messages equivalent. A client
// that asked for a reasoning level must not receive a default-effort answer
// while the wire says the request succeeded — the adapter refuses with the
// precise reason (I51) and the transport layer turns that into the typed
// request-not-sent proof.
func TestChatToAnthropicRequest_ReasoningEffortRejected(t *testing.T) {
	for _, effort := range []string{"low", "medium", "high"} {
		body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"` + effort + `"}`
		_, err := chatToAnthropicRequest([]byte(body))
		require.Error(t, err, "reasoning_effort %q must not be silently dropped", effort)
		assert.Contains(t, err.Error(), "reasoning_effort", "the field at fault must be named")
		assert.Contains(t, err.Error(), "rejecting", "the refusal must state the loud-reject contract")
	}
}

// TestChatToAnthropicRequest_DocumentedSimplifications pins behavior the T05
// review classified as visible-in-body and documented, not silent loss:
//   - stream_options: Anthropic streams always carry usage in the final
//     message_delta, so include_usage is honored implicitly; the key has no
//     equivalent and is not forwarded.
//   - temperature > 1: Anthropic rejects values above 1.0; the adapter clamps
//     into the valid range (lenient-routing simplification — I51 tightening
//     candidate, flagged for owner review in the T05 record).
func TestChatToAnthropicRequest_DocumentedSimplifications(t *testing.T) {
	got, err := chatToAnthropicRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":true},"temperature":1.7}`))
	require.NoError(t, err)
	assert.NotContains(t, string(got), "stream_options")

	var out map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(got, &out))
	assert.JSONEq(t, "1", string(out["temperature"]), "temperature above 1 is clamped into the Anthropic range")
	assert.JSONEq(t, "true", string(out["stream"]))
}
