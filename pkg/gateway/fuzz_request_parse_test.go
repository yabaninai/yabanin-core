package cli

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/openai"
	"github.com/stretchr/testify/require"
)

// Critical-go wave 3 facts: the request-body parser contract pins the raw-body
// opt-in, the client no-store directive spellings, the cache write gate, the
// message extraction/estimation helpers, the RT-04 raw patch and the reasoning
// effort injection. Every seed exercises observable facts, no production code
// is changed.
func TestRequestParseShapes(t *testing.T) {
	for i := range uint8(13) {
		if i < 6 {
			requestParseEarlyCase(t, int(i))
			continue
		}
		requestParseLateCase(t, int(i))
	}
}

// requestParseEarlyCase covers cases 0-5: raw-body detection, no-store
// directives, the cache gate and the extraction helpers.
func requestParseEarlyCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 0:
		// Raw-body opt-in: the explicit header wins over the content type,
		// and any non-JSON content type is raw.
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		r.Header.Set("X-Yabanin-Raw-Body", "1")
		require.True(t, isRawBody(r))
		r.Header.Set("X-Yabanin-Raw-Body", "TRUE")
		require.True(t, isRawBody(r))
		r.Header.Set("X-Yabanin-Raw-Body", "0")
		r.Header.Set("Content-Type", "text/plain")
		require.True(t, isRawBody(r))
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
		require.False(t, isRawBody(r))
		r.Header.Del("Content-Type")
		require.False(t, isRawBody(r))
	case 1:
		// CACHE-01: the directive name is case-insensitive, may carry
		// parameters, may split across lines; "x-no-store" never matches.
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		require.False(t, clientNoStore(r))
		r.Header.Set("Cache-Control", "no-store")
		require.True(t, clientNoStore(r))
		r.Header.Set("Cache-Control", "max-age=0, No-Store")
		require.True(t, clientNoStore(r))
		r.Header.Del("Cache-Control")
		r.Header.Add("Cache-Control", "public")
		r.Header.Add("Cache-Control", "private, NO-STORE=anything")
		require.True(t, clientNoStore(r))
		r.Header.Set("Cache-Control", "x-no-store")
		require.False(t, clientNoStore(r))
	case 2:
		// FIX-10 write gate: decodable chat.completion with every choice
		// carrying a non-null finish_reason.
		require.False(t, shouldCache(nil))
		require.False(t, shouldCache([]byte("<html>torn</html>")))
		require.False(t, shouldCache([]byte(`{"error":{"message":"x"}}`)))
		require.False(t, shouldCache([]byte(`{}`)))
		require.False(t, shouldCache([]byte(`{"choices":[]}`)))
		require.False(t, shouldCache([]byte(`{"choices":[{"finish_reason":null}]}`)))
		require.False(t, shouldCache([]byte(`{"choices":["stop"]}`)))
		require.False(t, shouldCache([]byte(`{"choices":[{"index":0}]}`)))
		require.True(t, shouldCache([]byte(`{"choices":[{"finish_reason":"stop"}]}`)))
	case 3:
		// Extraction helpers: last message is the prompt, empty content is
		// skipped in the flat view, the token estimate is ~4 chars/token.
		msgs := []openai.ChatMessage{
			{Role: "system", Content: "abcd efgh"},
			{Role: "user", Content: "hi"},
		}
		require.Equal(t, "hi", extractUserPrompt(msgs))
		require.Equal(t, []string{"abcd efgh", "hi"}, extractAllMessages(msgs))
		require.Equal(t, 2, estimateContextTokens(msgs))
		require.Empty(t, extractUserPrompt(nil))
		require.Empty(t, extractAllMessages([]openai.ChatMessage{{Role: "user"}}))
		require.Equal(t, 0, estimateContextTokens(nil))
	case 4:
		// extractChatMessages keeps only JSON-object entries.
		body := []byte(`{"messages":[{"role":"user"},{"content":5},5]}`)
		msgs := extractChatMessages(body)
		require.Len(t, msgs, 2)
		require.Equal(t, "user", msgs[0]["role"])
		require.Nil(t, extractChatMessages([]byte(`not json`)))
		require.Empty(t, extractChatMessages([]byte(`{"messages":5}`)))
	case 5:
		// The system prompt is the first system-role message, case-insensitive.
		msgs := []openai.ChatMessage{
			{Role: "user", Content: "q"},
			{Role: "SYSTEM", Content: "sys"},
			{Role: "system", Content: "later"},
		}
		require.Equal(t, "sys", extractSystemMessage(msgs))
		require.Empty(t, extractSystemMessage([]openai.ChatMessage{{Role: "user", Content: "q"}}))
	default:
		t.Fatalf("unknown early request-parse case %d", index)
	}
}

// requestParseLateCase covers cases 6-12: the raw JSON patch family, the
// reasoning-effort injection and the message token estimate.
func requestParseLateCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 6:
		// patchSingleTextPart: exactly one text part is rewritten in place,
		// the image part survives byte-for-byte; 0 or 2 text parts defer to
		// the whole-value replacement; a non-string type is an error.
		raw := json.RawMessage(`[{"type":"image_url","image_url":{"url":"u"}},{"type":"text","text":"old"}]`)
		patched, err := patchSingleTextPart(raw, json.RawMessage(`"new"`))
		require.NoError(t, err)
		var parts []map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(patched, &parts))
		require.Len(t, parts, 2)
		require.JSONEq(t, `{"url":"u"}`, string(parts[0]["image_url"]))
		require.Equal(t, `"new"`, string(parts[1]["text"]))
		two, err := patchSingleTextPart(json.RawMessage(`[{"type":"text"},{"type":"text"}]`), json.RawMessage(`"x"`))
		require.NoError(t, err)
		require.Nil(t, two)
		none, err := patchSingleTextPart(json.RawMessage(`[{"type":"image_url"}]`), json.RawMessage(`"x"`))
		require.NoError(t, err)
		require.Nil(t, none)
		bad, badErr := patchSingleTextPart(json.RawMessage(`[5]`), json.RawMessage(`"x"`))
		require.Error(t, badErr)
		require.Nil(t, bad)
	case 7:
		// patchMessageContent: string content swaps verbatim, a one-text-part
		// array keeps its shape, a multi-text array collapses to plain text.
		out, err := patchMessageContent(json.RawMessage(`{"role":"user","content":"old"}`), json.RawMessage(`"new"`))
		require.NoError(t, err)
		require.JSONEq(t, `{"role":"user","content":"new"}`, string(out))
		out, err = patchMessageContent(json.RawMessage(`{"role":"user","content":[{"type":"text","text":"old"}]}`), json.RawMessage(`"new"`))
		require.NoError(t, err)
		require.JSONEq(t, `{"role":"user","content":[{"type":"text","text":"new"}]}`, string(out))
		out, err = patchMessageContent(json.RawMessage(`{"role":"user","content":[{"type":"text"},{"type":"text"}]}`), json.RawMessage(`"new"`))
		require.NoError(t, err)
		require.JSONEq(t, `{"role":"user","content":"new"}`, string(out))
		out, err = patchMessageContent(json.RawMessage(`{"role":"user"}`), json.RawMessage(`"new"`))
		require.NoError(t, err)
		require.JSONEq(t, `{"role":"user","content":"new"}`, string(out))
		bad, badErr := patchMessageContent(json.RawMessage(`[5]`), json.RawMessage(`"x"`))
		require.Error(t, badErr)
		require.Nil(t, bad)
	case 8:
		// RT-04: only the last message's content changes; sibling messages
		// and unrelated fields keep their exact values.
		body := []byte(`{"model":"m","temperature":7,"messages":[` +
			`{"role":"system","content":"sys"},` +
			`{"role":"user","content":[{"type":"text","text":"q"}]}]}`)
		out, err := patchLastMessageContent(body, "rewritten")
		require.NoError(t, err)
		var root map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &root))
		require.JSONEq(t, `7`, string(root["temperature"]))
		var msgs []map[string]any
		require.NoError(t, json.Unmarshal(root["messages"], &msgs))
		require.Len(t, msgs, 2)
		require.Equal(t, "sys", msgs[0]["content"])
		content, ok := msgs[1]["content"].([]any)
		require.True(t, ok)
		require.Equal(t, "rewritten", content[0].(map[string]any)["text"])
		_, err = patchLastMessageContent([]byte(`{"model":"m"}`), "x")
		require.Error(t, err)
		_, err = patchLastMessageContent([]byte(`{"messages":[]}`), "x")
		require.Error(t, err)
		_, err = patchLastMessageContent([]byte(`{"messages":5}`), "x")
		require.Error(t, err)
		_, err = patchLastMessageContent([]byte(`torn`), "x")
		require.Error(t, err)
	case 9:
		// injectReasoningEffort: only a non-empty effort on a decodable JSON
		// object body is patched; every other shape passes through unchanged.
		out := injectReasoningEffort([]byte(`{"model":"m","reasoning_effort":"low"}`), "high")
		require.JSONEq(t, `{"model":"m","reasoning_effort":"high"}`, string(out))
		require.JSONEq(t, `{"model":"m"}`, string(injectReasoningEffort([]byte(`{"model":"m"}`), "")))
		empty := []byte{}
		require.Empty(t, injectReasoningEffort(empty, "high"))
		require.Equal(t, []byte(`torn`), injectReasoningEffort([]byte(`torn`), "high"))
		require.Equal(t, []byte(`null`), injectReasoningEffort([]byte(`null`), "high"))
		require.Equal(t, []byte(`[1,2]`), injectReasoningEffort([]byte(`[1,2]`), "high"))
	case 10:
		// estimateMessageTokens counts raw bytes of system/messages/tools at
		// ~4 bytes per token, rounded up; anything undecodable or empty is 0.
		body := []byte(`{"system":"abcd","messages":"efgh","tools":"ij"}`)
		// RawMessage byte lengths: 6 + 6 + 4 = 16 -> ceil(16/4) = 4.
		require.Equal(t, 4, estimateMessageTokens(body))
		require.Equal(t, 0, estimateMessageTokens([]byte(`{}`)))
		require.Equal(t, 0, estimateMessageTokens([]byte(`torn`)))
	case 11:
		// A single truncated choice poisons the whole document.
		require.False(t, shouldCache([]byte(`{"choices":[{"finish_reason":"stop"},{"finish_reason":null}]}`)))
	case 12:
		// A numeric part type cannot decode as a string: the patch refuses.
		bad, err := patchSingleTextPart(json.RawMessage(`[{"type":123}]`), json.RawMessage(`"x"`))
		require.Error(t, err)
		require.Nil(t, bad)
	default:
		t.Fatalf("unknown late request-parse case %d", index)
	}
}

// FuzzRequestParseContract drives changing bodies — well-formed, typed
// wrong and torn — through the request-parse gates with independent
// expected effects: the cache-write contract (decodable object, no error
// field, choices with non-null finish reasons), the message extraction
// (object entries only, values intact) and the effort injection (only the
// injected key changes).
func FuzzRequestParseContract(f *testing.F) {
	f.Add([]byte(`{"choices":[{"finish_reason":"stop"}]}`), "medium")
	f.Add([]byte(`{"choices":[{"finish_reason":null}]}`), "")
	f.Add([]byte(`{"choices":[{"finish_reason":"stop"},{"finish_reason":"length"}]}`), "high")
	f.Add([]byte(`{"choices":["stop"]}`), "x")
	f.Add([]byte(`{"choices":[]}`), "")
	f.Add([]byte(`{"error":{"message":"x"}}`), "")
	f.Add([]byte(`{}`), "")
	f.Add([]byte(`{"choices":[{"finish_reason":"stop"}],"messages":[{"role":"user"},{"content":5},5,null]}`), "")
	f.Add([]byte(`not json`), "")
	f.Add([]byte(``), "")
	f.Add([]byte(`{"messages":5}`), "")
	f.Add([]byte(`{"messages":[{"role":"user"},{"role":"assistant"}]}`), "low")
	f.Add([]byte(`[1]`), "")
	f.Add([]byte(`null`), "")
	f.Fuzz(func(t *testing.T, body []byte, effort string) {
		require.Equal(t, expectedCacheGate(t, body), shouldCache(body))
		requireMessageExtraction(t, body, extractChatMessages(body))
		requireEffortInjection(t, body, effort, injectReasoningEffort(body, effort))
	})
}

// expectedCacheGate re-derives the FIX-10 write contract: only a decodable
// JSON object without an error field and with at least one choice — every
// choice an object carrying a non-null finish_reason — may be written.
func expectedCacheGate(t *testing.T, body []byte) bool {
	t.Helper()
	if len(body) == 0 {
		return false
	}
	var resp interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false
	}
	root, ok := resp.(map[string]interface{})
	if !ok {
		return false
	}
	if _, hasError := root["error"]; hasError {
		return false
	}
	choices, _ := root["choices"].([]interface{})
	if len(choices) == 0 {
		return false
	}
	for _, raw := range choices {
		choice, ok := raw.(map[string]interface{})
		if !ok {
			return false
		}
		if fr, present := choice["finish_reason"]; !present || fr == nil {
			return false
		}
	}
	return true
}

// requireMessageExtraction pins extraction independently: nil only when the
// body cannot decode as an object; otherwise a slice holding exactly the
// object entries of the messages array, in order, with decoded values
// intact.
func requireMessageExtraction(t *testing.T, body []byte, msgs []map[string]interface{}) {
	t.Helper()
	var root map[string]interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		require.Nil(t, msgs)
		return
	}
	require.NotNil(t, msgs)
	rawMsgs, _ := root["messages"].([]interface{})
	var objectIdx []int
	for i, rm := range rawMsgs {
		if _, ok := rm.(map[string]interface{}); ok {
			objectIdx = append(objectIdx, i)
		}
	}
	require.Len(t, msgs, len(objectIdx))
	for out, i := range objectIdx {
		want, _ := rawMsgs[i].(map[string]interface{})
		require.Equal(t, want, msgs[out])
	}
}

// requireEffortInjection pins the patch contract: no effort or an
// undecodable body returns the input untouched; a decodable object carries
// the effort verbatim and every other key keeps its JSON value.
func requireEffortInjection(t *testing.T, body []byte, effort string, out []byte) {
	t.Helper()
	if effort == "" || len(body) == 0 {
		require.Equal(t, body, out)
		return
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		require.Equal(t, body, out)
		return
	}
	var patched map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &patched))
	require.Contains(t, patched, "reasoning_effort")
	enc, err := json.Marshal(effort)
	require.NoError(t, err)
	require.Equal(t, string(enc), string(patched["reasoning_effort"]))
	for k, v := range root {
		if k != "reasoning_effort" {
			require.JSONEq(t, string(v), string(patched[k]))
		}
	}
}
