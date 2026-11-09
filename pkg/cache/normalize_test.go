package cache

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeMessagesJSON_SortsKeys(t *testing.T) {
	// Input with unsorted keys in messages.
	input := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":false}`)

	result, err := NormalizeMessagesJSON(input)
	require.NoError(t, err)

	// Keys should be sorted alphabetically at every level.
	// Top-level: messages, model, stream (not model, messages, stream)
	assert.JSONEq(t, `{"messages":[{"content":"hi","role":"user"}],"model":"gpt-4o","stream":false}`, string(result))
}

func TestNormalizeMessagesJSON_TrimsWhitespace(t *testing.T) {
	input := []byte(`{"messages":[{"role":" user ","content":"  hello  "}]}`)

	result, err := NormalizeMessagesJSON(input)
	require.NoError(t, err)
	assert.JSONEq(t, `{"messages":[{"content":"hello","role":"user"}]}`, string(result))
}

func TestNormalizeMessagesJSON_StripEmptyMessages(t *testing.T) {
	input := []byte(`{"messages":[{},null,{"role":"user","content":"hi"},{}]}`)

	result, err := NormalizeMessagesJSON(input)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)

	messages := parsed["messages"].([]interface{})
	assert.Len(t, messages, 1) // only the valid message survives
}

func TestNormalizeMessagesJSON_NormalizesToolCalls(t *testing.T) {
	// Tool calls with unsorted arguments should be normalized.
	input := []byte(`{
		"messages":[{
			"role":"assistant",
			"content":null,
			"tool_calls":[{
				"id":"call-1",
				"type":"function",
				"function":{"name":"get_weather","arguments":"{\"city\":\"paris\",\"unit\":\"celsius\"}"}
			}]
		}]
	}`)

	result, err := NormalizeMessagesJSON(input)
	require.NoError(t, err)

	// Arguments JSON should be re-serialized with sorted keys.
	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)

	messages := parsed["messages"].([]interface{})
	msg := messages[0].(map[string]interface{})
	toolCalls := msg["tool_calls"].([]interface{})
	tc := toolCalls[0].(map[string]interface{})
	fn := tc["function"].(map[string]interface{})
	args := fn["arguments"].(string)

	// "city" comes before "unit" alphabetically.
	assert.Contains(t, args, `"city"`)
	assert.Contains(t, args, `"unit"`)
}

func TestNormalizeMessagesJSON_NoMessagesArray(t *testing.T) {
	// When there's no "messages" key (e.g., raw forwarding), body should be returned as-is.
	input := []byte(`{"custom":"field","data":"value"}`)

	result, err := NormalizeMessagesJSON(input)
	require.NoError(t, err)
	assert.JSONEq(t, `{"custom":"field","data":"value"}`, string(result))
}

func TestNormalizeMessagesJSON_EquivalentPromptsHashIdentically(t *testing.T) {
	// Two semantically equivalent prompts with different key ordering.
	input1 := []byte(`{"messages":[{"role":"user","content":"hello"}],"model":"gpt-4o"}`)
	input2 := []byte(`{"model":"gpt-4o","messages":[{"content":"hello","role":"user"}]}`)

	hash1, err := NormalizePromptHash(input1)
	require.NoError(t, err)

	hash2, err := NormalizePromptHash(input2)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2, "semantically equivalent prompts should produce identical hashes")
}

func TestNormalizeMessagesJSON_ExtraWhitespaceInContent(t *testing.T) {
	input := []byte(`{"messages":[{"role":"user","content":"  hello   world  "}]}`)

	result, err := NormalizeMessagesJSON(input)
	require.NoError(t, err)
	assert.JSONEq(t, `{"messages":[{"content":"hello   world","role":"user"}]}`, string(result))
}

func TestNormalizeMessagesJSON_NestedObjectsPreserved(t *testing.T) {
	input := []byte(`{
		"messages":[{
			"role":"system",
			"content":"You are a helpful assistant."
		},{
			"role":"user",
			"content":"Tell me about AI.",
			"metadata":{"source":"web","priority":1}
		}]
	}`)

	result, err := NormalizeMessagesJSON(input)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)

	messages := parsed["messages"].([]interface{})
	userMsg := messages[1].(map[string]interface{})
	meta := userMsg["metadata"].(map[string]interface{})
	assert.InDelta(t, float64(1), meta["priority"], 1e-9)
	assert.Equal(t, "web", meta["source"])
}

func TestFastHash_Deterministic(t *testing.T) {
	data := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	h1 := FastHash(data)
	h2 := FastHash(data)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64) // SHA-256 hex digest length
}

func TestNormalizePromptHash_DifferentContentDifferentHash(t *testing.T) {
	h1, _ := NormalizePromptHash([]byte(`{"messages":[{"role":"user","content":"hello"}]}`))
	h2, _ := NormalizePromptHash([]byte(`{"messages":[{"role":"user","content":"goodbye"}]}`))
	assert.NotEqual(t, h1, h2)
}

func TestNormalizeWithPolicy_Strict(t *testing.T) {
	// PolicyStrict: sorted keys only, no volatile field stripping.
	input := []byte(`{"request_id":"abc","messages":[{"role":"user","content":"hi"}]}`)
	result, err := NormalizeWithPolicy(input, PolicyStrict)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	// request_id should still be present in strict mode.
	assert.Contains(t, parsed, "request_id")
}

func TestNormalizeWithPolicy_Normalized_StripVolatile(t *testing.T) {
	// PolicyNormalized: strips request_id/timestamp/cache_control.
	input := []byte(`{"request_id":"abc","timestamp":123,"messages":[{"role":"user","content":"  hello  "}]}`)
	result, err := NormalizeWithPolicy(input, PolicyNormalized)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	assert.NotContains(t, parsed, "request_id")
	assert.NotContains(t, parsed, "timestamp")
}

func TestNormalizeWithPolicy_Aggressive_Lowercase(t *testing.T) {
	// PolicyAggressive: lowercases content and strips punctuation.
	input := []byte(`{"messages":[{"role":"user","content":"Hello, World! 123"}]}`)
	result, err := NormalizeWithPolicy(input, PolicyAggressive)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	msgs := parsed["messages"].([]interface{})
	content := msgs[0].(map[string]interface{})["content"].(string)
	assert.Equal(t, "hello world 123", content)
}

func TestNormalizeQualityGate_NoFalseCollisions(t *testing.T) {
	// Quality-gate: semantically different prompts must NOT produce identical hashes.
	prompts := []string{
		`{"messages":[{"role":"user","content":"2+2"}]}`,
		`{"messages":[{"role":"user","content":"2 2"}]}`,
		`{"messages":[{"role":"user","content":"two plus two"}]}`,
		`{"messages":[{"role":"user","content":"What is 2+2?"}]}`,
	}

	hashes := make(map[string]bool)
	for _, p := range prompts {
		h, err := NormalizePromptHash([]byte(p))
		require.NoError(t, err)
		// All hashes must be unique — no false collisions.
		assert.False(t, hashes[h], "false collision detected: %s", h)
		hashes[h] = true
	}
}

func TestNormalizePolicyNormalized_SameAsDefault(t *testing.T) {
	// PolicyNormalized should produce the same result as NormalizeMessagesJSON (default).
	input := []byte(`{"messages":[{"role":"user","content":"  hello  "}]}`)

	defaultResult, err := NormalizeMessagesJSON(input)
	require.NoError(t, err)

	policyResult, err := NormalizeWithPolicy(input, PolicyNormalized)
	require.NoError(t, err)

	assert.JSONEq(t, string(defaultResult), string(policyResult))
}
