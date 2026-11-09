package cache

// CACHE-02 regressions (DEEP-AUDIT 2026-10-31, P1): normalization must be
// lossless for JSON numbers and strict about whitespace. The float64 round
// trip collapsed every number literal through IEEE-754: 2^53 and 2^53+1
// normalized to identical bytes, so two distinguishable upstream requests
// shared one exact-cache response (the poisoning direction — a hit the
// client never asked for — never the safe miss direction). PolicyStrict,
// documented as "hash identical to the raw JSON (sorted keys only)", still
// TrimSpace'd content/name/role and re-serialized tool-call arguments,
// silently rewriting bytes the policy promised to keep verbatim.
//
// Number literals that are merely spelled differently (1e3 vs 1000, 1.0 vs 1)
// stay distinct under the fix: equal-after-collapse is the dangerous
// direction; a lower hit rate on exotic spellings is the acceptable cost.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cache02BigIntSeed = `{"model":"m","messages":[{"role":"user","content":"cache02-seed"}],"seed":9007199254740992}`
const cache02BigIntShift = `{"model":"m","messages":[{"role":"user","content":"cache02-seed"}],"seed":9007199254740993}`

func TestCACHE02_BigIntegersNormalizeDistinctly(t *testing.T) {
	// 2^53 is exactly representable as float64; 2^53+1 rounds back to it, so
	// the float64 round trip made both bodies normalize to identical bytes.
	n1, err := NormalizeMessagesJSON([]byte(cache02BigIntSeed))
	require.NoError(t, err)
	n2, err := NormalizeMessagesJSON([]byte(cache02BigIntShift))
	require.NoError(t, err)

	assert.NotEqual(t, string(n1), string(n2),
		"two requests differing in a beyond-float64 integer must not normalize to one byte sequence")
	assert.Contains(t, string(n2), "9007199254740993",
		"the shifted literal must survive normalization verbatim")

	h1, err := NormalizePromptHash([]byte(cache02BigIntSeed))
	require.NoError(t, err)
	h2, err := NormalizePromptHash([]byte(cache02BigIntShift))
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2,
		"the exact-cache key space must keep the two requests apart")
}

func TestCACHE02_BigIntegersNormalizeDistinctly_Strict(t *testing.T) {
	s1, err := NormalizeWithPolicy([]byte(cache02BigIntSeed), PolicyStrict)
	require.NoError(t, err)
	s2, err := NormalizeWithPolicy([]byte(cache02BigIntShift), PolicyStrict)
	require.NoError(t, err)

	assert.NotEqual(t, string(s1), string(s2),
		"strict normalization is not exempt from the lossless-integer contract")
}

func TestCACHE02_NestedAndSignedLiteralsPreserved(t *testing.T) {
	// Deep inside a tool call's arguments string — the float64 round trip
	// corrupted exactly the values an upstream tool contract may treat as
	// significant (ids, snowflakes, 64-bit handles).
	input := `{"messages":[{"role":"assistant","content":null,"tool_calls":[` +
		`{"id":"call_1","type":"function","function":{"name":"book","arguments":` +
		`"{\"order_id\":9007199254740993,\"delta\":-9007199254740993,\"nested\":{\"deep\":[9007199254740993]}}"}}]}]}`
	norm, err := NormalizeMessagesJSON([]byte(input))
	require.NoError(t, err)
	s := string(norm)
	assert.Contains(t, s, "9007199254740993")
	assert.Contains(t, s, "-9007199254740993")

	// Exotic-but-legal spellings stay distinct from their float64 twins:
	// equal-after-collapse poisons; a miss is always safe.
	pairs := [][2]string{
		{`{"messages":[{"role":"u","content":"x"}],"n":1e3}`, `{"messages":[{"role":"u","content":"x"}],"n":1000}`},
		{`{"messages":[{"role":"u","content":"x"}],"n":1.0}`, `{"messages":[{"role":"u","content":"x"}],"n":1}`},
		{`{"messages":[{"role":"u","content":"x"}],"n":1.50}`, `{"messages":[{"role":"u","content":"x"}],"n":1.5}`},
	}
	for _, p := range pairs {
		a, err := NormalizeMessagesJSON([]byte(p[0]))
		require.NoError(t, err)
		b, err := NormalizeMessagesJSON([]byte(p[1]))
		require.NoError(t, err)
		assert.NotEqual(t, string(a), string(b),
			"differently spelled literals must not collapse onto one key: %q vs %q", p[0], p[1])
	}
}

func TestCACHE02_StrictPolicyWhitespaceVerbatim(t *testing.T) {
	input := []byte(`{"messages":[{"role":" user ","name":" n ","content":"  padded  "}],"request_id":"r1"}`)

	strict, err := NormalizeWithPolicy(input, PolicyStrict)
	require.NoError(t, err)
	s := string(strict)
	assert.Contains(t, s, `"content":"  padded  "`,
		"PolicyStrict promised raw-JSON fidelity: content bytes are not whitespace to clean")
	assert.Contains(t, s, `"role":" user "`,
		"role is a string field under strict, not a token to trim")
	assert.Contains(t, s, `"name":" n "`,
		"name is a string field under strict, not a token to trim")
	assert.Contains(t, s, `"request_id":"r1"`,
		"strict keeps volatile top-level keys (they are part of the raw bytes)")

	// Control: the default policy still trims — the strictness above is the
	// strict policy's contract, not a regression of the balanced policy.
	norm, err := NormalizeWithPolicy(input, PolicyNormalized)
	require.NoError(t, err)
	assert.Contains(t, string(norm), `"content":"padded"`)
	assert.NotContains(t, string(norm), "request_id")
}

func TestCACHE02_StrictPolicyToolArgumentsVerbatim(t *testing.T) {
	input := []byte(`{"messages":[{"role":"assistant","tool_calls":[` +
		`{"id":"call_1","type":"function","function":{"name":"book","arguments":` +
		`"{ \"order_id\" : 9007199254740993 }"}}]}]}`)

	strict, err := NormalizeWithPolicy(input, PolicyStrict)
	require.NoError(t, err)

	var out struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(strict, &out))
	require.Len(t, out.Messages, 1)
	require.Len(t, out.Messages[0].ToolCalls, 1)
	assert.Equal(t, `{ "order_id" : 9007199254740993 }`, out.Messages[0].ToolCalls[0].Function.Arguments,
		"under strict the arguments STRING is content: verbatim bytes, no re-serialization, no whitespace cleanup")

	// Control: the default policy re-serializes arguments (sorted keys,
	// compact) — its documented behavior, unchanged, now with lossless
	// numbers: the arguments STRING becomes the compact form with the
	// original literal intact.
	norm, err := NormalizeWithPolicy(input, PolicyNormalized)
	require.NoError(t, err)
	assert.Contains(t, string(norm), `"arguments":"{\"order_id\":9007199254740993}"`,
		"normalized keeps compacting tool arguments — now with lossless numbers")
}

// TestCACHE02_RouteVersionNamespacePin pins the deliberate cache-namespace
// bump that ships with the lossless-normalization change (the hashing-guard
// decision, CACHE-02): old normalization could COLLAPSE two different bodies
// onto one key; the new normalization can no longer reproduce an old entry's
// key bytes for a sibling literal (e.g. an entry written for 2^53+1 under the
// collapsed key 2^53 was reachable by a new lookup of literal 2^53). The
// RouteVersion bump moves every new write into a fresh namespace, so v2
// entries are never read again — a safe, silent miss and refill; legacy keys
// are neither read nor deleted, they expire through their TTL. Pinning the
// literal makes the invalidation decision reviewed state, not accidental
// drift.
func TestCACHE02_RouteVersionNamespacePin(t *testing.T) {
	assert.Equal(t, "v3", RouteVersion,
		"CACHE-02 shipped a normalization change: the namespace must stay bumped past v2")
}

// Silence lint if strings becomes unused after refactors (kept used above).
var _ = strings.Contains
