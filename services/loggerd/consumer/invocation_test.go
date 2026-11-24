package consumer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Invocation identity contract: only an ABSENT invocation_id field may take
// the legacy dedupe domain. A present value that is not a canonical UUID
// string must surface as malformed so the delivery parks — silently
// downgrading it to legacy would reopen duplicate billing. These tests pin
// the presence/type/spelling rules at every layer they touch.

// rawFields decodes a JSON object the way the stream/DLQ/facts paths do, so
// wrong-typed values arrive as their real decoded JSON types.
func rawFields(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	out := map[string]interface{}{}
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	return out
}

func TestInvocationField_AbsentTakesLegacyDomain(t *testing.T) {
	rawText, id, malformed := invocationField(rawFields(t, `{}`))
	assert.Empty(t, rawText)
	assert.Nil(t, id, "absent field is the legacy domain, not a malformed one")
	assert.False(t, malformed)
}

func TestInvocationField_CanonicalSpellingsAccepted(t *testing.T) {
	const canonical = "0f1e2d3c-4b5a-4968-8776-655443332211"
	for _, tc := range []struct {
		name string
		body string
	}{
		{"lowercase", `{"invocation_id":"0f1e2d3c-4b5a-4968-8776-655443332211"}`},
		{"uppercase normalized", `{"invocation_id":"0F1E2D3C-4B5A-4968-8776-655443332211"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rawText, id, malformed := invocationField(rawFields(t, tc.body))
			require.False(t, malformed, "raw %q", rawText)
			require.IsType(t, "", id)
			assert.Equal(t, canonical, id.(string))
		})
	}
}

func TestInvocationField_PresentButMalformedNeverLegacy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		rawText string
	}{
		{"empty string", `{"invocation_id":""}`, ""},
		{"URN spelling", `{"invocation_id":"urn:uuid:0f1e2d3c-4b5a-4968-8776-655443332211"}`, "urn:uuid:0f1e2d3c-4b5a-4968-8776-655443332211"},
		{"braced spelling", `{"invocation_id":"{0f1e2d3c-4b5a-4968-8776-655443332211}"}`, "{0f1e2d3c-4b5a-4968-8776-655443332211}"},
		{"compact spelling", `{"invocation_id":"0f1e2d3c4b5a49688776655443332211"}`, "0f1e2d3c4b5a49688776655443332211"},
		{"wrong hyphen layout", `{"invocation_id":"0f1e2d3c4-b5a4-9688-7766-554433332211"}`, "0f1e2d3c4-b5a4-9688-7766-554433332211"},
		{"not a uuid", `{"invocation_id":"ses_f7c8cea03ffeQF8w3WLp7oRA9w"}`, "ses_f7c8cea03ffeQF8w3WLp7oRA9w"},
		{"numeric", `{"invocation_id":123456789012345678901234567890123456}`, "number"},
		{"json null", `{"invocation_id":null}`, "null"},
		{"bool", `{"invocation_id":true}`, "bool"},
		{"object", `{"invocation_id":{"id":"0f1e2d3c-4b5a-4968-8776-655443332211"}}`, "object"},
		{"array", `{"invocation_id":["0f1e2d3c-4b5a-4968-8776-655443332211"]}`, "array"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rawText, id, malformed := invocationField(rawFields(t, tc.body))
			assert.True(t, malformed, "present value must park, never downgrade to legacy")
			assert.Nil(t, id)
			assert.Equal(t, tc.rawText, rawText)
		})
	}
}

// The mapper must carry the same verdict: present-but-malformed values never
// bind an invocation identity, and absent stays legacy.
func TestParseRequestEvent_InvocationDomain(t *testing.T) {
	ev := parseRequestEvent(rawFields(t, `{}`))
	assert.Nil(t, ev.invocationIDValue)
	assert.False(t, ev.invocationMalformed)

	ev = parseRequestEvent(rawFields(t, `{"invocation_id":"0f1e2d3c-4b5a-4968-8776-655443332211"}`))
	require.IsType(t, "", ev.invocationIDValue)
	assert.Equal(t, "0f1e2d3c-4b5a-4968-8776-655443332211", ev.invocationIDValue.(string))
	assert.False(t, ev.invocationMalformed)

	for _, body := range []string{
		`{"invocation_id":""}`,
		`{"invocation_id":42}`,
		`{"invocation_id":null}`,
		`{"invocation_id":{}}`,
		`{"invocation_id":"urn:uuid:0f1e2d3c-4b5a-4968-8776-655443332211"}`,
	} {
		ev := parseRequestEvent(rawFields(t, body))
		assert.Nil(t, ev.invocationIDValue, body)
		assert.True(t, ev.invocationMalformed, body)
	}
}

// The facts allowlist is the terminal-facts projection contract: billing and
// attribution dimensions only. Content and free-form fields must stay out so
// recovery is content-free by construction; editing the set is deliberate.
func TestTerminalFactsFields_AllowlistPinned(t *testing.T) {
	assert.Equal(t, []string{
		"event_type", "used_org_key", "org_id", "request_id", "invocation_id",
		"model_requested", "model_used", "status_code", "duration_ms",
		"tokens_in", "tokens_out", "estimated_cost_usd", "resale_cost_usd",
		"cost_status", "usage_source", "termination", "ts",
		"session_id", "api_key_id", "session_key_id", "team_id",
		"agent_id", "user_id", "task_id", "endpoint",
		"cache_hit_type", "cache_read_tokens", "cache_creation_tokens",
		"ab_group", "tier_used", "counterfactual_cost_usd", "prompt_hash",
		"reservations", "first_token_ms", "attempt_count", "retry_count",
	}, terminalFactsFields)
}

// Recovery fails closed on content: the allowlist is enforced structurally,
// so even a corrupt facts projection carrying payload/response captures,
// free-form labels (object or wire-encoded string) or raw error text binds
// nothing beyond the allowlisted dimensions.
func TestParseTerminalFactsEvent_ContentFailsClosed(t *testing.T) {
	ev := parseTerminalFactsEvent(rawFields(t, `{
		"event_type":"request.completed","org_id":"org-1","request_id":"req-1",
		"invocation_id":"0f1e2d3c-4b5a-4968-8776-655443332211",
		"prompt_hash":"a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
		"payload":"top secret prompt","processed_response":"top secret response",
		"upstream_response":{"choices":[]},
		"labels":{"team":"x"},
		"error":"raw provider error"
	}`))
	assert.Nil(t, ev.responseJSON, "payload must not bind on the facts path")
	assert.Nil(t, ev.upstreamRespJSON, "upstream captures must not bind on the facts path")
	assert.Nil(t, ev.upstreamReqJSON)
	assert.Empty(t, ev.upstreamResponse, "no tool-call sample can be derived from facts")
	assert.Equal(t, []byte("{}"), ev.labels, "free-form labels never ride facts")
	assert.Empty(t, ev.errorMsg, "raw error text never rides facts")
	require.NotNil(t, ev.promptHash, "the allowlisted prompt digest binds")
	assert.Equal(t, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", ev.promptHash)

	// Wire-shaped labels (JSON-encoded string) are stripped just the same.
	ev = parseTerminalFactsEvent(rawFields(t, `{"labels":"{\"team\":\"x\"}"}`))
	assert.Equal(t, []byte("{}"), ev.labels)
}

// Row level: setInvocation appends AFTER attribution, so every pinned
// argument position (0..42) is unchanged, and only invocation rows carry the
// ON CONFLICT replay guard — legacy rows keep the byte-identical statement.
func TestRequestLogRow_SetInvocationPinsPositionsAndLegacyBytes(t *testing.T) {
	base := map[string]interface{}{
		"event_type": "request.completed",
		"org_id":     "org-inv",
		"request_id": "req-inv",
		"session_id": "sess-inv",
		"ts":         "1732200000000",
	}
	ev := parseRequestEvent(rawFields(t, mustJSON(t, base)))

	legacy := fullRequestLogRow(ev, "sess-inv", nil, 200)
	legacy.setAttribution(int64(11), nil)

	invoked := fullRequestLogRow(ev, "sess-inv", nil, 200)
	invoked.setAttribution(int64(11), nil)
	invoked.setInvocation(ev.invocationIDValue)
	assert.Nil(t, ev.invocationIDValue, "this base event has no invocation_id: legacy domain")
	assert.Len(t, invoked.args(), len(legacy.args()), "nil invocation is a no-op")

	uuidVal := "0f1e2d3c-4b5a-4968-8776-655443332211"
	invoked = fullRequestLogRow(parseRequestEvent(rawFields(t,
		mustJSON(t, withField(base, "invocation_id", uuidVal)))), "sess-inv", nil, 200)
	invoked.setAttribution(int64(11), nil)
	invoked.setInvocation(uuidVal)

	require.Len(t, invoked.args(), len(legacy.args())+1, "invocation_id appends exactly one bound column")
	for i := range legacy.args() {
		assert.Equal(t, legacy.args()[i], invoked.args()[i], "pinned position %d unchanged", i)
	}
	assert.Equal(t, uuidVal, invoked.args()[len(legacy.args())])

	assert.NotContains(t, legacy.insertSQL(), "ON CONFLICT", "legacy statement stays byte-compatible")
	assert.Contains(t, invoked.insertSQL(), "invocation_id")
	assert.True(t, strings.HasSuffix(invoked.insertSQL(),
		" ON CONFLICT (invocation_id) WHERE invocation_id IS NOT NULL DO NOTHING"),
		"replay guard renders after the VALUES list: %s", invoked.insertSQL())
	assert.NotContains(t, strings.Replace(invoked.insertSQL(), " ON CONFLICT (invocation_id) WHERE invocation_id IS NOT NULL DO NOTHING", "", 1),
		"ON CONFLICT")
}

func withField(base map[string]interface{}, key string, value any) map[string]interface{} {
	out := make(map[string]interface{}, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[key] = value
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	body, err := json.Marshal(v)
	require.NoError(t, err)
	return string(body)
}
