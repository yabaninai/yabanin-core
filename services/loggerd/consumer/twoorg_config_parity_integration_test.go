//go:build integration

package consumer

// N01-P02 T09 — old/new configuration parity for the ONE two-org scenario
// on real stands: the same event shape for org A and org B is driven through
// the real worker boundary under the legacy profile (full captures), the
// strict metadata-only profile, an UNSUPPORTED operator value, and both wire
// override directions — and the durable results must differ ONLY in content.
//
//	Pinned per org, per profile:
//	  - parity: org attribution, request identity, model/usage/cost columns
//	    and the per-org policy decision are identical across profiles; the
//	    strict pass is a pure content redaction, never a re-attribution;
//	  - strict: no sentinel survives in ANY stored column, the error column
//	    carries the fixed redaction notice, and the prompt digest is
//	    recomputed from the body (a malformed supplied digest is never
//	    stored);
//	  - unsupported configuration: an unknown YABANIN_LOG_CONTENT_PROFILE
//	    value fails CLOSED to strict — the unsupported value never widens
//	    retention — and an unsupported event type is never persisted nor
//	    archived (documented refusal, no error surface);
//	  - wire overrides: the strictest of the local and the wire declaration
//	    wins in both directions, on real deliveries;
//	  - DLQ parity: side-by-side poisons on the real Redis DLQ stream — the
//	    legacy envelope keeps its own org's captures, the strict envelope is
//	    the bounded allowlist shape — and neither envelope ever carries the
//	    other org's sentinel (per-org identity preserved per profile).

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	twoOrgParityUnsupportedEnv = "full-content-please" // unsupported operator value
	twoOrgParityReqA2          = "req-twoorg-parity-a2"
	twoOrgParityReqB2          = "req-twoorg-parity-b2"
	twoOrgParityReqA3          = "req-twoorg-parity-a3"
	twoOrgParityMarkerA2       = "TWOORG-A PARITY SECOND MARKER"
	twoOrgParityMarkerB2       = "TWOORG-B PARITY SECOND MARKER"
	twoOrgParityMarkerA3       = "TWOORG-A PARITY THIRD MARKER"
	twoOrgParityPoisonA        = "TWOORG-A PARITY POISON MARKER"
	twoOrgParityPoisonB        = "TWOORG-B PARITY POISON MARKER"
)

// twoOrgParityDeliver provisions a fresh consumer under the CURRENT process
// content profile and drives one message through the real boundary.
func twoOrgParityDeliver(t *testing.T, env *twoOrgJointTest, msg redis.XMessage, requestID string) {
	t.Helper()
	c := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	c.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: env.store})
	c.handleMessage(env.ctx, msg)
	var orgID string
	require.NoError(t, env.pool.QueryRow(env.ctx,
		"SELECT org_id::text FROM request_logs WHERE request_id = $1", requestID).Scan(&orgID),
		"the parity pass must persist %s", requestID)
	require.Equal(t, msg.Values["org_id"], orgID, "each pass lands under the event's declared org")
}

// twoOrgParityRow asserts the org attribution and returns the full row JSON.
func twoOrgParityRow(t *testing.T, env *twoOrgJointTest, requestID, orgID string) map[string]interface{} {
	t.Helper()
	row := twoOrgRowJSON(t, env, requestID)
	require.Equal(t, orgID, row["org_id"], "%s keeps its own org attribution", requestID)
	return row
}

// requireNoSentinel fails if any stored column of the row carries the
// sentinel (row_to_json covers every column, so a single search proves the
// strict pass stripped everything).
func requireNoSentinel(t *testing.T, row map[string]interface{}, sentinels ...string) {
	t.Helper()
	body, err := json.Marshal(row)
	require.NoError(t, err)
	for _, s := range sentinels {
		assert.NotContains(t, string(body), s, "no stored column may carry the sentinel under strict storage")
	}
}

func TestTwoOrg_ConfigParity_LegacyVsStrict(t *testing.T) {
	env := newTwoOrgJoint(t)
	on := true
	require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgA, &on))
	require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgB, &on))

	// ── Legacy pass (org A): the old configuration keeps full captures. ──
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "") // legacy
	twoOrgParityDeliver(t, env, env.deliverA, env.reqA)
	rowLegacyA := twoOrgParityRow(t, env, env.reqA, env.orgA)
	bodyLegacyA, err := json.Marshal(rowLegacyA)
	require.NoError(t, err)
	assert.Contains(t, string(bodyLegacyA), env.markerA,
		"the legacy pass keeps the org's own content captures")

	// ── Strict pass (org B): the new configuration strips every capture. ─
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	twoOrgParityDeliver(t, env, env.deliverB, env.reqB)
	rowStrictB := twoOrgParityRow(t, env, env.reqB, env.orgB)
	requireNoSentinel(t, rowStrictB, env.markerB, "JOINT SECRET", "PROMPT BODY")
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, rowStrictB["error"],
		"the strict error column carries the fixed redaction notice")
	assert.Equal(t, eventpublisher.ResolvePromptHash("definitely-not-a-valid-digest", env.markerB+" PROMPT BODY"),
		rowStrictB["prompt_hash"],
		"the malformed supplied digest is recomputed from the body, never stored verbatim")
	assert.Nil(t, rowStrictB["response"], "the strict response snapshot binds NULL")

	// ── Parity: the profiles differ ONLY in content. ─────────────────────
	// Same event shape, different org: every non-content column must match
	// byte-for-byte across the legacy and the strict pass.
	for _, field := range []string{
		"model_requested", "model_used", "upstream_url", "method",
		"status_code", "duration_ms", "tokens_in", "tokens_out", "cost_in_usd",
	} {
		assert.Equal(t, rowLegacyA[field], rowStrictB[field],
			"parity column %s: strict is a content redaction, never a semantic change", field)
	}
	// Both profiles commit the per-org policy decision identically.
	polA, totalA, err := env.store.ListPolicyDecisions(env.ctx, env.orgA, adminstore.PolicyDecisionFilters{})
	require.NoError(t, err)
	polB, totalB, err := env.store.ListPolicyDecisions(env.ctx, env.orgB, adminstore.PolicyDecisionFilters{})
	require.NoError(t, err)
	require.EqualValues(t, 1, totalA)
	require.EqualValues(t, 1, totalB)
	assert.Equal(t, twoOrgPolicyA, polA[0].PolicyID)
	assert.Equal(t, twoOrgPolicyB, polB[0].PolicyID)
	assert.Equal(t, "allow", polA[0].Verdict)
	assert.Equal(t, "enforce", polA[0].Mode)

	// ── Unsupported operator value fails CLOSED to strict. ───────────────
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", twoOrgParityUnsupportedEnv)
	twoOrgParityDeliver(t, env, redis.XMessage{
		ID:     "twoorg-parity-a2-1",
		Values: twoOrgCompletedEvent(twoOrgParityReqA2, env.orgA, twoOrgParityMarkerA2, twoOrgSessionA, twoOrgToolA, twoOrgPolicyA),
	}, twoOrgParityReqA2)
	rowUnsupported := twoOrgParityRow(t, env, twoOrgParityReqA2, env.orgA)
	requireNoSentinel(t, rowUnsupported, twoOrgParityMarkerA2, "PARITY SECOND MARKER")
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, rowUnsupported["error"],
		"an unsupported profile value degrades to strict, never to legacy")

	// ── Wire overrides: the strictest declaration wins, both directions. ─
	// Local strict + wire legacy: the wire must not widen.
	wireLegacy := twoOrgCompletedEvent(twoOrgParityReqA3, env.orgA, twoOrgParityMarkerA3, twoOrgSessionA, twoOrgToolA, twoOrgPolicyA)
	wireLegacy["content_profile"] = "legacy"
	twoOrgParityDeliver(t, env, redis.XMessage{ID: "twoorg-parity-a3-1", Values: wireLegacy}, twoOrgParityReqA3)
	rowWireLegacy := twoOrgParityRow(t, env, twoOrgParityReqA3, env.orgA)
	requireNoSentinel(t, rowWireLegacy, twoOrgParityMarkerA3, "PARITY THIRD MARKER")

	// Local legacy + wire metadata-only: the wire tightens.
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	wireStrict := twoOrgCompletedEvent(twoOrgParityReqB2, env.orgB, twoOrgParityMarkerB2, twoOrgSessionB, twoOrgToolB, twoOrgPolicyB)
	wireStrict["content_profile"] = "metadata-only"
	twoOrgParityDeliver(t, env, redis.XMessage{ID: "twoorg-parity-b2-1", Values: wireStrict}, twoOrgParityReqB2)
	rowWireStrict := twoOrgParityRow(t, env, twoOrgParityReqB2, env.orgB)
	requireNoSentinel(t, rowWireStrict, twoOrgParityMarkerB2, "PARITY SECOND MARKER")

	// ── Unsupported event type: documented refusal, nothing durable. ─────
	unknownType := twoOrgCompletedEvent("req-twoorg-parity-unknown", env.orgB, twoOrgParityMarkerB2, twoOrgSessionB, twoOrgToolB, twoOrgPolicyB)
	unknownType["event_type"] = "request.teleport_future"
	c := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	c.handleMessage(env.ctx, redis.XMessage{ID: "twoorg-parity-unknown-1", Values: unknownType})
	var unknownRows int64
	require.NoError(t, env.pool.QueryRow(env.ctx,
		"SELECT count(*) FROM request_logs WHERE request_id=$1", "req-twoorg-parity-unknown").Scan(&unknownRows))
	assert.Zero(t, unknownRows, "an unsupported event type is never persisted")
	assert.Equal(t, 0, twoOrgIntDLQSize(t, env.rdb, env.ctx),
		"an unsupported event type is a documented refusal, not poison")

	// ── DLQ parity: one poison per org per profile, side by side. ────────
	poisonOrgA, poisonOrgB := uuid.NewString(), uuid.NewString() // FK violations
	msgPoisonB := redis.XMessage{ID: "twoorg-parity-dlq-b-1", Values: twoOrgCompletedEvent(
		"req-twoorg-parity-poison-b", poisonOrgB, twoOrgParityPoisonB, twoOrgSessionB, twoOrgToolB, twoOrgPolicyB)}
	msgPoisonA := redis.XMessage{ID: "twoorg-parity-dlq-a-1", Values: twoOrgCompletedEvent(
		"req-twoorg-parity-poison-a", poisonOrgA, twoOrgParityPoisonA, twoOrgSessionA, twoOrgToolA, twoOrgPolicyA)}

	// Legacy local: B's poison archive keeps B's own captures.
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	cLegacy := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	for i := 0; i <= maxRetries; i++ {
		cLegacy.handleMessage(env.ctx, msgPoisonB)
	}
	// Strict local: A's poison archive is the bounded allowlist shape.
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	cStrict := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
	for i := 0; i <= maxRetries; i++ {
		cStrict.handleMessage(env.ctx, msgPoisonA)
	}

	fieldsB, envB := twoOrgFindDLQEnvelope(t, env.rdb, "req-twoorg-parity-poison-b")
	fieldsA, envA := twoOrgFindDLQEnvelope(t, env.rdb, "req-twoorg-parity-poison-a")

	// Each envelope keeps its own identity, under its own profile.
	assert.Equal(t, poisonOrgB, envB.Values["org_id"])
	assert.Equal(t, "req-twoorg-parity-poison-b", envB.Values["request_id"])
	assert.Equal(t, poisonOrgA, envA.Values["org_id"])
	assert.Equal(t, "req-twoorg-parity-poison-a", envA.Values["request_id"])

	payloadB, _ := fieldsB["payload"].(string)
	assert.Contains(t, payloadB, twoOrgParityPoisonB, "the legacy archive keeps the poisoned org's own captures")
	assert.NotContains(t, payloadB, twoOrgParityPoisonA, "B's envelope must never carry A's sentinel")
	assert.NotContains(t, payloadB, "req-twoorg-parity-poison-a")

	payloadA, _ := fieldsA["payload"].(string)
	var strictEnvelope eventpublisher.DLQEnvelope
	require.NoError(t, json.Unmarshal([]byte(payloadA), &strictEnvelope))
	for _, capture := range []string{"payload", "upstream_payload", "upstream_response"} {
		assert.NotContains(t, strictEnvelope.Values, capture,
			"the strict archive allowlist drops every content capture")
	}
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, strictEnvelope.Values["error"],
		"the strict archive error is the fixed notice")
	assert.NotContains(t, payloadA, twoOrgParityPoisonB, "A's envelope must never carry B's sentinel")
	assert.NotContains(t, payloadA, "req-twoorg-parity-poison-b")

	// Exactly one archived envelope per poisoned event on the shared stream.
	assert.Equal(t, 2, twoOrgIntDLQSize(t, env.rdb, env.ctx),
		"exactly one DLQ entry per poison, per org, per profile")
}
