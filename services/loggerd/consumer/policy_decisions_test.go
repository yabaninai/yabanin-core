package consumer

// OP-9 acceptance:
//   - unit: the `policy` field parser — absent/empty is the legacy shape
//     (skip), a malformed payload skips counted, BOTH payload shapes decode
//     legacy single object lands one row; evidence is STRIPPED from findings
//     (content never lands);
//   - live (disposable PG): an event with an array `policy` lands one
//     policy_decisions row PER element, a single-object payload lands one,
//     an event without it lands none; the writer is RLS-clean (the same
//     delivery succeeds under the yabanin_app posture where the org GUC pin
//     is mandatory) and the org-scoped read of the OTHER org sees nothing;
//   - retention: rows older than the 90d window are purged, fresh ones live.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePolicyDecision(t *testing.T) {
	valid := `{"policy_id":"11111111-1111-1111-1111-111111111111","version":3,"mode":"shadow",` +
		`"verdict":"mask","duration_ms":7,"findings":[` +
		`{"step":"s1","category":"pan","severity":"high","span":"0:16","action":"mask","evidence":"4111111111111111"},` +
		`{"step":"s2","category":"secrets","severity":"medium","action":"flag"}]}`

	t.Run("absent or empty field is the legacy event: nil, no error counted", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		assert.Empty(t, parsePolicyDecision(map[string]interface{}{}))
		assert.Empty(t, parsePolicyDecision(map[string]interface{}{"policy": ""}))
		assert.Empty(t, parsePolicyDecision(map[string]interface{}{"policy": nil}))
		assert.Empty(t, parsePolicyDecision(map[string]interface{}{"policy": 42}))
		assert.Equal(t, before, policyDecodeErrors.Load(), "absence is the norm, not a decode error")
	})

	t.Run("malformed or invalid payloads skip counted", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		for name, fields := range map[string]map[string]interface{}{
			"bad json":      {"policy": "{nope"},
			"empty verdict": {"policy": `{"policy_id":"p","mode":"shadow","verdict":""}`},
			"empty policy":  {"policy": `{"policy_id":"","mode":"shadow","verdict":"deny"}`},
			"bad mode":      {"policy": `{"policy_id":"p","mode":"kill","verdict":"deny"}`},
			"non-object":    {"policy": `["deny"]`},
		} {
			assert.Empty(t, parsePolicyDecision(fields), "case %s must skip", name)
		}
		assert.Equal(t, before+5, policyDecodeErrors.Load(), "every unusable payload counts")
	})

	t.Run("legacy single-object payload decodes to one row (F-1 legacy compatibility)", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		d := parsePolicyDecision(map[string]interface{}{"policy": valid})
		require.Len(t, d, 1)
		assert.Equal(t, "11111111-1111-1111-1111-111111111111", d[0].PolicyID)
		assert.Equal(t, int64(3), d[0].Version)
		assert.Equal(t, modeShadow, d[0].Mode)
		assert.Equal(t, "mask", d[0].Verdict)
		assert.Equal(t, int64(7), d[0].DurationMs)
		assert.Equal(t, before, policyDecodeErrors.Load())
	})

	t.Run("OP-8 array payload: one decision per element (F-1)", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		arr := "[" + valid + "," +
			`{"policy_id":"44444444-4444-4444-4444-444444444444","version":9,"mode":"enforce",` +
			`"verdict":"deny","duration_ms":11,"findings":[]}]`
		d := parsePolicyDecision(map[string]interface{}{"policy": arr})
		require.Len(t, d, 2, "one row per executed policy")
		assert.Equal(t, "11111111-1111-1111-1111-111111111111", d[0].PolicyID)
		assert.Equal(t, "44444444-4444-4444-4444-444444444444", d[1].PolicyID)
		assert.Equal(t, "enforce", d[1].Mode)
		assert.Equal(t, "deny", d[1].Verdict)
		assert.Equal(t, before, policyDecodeErrors.Load())
	})

	t.Run("empty array is the producer's nothing-evaluated: zero rows, not an error", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		assert.Empty(t, parsePolicyDecision(map[string]interface{}{"policy": `[]`}))
		assert.Equal(t, before, policyDecodeErrors.Load())
	})

	t.Run("array elements are independent: a valid decision never dies with an invalid sibling", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		arr := `[{"policy_id":"","mode":"shadow","verdict":"deny"},` + valid + `,"{nope",` +
			`{"policy_id":"p","mode":"kill","verdict":"deny"}]`
		d := parsePolicyDecision(map[string]interface{}{"policy": arr})
		require.Len(t, d, 1, "only the valid element lands")
		assert.Equal(t, "11111111-1111-1111-1111-111111111111", d[0].PolicyID)
		assert.Equal(t, before+3, policyDecodeErrors.Load(), "every unusable element counts individually")
	})

	t.Run("array payload is truncated tail-first at the decisions cap", func(t *testing.T) {
		payload := "["
		for i := 0; i < policyDecisionMaxDecisions+3; i++ {
			if i > 0 {
				payload += ","
			}
			payload += fmt.Sprintf(`{"policy_id":"p%d","version":1,"mode":"shadow","verdict":"flag"}`, i)
		}
		payload += "]"
		d := parsePolicyDecision(map[string]interface{}{"policy": payload})
		assert.Len(t, d, policyDecisionMaxDecisions, "tail decisions are dropped")
	})

	t.Run("valid payload decodes; evidence never survives", func(t *testing.T) {
		d := parsePolicyDecision(map[string]interface{}{"policy": valid})
		require.Len(t, d, 1)
		assert.NotContains(t, string(d[0].Findings), "4111111111111111", "evidence (content) is stripped")
		assert.NotContains(t, string(d[0].Findings), "evidence")
		assert.Contains(t, string(d[0].Findings), `"category":"pan"`)
		assert.Contains(t, string(d[0].Findings), `"severity":"high"`)
		assert.Contains(t, string(d[0].Findings), `"step":"s1"`)
		assert.Contains(t, string(d[0].Findings), `"action":"mask"`)
		assert.Contains(t, string(d[0].Findings), `"category":"secrets"`)
	})

	t.Run("numeric fields are clamped to non-negative; findings capped with markers", func(t *testing.T) {
		payload := `{"policy_id":"p","version":-5,"mode":"enforce","verdict":"deny","duration_ms":-1,"findings":[`
		for i := 0; i < policyDecisionMaxFindings+5; i++ {
			if i > 0 {
				payload += ","
			}
			payload += fmt.Sprintf(`{"step":"s%d","category":"c","severity":"low","action":"allow"}`, i)
		}
		payload += `]}`
		d := parsePolicyDecision(map[string]interface{}{"policy": payload})
		require.Len(t, d, 1)
		assert.Equal(t, int64(0), d[0].Version, "negative version clamps to 0 (unknown)")
		assert.Equal(t, int64(0), d[0].DurationMs)
		env := decodeStoredEnvelope(t, d[0].Findings)
		assert.Len(t, env.Findings, policyDecisionMaxFindings, "tail findings are dropped")
		assert.Equal(t, policyDecisionMaxFindings+5, env.FindingsTotal, "the honest total survives the clip")
		assert.True(t, env.FindingsTruncated, "the clip is stamped, never silent")
	})

	t.Run("legacy payload wraps in a completeness-unknown envelope", func(t *testing.T) {
		d := parsePolicyDecision(map[string]interface{}{"policy": valid})
		require.Len(t, d, 1)
		env := decodeStoredEnvelope(t, d[0].Findings)
		assert.Equal(t, policyStoredEnvelopeVersion, env.EnvelopeVersion)
		assert.Equal(t, "unknown", env.TraceCompleteness,
			"legacy producers carry no trace information — surfaced as unknown, never as 'no steps ran'")
		assert.Len(t, env.Findings, 2)
		assert.Nil(t, env.Steps, "no fabricated steps")
		assert.Empty(t, env.Hook, "no fabricated hook")
		assert.Nil(t, env.Matched, "no fabricated matched")
		assert.Empty(t, env.EffectiveAction)
		assert.Empty(t, env.AppliedAction)
	})

	t.Run("envelope v1 passes through with consumer bounds re-stamped", func(t *testing.T) {
		wire := `{"policy_id":"p","version":1,"mode":"enforce","verdict":"deny","duration_ms":5,` +
			`"envelope_version":1,"hook":"pre_upstream","rule_namespace":"policy","matched":true,` +
			`"effective_action":"deny","applied_action":"deny","trace_completeness":"full",` +
			`"steps":[{"step":"word","outcome":"ran","duration_ms":2},{"step":"judge","outcome":"skipped","error":"short-circuited after deny"}],` +
			`"steps_total":2,"findings":[{"step":"word","category":"c","severity":"high","action":"deny","evidence":"SECRET-EVIDENCE"}],` +
			`"findings_total":1}`
		d := parsePolicyDecision(map[string]interface{}{"policy": wire})
		require.Len(t, d, 1)
		env := decodeStoredEnvelope(t, d[0].Findings)
		assert.Equal(t, 1, env.EnvelopeVersion)
		assert.Equal(t, "pre_upstream", env.Hook)
		assert.Equal(t, "policy", env.RuleNamespace)
		require.NotNil(t, env.Matched)
		assert.True(t, *env.Matched)
		assert.Equal(t, "deny", env.EffectiveAction)
		assert.Equal(t, "deny", env.AppliedAction)
		assert.Equal(t, "full", env.TraceCompleteness)
		require.Len(t, env.Steps, 2)
		assert.Equal(t, "skipped", env.Steps[1].Outcome)
		assert.Equal(t, "short-circuited after deny", env.Steps[1].Error, "engine skip reasons survive content-free")
		assert.Equal(t, 2, env.StepsTotal)
		assert.NotContains(t, string(d[0].Findings), "SECRET-EVIDENCE", "envelope findings are sanitized like bare ones")
	})

	t.Run("unknown envelope version degrades to the stripped marker", func(t *testing.T) {
		wire := `{"policy_id":"p","version":1,"mode":"enforce","verdict":"deny","duration_ms":1,"envelope_version":99,` +
			`"findings":[{"step":"s","category":"c","severity":"low","action":"allow"}]}`
		d := parsePolicyDecision(map[string]interface{}{"policy": wire})
		require.Len(t, d, 1, "the decision still lands (the request keeps its record)")
		var env storedEnvelope
		require.NoError(t, json.Unmarshal(d[0].Findings, &env))
		assert.Equal(t, 99, env.EnvelopeVersion, "the version marker stays visible")
		assert.Nil(t, env.Findings, "nothing inside an unknown version is interpreted")
		assert.Nil(t, env.Steps)
		assert.Empty(t, env.TraceCompleteness)
	})

	t.Run("step traces are capped with honest totals", func(t *testing.T) {
		wire := `{"policy_id":"p","version":1,"mode":"shadow","verdict":"allow","duration_ms":1,` +
			`"envelope_version":1,"trace_completeness":"partial","steps":[`
		for i := 0; i < policyDecisionMaxSteps+4; i++ {
			if i > 0 {
				wire += ","
			}
			wire += fmt.Sprintf(`{"step":"s%d","outcome":"ran"}`, i)
		}
		wire += `],"steps_total":68}`
		d := parsePolicyDecision(map[string]interface{}{"policy": wire})
		require.Len(t, d, 1)
		env := decodeStoredEnvelope(t, d[0].Findings)
		assert.Len(t, env.Steps, policyDecisionMaxSteps, "consumer re-enforces the producer bound")
		assert.Equal(t, policyDecisionMaxSteps+4, env.StepsTotal)
		assert.True(t, env.StepsTruncated, "consumer clip is stamped even when the producer claim lagged")
	})
}

// decodeStoredEnvelope unmarshals one decision's storage envelope.
func decodeStoredEnvelope(t *testing.T, raw json.RawMessage) storedEnvelope {
	t.Helper()
	var env storedEnvelope
	require.NoError(t, json.Unmarshal(raw, &env), "storage payload must be the envelope object: %s", raw)
	return env
}

// seedPolicyDecisionOrg creates one org and returns its id (fixtures own
// their context: the cleanup runs after the test's ctx may be gone).
func seedPolicyDecisionOrg(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var orgID string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		name, name).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = $1", orgID)
	})
	return orgID
}

// seedDecisionRowRaw inserts a decision row bypassing the writer (fixtures).
func seedDecisionRowRaw(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID, requestID string, age time.Duration) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO policy_decisions (org_id, request_id, policy_id, policy_version, mode, verdict, findings, duration_ms, created_at)
		 VALUES ($1::uuid, $2, 'pol-fix', 1, 'shadow', 'flag', '[]'::jsonb, 0, now() - $3::interval)`,
		orgID, requestID, fmt.Sprintf("%d seconds", int64(age.Seconds())))
	require.NoError(t, err)
}

func countPolicyDecisions(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions WHERE org_id = $1::uuid`, orgID).Scan(&n))
	return n
}

// eventWithPolicy builds one request.completed event field map.
func eventWithPolicy(orgID, requestID string, policy string) redis.XMessage {
	fields := map[string]interface{}{
		"event_type":  "request.completed",
		"org_id":      orgID,
		"request_id":  requestID,
		"model_used":  "gpt-test",
		"status_code": "200",
	}
	if policy != "" {
		fields["policy"] = policy
	}
	return redis.XMessage{Values: fields}
}

// TestPolicyDecisionWriter_Live: the writer lands one row per event that
// carries a `policy` payload — with every field — and skips legacy events.
func TestPolicyDecisionWriter_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-writer-org")

	c := New(nil, NewDBOps(pool), "events:queue", slog.New(slog.DiscardHandler))

	policy := `{"policy_id":"22222222-2222-2222-2222-222222222222","version":4,"mode":"enforce",` +
		`"verdict":"deny","duration_ms":23,"findings":[{"step":"s1","category":"injection","severity":"high","action":"deny","evidence":"ignore previous instructions"}]}`
	require.NoError(t, c.handleRequestComplete(ctx, eventWithPolicy(orgID, "req-dec-1", policy)))

	var orgIDCol, requestID, policyID, mode, verdict string
	var version int
	var durationMs int64
	var findings []byte
	var createdAt time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT org_id::text, request_id, policy_id, policy_version, mode, verdict, findings, duration_ms, created_at
		 FROM policy_decisions WHERE request_id = 'req-dec-1'`).
		Scan(&orgIDCol, &requestID, &policyID, &version, &mode, &verdict, &findings, &durationMs, &createdAt))
	assert.Equal(t, orgID, orgIDCol)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", policyID)
	assert.Equal(t, 4, version)
	assert.Equal(t, "enforce", mode)
	assert.Equal(t, "deny", verdict)
	assert.Equal(t, int64(23), durationMs)
	assert.NotContains(t, string(findings), "ignore previous instructions", "content never lands")
	assert.NotContains(t, string(findings), "evidence")
	assert.WithinDuration(t, time.Now().UTC(), createdAt, 2*time.Minute, "delivery time is the event business time here (no ts field)")

	// Legacy event (no policy field): the normal pre-OP-8 shape — no row.
	require.NoError(t, c.handleRequestComplete(ctx, eventWithPolicy(orgID, "req-dec-legacy", "")))
	assert.Equal(t, int64(1), countPolicyDecisions(ctx, t, pool, orgID), "legacy event must not produce a decision row")
}

// TestPolicyDecisionWriter_EnvelopeStorage_Live: CORE-TRACE-05 — every
// stored decision lands as the versioned envelope OBJECT in findings jsonb
// (additive; no migration). A v1 producer payload keeps its evaluation
// contract through the real transport; a legacy payload is wrapped with
// trace_completeness=unknown — surfaced as "no information", never as
// "no steps ran".
func TestPolicyDecisionWriter_EnvelopeStorage_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-envelope-org")

	c := New(nil, NewDBOps(pool), "events:queue", slog.New(slog.DiscardHandler))

	v1 := `[{"policy_id":"77777777-7777-7777-7777-777777777777","version":3,"mode":"shadow",` +
		`"verdict":"allow","duration_ms":4,"findings":[{"step":"scan.pii","category":"innsnils","severity":"high","action":"deny"}],` +
		`"envelope_version":1,"hook":"pre_upstream","rule_namespace":"policy","matched":true,` +
		`"effective_action":"deny","applied_action":"allow","trace_completeness":"full",` +
		`"steps":[{"step":"scan.pii","outcome":"ran","duration_ms":3},{"step":"judge","outcome":"skipped","error":"short-circuited after deny"}],` +
		`"steps_total":2,"findings_total":1}]`
	legacy := `[{"policy_id":"88888888-8888-8888-8888-888888888888","version":1,"mode":"enforce","verdict":"flag","duration_ms":2,` +
		`"findings":[{"step":"word","category":"secrets","severity":"medium","action":"flag"}]}]`
	require.NoError(t, c.handleRequestComplete(ctx, eventWithPolicy(orgID, "req-dec-env-v1", v1)))
	require.NoError(t, c.handleRequestComplete(ctx, eventWithPolicy(orgID, "req-dec-env-legacy", legacy)))

	read := func(requestID string) []byte {
		t.Helper()
		var findings []byte
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT findings FROM policy_decisions WHERE request_id = $1`, requestID).Scan(&findings))
		return findings
	}

	var env storedEnvelope
	require.NoError(t, json.Unmarshal(read("req-dec-env-v1"), &env), "v1 payload lands as the envelope object")
	assert.Equal(t, policyStoredEnvelopeVersion, env.EnvelopeVersion)
	assert.Equal(t, "pre_upstream", env.Hook)
	assert.Equal(t, "policy", env.RuleNamespace)
	require.NotNil(t, env.Matched)
	assert.True(t, *env.Matched)
	assert.Equal(t, "deny", env.EffectiveAction, "shadow would-have stays explicit in storage")
	assert.Equal(t, "allow", env.AppliedAction)
	assert.Equal(t, "full", env.TraceCompleteness)
	assert.Equal(t, 2, env.StepsTotal)
	require.Len(t, env.Steps, 2)
	assert.Equal(t, "skipped", env.Steps[1].Outcome, "the early-deny tail is stored, not lost")
	assert.Equal(t, 1, env.FindingsTotal)

	env = storedEnvelope{}
	require.NoError(t, json.Unmarshal(read("req-dec-env-legacy"), &env))
	assert.Equal(t, policyStoredEnvelopeVersion, env.EnvelopeVersion)
	assert.Equal(t, "unknown", env.TraceCompleteness, "legacy payloads surface unknown, not 'no steps ran'")
	assert.Len(t, env.Findings, 1)
	assert.Nil(t, env.Steps, "no fabricated steps for legacy payloads")
}

// publishes `policy` as a JSON ARRAY — one decision per executed policy — and
// the writer must land one policy_decisions row PER element in the same
// delivery (this is the exact shape the acceptance stand produced and the
// old single-object parser dropped: policy_decisions stayed empty forever).
func TestPolicyDecisionWriter_ArrayPayload_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-array-org")

	c := New(nil, NewDBOps(pool), "events:queue", slog.New(slog.DiscardHandler))

	arr := `[{"policy_id":"55555555-5555-5555-5555-555555555555","name":"sovereign-default","version":2,` +
		`"mode":"shadow","verdict":"allow","duration_ms":3,"findings":[` +
		`{"step":"scan.pii","category":"innsnils","severity":"high","action":"flag","evidence":"123-456-789 00"}]},` +
		`{"policy_id":"66666666-6666-6666-6666-666666666666","version":1,"mode":"enforce",` +
		`"verdict":"deny","duration_ms":1,"findings":[]}]`
	require.NoError(t, c.handleRequestComplete(ctx, eventWithPolicy(orgID, "req-dec-arr", arr)))

	type row struct {
		policyID string
		version  int
		mode     string
		verdict  string
	}
	rows := func() []row {
		t.Helper()
		var out []row
		got, err := pool.Query(ctx,
			`SELECT policy_id::text, policy_version, mode, verdict FROM policy_decisions
			 WHERE org_id = $1::uuid AND request_id = 'req-dec-arr' ORDER BY policy_id`, orgID)
		require.NoError(t, err)
		defer got.Close()
		for got.Next() {
			var r row
			require.NoError(t, got.Scan(&r.policyID, &r.version, &r.mode, &r.verdict))
			out = append(out, r)
		}
		require.NoError(t, got.Err())
		return out
	}()

	require.Len(t, rows, 2, "one policy_decisions row per array element")
	assert.Equal(t, row{"55555555-5555-5555-5555-555555555555", 2, "shadow", "allow"}, rows[0])
	assert.Equal(t, row{"66666666-6666-6666-6666-666666666666", 1, "enforce", "deny"}, rows[1])

	// Evidence from the array findings never lands (content-free log).
	var leaked int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions WHERE request_id = 'req-dec-arr' AND findings::text LIKE '%123-456-789%'`).
		Scan(&leaked))
	assert.Zero(t, leaked, "evidence (content) is stripped from every decision row")
}

// TestPolicyDecisionWriter_RLSPosture_Live: the same delivery through the
// application-role pool (yabanin_app, NOBYPASSRLS, FORCE RLS) succeeds only
// because the writer pins the org GUC in the delivery tx; the org-scoped
// read of the OTHER org sees nothing.
func TestPolicyDecisionWriter_RLSPosture_Live(t *testing.T) {
	appPool := testdb.PostgresApp(t, "e2e")
	superPool := testdb.Postgres(t)
	ctx := context.Background()
	orgA := seedPolicyDecisionOrg(t, superPool, "pdec-rls-writer-a")
	orgB := seedPolicyDecisionOrg(t, superPool, "pdec-rls-writer-b")

	c := New(nil, NewDBOps(appPool), "events:queue", slog.New(slog.DiscardHandler))
	policy := `{"policy_id":"33333333-3333-3333-3333-333333333333","version":1,"mode":"shadow","verdict":"flag","duration_ms":1,"findings":[]}`
	require.NoError(t, c.handleRequestComplete(ctx, eventWithPolicy(orgA, "req-rls-dec", policy)),
		"the writer must be RLS-clean under the application posture (org GUC pin)")
	assert.Equal(t, int64(1), countPolicyDecisions(ctx, t, superPool, orgA))

	// Store reads are org-scoped: org B sees nothing of org A's decisions.
	store := adminstore.New(appPool, slog.New(slog.DiscardHandler), nil)
	_, totalB, err := store.ListPolicyDecisions(ctx, orgB, adminstore.PolicyDecisionFilters{PageFilter: adminstore.NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Zero(t, totalB, "org B's read never leaks org A's decisions")

	rows, totalA, err := store.ListPolicyDecisions(ctx, orgA, adminstore.PolicyDecisionFilters{PageFilter: adminstore.NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Equal(t, int64(1), totalA)
	require.Len(t, rows, 1)
	assert.Equal(t, "req-rls-dec", rows[0].RequestID)
}

// TestPurgePolicyDecisions_Live: rows older than the window are deleted,
// fresh rows live; the purge is per-org GUC-pinned (runs under the
// application posture where a global DELETE would see nothing).
func TestPurgePolicyDecisions_Live(t *testing.T) {
	appPool := testdb.PostgresApp(t, "e2e")
	superPool := testdb.Postgres(t)
	ctx := context.Background()
	orgPurge := seedPolicyDecisionOrg(t, superPool, "pdec-purge-org")
	orgKeep := seedPolicyDecisionOrg(t, superPool, "pdec-purge-keep")

	seedDecisionRowRaw(ctx, t, superPool, orgPurge, "req-old", 91*24*time.Hour)
	seedDecisionRowRaw(ctx, t, superPool, orgPurge, "req-fresh", time.Hour)
	seedDecisionRowRaw(ctx, t, superPool, orgKeep, "req-keep-old", 95*24*time.Hour)

	deleted, err := PurgeExpiredPolicyDecisions(ctx, appPool, 500, PolicyDecisionsRetentionDays)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, deleted, int64(1), "the expired rows of both orgs are deleted")
	assert.Equal(t, int64(1), countPolicyDecisions(ctx, t, superPool, orgPurge), "only the fresh row of the purge org survives")

	var freshAlive int64
	require.NoError(t, superPool.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions WHERE request_id = 'req-fresh'`).Scan(&freshAlive))
	assert.Equal(t, int64(1), freshAlive, "fresh rows live")

	// A different org's expired row must be gone too (the purge walks all
	// orgs) — but only decision-log rows of ITS org scope.
	var keepAlive int64
	require.NoError(t, superPool.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions WHERE request_id = 'req-keep-old'`).Scan(&keepAlive))
	assert.Zero(t, keepAlive, "expired rows are purged in every org")
}

// Event.Policy shape (pkg/eventpublisher/publisher.go, the OP-8 array
// execution order, the first carrying finding evidence that must NEVER land.
const goldenPolicyArray = `[{"policy_id":"55555555-5555-5555-5555-555555555555","name":"sovereign-default","version":2,` +
	`"mode":"shadow","verdict":"allow","duration_ms":3,"findings":[` +
	`{"step":"scan.pii","category":"innsnils","severity":"high","action":"flag","evidence":"123-456-789 00"}]},` +
	`{"policy_id":"66666666-6666-6666-6666-666666666666","version":1,"mode":"enforce",` +
	`"verdict":"deny","duration_ms":1,"findings":[]}]`

// carrying the golden Policy array goes through the REAL gateway transport
// (RedisPublisher.Publish, the `policy` stream field) and the REAL consumer
// dispatch entry (deliverEvent, not a direct handler call), and lands the
// documented loggerd record: one policy_decisions row per array element in
// the same delivery tx as the request log, readable through
// adminstore.ListPolicyDecisions (the GET /policy-decisions surface), with
// finding evidence stripped. The deny-path request.invalid case is D1-gated
// and intentionally absent here.
func TestCrossPacketPolicyGolden_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-crosspacket-org")

	// Producer side: the real transport mapping (the `policy` field of the
	// events:queue entry), not a hand-built fields map.
	pub := eventpublisher.NewRedisPublisher(rdb, "events:queue")
	require.NoError(t, pub.Publish(ctx, &eventpublisher.Event{
		EventType:      "request.completed",
		Source:         "gateway",
		RequestID:      "req-xpack-golden",
		OrgID:          orgID,
		ModelRequested: "gpt-4o",
		ModelUsed:      "gpt-4o",
		StatusCode:     200,
		Method:         "POST",
		Policy:         goldenPolicyArray,
	}))

	entries, err := rdb.XRange(ctx, "events:queue", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, entries, 1, "exactly the published stream entry")

	// Consumer side: the real dispatch entry point.
	c := New(nil, NewDBOps(pool), "events:queue", slog.New(slog.DiscardHandler))
	before := policyDecodeErrors.Load()
	require.NoError(t, c.deliverEvent(ctx, entries[0], "request.completed"),
		"the real dispatch entry must accept the producer-shaped event")
	assert.Equal(t, before, policyDecodeErrors.Load(), "the golden shape decodes clean")

	// The decisions commit in the same delivery tx as the request log.
	var logs int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE request_id = 'req-xpack-golden'`).Scan(&logs))
	assert.Equal(t, int64(1), logs, "the request log row commits with the decisions")

	// The org's own read (GET /policy-decisions surface) sees one row per
	// array element.
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	rows, total, err := store.ListPolicyDecisions(ctx, orgID,
		adminstore.PolicyDecisionFilters{PageFilter: adminstore.NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total, "one policy_decisions row per array element")
	require.Len(t, rows, 2)

	byPolicy := make(map[string]adminstore.PolicyDecision, len(rows))
	for _, r := range rows {
		byPolicy[r.PolicyID] = r
	}
	shadow, ok := byPolicy["55555555-5555-5555-5555-555555555555"]
	require.True(t, ok, "the shadow decision lands")
	assert.Equal(t, "req-xpack-golden", shadow.RequestID)
	assert.Equal(t, 2, shadow.PolicyVersion)
	assert.Equal(t, "shadow", shadow.Mode)
	assert.Equal(t, "allow", shadow.Verdict)
	assert.Equal(t, int64(3), shadow.DurationMs)
	assert.Contains(t, string(shadow.Findings), "innsnils", "findings re-render content-free")
	assert.Contains(t, string(shadow.Findings), "scan.pii")

	deny, ok := byPolicy["66666666-6666-6666-6666-666666666666"]
	require.True(t, ok, "the deny decision lands")
	assert.Equal(t, 1, deny.PolicyVersion)
	assert.Equal(t, "enforce", deny.Mode)
	assert.Equal(t, "deny", deny.Verdict)

	// Evidence never lands — on any row.
	for _, r := range rows {
		assert.NotContains(t, string(r.Findings), "123-456-789", "evidence (content) is stripped")
		assert.NotContains(t, string(r.Findings), "evidence")
	}
}

// ---------------------------------------------------------------------------
// array-vs-object faults and mixed-version payloads — proven through the
// REAL dispatch entry (deliverEvent) with the REAL producer transport
// (RedisPublisher) where the wire shape matters. Contract (e): unusable
// payloads are counted and skipped, the request log still commits, the
// delivery still ACKs — a bad producer never wedges the stream, and a
// partial landing (one valid decision among invalid siblings) is never
// mistaken for success. Operation repeat (the lost-ACK replay), the
// cancel/interrupt axis and recovery have dedicated tests below. The
// deny-path request.invalid case stays D1-gated: no request.invalid
// fixtures in this packet (contract (c) file map).
// ---------------------------------------------------------------------------

// publishPolicyFault publishes one producer-shaped event through the real
// RedisPublisher transport and returns the exact stream entry (XRANGE), so
// deliverEvent sees the field map a real — possibly buggy — producer writes.
func publishPolicyFault(t *testing.T, ctx context.Context, rdb *redis.Client, ev *eventpublisher.Event) redis.XMessage {
	t.Helper()
	require.NoError(t, eventpublisher.NewRedisPublisher(rdb, "events:queue").Publish(ctx, ev))
	entries, err := rdb.XRange(ctx, "events:queue", "-", "+").Result()
	require.NoError(t, err)
	require.NotEmpty(t, entries, "the published entry is on the stream")
	return entries[len(entries)-1]
}

// negativeEvent is the minimal completed-event template around the fault
// carrier: the same shape the G2 golden proves delivers a request_logs row.
func negativeEvent(orgID, requestID, policy string) *eventpublisher.Event {
	return &eventpublisher.Event{
		EventType:      "request.completed",
		Source:         "gateway",
		RequestID:      requestID,
		OrgID:          orgID,
		ModelRequested: "gpt-4o",
		ModelUsed:      "gpt-4o",
		StatusCode:     200,
		Method:         "POST",
		Policy:         policy,
	}
}

// requireDecisionRows counts the decision rows of one request.
func requireDecisionRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, requestID string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions WHERE request_id = $1`, requestID).Scan(&n))
	return n
}

// requireRequestLog asserts the request log committed (the delivery tx).
func requireRequestLog(ctx context.Context, t *testing.T, pool *pgxpool.Pool, requestID string, want int64) {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE request_id = $1`, requestID).Scan(&n))
	assert.Equal(t, want, n, "request_logs rows for "+requestID)
}

// wire shape from the contract (e) array-vs-object axis degrades exactly as
// pinned — counted/skip, zero or partial rows, delivery ACKs, the request
// log commits. A bad producer never wedges the stream.
func TestPolicyDeliveryNegativeShapes_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-negative-org")

	c := New(nil, NewDBOps(pool), "events:queue", slog.New(slog.DiscardHandler))

	t.Run("malformed json: ACK, one counted error, request log still commits, zero rows", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		entry := publishPolicyFault(t, ctx, rdb, negativeEvent(orgID, "req-neg-badjson", "{nope"))
		require.NoError(t, c.deliverEvent(ctx, entry, "request.completed"),
			"a bad policy payload must never fail (nack/wedge) the delivery")
		assert.Equal(t, before+1, policyDecodeErrors.Load(), "the malformed payload counts once")
		assert.Zero(t, requireDecisionRows(ctx, t, pool, "req-neg-badjson"))
		requireRequestLog(ctx, t, pool, "req-neg-badjson", 1)
	})

	t.Run("array of non-objects: every element counts individually, zero rows", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		entry := publishPolicyFault(t, ctx, rdb, negativeEvent(orgID, "req-neg-nonobjects", `["deny","allow"]`))
		require.NoError(t, c.deliverEvent(ctx, entry, "request.completed"))
		assert.Equal(t, before+2, policyDecodeErrors.Load(),
			"array decode succeeds, so every unusable element counts on its own")
		assert.Zero(t, requireDecisionRows(ctx, t, pool, "req-neg-nonobjects"))
		requireRequestLog(ctx, t, pool, "req-neg-nonobjects", 1)
	})

	t.Run("empty array: zero rows, nothing counted (nothing evaluated is the norm)", func(t *testing.T) {
		before := policyDecodeErrors.Load()
		entry := publishPolicyFault(t, ctx, rdb, negativeEvent(orgID, "req-neg-emptyarr", `[]`))
		require.NoError(t, c.deliverEvent(ctx, entry, "request.completed"))
		assert.Equal(t, before, policyDecodeErrors.Load(), "an empty array is not a decode error")
		assert.Zero(t, requireDecisionRows(ctx, t, pool, "req-neg-emptyarr"))
		requireRequestLog(ctx, t, pool, "req-neg-emptyarr", 1)
	})

	t.Run("mixed validity: the valid element lands, unusable siblings count individually", func(t *testing.T) {
		// Contract (f).2: one valid decision among three unusable siblings.
		before := policyDecodeErrors.Load()
		entry := publishPolicyFault(t, ctx, rdb, negativeEvent(orgID, "req-neg-mixed",
			`[{"policy_id":"","mode":"shadow","verdict":"deny"},`+
				`{"policy_id":"11111111-1111-1111-1111-111111111111","version":3,"mode":"shadow",`+
				`"verdict":"mask","duration_ms":7,"findings":[]},`+
				`"{nope",{"policy_id":"p","mode":"kill","verdict":"deny"}]`))
		require.NoError(t, c.deliverEvent(ctx, entry, "request.completed"),
			"partial validity is a degraded landing, not a delivery failure")
		assert.Equal(t, before+3, policyDecodeErrors.Load(), "each unusable element counts on its own")
		assert.Equal(t, int64(1), requireDecisionRows(ctx, t, pool, "req-neg-mixed"),
			"exactly the valid element lands — a partial landing is never treated as success")

		var policyID, verdict string
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT policy_id::text, verdict FROM policy_decisions WHERE request_id = 'req-neg-mixed'`).
			Scan(&policyID, &verdict))
		assert.Equal(t, "11111111-1111-1111-1111-111111111111", policyID)
		assert.Equal(t, "mask", verdict)
		requireRequestLog(ctx, t, pool, "req-neg-mixed", 1)
	})
}

// contract (e) — an OLD producer's legacy single-object payload through the
// real transport lands exactly one decision row with zero decode errors.
// (The reverse — NEW producer array into a pre-62062b38 consumer — stays the
// documented rolling-deploy limitation: counted skip, not code-fixable here.)
func TestPolicyDecisionMixedVersion_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-mixedver-org")

	legacy := `{"policy_id":"22222222-2222-2222-2222-222222222222","version":4,"mode":"enforce",` +
		`"verdict":"deny","duration_ms":23,"findings":[]}`
	entry := publishPolicyFault(t, ctx, rdb, negativeEvent(orgID, "req-mv-legacy", legacy))

	c := New(nil, NewDBOps(pool), "events:queue", slog.New(slog.DiscardHandler))
	before := policyDecodeErrors.Load()
	require.NoError(t, c.deliverEvent(ctx, entry, "request.completed"))
	assert.Equal(t, before, policyDecodeErrors.Load(), "the legacy shape decodes clean")
	assert.Equal(t, int64(1), requireDecisionRows(ctx, t, pool, "req-mv-legacy"),
		"old producer + new consumer: exactly one row")
	requireRequestLog(ctx, t, pool, "req-mv-legacy", 1)
}

// stream entry delivered twice (the lost-ACK redelivery the retry path
// produces). The durable inbox dedupes the replay: exactly one request_logs
// row and one decision row per element survive; the second delivery reports
// success (done, not failed) so the message ACKs without duplicate rows.
func TestPolicyDecisionReplay_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-replay-org")

	entry := publishPolicyFault(t, ctx, rdb, negativeEvent(orgID, "req-replay-golden", goldenPolicyArray))

	c := New(nil, NewDBOps(pool), "events:queue", slog.New(slog.DiscardHandler))
	require.NoError(t, c.deliverEvent(ctx, entry, "request.completed"), "first delivery lands")
	require.NoError(t, c.deliverEvent(ctx, entry, "request.completed"),
		"the replay must report success (already delivered), never an error")

	assert.Equal(t, int64(2), requireDecisionRows(ctx, t, pool, "req-replay-golden"),
		"the replay lands no duplicate decision rows (one per golden element)")
	requireRequestLog(ctx, t, pool, "req-replay-golden", 1)
}

// whose context dies mid-flight (shutdown, delivery timeout) must land
// NOTHING: the delivery transaction aborts before any write, so no partial
// request log, no orphan decision rows, no counted decode error — and the
// delivery reports failure (NACK → the stream retries). The follow-up
// redelivery of the SAME stream entry recovers: every golden decision lands
// exactly once. An interrupted state is never mistaken for success.
func TestPolicyDecisionInterrupt_Live(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	ctx := context.Background()
	orgID := seedPolicyDecisionOrg(t, pool, "pdec-interrupt-org")

	entry := publishPolicyFault(t, ctx, rdb, negativeEvent(orgID, "req-interrupt-golden", goldenPolicyArray))

	c := New(nil, NewDBOps(pool), "events:queue", slog.New(slog.DiscardHandler))
	interrupted, cancel := context.WithCancel(ctx)
	cancel()
	before := policyDecodeErrors.Load()
	require.Error(t, c.deliverEvent(interrupted, entry, "request.completed"),
		"a dead context must fail the delivery, never report success")
	require.ErrorIs(t, c.deliverEvent(interrupted, entry, "request.completed"), context.Canceled,
		"the failure carries the interrupt reason for the retry path")
	assert.Equal(t, before, policyDecodeErrors.Load(), "an interrupt is not a payload decode error")
	assert.Zero(t, requireDecisionRows(ctx, t, pool, "req-interrupt-golden"),
		"the aborted attempt lands zero decision rows")
	requireRequestLog(ctx, t, pool, "req-interrupt-golden", 0)

	require.NoError(t, c.deliverEvent(ctx, entry, "request.completed"),
		"the redelivery after the interrupt recovers")
	assert.Equal(t, int64(2), requireDecisionRows(ctx, t, pool, "req-interrupt-golden"),
		"one decision row per golden element, exactly once")
	requireRequestLog(ctx, t, pool, "req-interrupt-golden", 1)
}
