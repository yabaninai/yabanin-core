package adminstore

// OP-9 acceptance against the disposable, fully migrated Postgres stand
// (testcontainers, same contract as mcpcreds_int_test.go):
//   - the 0009 up/down pair applies and reverts cleanly;
//   - List filters (verdict / mode / policy_id), pagination + honest total;
//   - RLS two-org isolation (org-scoped reads never leak, unbound sees
//     nothing) — the store's GUC-pinned read path under FORCE RLS.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedPolicyDecisionRowDB inserts one decision row via raw SQL (the writer
// contract lives in services/loggerd/consumer; here the row store is what's
// under test).
func seedPolicyDecisionRowDB(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, requestID, policyID string, version int, mode, verdict string, createdAt time.Time) {
	t.Helper()
	seedPolicyDecisionRawDB(t, ctx, pool, orgID, requestID, policyID, version, mode, verdict,
		fmt.Sprintf(`[{"step":"s1","category":"pan","severity":"high","action":"%s"}]`, verdict), createdAt)
}

// seedPolicyDecisionRawDB inserts one decision row with explicit findings
// jsonb (CORE-TRACE-02: the step/window/version filters need varied shapes).
func seedPolicyDecisionRawDB(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, requestID, policyID string, version int, mode, verdict, findings string, createdAt time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO policy_decisions (org_id, request_id, policy_id, policy_version, mode, verdict, findings, duration_ms, created_at)
		 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
		orgID, requestID, policyID, version, mode, verdict, findings, 12, createdAt)
	require.NoError(t, err, "seed policy_decisions fixture")
}

// TestPolicyDecisions_FiltersAndPagination_Integration pins the list
// contract on a real database: org scoping, the three filters, newest-first
// order and the honest total beyond the page.
func TestPolicyDecisions_FiltersAndPagination_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	orgA, err := store.CreateOrganization(ctx, fmt.Sprintf("pdec-a-%d", suffix), fmt.Sprintf("pdec-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("pdec-b-%d", suffix), fmt.Sprintf("pdec-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA.ID, orgB.ID})
	})

	now := time.Now().UTC()
	seedPolicyDecisionRowDB(t, ctx, pool, orgA.ID, "req-a1", "pol-a", 2, "enforce", "deny", now)
	seedPolicyDecisionRowDB(t, ctx, pool, orgA.ID, "req-a2", "pol-a", 2, "shadow", "flag", now.Add(-time.Minute))
	seedPolicyDecisionRowDB(t, ctx, pool, orgA.ID, "req-a3", "pol-other", 1, "shadow", "allow", now.Add(-2*time.Minute))
	seedPolicyDecisionRowDB(t, ctx, pool, orgB.ID, "req-b1", "pol-b", 1, "enforce", "deny", now)

	// All of org A: newest first, honest total.
	rows, total, err := store.ListPolicyDecisions(ctx, orgA.ID, PolicyDecisionFilters{PageFilter: NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	require.Len(t, rows, 3)
	assert.Equal(t, "req-a1", rows[0].RequestID, "newest first")

	// Verdict filter.
	rows, total, err = store.ListPolicyDecisions(ctx, orgA.ID, PolicyDecisionFilters{Verdict: "deny", PageFilter: NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "req-a1", rows[0].RequestID)

	// Mode filter.
	_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, PolicyDecisionFilters{Mode: "shadow", PageFilter: NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)

	// policy_id filter.
	rows, total, err = store.ListPolicyDecisions(ctx, orgA.ID, PolicyDecisionFilters{PolicyID: "pol-other", PageFilter: NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "req-a3", rows[0].RequestID)

	// Pagination: the page beyond the size keeps the honest total.
	rows, total, err = store.ListPolicyDecisions(ctx, orgA.ID, PolicyDecisionFilters{PageFilter: NewPageFilter(2, 2)})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	require.Len(t, rows, 1)

	// Org B sees none of org A's rows through the same read path.
	_, total, err = store.ListPolicyDecisions(ctx, orgB.ID, PolicyDecisionFilters{PolicyID: "pol-a", PageFilter: NewPageFilter(1, 50)})
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)

	// Structured findings survive the round-trip as jsonb (evidence-free by
	// the writer contract; the store never rewrites them).
	rows, _, err = store.ListPolicyDecisions(ctx, orgA.ID, PolicyDecisionFilters{Verdict: "deny", PageFilter: NewPageFilter(1, 50)})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	var findings []map[string]any
	require.NoError(t, json.Unmarshal(rows[0].Findings, &findings))
	require.Len(t, findings, 1)
	assert.Equal(t, "pan", findings[0]["category"])
	assert.Equal(t, "s1", findings[0]["step"])
	assert.Equal(t, "high", findings[0]["severity"])
	assert.Equal(t, "deny", findings[0]["action"])
	assert.Equal(t, "enforce", rows[0].Mode)
	assert.Equal(t, 2, rows[0].PolicyVersion)
	assert.Equal(t, int64(12), rows[0].DurationMs)
	assert.Equal(t, "req-a1", rows[0].RequestID)
}

// TestPolicyDecisions_RLS_OrgIsolation_Integration: under the application
// posture (SET ROLE yabanin_app + app.current_org GUC, FORCE RLS) a bound
// session sees only its org's decision rows, an unbound session sees nothing
// (fail closed), and a cross-org INSERT is rejected by the WITH CHECK arm.
func TestPolicyDecisions_RLS_OrgIsolation_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	var orgA, orgB string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
		fmt.Sprintf("pdec-rls-a-%d", suffix), fmt.Sprintf("pdec-rls-a-%d", suffix)).Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
		fmt.Sprintf("pdec-rls-b-%d", suffix), fmt.Sprintf("pdec-rls-b-%d", suffix)).Scan(&orgB))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA, orgB})
	})

	seedPolicyDecisionRowDB(t, ctx, pool, orgA, "req-rls-a", "pol-a", 1, "enforce", "deny", time.Now().UTC())
	seedPolicyDecisionRowDB(t, ctx, pool, orgB, "req-rls-b", "pol-b", 1, "shadow", "flag", time.Now().UTC())

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, "yabanin_app", currentUser, "RLS assertions are void unless the session is downgraded")

	// Bound to org A: only org A's rows.
	_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgA)
	require.NoError(t, err)

	var seen int
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions`).Scan(&seen))
	assert.Equal(t, 1, seen, "a bound session must see only its own org's decisions")
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions WHERE org_id = $1::uuid`, orgB).Scan(&seen))
	assert.Zero(t, seen, "a bound session must not see the foreign org's decisions")

	// Cross-org INSERT violates the WITH CHECK arm.
	_, err = conn.Exec(ctx,
		`INSERT INTO policy_decisions (org_id, request_id, policy_id, policy_version, mode, verdict, findings, duration_ms)
		 VALUES ($1::uuid, 'req-evil', 'pol-evil', 1, 'enforce', 'allow', '[]'::jsonb, 0)`, orgB)
	require.Error(t, err, "cross-org insert must be rejected by the org_isolation policy")

	// Unbound session (empty GUC): nothing is visible — fail closed.
	_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
	require.NoError(t, err)
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM policy_decisions`).Scan(&seen))
	assert.Zero(t, seen, "an unbound session must see no decision rows at all")
}

// TestPolicyDecisions_TwoWaySearch_Integration pins the CORE-TRACE-02 store
// contract on a real database: the additive filters (policy_version with 0
// as a real legacy value, request_id org-scoped even when foreign orgs reuse
// the same id, step via the findings containment probe, inclusive time
// window) combine correctly on the decisions entity, and the requests
// entity counts UNIQUE requests (never evaluations), excludes request-less
// rows and honors the same filters in its totals.
func TestPolicyDecisions_TwoWaySearch_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	orgA, err := store.CreateOrganization(ctx, fmt.Sprintf("pdec-tws-a-%d", suffix), fmt.Sprintf("pdec-tws-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("pdec-tws-b-%d", suffix), fmt.Sprintf("pdec-tws-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA.ID, orgB.ID})
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	// org A: req-multi carries three evaluations across policies/versions/
	// verdicts/steps; req-single one; one legacy row has no request id.
	seedPolicyDecisionRawDB(t, ctx, pool, orgA.ID, "req-multi", "pol-1", 2, "enforce", "deny",
		`[{"step":"in","category":"pan","severity":"high","action":"deny"}]`, now)
	seedPolicyDecisionRawDB(t, ctx, pool, orgA.ID, "req-multi", "pol-2", 0, "shadow", "flag",
		`[{"step":"redact","category":"secret","severity":"high","action":"mask"}]`, now.Add(time.Minute))
	seedPolicyDecisionRawDB(t, ctx, pool, orgA.ID, "req-multi", "pol-1", 2, "enforce", "allow",
		`[]`, now.Add(2*time.Minute))
	seedPolicyDecisionRawDB(t, ctx, pool, orgA.ID, "req-single", "pol-3", 1, "enforce", "flag",
		`[{"step":"in","category":"url","severity":"low","action":"flag"}]`, now.Add(3*time.Minute))
	seedPolicyDecisionRawDB(t, ctx, pool, orgA.ID, "", "pol-1", 2, "enforce", "deny",
		`[]`, now.Add(4*time.Minute))
	// Review F2 (2026-11-01): the input/in superset pair row — a stored step
	// value that CONTAINS the shorter queries "in" and "input" as proper
	// substrings/prefixes, in an element LONGER than the minimal probe (the
	// stored finding also carries category/severity/action). Request-less and
	// outside the window subtest's bounds so every other subtest's totals
	// stay untouched.
	seedPolicyDecisionRawDB(t, ctx, pool, orgA.ID, "", "pol-4", 3, "enforce", "flag",
		`[{"step":"input_tokens","category":"usage","severity":"low","action":"flag"}]`, now.Add(5*time.Minute))
	// org B REUSES req-multi (request ids are only unique per org) — the
	// request_id filter must never leak across the org boundary.
	seedPolicyDecisionRawDB(t, ctx, pool, orgB.ID, "req-multi", "pol-b", 1, "enforce", "deny",
		`[{"step":"in","category":"pan","severity":"high","action":"deny"}]`, now)

	page := func() PolicyDecisionFilters { return PolicyDecisionFilters{PageFilter: NewPageFilter(1, 50)} }

	t.Run("policy_version matches exactly, including the legacy 0", func(t *testing.T) {
		v2 := 2
		rows, total, err := store.ListPolicyDecisions(ctx, orgA.ID, func() PolicyDecisionFilters { f := page(); f.PolicyVersion = &v2; return f }())
		require.NoError(t, err)
		assert.Equal(t, int64(3), total, "pol-1@v2 rows: deny, allow and the request-less deny")
		for _, r := range rows {
			assert.Equal(t, 2, r.PolicyVersion)
		}
		v0 := 0
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, func() PolicyDecisionFilters { f := page(); f.PolicyVersion = &v0; return f }())
		require.NoError(t, err)
		assert.Equal(t, int64(1), total, "version 0 is a REAL filter value (unknown legacy), not 'no filter'")
	})

	t.Run("request_id is exact and org-scoped", func(t *testing.T) {
		f := page()
		f.RequestID = "req-multi"
		rows, total, err := store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(3), total, "org A's req-multi evaluations only")
		for _, r := range rows {
			assert.Equal(t, orgA.ID, r.OrgID)
		}
		fb := page()
		fb.RequestID = "req-multi"
		_, totalB, err := store.ListPolicyDecisions(ctx, orgB.ID, fb)
		require.NoError(t, err)
		assert.Equal(t, int64(1), totalB, "org B's same-id request stays in org B")
	})

	t.Run("step matches decisions carrying that finding step", func(t *testing.T) {
		f := page()
		f.Step = "redact"
		rows, total, err := store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, "req-multi", rows[0].RequestID)
		assert.Equal(t, "pol-2", rows[0].PolicyID)

		f.Step = "no-such-step"
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total)

		// Review F2 (2026-11-01): the input/in superset pair makes this pin
		// sensitive to every whole-value degradation — substring, prefix,
		// whole-array-equals and direction-flipped probes all fail these
		// assertions, so the semantics cannot silently weaken.
		//
		// 'in' is a proper substring (and prefix) of the stored
		// 'input_tokens': whole-value matching returns exactly the two 'in'
		// rows, never the superset value.
		f.Step = "in"
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(2), total, "'in' matches its own steps only — never inside 'input_tokens' (substring/prefix degradation caught)")

		// (a) A shorter probe matches the longer stored value: the probe
		// [{"step":"input_tokens"}] carries only the step key while the
		// stored finding element also carries category/severity/action —
		// the minimal probe must be contained in the longer stored element
		// (whole-array/equals degradation caught).
		f.Step = "input_tokens"
		rows, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		require.Len(t, rows, 1)
		assert.Equal(t, "pol-4", rows[0].PolicyID, "the input_tokens element is matched by its minimal step probe")

		// A proper prefix is not the whole value.
		f.Step = "input"
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total, "'input' must not prefix-match the stored 'input_tokens'")

		// (b) A SUPERSET query never matches the shorter stored value: jsonb
		// string containment is equality, so 'input_tokens_extra' must not
		// match the stored 'input_tokens' (direction-flipped /
		// reverse-substring degradation caught).
		f.Step = "input_tokens_extra"
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total, "a superset step query must not match the shorter stored value")
	})

	// CORE-TRACE-05: the consumer stores decisions as versioned envelope
	// OBJECTS (the findings array under the "findings" key). The step filter
	// must match the nested layout with the SAME whole-value semantics while
	// the legacy-array pins above stay untouched. The envelope row is
	// request-less and outside the window subtest's bounds so every other
	// subtest's totals stay untouched.
	t.Run("step matches envelope-object rows with unchanged semantics", func(t *testing.T) {
		seedPolicyDecisionRawDB(t, ctx, pool, orgA.ID, "", "pol-env", 1, "enforce", "deny",
			`{"envelope_version":1,"findings":[{"step":"env-step","category":"pan","severity":"high","action":"deny"}],"trace_completeness":"full"}`,
			now.Add(6*time.Minute))

		f := page()
		f.Step = "env-step"
		rows, total, err := store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total, "the nested findings array is probed")
		require.Len(t, rows, 1)
		assert.Equal(t, "pol-env", rows[0].PolicyID)

		// Whole-value semantics survive the nested probe.
		f.Step = "env"
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total, "'env' must not prefix-match 'env-step' in the nested array")

		f.Step = "env-step-extra"
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total, "a superset query must not match the nested value")

		// A scalar findings value (the unknown-version stripped marker
		// stores an object; a hostile row could hold any jsonb) must never
		// false-positive through the object arm.
		seedPolicyDecisionRawDB(t, ctx, pool, orgA.ID, "", "pol-marker", 1, "enforce", "flag",
			`{"envelope_version":99}`, now.Add(7*time.Minute))
		f.Step = "envelope_version"
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total, "the object arm probes findings->'findings', never the envelope keys")

		// The legacy-array pins still hold with the envelope arm in place.
		f.Step = "in"
		_, total, err = store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(2), total, "legacy-array matching is unchanged by the envelope arm")
	})

	t.Run("time window is inclusive on both bounds", func(t *testing.T) {
		f := page()
		f.CreatedFrom = ptrTime(now.Add(time.Minute))
		f.CreatedTo = ptrTime(now.Add(3 * time.Minute))
		rows, total, err := store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(3), total, "bounds inclusive: 1m, 2m, 3m rows")
		for _, r := range rows {
			assert.False(t, r.CreatedAt.Before(*f.CreatedFrom) || r.CreatedAt.After(*f.CreatedTo))
		}
	})

	t.Run("filters combine", func(t *testing.T) {
		v2 := 2
		f := page()
		f.RequestID = "req-multi"
		f.PolicyID = "pol-1"
		f.PolicyVersion = &v2
		f.Verdict = "deny"
		f.Step = "in"
		rows, total, err := store.ListPolicyDecisions(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		require.Len(t, rows, 1)
		assert.Equal(t, "req-multi", rows[0].RequestID)
		assert.Equal(t, "deny", rows[0].Verdict)
	})

	t.Run("requests entity counts unique requests and honors the filters", func(t *testing.T) {
		rows, total, err := store.ListPolicyDecisionRequests(ctx, orgA.ID, page())
		require.NoError(t, err)
		assert.Equal(t, int64(2), total, "req-multi + req-single; the request-less row is not a request")
		require.Len(t, rows, 2)
		assert.Equal(t, "req-single", rows[0].RequestID, "most recent activity first")
		assert.Equal(t, int64(1), rows[0].Evaluations)
		assert.Equal(t, "req-multi", rows[1].RequestID)
		assert.Equal(t, int64(3), rows[1].Evaluations, "three evaluations are ONE request")
		assert.True(t, rows[1].FirstSeenAt.Equal(now), "first_seen = min(created_at)")
		assert.True(t, rows[1].LastSeenAt.Equal(now.Add(2*time.Minute)), "last_seen = max(created_at)")

		// verdict=deny leaves req-multi(d-1) visible; the request-less deny
		// row must not invent a request. Totals follow the FILTERED entity.
		f := page()
		f.Verdict = "deny"
		rows, total, err = store.ListPolicyDecisionRequests(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		require.Len(t, rows, 1)
		assert.Equal(t, "req-multi", rows[0].RequestID)
		assert.Equal(t, int64(1), rows[0].Evaluations)

		// The step filter narrows the request set too (redact only on req-multi).
		f = page()
		f.Step = "redact"
		rows, total, err = store.ListPolicyDecisionRequests(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, "req-multi", rows[0].RequestID)

		// request_id filter on the requests entity: the single-request lookup.
		f = page()
		f.RequestID = "req-single"
		rows, total, err = store.ListPolicyDecisionRequests(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, "req-single", rows[0].RequestID)
	})

	t.Run("requests entity pagination pages unique requests with honest totals", func(t *testing.T) {
		f := PolicyDecisionFilters{PageFilter: NewPageFilter(2, 1)}
		rows, total, err := store.ListPolicyDecisionRequests(ctx, orgA.ID, f)
		require.NoError(t, err)
		assert.Equal(t, int64(2), total, "two unique requests total")
		require.Len(t, rows, 1)
		assert.Equal(t, "req-multi", rows[0].RequestID, "page 2 of size 1 holds the older request")

		// Foreign org: its same-id request never leaks into org A's totals.
		_, total, err = store.ListPolicyDecisionRequests(ctx, orgB.ID, page())
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
	})
}

// ptrTime is a small helper for filter fixtures (CORE-TRACE-02).
func ptrTime(t time.Time) *time.Time { return &t }
