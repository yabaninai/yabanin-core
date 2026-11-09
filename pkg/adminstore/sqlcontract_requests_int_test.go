package adminstore

// ListRequests / RequestStats / GetRequestDetail, the full YQL allowlist
// (every operator of every field kind, every orderable field in both
// directions, honest empty results, injection refusal) driven end-to-end
// through ListRequests, the label surface (request labels 0004, api-key
// labels + CAS 0014, ListLabelKeys) and the label policy (0013), tool calls
// (report + per-request calls/invocations) and lineage — all against the
// (unknown org, empty windows, parse errors, precondition mismatches) are
// asserted where they pin the contract; any *pgconn.PgError fails via
// contract().
//
// The 03a fixture lacks agent/task/ttft-tagged log rows, tool_calls,
// tool_call_invocations, request_lineage and label_policies rows, so
// seedRequestsExtension adds a per-test extension seed — the harness file is
// untouched. Helpers here carry the req prefix so sibling 03b…03f files can
// coexist in the package.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/lineage"
	"github.com/stretchr/testify/require"
)

// seedRequestsExtension extends the shared 03a fixture with the request
// domain data the harness cannot know about: one fully-tagged org-A log row
// (agent, task, ttft/attempt/retry counts, cache hit, labels, response
// snapshot), tool_calls rows for two requests, per-occurrence invocations
// (one with id+arguments, one bare), lineage attestations for both orgs and
// a place for label_policies (written by the policy test itself). Cleanup
// removes exactly the rows the harness teardown cannot reach.
func seedRequestsExtension(t *testing.T, pool *pgxpool.Pool, fx *contractFixture) {
	t.Helper()
	ctx := context.Background()

	// rx row points at. client_session is UNIQUE — the token keeps the seed
	// safe alongside the serialized sibling runs. home_region must match the
	// request_logs seed ('GLOBAL'); region_isolation RLS keys off it.
	var sessID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO sessions (org_id, client_session, home_region)
		VALUES ($1::uuid, $2, 'GLOBAL') RETURNING id::text`,
		fx.OrgA, fx.Token+"-sess-a").Scan(&sessID), "seed extension sessions row")

	_, err := pool.Exec(ctx, `
		INSERT INTO request_logs (
			org_id, team_id, agent_id, session_id, model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, created_at, request_id, cost_in_usd, counterfactual_cost_usd,
			cache_hit_type, tier_used, ab_group, labels, cost_status, usage_source, endpoint,
			home_region, task_id, first_token_ms, attempt_count, retry_count, response
		) VALUES (
			$1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $5, 200, 250,
			120, 80, $6, $7, 0.000020, 0.000040,
			'exact', 'smart', '', $8::jsonb, 'priced', 'provider', 'chat.completions',
			'GLOBAL', 'code-gen', 120, 2, 1, '{"body":"imp03e"}'::jsonb)`,
		fx.OrgA, fx.TeamA1, fx.AgentKeyA, sessID, fx.Token+"-m-smart",
		time.Now().Add(-time.Hour), fx.Token+"-rx",
		`{"env":"prod","issue":"PAY-9"}`)
	require.NoError(t, err, "seed extension request_logs row")

	_, err = pool.Exec(ctx, `
		INSERT INTO tool_calls (request_id, org_id, task_id, model_used, tool_name) VALUES
			($1, $2::uuid, 'code-gen', $3, 'web_search'),
			($1, $2::uuid, 'code-gen', $3, 'code_interpreter'),
			($4, $2::uuid, NULL, $3, 'web_search')`,
		fx.Token+"-rx", fx.OrgA, fx.Token+"-m-smart", fx.Token+"-r1")
	require.NoError(t, err, "seed tool_calls")

	_, err = pool.Exec(ctx, `
		INSERT INTO tool_call_invocations (request_id, org_id, seq, call_id, tool_name, arguments) VALUES
			($1, $2::uuid, 1, 'call-1', 'web_search', '{"q":"imp03e"}'),
			($1, $2::uuid, 2, NULL, 'code_interpreter', NULL)`,
		fx.Token+"-rx", fx.OrgA)
	require.NoError(t, err, "seed tool_call_invocations")

	lineageRows := []struct {
		id    string
		org   string
		ts    time.Time
		model string
	}{
		{fx.Token + "-lin1", fx.OrgA, time.Now().Add(-time.Hour), fx.Token + "-m-smart"},
		{fx.Token + "-lin2", fx.OrgA, time.Now().Add(-24 * time.Hour), fx.Token + "-m-fast"},
		{fx.Token + "-linb", fx.OrgB, time.Now().Add(-2 * time.Hour), fx.Token + "-m-smart"},
	}
	for _, lr := range lineageRows {
		att := lineage.Attestation{
			RequestID:        lr.id,
			OrgID:            lr.org,
			Timestamp:        lr.ts.UTC().Format(time.RFC3339Nano),
			ModelUsed:        lr.model,
			InferenceRegion:  "EU-DE",
			ModelOrigin:      "US",
			LogStorageRegion: "EU-FR",
			ProviderEntity:   "US",
			RegionEvidence:   "provider_attested",
		}
		raw, merr := json.Marshal(att)
		require.NoError(t, merr, "marshal lineage attestation")
		hash, herr := att.Hash()
		require.NoError(t, herr, "hash lineage attestation")
		_, err = pool.Exec(ctx, `
			INSERT INTO request_lineage (request_id, org_id, ts, model_used, inference_region,
				model_origin_country, log_storage_region, provider_entity_jurisdiction,
				attestation_hash, raw_attestation, region_evidence)
			VALUES ($1, $2, $3, $4, 'EU-DE', 'US', 'EU-FR', 'US', $5, $6::jsonb, 'provider_attested')`,
			lr.id, lr.org, lr.ts, lr.model, hash, string(raw))
		require.NoError(t, err, "seed request_lineage %s", lr.id)
	}

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("requests extension cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM tool_call_invocations WHERE request_id LIKE $1`, fx.Token+"%")
		cleanup(`DELETE FROM tool_calls WHERE request_id LIKE $1`, fx.Token+"%")
		cleanup(`DELETE FROM label_policies WHERE org_id::text = ANY($1)`, []string{fx.OrgA, fx.OrgB})
		// The rx log row must go before the session row (sessions FK has no
		// cascade and this cleanup runs before the org-scoped fixture wipe).
		cleanup(`DELETE FROM request_logs WHERE request_id = $1`, fx.Token+"-rx")
		cleanup(`DELETE FROM sessions WHERE client_session = $1`, fx.Token+"-sess-a")
		// request_lineage is append-only by design (PB1.2 tamper-evidence):
		// the seeded attestations stay. They are token-scoped and org-scoped
		// (fresh org per run), so they never leak into another run's answers.
	})
}

// reqYQLSpecs lists the canonical YQL field specs sorted by name.
func reqYQLSpecs() []*yqlFieldSpec {
	seen := map[string]bool{}
	specs := make([]*yqlFieldSpec, 0, len(yqlFields))
	for _, spec := range yqlFields {
		if !seen[spec.name] {
			seen[spec.name] = true
			specs = append(specs, spec)
		}
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].name < specs[j].name })
	return specs
}

// reqSeededSessionID returns the uuid the extension seed wrote into the rx
// row's session_id — the fixture value the YQL session cases filter against.
func reqSeededSessionID(t *testing.T, pool *pgxpool.Pool, fx *contractFixture) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT COALESCE(session_id::text, '') FROM request_logs WHERE org_id::text = $1 AND request_id = $2`,
		fx.OrgA, fx.Token+"-rx").Scan(&id))
	require.NotEmpty(t, id, "extension seed must tag the rx row with a session")
	return id
}

// TestSQLContractRequests_ListFilters drives the ListRequests/RequestStats
// flat-filter matrix on the real stand: every optional filter, period
// combinations, honest empty results, pagination agreement and the shadow
// exclusion. ListRequests org scope is positional ($1) — there is no
// "without org" variant; the degenerate case is the unknown org.
func TestSQLContractRequests_ListFilters(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)
	from, to := fx.From, fx.To

	run := func(name string, f RequestListFilters, want func(rows []RequestListRow, total int)) {
		t.Helper()
		contract(t, "ListRequests/"+name, func(ctx context.Context) error {
			rows, total, err := store.ListRequests(ctx, f)
			if err != nil {
				return err
			}
			if want != nil {
				want(rows, total)
			}
			return nil
		})
	}

	run("orgA-all", RequestListFilters{OrgID: fx.OrgA}, func(rows []RequestListRow, total int) {
		if total != 6 || len(rows) != 6 {
			t.Errorf("orgA-all: expected the 6 seeded non-shadow org-A rows, got total=%d rows=%d", total, len(rows))
		}
		seen := 0
		for _, r := range rows {
			if r.RequestID == fx.Token+"-r1" {
				seen++ // the shadow mirror shares this request_id and must not appear
			}
		}
		if seen != 1 {
			t.Errorf("orgA-all: request r1 must appear exactly once (shadow excluded), got %d", seen)
		}
	})
	run("orgB-isolated", RequestListFilters{OrgID: fx.OrgB}, func(rows []RequestListRow, total int) {
		if total != 2 {
			t.Errorf("orgB-isolated: expected exactly the 2 seeded org-B rows, got total=%d", total)
		}
		for _, r := range rows {
			if r.OrgID != fx.OrgB {
				t.Errorf("orgB-isolated: cross-org leak: row %s carries org %s", r.RequestID, r.OrgID)
			}
		}
	})
	// The zero uuid is a well-formed org id no fixture ever creates — the
	// honest empty answer (org ids are uuid-typed end to end).
	const noOrg = "00000000-0000-0000-0000-000000000000"
	run("unknown-org-empty", RequestListFilters{OrgID: noOrg}, func(rows []RequestListRow, total int) {
		if total != 0 || len(rows) != 0 {
			t.Errorf("unknown-org-empty: expected an honest empty result, got total=%d rows=%d", total, len(rows))
		}
	})

	run("model-hit", RequestListFilters{OrgID: fx.OrgA, Model: fx.Token + "-m-fast"}, func(_ []RequestListRow, total int) {
		if total != 1 {
			t.Errorf("model-hit: expected 1 m-fast row, got %d", total)
		}
	})
	run("model-miss", RequestListFilters{OrgID: fx.OrgA, Model: fx.Token + "-no-such"}, func(_ []RequestListRow, total int) {
		if total != 0 {
			t.Errorf("model-miss: expected 0 rows, got %d", total)
		}
	})

	run("from-only", RequestListFilters{OrgID: fx.OrgA, From: time.Now().Add(-12 * time.Hour)}, func(_ []RequestListRow, total int) {
		if total != 2 {
			t.Errorf("from-only: expected day-0 rows (r1, rx), got %d", total)
		}
	})
	run("to-only", RequestListFilters{OrgID: fx.OrgA, To: time.Now().Add(-12 * time.Hour)}, func(_ []RequestListRow, total int) {
		if total != 4 {
			t.Errorf("to-only: expected day-1/day-2 rows (r2, r3, r4, r5), got %d", total)
		}
	})
	run("full-window", RequestListFilters{OrgID: fx.OrgA, From: from, To: to}, func(_ []RequestListRow, total int) {
		if total != 6 {
			t.Errorf("full-window: expected all 6 non-shadow rows, got %d", total)
		}
	})
	run("empty-window", RequestListFilters{OrgID: fx.OrgA, From: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)}, func(_ []RequestListRow, total int) {
		if total != 0 {
			t.Errorf("empty-window: expected an honest 0, got %d", total)
		}
	})

	run("min-status", RequestListFilters{OrgID: fx.OrgA, MinStatus: 400}, func(_ []RequestListRow, total int) {
		if total != 1 {
			t.Errorf("min-status: expected only the 500 row, got %d", total)
		}
	})
	run("error-only", RequestListFilters{OrgID: fx.OrgA, ErrorOnly: true}, func(_ []RequestListRow, total int) {
		if total != 1 {
			t.Errorf("error-only: expected only the error row, got %d", total)
		}
	})

	run("task-id", RequestListFilters{OrgID: fx.OrgA, TaskID: "code-gen"}, func(_ []RequestListRow, total int) {
		if total != 1 {
			t.Errorf("task-id: expected the tagged rx row, got %d", total)
		}
	})
	run("agent-id", RequestListFilters{OrgID: fx.OrgA, AgentID: fx.AgentKeyA}, func(_ []RequestListRow, total int) {
		if total != 1 {
			t.Errorf("agent-id: expected the agent-tagged rx row, got %d", total)
		}
	})
	// contract run): the flat AgentID filter cast the raw value with
	// $n::uuid, so a garbage ?agent_id= surfaced as PgError 22P02 and the
	// handler answered 500. The filter now compares ::text like the YQL
	// `agent` field, so an invalid value is an honest empty result.
	run("agent-id-invalid", RequestListFilters{OrgID: fx.OrgA, AgentID: "not-a-uuid"},
		func(rows []RequestListRow, total int) {
			if total != 0 || len(rows) != 0 {
				t.Errorf("agent-id-invalid: expected an honest empty, got total=%d rows=%d", total, len(rows))
			}
		})
	run("request-id", RequestListFilters{OrgID: fx.OrgA, RequestID: fx.Token + "-r2"}, func(rows []RequestListRow, total int) {
		if total != 1 || len(rows) != 1 {
			t.Errorf("request-id: expected a single r2 row, got total=%d rows=%d", total, len(rows))
			return
		}
		if rows[0].Labels["env"] != "prod" {
			t.Errorf("request-id: labels attribution (0004) must surface on the list row, got %v", rows[0].Labels)
		}
	})

	run("min-latency", RequestListFilters{OrgID: fx.OrgA, MinLatencyMs: 150}, func(_ []RequestListRow, total int) {
		if total != 1 {
			t.Errorf("min-latency: expected only the 250ms rx row, got %d", total)
		}
	})
	run("max-latency", RequestListFilters{OrgID: fx.OrgA, MaxLatencyMs: 50}, func(_ []RequestListRow, total int) {
		if total != 0 {
			t.Errorf("max-latency: expected an honest 0, got %d", total)
		}
	})
	run("min-tokens", RequestListFilters{OrgID: fx.OrgA, MinTokens: 190}, func(_ []RequestListRow, total int) {
		if total != 2 { // r1 (120+80) and rx (120+80)
			t.Errorf("min-tokens: expected r1 and rx, got %d", total)
		}
	})
	run("max-tokens", RequestListFilters{OrgID: fx.OrgA, MaxTokens: 100}, func(_ []RequestListRow, total int) {
		if total != 2 { // r2 (90) and r4 (10); r5 totals 130
			t.Errorf("max-tokens: expected r2 and r4 only, got %d", total)
		}
	})
	run("min-cost", RequestListFilters{OrgID: fx.OrgA, MinCostUSD: 0.00001}, func(_ []RequestListRow, total int) {
		if total != 2 { // r1 (0.000012) and rx (0.000020)
			t.Errorf("min-cost: expected r1 and rx, got %d", total)
		}
	})
	run("max-cost", RequestListFilters{OrgID: fx.OrgA, MaxCostUSD: 0.000005}, func(_ []RequestListRow, total int) {
		if total != 3 { // r2, r4, r5 — zero-cost rows stay visible
			t.Errorf("max-cost: expected the zero-cost rows, got %d", total)
		}
	})

	run("cache-exact", RequestListFilters{OrgID: fx.OrgA, CacheHit: "exact"}, func(_ []RequestListRow, total int) {
		if total != 2 { // r2 and rx
			t.Errorf("cache-exact: expected r2 and rx, got %d", total)
		}
	})
	run("cache-miss", RequestListFilters{OrgID: fx.OrgA, CacheHit: "miss"}, func(_ []RequestListRow, total int) {
		if total != 4 { // r1, r3, r4, r5 — no cache_hit_type recorded
			t.Errorf("cache-miss: expected the un-cached rows, got %d", total)
		}
	})
	run("cache-semantic-empty", RequestListFilters{OrgID: fx.OrgA, CacheHit: "semantic"}, func(_ []RequestListRow, total int) {
		if total != 0 {
			t.Errorf("cache-semantic-empty: expected an honest 0, got %d", total)
		}
	})

	run("content-search-error", RequestListFilters{OrgID: fx.OrgA, ContentSearch: "exploded"}, func(_ []RequestListRow, total int) {
		if total != 1 {
			t.Errorf("content-search-error: expected the r4 error row, got %d", total)
		}
	})
	run("content-search-body", RequestListFilters{OrgID: fx.OrgA, ContentSearch: "imp03e"}, func(_ []RequestListRow, total int) {
		if total != 1 {
			t.Errorf("content-search-body: expected the rx response snapshot row, got %d", total)
		}
	})
	run("content-search-empty", RequestListFilters{OrgID: fx.OrgA, ContentSearch: "zz-no-such-body"}, func(_ []RequestListRow, total int) {
		if total != 0 {
			t.Errorf("content-search-empty: expected an honest 0, got %d", total)
		}
	})

	run("combined", RequestListFilters{OrgID: fx.OrgA, From: from, To: to, Model: fx.Token + "-m-smart", MinStatus: 200, CacheHit: "miss"}, func(_ []RequestListRow, total int) {
		if total != 2 { // r1 (200) and r4 (500 — MinStatus is a floor, not "success")
			t.Errorf("combined: expected r1 and r4, got %d", total)
		}
	})

	// Pagination: two pages agree with the count and never overlap.
	type page struct {
		rows  []RequestListRow
		total int
	}
	pages := [2]page{}
	for i, p := range []int{1, 2} {
		contract(t, fmt.Sprintf("ListRequests/page-%d", p), func(ctx context.Context) error {
			rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Page: p, PageSize: 3})
			if err != nil {
				return err
			}
			pages[i] = page{rows: rows, total: total}
			return nil
		})
	}
	if pages[0].total != 6 || pages[1].total != 6 {
		t.Errorf("pages: total must agree across pages, got %d and %d", pages[0].total, pages[1].total)
	}
	for _, a := range pages[0].rows {
		for _, b := range pages[1].rows {
			if a.RequestID == b.RequestID {
				t.Errorf("pages: request %s must not repeat across pages", a.RequestID)
			}
		}
	}

	// RequestStats over the same filter set (order tail ignored by design).
	contract(t, "RequestStats/orgA", func(ctx context.Context) error {
		st, err := store.RequestStats(ctx, RequestListFilters{OrgID: fx.OrgA, From: from, To: to})
		if err != nil {
			return err
		}
		if st == nil || st.TotalRequests != 6 {
			t.Errorf("RequestStats/orgA: expected the 6 non-shadow rows, got %+v", st)
			return nil
		}
		if st.SuccessRate < 0.83 || st.SuccessRate > 0.84 { // 5/6
			t.Errorf("RequestStats/orgA: success rate must be 5/6, got %f", st.SuccessRate)
		}
		if st.TotalTokensIn != 460 {
			t.Errorf("RequestStats/orgA: tokens_in sum must be 460, got %d", st.TotalTokensIn)
		}
		return nil
	})
	contract(t, "RequestStats/unknown-org", func(ctx context.Context) error {
		st, err := store.RequestStats(ctx, RequestListFilters{OrgID: "00000000-0000-0000-0000-000000000000"})
		if err != nil {
			return err
		}
		if st.TotalRequests != 0 || st.TotalCostUSD != 0 {
			t.Errorf("RequestStats/unknown-org: expected zeros, got %+v", st)
		}
		return nil
	})
	contract(t, "RequestStats/error-only", func(ctx context.Context) error {
		st, err := store.RequestStats(ctx, RequestListFilters{OrgID: fx.OrgA, ErrorOnly: true})
		if err != nil {
			return err
		}
		if st.TotalRequests != 1 {
			t.Errorf("RequestStats/error-only: expected the single error row, got %d", st.TotalRequests)
		}
		return nil
	})
}

// TestSQLContractRequests_PayloadSearchDenied pins denial before search,
// count, pagination, and stats aggregation. A caller without either ownership
// or a payload grant cannot infer the secret-only match from any result path.
func TestSQLContractRequests_PayloadSearchDenied(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)

	f := RequestListFilters{
		OrgID:                   fx.OrgA,
		PayloadUserID:           "00000000-0000-0000-0000-000000000099",
		PayloadAuthorizationSet: true,
		PayloadSearchAllowed:    false,
		ContentSearch:           "imp03e",
		Page:                    1,
		PageSize:                1,
	}
	contract(t, "ListRequests/payload-search-denied", func(ctx context.Context) error {
		rows, total, err := store.ListRequests(ctx, f)
		if err != nil {
			return err
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("denied payload search exposed result: total=%d rows=%d", total, len(rows))
		}
		return nil
	})
	contract(t, "RequestStats/payload-search-denied", func(ctx context.Context) error {
		stats, err := store.RequestStats(ctx, f)
		if err != nil {
			return err
		}
		if stats.TotalRequests != 0 || stats.TotalTokensIn != 0 || stats.TotalTokensOut != 0 || stats.TotalCostUSD != 0 {
			t.Errorf("denied payload search affected aggregate: %+v", stats)
		}
		return nil
	})
}

// TestSQLContractRequests_YQLFilters drives every allowlist operator of every
// field kind through ListRequests end-to-end (the request explorer path): the
// scalar/list/regex operators per kind, `is [not] empty` on the nullable
// fields, the dynamic label.<key> family and the boolean combinations — with
// and without the flat window so both placeholder-numbering bases ($n
// continuing after org / after org+from+to) execute on real Postgres.
func TestSQLContractRequests_YQLFilters(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)
	sessID := reqSeededSessionID(t, pool, fx)

	cases := []struct {
		name   string
		filter string
		none   bool // honest empty result expected
		window bool // combine with the flat from/to window
	}{
		// Every generated operator case runs here too (below); this table
		// pins the semantic anchors: matching values, honest empties.
		{"status-eq-hit", "status = 200", false, false},
		{"status-eq-miss", "status = 999", true, false},
		{"model-eq-miss", "model = zz-no-such-model", true, false},
		{"request-eq-miss", "request = zz-no-such-request", true, false},
		{"cost-range", "cost >= 0.000012 and cost <= 0.000020", false, false},
		{"created-lt-empty", "created < 2020-01-01", true, false},
		{"created-ge-hit", "created >= -1d", false, false},
		{"cache-in", "cache in (exact, miss)", false, false},
		{"task-eq-hit", "task = code-gen", false, false},
		{"agent-eq-hit", "agent = " + fx.AgentKeyA, false, false},
		{"session-eq-hit", "session = " + sessID, false, false},
		{"session-alias-hit", "session_id = " + sessID, false, false},
		{"session-eq-miss", "session = 00000000-0000-0000-0000-000000000000", true, false},
		{"session-empty", "session is empty", false, false},
		{"error-eq-hit", `error = "upstream exploded"`, false, false},
		{"text-tilde-hit", "text ~ imp03e", false, true},
		{"text-bang-tilde", "text !~ imp03e", false, true},
		{"label-eq-hit", "label.env = prod", false, true},
		{"label-eq-miss", "label.env = zz-nope", true, false},
		{"label-ne", "label.env != dev", false, true},
		{"label-tilde", "label.env ~ pr", false, false},
		{"label-bang-tilde", "label.env !~ pr", false, false},
		{"label-in", "label.env in (prod, dev)", false, false},
		{"label-not-in", "label.env not in (dev)", false, false},
		{"label-in-second-key", "label.issue in (PAY-9, PAY-1)", false, false},
		{"label-empty", "label.env is empty", false, false},
		{"label-not-empty", "label.env is not empty", false, false},
		{"label-missing-key-empty", "label.zzz is empty", false, false},
		{"bool-and", "status >= 200 and status < 300", false, true},
		{"bool-or", "model ~ smart or model ~ fast", false, true},
		{"bool-not", "not (status >= 400)", false, true},
		{"bool-parens", "(status = 200 or status = 500) and cost >= 0", false, true},
		{"bool-tool-task", "tool ~ web and task = code-gen", false, true},
		{"order-tail", "status = 200 order by cost desc", false, true},
		{"order-tail-label", "created >= -2d and label.env = prod order by created asc", false, true},
		{"order-tail-session", "session = " + sessID + " order by created asc", false, false},
		{"double-eq-alias", "status == 200", false, false},
	}
	run := func(name, filter string, none, window bool) {
		t.Helper()
		rq, err := ParseYQL(filter)
		if err != nil {
			t.Errorf("%s: contract filter must parse: %v", name, err)
			return
		}
		f := RequestListFilters{OrgID: fx.OrgA, Query: rq, PageSize: 200}
		if window {
			f.From, f.To = fx.From, fx.To
		}
		contract(t, "ListRequests/yql/"+name, func(ctx context.Context) error {
			rows, total, err := store.ListRequests(ctx, f)
			if err != nil {
				return err
			}
			if none && total != 0 {
				t.Errorf("%s: expected an honest empty result, got total=%d", name, total)
			}
			if !none && (total == 0 || len(rows) == 0) {
				t.Errorf("%s: expected at least one row, got total=%d rows=%d", name, total, len(rows))
			}
			return nil
		})
	}
	for _, c := range cases {
		run(c.name, c.filter, c.none, c.window)
	}

	// Operator × field generation: every op of every kind on every canonical
	// field, plus `is [not] empty` on the nullable ones. Values match seeded
	// rows, so each generated case expects at least one row except the
	// per-field misses noted below.
	one := map[string]string{
		"request": fx.Token + "-r1",
		"model":   fx.Token + "-m-smart", "model_requested": fx.Token + "-m-smart",
		"status": "200", "cost": "0.000012", "tokens": "200",
		"tokens_in": "120", "tokens_out": "80", "latency": "100",
		"ttft": "120", "retries": "1", "attempts": "2",
		"task": "code-gen", "agent": fx.AgentKeyA,
		"session": sessID,
		"cache":   "exact", "error": `"upstream exploded"`,
		"created": "-1d", "text": "imp03e", "tool": "web_search",
	}
	two := map[string]string{
		"request":         fx.Token + "-r1, " + fx.Token + "-r2",
		"model":           fx.Token + "-m-smart, " + fx.Token + "-m-fast",
		"model_requested": fx.Token + "-m-smart, " + fx.Token + "-m-fast",
		"status":          "200, 500", "cost": "0.000012, 0.000020",
		"tokens": "200, 300", "tokens_in": "120, 90", "tokens_out": "80, 70",
		"latency": "100, 250", "ttft": "120, 130", "retries": "1, 2", "attempts": "2, 3",
		"task": "code-gen, other-task", "agent": fx.AgentKeyA + ", 00000000-0000-0000-0000-000000000000",
		"session": sessID + ", 00000000-0000-0000-0000-000000000000",
		"cache":   "exact, miss",
		"error":   `"upstream exploded", "upstream timeout"`,
	}
	// `...` flags mark the honest-empty combinations: an exact time equality
	// the seed cannot hit, fields seeded never-null for `is empty`, SQL NULL
	// semantics of `!=`/`not in` on the truly-nullable text/uuid columns, and
	// the seeded defaults (attempt_count/retry_count default 0 — no NULLs;
	// duration_ms always 100/250; status only 200/500).
	expectNone := map[string]bool{
		"created =": true, "model_requested is empty": true,
		"status <": true, "status not in": true,
		"latency <": true, "latency not in": true,
		"tokens >": true, "tokens_in >": true, "tokens_out >": true,
		"ttft !=": true, "ttft >": true, "ttft <": true, "ttft not in": true,
		"retries >": true, "retries is empty": true,
		"attempts >": true, "attempts is empty": true,
		"task !=": true, "task not in": true,
		"agent !=": true, "agent not in": true,
		// session_id is NULL on every row but rx: SQL NULL cannot satisfy
		// != / not in, so those stay honest empties (the `=`/`in`/`~`
		// variants still hit the tagged row).
		"session !=": true, "session not in": true,
		"cache !=": true, "cache not in": true,
		"error !=": true, "error not in": true,
	}
	for _, spec := range reqYQLSpecs() {
		v, ok := one[spec.name]
		if !ok {
			continue
		}
		for op := range yqlOpsFor(spec.kind) {
			filter := fmt.Sprintf("%s %s %s", spec.name, op, v)
			if op == "in" || op == "not in" {
				filter = fmt.Sprintf("%s %s (%s)", spec.name, op, two[spec.name])
			}
			none := expectNone[spec.name+" "+op]
			run("gen/"+spec.name+" "+op, filter, none, false)
		}
		if spec.nullable {
			for _, tail := range []string{"is empty", "is not empty"} {
				none := expectNone[spec.name+" "+tail]
				run("gen/"+spec.name+" "+tail, spec.name+" "+tail, none, false)
			}
		}
	}

	// The tool EXISTS family over the seeded tool_calls.
	for _, filter := range []string{
		"tool = web_search", "tool != web_search", "tool ~ web", "tool !~ zz",
		"tool is empty", "tool is not empty",
	} {
		run("tool/"+filter, filter, false, false)
	}

	// Parse-time refusals stay parse-time: no SQL is ever produced for an
	// unknown field, an unsupported operator/kind pair, a bad value or a
	// non-nullable is-empty. Each must surface as *YQLError with a position.
	refusals := []string{
		"request is empty",
		"status ~ 2",
		"created = not-a-date",
		"cache = wrongvalue",
		"zz-field = 1",
		`label.env"; DROP TABLE x = 1`,
		"status = 200 order by (select 1)",
		"status = 200 order by status; drop table request_logs",
		"model = \"unterminated",
		"model in (" + strings.TrimSuffix(strings.Repeat("v, ", 41), ", ") + ")",
		strings.Repeat("x", MaxYQLLen+1),
	}
	for _, filter := range refusals {
		name := filter
		if len(name) > 40 {
			name = name[:40] + "…"
		}
		_, err := ParseYQL(filter)
		if err == nil {
			t.Errorf("refusal %q: expected a parse error, got a query", name)
			continue
		}
		var yErr *YQLError
		require.ErrorAs(t, err, &yErr, "refusal %q must be a *YQLError", name)
		if yErr.Position() < 0 {
			t.Errorf("refusal %q: position must be non-negative", name)
		}
	}
}

// reqOrderKey extracts the sort key a YQL order-by field maps to in
// RequestListRow (num for numeric/time fields, str for text; isNull mirrors
// the SQL NULL so the NULLS-LAST contract is checkable).
func reqOrderKey(name string, r RequestListRow) (num float64, str string, isNull bool) {
	switch name {
	case "request":
		return 0, r.RequestID, r.RequestID == ""
	case "model":
		return 0, r.ModelUsed, false
	case "model_requested":
		return 0, r.ModelRequested, r.ModelRequested == ""
	case "status":
		return float64(r.StatusCode), "", false
	case "cost":
		return r.CostUSD, "", false
	case "tokens":
		return float64(r.TokensIn + r.TokensOut), "", false
	case "tokens_in":
		return float64(r.TokensIn), "", false
	case "tokens_out":
		return float64(r.TokensOut), "", false
	case "latency":
		return float64(r.DurationMs), "", false
	case "ttft":
		if r.FirstTokenMs == nil {
			return 0, "", true
		}
		return float64(*r.FirstTokenMs), "", false
	case "retries":
		if r.RetryCount == nil {
			return 0, "", true
		}
		return float64(*r.RetryCount), "", false
	case "attempts":
		if r.AttemptCount == nil {
			return 0, "", true
		}
		return float64(*r.AttemptCount), "", false
	case "task":
		return 0, r.TaskID, r.TaskID == ""
	case "session":
		return 0, r.SessionID, r.SessionID == ""
	case "cache":
		return 0, r.CacheHitType, r.CacheHitType == ""
	case "error":
		return 0, r.ErrorMsg, r.ErrorMsg == ""
	case "created":
		return float64(r.CreatedAt.UnixMilli()), "", false
	}
	// agent has no list-row projection — ordering is execution-checked only.
	return 0, "", false
}

// reqAssertOrdered verifies the QueryOrder.sql contract on returned rows:
// non-null keys are monotonic in the requested direction and, for nullable
// fields, NULL rows sort last in both directions (ASC default NULLS LAST,
// DESC explicit NULLS LAST).
func reqAssertOrdered(t *testing.T, name, field string, desc bool, rows []RequestListRow) {
	t.Helper()
	for i := 1; i < len(rows); i++ {
		pn, ps, pnull := reqOrderKey(field, rows[i-1])
		cn, cs, cnull := reqOrderKey(field, rows[i])
		if pnull && !cnull {
			t.Errorf("%s: NULL row sorts before a non-NULL row (NULLS LAST contract)", name)
			return
		}
		if pnull || cnull {
			continue
		}
		cmp := 0
		switch {
		case pn < cn:
			cmp = -1
		case pn > cn:
			cmp = 1
		default:
			cmp = strings.Compare(ps, cs)
		}
		if desc && cmp < 0 {
			t.Errorf("%s: row %d breaks DESC monotonicity (%v/%q < %v/%q)",
				name, i, pn, ps, cn, cs)
			return
		}
		if !desc && cmp > 0 {
			t.Errorf("%s: row %d breaks ASC monotonicity (%v/%q > %v/%q)",
				name, i, pn, ps, cn, cs)
			return
		}
	}
}

// TestSQLContractRequests_YQLOrderBy executes the end-to-end list ordering
// delegated to ListRequests) plus the order-only query and the stats path
// that ignores the order tail by design.
func TestSQLContractRequests_YQLOrderBy(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)

	for _, spec := range reqYQLSpecs() {
		if !spec.orderable {
			continue
		}
		for _, desc := range []bool{false, true} {
			dir := "asc"
			if desc {
				dir = "desc"
			}
			name := "ListRequests/order/" + spec.name + "/" + dir
			rq, err := ParseYQL("order by " + spec.name + " " + dir)
			if err != nil {
				t.Errorf("%s: order query must parse: %v", name, err)
				continue
			}
			contract(t, name, func(ctx context.Context) error {
				rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq, PageSize: 200})
				if err != nil {
					return err
				}
				if total == 0 || len(rows) == 0 {
					t.Errorf("%s: expected rows to order, got total=%d", name, total)
					return nil
				}
				if spec.name != "agent" {
					reqAssertOrdered(t, name, spec.name, desc, rows)
				}
				return nil
			})
		}
	}

	// Order-only query: no WHERE fragment, list still ordered.
	contract(t, "ListRequests/order-only", func(ctx context.Context) error {
		rq, err := ParseYQL("order by cost desc")
		if err != nil {
			return err
		}
		rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if total != 6 {
			t.Errorf("order-only: expected the 6 non-shadow rows, got %d", total)
			return nil
		}
		reqAssertOrdered(t, "ListRequests/order-only", "cost", true, rows)
		return nil
	})

	// RequestStats shares the WHERE but ignores the ORDER tail.
	contract(t, "RequestStats/order-tail", func(ctx context.Context) error {
		rq, err := ParseYQL("status >= 400 order by created desc")
		if err != nil {
			return err
		}
		st, err := store.RequestStats(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if st.TotalRequests != 1 {
			t.Errorf("RequestStats/order-tail: expected the single error row, got %d", st.TotalRequests)
		}
		return nil
	})
}

// TestSQLContractRequests_YQLInjection pins the injection-proof compilation:
// hostile values stay bound parameters (the query returns an honest empty
// result, the table survives), ILIKE metacharacters never break or widen the
// predicate, and hostile field/order tails are refused at parse time.
func TestSQLContractRequests_YQLInjection(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)

	// The classic statement-injection payload inside a quoted value.
	contract(t, "injection/drop-table-value", func(ctx context.Context) error {
		rq, err := ParseYQL(`request = "'; DROP TABLE request_logs;--"`)
		if err != nil {
			return err
		}
		rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("injection/drop-table-value: expected an honest empty result, got total=%d", total)
		}
		var alive int
		if qerr := pool.QueryRow(ctx, `SELECT count(*) FROM request_logs`).Scan(&alive); qerr != nil {
			return qerr
		}
		if alive == 0 {
			t.Error("injection/drop-table-value: request_logs did not survive — the payload executed")
		}
		return nil
	})

	// Boolean-literal smuggling must not widen the predicate to all rows.
	contract(t, "injection/or-tautology", func(ctx context.Context) error {
		rq, err := ParseYQL(`model = "x' OR '1'='1"`)
		if err != nil {
			return err
		}
		_, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if total != 0 {
			t.Errorf("injection/or-tautology: the payload matched %d rows — values are not bound", total)
		}
		return nil
	})

	// ILIKE metacharacters as literal content: a business answer, never a
	// SQL error and never a full-table match from a bare %.
	for _, filter := range []string{`error ~ "%'_"`, `text ~ "%'_"`, `label.env ~ "%'_"`} {
		contract(t, "injection/ilike "+filter, func(ctx context.Context) error {
			rq, err := ParseYQL(filter)
			if err != nil {
				return err
			}
			_, _, err = store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
			return err
		})
	}

	// Hostile identifier positions were proven parse-refused in the filter
	// test; here the same holds through a direct parse check.
	_, perr := ParseYQL("status = 200 order by status; drop table request_logs")
	require.Error(t, perr, "hostile order tail must be refused at parse time")
}

// TestSQLContractRequests_Labels covers the label attribution surface:
// request labels (0004) through the list and detail reads, ListLabelKeys,
// the api-key label write (0014) and its CAS variant.
func TestSQLContractRequests_Labels(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)

	// Detail: labels + tool calls + per-occurrence invocations (0014 reads).
	contract(t, "GetRequestDetail/rx", func(ctx context.Context) error {
		contentCtx := WithRequestPayloadAccess(ctx, RequestPayloadAccess{Grant: true})
		d, err := store.GetRequestDetail(contentCtx, fx.OrgA, fx.Token+"-rx")
		if err != nil {
			return err
		}
		if d.Labels["env"] != "prod" || d.Labels["issue"] != "PAY-9" {
			t.Errorf("GetRequestDetail/rx: labels must round-trip, got %v", d.Labels)
		}
		if len(d.ToolCalls) != 2 || d.ToolCalls[0].ToolName != "web_search" || d.ToolCalls[1].ToolName != "code_interpreter" {
			t.Errorf("GetRequestDetail/rx: tool calls must list both names in id order, got %v", d.ToolCalls)
		}
		if len(d.ToolCallInvocations) != 2 {
			t.Errorf("GetRequestDetail/rx: expected 2 invocations, got %d", len(d.ToolCallInvocations))
			return nil
		}
		inv := d.ToolCallInvocations[0]
		if inv.Seq != 1 || inv.CallID == nil || *inv.CallID != "call-1" || inv.Arguments == nil || *inv.Arguments != `{"q":"imp03e"}` {
			t.Errorf("GetRequestDetail/rx: invocation 1 must carry id and arguments, got %+v", inv)
		}
		if d.ToolCallInvocations[1].CallID != nil || d.ToolCallInvocations[1].Arguments != nil {
			t.Errorf("GetRequestDetail/rx: invocation 2 must tolerate NULL id/arguments, got %+v", d.ToolCallInvocations[1])
		}
		return nil
	})

	// Detail for a request with a tool_call but no invocations (legacy rows).
	contract(t, "GetRequestDetail/r1", func(ctx context.Context) error {
		contentCtx := WithRequestPayloadAccess(ctx, RequestPayloadAccess{Grant: true})
		d, err := store.GetRequestDetail(contentCtx, fx.OrgA, fx.Token+"-r1")
		if err != nil {
			return err
		}
		if len(d.ToolCalls) != 1 || d.ToolCalls[0].ToolName != "web_search" {
			t.Errorf("GetRequestDetail/r1: expected the seeded web_search call, got %v", d.ToolCalls)
		}
		if len(d.ToolCallInvocations) != 0 {
			t.Errorf("GetRequestDetail/r1: expected no invocations, got %d", len(d.ToolCallInvocations))
		}
		return nil
	})

	// Cross-org and missing lookups answer ErrNotFound without leaking
	// existence.
	contract(t, "GetRequestDetail/cross-org", func(ctx context.Context) error {
		contentCtx := WithRequestPayloadAccess(ctx, RequestPayloadAccess{Grant: true})
		_, err := store.GetRequestDetail(contentCtx, fx.OrgB, fx.Token+"-rx")
		if err != ErrNotFound {
			t.Errorf("GetRequestDetail/cross-org: expected ErrNotFound, got %v", err)
		}
		return nil
	})
	contract(t, "GetRequestDetail/missing", func(ctx context.Context) error {
		contentCtx := WithRequestPayloadAccess(ctx, RequestPayloadAccess{Grant: true})
		_, err := store.GetRequestDetail(contentCtx, fx.OrgA, "zz-missing")
		if err != ErrNotFound {
			t.Errorf("GetRequestDetail/missing: expected ErrNotFound, got %v", err)
		}
		return nil
	})

	// Label keys over the window (0004 data) and the honest empty answer.
	contract(t, "ListLabelKeys/orgA", func(ctx context.Context) error {
		keys, err := store.ListLabelKeys(ctx, fx.OrgA, fx.From, fx.To)
		if err != nil {
			return err
		}
		byKey := map[string]LabelKeyStat{}
		for _, k := range keys {
			byKey[k.Key] = k
		}
		env, ok := byKey["env"]
		if !ok || env.Requests < 3 || env.ApproxDistinctValues < 2 {
			t.Errorf("ListLabelKeys/orgA: env must aggregate 3 rows / 2 values, got %+v (keys %v)", env, byKey)
		}
		if _, ok := byKey["issue"]; !ok {
			t.Errorf("ListLabelKeys/orgA: the issue key is missing: %v", byKey)
		}
		return nil
	})
	contract(t, "ListLabelKeys/unknown-org", func(ctx context.Context) error {
		keys, err := store.ListLabelKeys(ctx, "00000000-0000-0000-0000-000000000000", fx.From, fx.To)
		if err != nil {
			return err
		}
		if len(keys) != 0 {
			t.Errorf("ListLabelKeys/unknown-org: expected an empty slice, got %v", keys)
		}
		return nil
	})

	// API-key labels (0014): plain write, verify, clear, missing id.
	contract(t, "UpdateAPIKeyLabels/write", func(ctx context.Context) error {
		err := store.UpdateAPIKeyLabels(ctx, fx.APIKeyA, map[string]string{"team": "alpha", "issue": "IMP-03E"}, true, true, false)
		if err != nil {
			return err
		}
		var raw []byte
		var locked, mint, usage bool
		if err := pool.QueryRow(ctx,
			`SELECT labels, labels_locked, can_mint_sessions, can_read_usage FROM api_keys WHERE id::text = $1`,
			fx.APIKeyA).Scan(&raw, &locked, &mint, &usage); err != nil {
			return err
		}
		got := map[string]string{}
		if err := json.Unmarshal(raw, &got); err != nil {
			return err
		}
		if got["team"] != "alpha" || got["issue"] != "IMP-03E" || !locked || !mint || usage {
			t.Errorf("UpdateAPIKeyLabels/write: labels/flags must persist, got %v %v %v %v", got, locked, mint, usage)
		}
		return nil
	})
	contract(t, "UpdateAPIKeyLabels/clear", func(ctx context.Context) error {
		if err := store.UpdateAPIKeyLabels(ctx, fx.APIKeyA, nil, false, false, false); err != nil {
			return err
		}
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT labels FROM api_keys WHERE id::text = $1`, fx.APIKeyA).Scan(&raw); err != nil {
			return err
		}
		if string(raw) != "{}" {
			t.Errorf("UpdateAPIKeyLabels/clear: nil labels must store {}, got %s", raw)
		}
		return nil
	})
	contract(t, "UpdateAPIKeyLabels/missing", func(ctx context.Context) error {
		err := store.UpdateAPIKeyLabels(ctx, "ffffffff-ffff-ffff-ffff-ffffffffffff", map[string]string{"k": "v"}, false, false, false)
		if err != ErrNotFound {
			t.Errorf("UpdateAPIKeyLabels/missing: expected ErrNotFound, got %v", err)
		}
		return nil
	})

	// CAS (0014): unconditional, expected-state success, mismatch and a
	// vanished row.
	contract(t, "UpdateAPIKeyLabelsPreconditioned", func(ctx context.Context) error {
		st, err := store.UpdateAPIKeyLabelsPreconditioned(ctx, fx.APIKeyA,
			map[string]string{"team": "alpha"}, true, false, true, nil)
		if err != nil {
			return err
		}
		if !st.LabelsLocked || st.CanMintSessions || !st.CanReadUsage || st.Labels["team"] != "alpha" {
			t.Errorf("CAS unconditional: unexpected state %+v", st)
		}
		return nil
	})
	contract(t, "UpdateAPIKeyLabelsPreconditioned/match", func(ctx context.Context) error {
		expect := &APIKeyLabelsState{
			Labels: map[string]string{"team": "alpha"}, LabelsLocked: true, CanMintSessions: false, CanReadUsage: true,
		}
		st, err := store.UpdateAPIKeyLabelsPreconditioned(ctx, fx.APIKeyA,
			map[string]string{"team": "beta"}, false, true, false, expect)
		if err != nil {
			return err
		}
		if st.Labels["team"] != "beta" || st.LabelsLocked || !st.CanMintSessions || st.CanReadUsage {
			t.Errorf("CAS match: unexpected new state %+v", st)
		}
		return nil
	})
	contract(t, "UpdateAPIKeyLabelsPreconditioned/mismatch", func(ctx context.Context) error {
		stale := &APIKeyLabelsState{
			Labels: map[string]string{"team": "alpha"}, LabelsLocked: true, CanMintSessions: false, CanReadUsage: true,
		}
		st, err := store.UpdateAPIKeyLabelsPreconditioned(ctx, fx.APIKeyA,
			map[string]string{"team": "gamma"}, false, false, false, stale)
		if err != ErrPreconditionFailed {
			t.Errorf("CAS mismatch: expected ErrPreconditionFailed, got %v", err)
		}
		if st == nil || st.Labels["team"] != "beta" {
			t.Errorf("CAS mismatch: the current state must be returned, got %+v", st)
		}
		return nil
	})
	contract(t, "UpdateAPIKeyLabelsPreconditioned/missing", func(ctx context.Context) error {
		_, err := store.UpdateAPIKeyLabelsPreconditioned(ctx, "ffffffff-ffff-ffff-ffff-ffffffffffff",
			map[string]string{"k": "v"}, false, false, false, nil)
		if err != ErrNotFound {
			t.Errorf("CAS missing: expected ErrNotFound, got %v", err)
		}
		return nil
	})
}

func TestSQLContractRequests_PayloadAuthorization(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)
	ctx := context.Background()
	owner := "00000000-0000-4000-8000-000000000001"
	other := "00000000-0000-4000-8000-000000000002"
	_, err := pool.Exec(ctx, `UPDATE request_logs SET user_id = $2::uuid WHERE request_id = $1`, fx.Token+"-rx", other)
	require.NoError(t, err)

	textQuery, err := ParseYQL(`text ~ "imp03e"`)
	require.NoError(t, err)
	for _, expression := range []string{
		`not (text !~ "imp03e")`,
		`status = 200 or text ~ "imp03e"`,
		`not (status = 500 or text !~ "imp03e")`,
	} {
		query, parseErr := ParseYQL(expression)
		require.NoError(t, parseErr, "adversarial YQL must parse: %s", expression)
		rows, count, queryErr := store.ListRequests(ctx, RequestListFilters{
			OrgID: fx.OrgA, Query: query, PayloadUserID: owner,
			PayloadSearchAllowed: true, PayloadAuthorizationSet: true, Page: 1, PageSize: 20,
		})
		require.NoError(t, queryErr, "YQL: %s", expression)
		require.Empty(t, rows, "YQL must not escape owner scope: %s", expression)
		require.Zero(t, count, "YQL must not escape owner scope: %s", expression)
	}
	rows, total, err := store.ListRequests(ctx, RequestListFilters{
		OrgID: fx.OrgA, Query: textQuery, PayloadUserID: owner,
		PayloadSearchAllowed: true, PayloadAuthorizationSet: true, Page: 1, PageSize: 20,
	})
	require.NoError(t, err)
	require.Empty(t, rows, "YQL body search must not match foreign payload")
	require.Zero(t, total)

	stats, err := store.RequestStats(ctx, RequestListFilters{OrgID: fx.OrgA, OwnerUserID: owner})
	require.NoError(t, err)
	require.Zero(t, stats.TotalRequests, "stats must exclude foreign request rows")

	_, err = store.GetRequestDetail(WithRequestPayloadAccess(ctx, RequestPayloadAccess{UserID: owner}), fx.OrgA, fx.Token+"-rx")
	require.ErrorIs(t, err, ErrNotFound, "foreign detail without grant or org-wide metadata permission is hidden")

	detail, err := store.GetRequestDetail(WithRequestPayloadAccess(ctx, RequestPayloadAccess{
		UserID: owner, OrgWideMetadata: true,
	}), fx.OrgA, fx.Token+"-rx")
	require.NoError(t, err)
	require.Empty(t, detail.ToolCallInvocations)
	require.Empty(t, detail.ToolCalls)
	require.NotContains(t, string(detail.Response), "imp03e")
}

// reqPolicyEqual reports whether the stored policy jsonb equals the expected
// value semantically (jsonb normalizes whitespace and key order, so raw byte
// comparison cannot pin the round-trip).
func reqPolicyEqual(t *testing.T, stored []byte, want any) bool {
	t.Helper()
	var got any
	if err := json.Unmarshal(stored, &got); err != nil {
		t.Errorf("policy jsonb: %v", err)
		return false
	}
	return reflect.DeepEqual(got, want)
}

// TestSQLContractRequests_LabelPolicy covers the org label policy CRUD
// (0013): the default fallback, upsert insert and conflict-update paths,
// org scoping and delete (including deleting an absent row).
func TestSQLContractRequests_LabelPolicy(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)

	contract(t, "GetLabelPolicy/default", func(ctx context.Context) error {
		row, ok, err := store.GetLabelPolicy(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if ok {
			t.Errorf("GetLabelPolicy/default: org A must start on the default policy, got %+v", row)
		}
		return nil
	})
	contract(t, "UpsertLabelPolicy/insert", func(ctx context.Context) error {
		if err := store.UpsertLabelPolicy(ctx, fx.OrgA, []byte(`{"rules":[{"match":"env","set":"tier"}]}`), "imp03e"); err != nil {
			return err
		}
		row, ok, err := store.GetLabelPolicy(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		// jsonb normalizes whitespace and key order — compare semantically.
		if !ok || !reqPolicyEqual(t, row.Policy, map[string]any{
			"rules": []any{map[string]any{"match": "env", "set": "tier"}},
		}) || row.UpdatedBy != "imp03e" || row.UpdatedAt.IsZero() {
			t.Errorf("UpsertLabelPolicy/insert: policy must round-trip, got ok=%v %+v", ok, row)
		}
		return nil
	})
	contract(t, "UpsertLabelPolicy/conflict-update", func(ctx context.Context) error {
		if err := store.UpsertLabelPolicy(ctx, fx.OrgA, []byte(`{"rules":[]}`), "imp03e-2"); err != nil {
			return err
		}
		row, ok, err := store.GetLabelPolicy(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if !ok || !reqPolicyEqual(t, row.Policy, map[string]any{"rules": []any{}}) || row.UpdatedBy != "imp03e-2" {
			t.Errorf("UpsertLabelPolicy/conflict-update: the upsert must replace, got ok=%v %+v", ok, row)
		}
		return nil
	})
	contract(t, "LabelPolicy/org-scope", func(ctx context.Context) error {
		if err := store.UpsertLabelPolicy(ctx, fx.OrgB, []byte(`{"rules":[{"match":"b"}]}`), "imp03e-b"); err != nil {
			return err
		}
		rowA, okA, err := store.GetLabelPolicy(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		rowB, okB, err := store.GetLabelPolicy(ctx, fx.OrgB)
		if err != nil {
			return err
		}
		if !okB || !reqPolicyEqual(t, rowB.Policy, map[string]any{
			"rules": []any{map[string]any{"match": "b"}},
		}) {
			t.Errorf("LabelPolicy/org-scope: org B policy missing, got ok=%v %+v", okB, rowB)
		}
		if !okA || reqPolicyEqual(t, rowA.Policy, map[string]any{
			"rules": []any{map[string]any{"match": "b"}},
		}) {
			t.Errorf("LabelPolicy/org-scope: org A policy must be its own, got ok=%v %+v", okA, rowA)
		}
		return nil
	})
	contract(t, "DeleteLabelPolicy", func(ctx context.Context) error {
		if err := store.DeleteLabelPolicy(ctx, fx.OrgA); err != nil {
			return err
		}
		_, ok, err := store.GetLabelPolicy(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if ok {
			t.Error("DeleteLabelPolicy: org A must fall back to the default after delete")
		}
		if err := store.DeleteLabelPolicy(ctx, fx.OrgA); err != nil {
			t.Errorf("DeleteLabelPolicy/absent: deleting an absent row must be a no-op, got %v", err)
		}
		return nil
	})
}

// TestSQLContractRequests_ToolCalls covers the cross-request tool report and
// its honest empty answer, plus the day-window bounds.
func TestSQLContractRequests_ToolCalls(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)

	contract(t, "GetToolCallsReport/orgA", func(ctx context.Context) error {
		rep, err := store.GetToolCallsReport(ctx, fx.OrgA, 7)
		if err != nil {
			return err
		}
		if rep.TotalCalls != 3 || rep.DistinctTools != 2 || rep.RequestsUsing != 2 {
			t.Errorf("GetToolCallsReport/orgA: expected 3 calls / 2 tools / 2 requests, got %+v", rep)
		}
		if len(rep.Top) != 2 || rep.Top[0].Tool != "web_search" || rep.Top[0].Calls != 2 {
			t.Errorf("GetToolCallsReport/orgA: top must lead with web_search×2, got %+v", rep.Top)
			return nil
		}
		if rep.Top[0].Share < 66.0 || rep.Top[0].Share > 67.0 {
			t.Errorf("GetToolCallsReport/orgA: share must be 2/3 of calls, got %f", rep.Top[0].Share)
		}
		if len(rep.ByModel) != 1 || rep.ByModel[0].Calls != 3 {
			t.Errorf("GetToolCallsReport/orgA: by-model must group all 3 calls, got %+v", rep.ByModel)
		}
		return nil
	})
	contract(t, "GetToolCallsReport/unknown-org", func(ctx context.Context) error {
		rep, err := store.GetToolCallsReport(ctx, "00000000-0000-0000-0000-000000000000", 7)
		if err != nil {
			return err
		}
		if rep.TotalCalls != 0 || rep.DistinctTools != 0 || rep.RequestsUsing != 0 || len(rep.Top) != 0 || len(rep.ByModel) != 0 {
			t.Errorf("GetToolCallsReport/unknown-org: expected an empty report, got %+v", rep)
		}
		return nil
	})
	contract(t, "GetToolCallsReport/day-bounds", func(ctx context.Context) error {
		if _, err := store.GetToolCallsReport(ctx, fx.OrgA, 0); err != nil { // clamps to 30
			return fmt.Errorf("days=0: %w", err)
		}
		_, err := store.GetToolCallsReport(ctx, fx.OrgA, 366)
		return err
	})
}

// TestSQLContractRequests_Lineage covers the lineage reads: the attestation
// round-trip by request id, org listing with limit and the filtered variant
// across every model/period combination (including the honest empties).
func TestSQLContractRequests_Lineage(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)
	lin1 := fx.Token + "-lin1"

	contract(t, "GetLineageByRequestID/hit", func(ctx context.Context) error {
		att, err := store.GetLineageByRequestID(ctx, lin1)
		if err != nil {
			return err
		}
		if att.RequestID != lin1 || att.ModelUsed != fx.Token+"-m-smart" ||
			att.InferenceRegion != "EU-DE" || att.LogStorageRegion != "EU-FR" ||
			att.ModelOrigin != "US" || att.ProviderEntity != "US" || att.RegionEvidence != "provider_attested" {
			t.Errorf("GetLineageByRequestID/hit: attestation must round-trip, got %+v", att)
		}
		return nil
	})
	contract(t, "GetLineageByRequestID/missing", func(ctx context.Context) error {
		_, err := store.GetLineageByRequestID(ctx, "zz-missing")
		if err == nil || !strings.Contains(err.Error(), "lineage not found") {
			t.Errorf("GetLineageByRequestID/missing: expected the not-found business error, got %v", err)
		}
		return nil
	})

	contract(t, "ListLineageByOrg", func(ctx context.Context) error {
		rows, err := store.ListLineageByOrg(ctx, fx.OrgA, 10)
		if err != nil {
			return err
		}
		if len(rows) != 2 || rows[0].RequestID != lin1 {
			t.Errorf("ListLineageByOrg: expected 2 rows newest-first, got %+v", rows)
		}
		return nil
	})
	contract(t, "ListLineageByOrg/limit", func(ctx context.Context) error {
		rows, err := store.ListLineageByOrg(ctx, fx.OrgA, 1)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			t.Errorf("ListLineageByOrg/limit: expected 1 row, got %d", len(rows))
		}
		return nil
	})
	contract(t, "ListLineageByOrg/unknown-org", func(ctx context.Context) error {
		rows, err := store.ListLineageByOrg(ctx, "00000000-0000-0000-0000-000000000000", 10)
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			t.Errorf("ListLineageByOrg/unknown-org: expected an honest empty, got %d", len(rows))
		}
		return nil
	})

	type linCase struct {
		name  string
		model string
		from  time.Time
		to    time.Time
		limit int
		want  int
	}
	now := time.Now()
	cases := []linCase{
		{"no-filters", "", time.Time{}, time.Time{}, 10, 2},
		{"model-hit", fx.Token + "-m-fast", time.Time{}, time.Time{}, 10, 1},
		{"model-miss", fx.Token + "-no-such", time.Time{}, time.Time{}, 10, 0},
		{"from-only", "", now.Add(-2 * time.Hour), time.Time{}, 10, 1},
		{"to-only", "", time.Time{}, now.Add(-12 * time.Hour), 10, 1},
		{"from-and-to", "", now.Add(-30 * time.Hour), now.Add(-20 * time.Hour), 10, 1},
		{"model-and-window", fx.Token + "-m-smart", now.Add(-2 * time.Hour), now, 10, 1},
		{"model-and-window-miss", fx.Token + "-m-fast", now.Add(-2 * time.Hour), now, 10, 0},
		{"empty-window", "", now.Add(+time.Hour), now.Add(+2 * time.Hour), 10, 0},
		{"limit-zero", "", time.Time{}, time.Time{}, 0, 0},
		{"limit-one", "", time.Time{}, time.Time{}, 1, 1},
	}
	for _, c := range cases {
		contract(t, "ListLineageByOrgFiltered/"+c.name, func(ctx context.Context) error {
			rows, err := store.ListLineageByOrgFiltered(ctx, fx.OrgA, c.model, c.from, c.to, c.limit)
			if err != nil {
				return err
			}
			if len(rows) != c.want {
				t.Errorf("ListLineageByOrgFiltered/%s: expected %d rows, got %d", c.name, c.want, len(rows))
			}
			return nil
		})
	}
}

// session/session_id field (uuid column compared through ::text, so a
// garbage value is an honest empty, never a cast 500), the session_id
// projection on list rows and the request detail, and the injection posture
// of the new field (values stay bound, the table survives).
func TestSQLContractRequests_Session(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedRequestsExtension(t, pool, fx)
	sessID := reqSeededSessionID(t, pool, fx)

	// YQL filter hit: exactly the tagged row, and the list row carries the id.
	rq, err := ParseYQL("session = " + sessID)
	require.NoError(t, err, "the session field must be allowlisted")
	contract(t, "ListRequests/session-eq", func(ctx context.Context) error {
		rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq, PageSize: 200})
		if err != nil {
			return err
		}
		if total != 1 || len(rows) != 1 || rows[0].RequestID != fx.Token+"-rx" {
			t.Errorf("session-eq: expected exactly the rx row, got total=%d rows=%d", total, len(rows))
			return nil
		}
		if rows[0].SessionID != sessID {
			t.Errorf("session-eq: the list row must carry session_id %s, got %q", sessID, rows[0].SessionID)
		}
		return nil
	})

	// Alias: session_id parses to the same canonical field.
	rq, err = ParseYQL("session_id = " + sessID)
	require.NoError(t, err, "the session_id alias must be allowlisted")
	contract(t, "ListRequests/session-alias", func(ctx context.Context) error {
		_, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if total != 1 {
			t.Errorf("session-alias: expected exactly the rx row, got total=%d", total)
		}
		return nil
	})

	// Untagged rows answer `is empty` (5 of the 6 non-shadow org-A rows).
	rq, err = ParseYQL("session is empty")
	require.NoError(t, err)
	contract(t, "ListRequests/session-empty", func(ctx context.Context) error {
		_, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if total != 5 {
			t.Errorf("session-empty: expected the 5 untagged rows, got %d", total)
		}
		return nil
	})

	// SQL NULL semantics: the 5 NULL rows cannot satisfy !=, so the only
	// non-null row fails the predicate — an honest empty, documented.
	rq, err = ParseYQL("session != " + sessID)
	require.NoError(t, err)
	contract(t, "ListRequests/session-ne-null-semantics", func(ctx context.Context) error {
		_, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if total != 0 {
			t.Errorf("session-ne: NULL rows cannot satisfy !=, expected 0, got %d", total)
		}
		return nil
	})

	// A non-uuid value must never surface as a 22P02 cast error (500): the
	// ::text comparison turns it into an honest empty (mirror of agent).
	rq, err = ParseYQL("session = not-a-uuid")
	require.NoError(t, err)
	contract(t, "ListRequests/session-invalid-uuid", func(ctx context.Context) error {
		rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("session-invalid-uuid: expected an honest empty, got total=%d rows=%d", total, len(rows))
		}
		return nil
	})

	// Order by session in both directions: execution plus the NULLS-LAST
	// contract over the returned rows (only rx is non-null).
	for _, dir := range []string{"asc", "desc"} {
		rq, err := ParseYQL("order by session " + dir)
		require.NoError(t, err)
		contract(t, "ListRequests/order/session/"+dir, func(ctx context.Context) error {
			rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq, PageSize: 200})
			if err != nil {
				return err
			}
			if total != 6 {
				t.Errorf("order/session/%s: expected the 6 non-shadow rows, got %d", dir, total)
				return nil
			}
			reqAssertOrdered(t, "order/session/"+dir, "session", dir == "desc", rows)
			return nil
		})
	}

	// Detail: the tagged row exposes its session, untagged stay empty.
	contract(t, "GetRequestDetail/session", func(ctx context.Context) error {
		contentCtx := WithRequestPayloadAccess(ctx, RequestPayloadAccess{Grant: true})
		d, err := store.GetRequestDetail(contentCtx, fx.OrgA, fx.Token+"-rx")
		if err != nil {
			return err
		}
		if d.SessionID != sessID {
			t.Errorf("detail/rx: session_id must round-trip, got %q want %s", d.SessionID, sessID)
		}
		bare, err := store.GetRequestDetail(contentCtx, fx.OrgA, fx.Token+"-r1")
		if err != nil {
			return err
		}
		if bare.SessionID != "" {
			t.Errorf("detail/r1: an untagged row must carry an empty session_id, got %q", bare.SessionID)
		}
		return nil
	})

	// Injection posture of the new field: the hostile value stays a bound
	// parameter (honest empty) and the table survives.
	contract(t, "injection/session-value", func(ctx context.Context) error {
		rq, err := ParseYQL(`session = "'; DROP TABLE request_logs;--"`)
		if err != nil {
			return err
		}
		_, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Query: rq})
		if err != nil {
			return err
		}
		if total != 0 {
			t.Errorf("injection/session-value: the payload matched %d rows — values are not bound", total)
		}
		var alive int
		if qerr := pool.QueryRow(ctx, `SELECT count(*) FROM request_logs`).Scan(&alive); qerr != nil {
			return qerr
		}
		if alive == 0 {
			t.Error("injection/session-value: request_logs did not survive — the payload executed")
		}
		return nil
	})
}
