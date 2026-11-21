package adminstore

// Read-side invocation identity for retained tool facts against a real
// PostgreSQL (disposable testcontainers stand). Migration 0030 gives
// tool_calls and tool_call_invocations a nullable invocation_id bound to the
// delivery's own invocation identity; migration 0028 lets two legitimate
// invocations from one org share a client request id. These oracles pin the
// reader contract on top of both:
//
//   - detail children bind by invocation identity: invocation A's row sees
//     only A's tools, invocation B's row only B's — never the sibling's;
//   - legacy NULL-invocation facts never attach to an invocation-bearing
//     row (linkage is never guessed), and keep attaching to a legacy row
//     whose correlation it uniquely carries;
//   - one consistent association rule everywhere (list projection, YQL
//     positive/negated/is-empty, detail names/occurrences, report count):
//     a NULL-invocation fact emitted by a pre-0030 writer mode for a minted
//     request attaches to that request's sole carrier, and a correlation
//     carried by two rows attaches its NULL facts to neither;
//   - the same correlation string in another org never steals facts
//     (carrier counting and every join stay org-scoped);
//   - the list ToolCalls column and the YQL tool filter carry the same
//     per-invocation scope, and paging keeps each row's own names;
//   - the tool report counts physical request identities, not client
//     correlations: A and B count as two requests, an ambiguous legacy
//     correlation attributes to no row (mirroring the detail guard), and a
//     fact whose request rows are gone still counts once — per minted
//     invocation when invocation identity survives.

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

// newToolFactsReaderOrg creates an isolated organization for the reader
// oracles and cleans its rows on teardown.
func newToolFactsReaderOrg(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var orgID string
	require.NoError(t, pool.QueryRow(context.Background(),
		"INSERT INTO organizations (name, slug) VALUES ('Tool facts reader', $1) RETURNING id::text",
		fmt.Sprintf("tool-facts-reader-%d", time.Now().UnixNano())).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM tool_call_invocations WHERE org_id = $1", orgID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM tool_calls WHERE org_id = $1", orgID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM request_logs WHERE org_id = $1", orgID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})
	return orgID
}

// insertReaderRow seeds one request_logs row and returns its immutable id.
// requestID nil = NULL correlation; invocationID nil = legacy row.
func insertReaderRow(t *testing.T, pool *pgxpool.Pool, orgID string, requestID, invocationID *string, tokensIn int64, createdAt time.Time) int64 {
	t.Helper()
	var id int64
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO request_logs (org_id, home_region, model_requested, model_used, status_code,
		   duration_ms, tokens_in, tokens_out, request_id, invocation_id, created_at)
		 VALUES ($1, 'sg', 'm', 'm', 200, 10, $2, 3, $3, $4, $5) RETURNING id`,
		orgID, tokensIn, requestID, invocationID, createdAt).Scan(&id))
	return id
}

// insertReaderFact seeds one tool_calls row (the distinct-name table).
func insertReaderFact(t *testing.T, pool *pgxpool.Pool, orgID, requestID string, invocationID *string, toolName string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		"INSERT INTO tool_calls (org_id, request_id, invocation_id, tool_name) VALUES ($1, $2, $3, $4)",
		orgID, requestID, invocationID, toolName)
	require.NoError(t, err)
}

// insertReaderOccurrence seeds one tool_call_invocations row. arguments is
// authored JSON text; each caller seeds a distinct payload so argument
// attribution is independently catchable from name attribution.
func insertReaderOccurrence(t *testing.T, pool *pgxpool.Pool, orgID, requestID string, invocationID *string, seq int, callID, toolName, arguments string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		"INSERT INTO tool_call_invocations (org_id, request_id, invocation_id, seq, call_id, tool_name, arguments) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		orgID, requestID, invocationID, seq, callID, toolName, arguments)
	require.NoError(t, err)
}

// decodeReaderArgs parses an occurrence's arguments JSON for comparison,
// robust to text-form differences in how the column round-trips.
func decodeReaderArgs(t *testing.T, s *string) map[string]any {
	t.Helper()
	require.NotNil(t, s)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(*s), &m))
	return m
}

// mustParseYQL compiles a YQL expression or fails the test.
func mustParseYQL(t *testing.T, q string) *RequestQuery {
	t.Helper()
	rq, err := ParseYQL(q)
	require.NoError(t, err)
	return rq
}

// toolNames flattens a detail's distinct tool calls for assertion.
func toolNames(calls []RequestToolCall) []string {
	names := make([]string, 0, len(calls))
	for _, c := range calls {
		names = append(names, c.ToolName)
	}
	return names
}

// TestToolFacts_DetailBindsByInvocation is the A/B oracle: two invocations
// sharing org, correlation and timestamp, each with its own invocation-bound
// tool facts. Each row's detail carries exactly its own tools and
// occurrences — positive scope for the row's own facts, negative for the
// sibling's — and a legacy NULL-invocation fact under the same correlation
// attaches to neither row (0030: linkage is never guessed).
func TestToolFacts_DetailBindsByInvocation(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newToolFactsReaderOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	shared := "ab-correlation"
	invA, invB := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	insertReaderRow(t, pool, orgID, &shared, &invA, 7, stamp)
	insertReaderRow(t, pool, orgID, &shared, &invB, 19, stamp)
	insertReaderFact(t, pool, orgID, shared, &invA, "alpha")
	insertReaderFact(t, pool, orgID, shared, &invB, "beta")
	insertReaderFact(t, pool, orgID, shared, nil, "stale-legacy")
	insertReaderOccurrence(t, pool, orgID, shared, &invA, 1, "ca-1", "alpha", `{"limit":7}`)
	insertReaderOccurrence(t, pool, orgID, shared, &invB, 1, "cb-1", "beta", `{"limit":19}`)

	store := New(pool, slog.Default(), nil)
	details, total, err := exportOrgDetails(t, store, orgID, RequestPayloadAccess{Grant: true, OrgWideMetadata: true}, 10)
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, details, 2)

	byToken := map[int64]*RequestDetail{}
	for _, d := range details {
		byToken[d.TokensIn] = d
	}
	a, b := byToken[7], byToken[19]
	require.NotNil(t, a, "invocation A row exports")
	require.NotNil(t, b, "invocation B row exports")

	assert.Equal(t, []string{"alpha"}, toolNames(a.ToolCalls), "A sees exactly its own tool")
	assert.Equal(t, []string{"beta"}, toolNames(b.ToolCalls), "B sees exactly its own tool")
	require.Len(t, a.ToolCallInvocations, 1)
	assert.Equal(t, "alpha", a.ToolCallInvocations[0].ToolName)
	require.NotNil(t, a.ToolCallInvocations[0].CallID)
	assert.Equal(t, "ca-1", *a.ToolCallInvocations[0].CallID)
	assert.Equal(t, map[string]any{"limit": float64(7)}, decodeReaderArgs(t, a.ToolCallInvocations[0].Arguments),
		"A's decoded argument belongs to A's invocation")
	require.Len(t, b.ToolCallInvocations, 1)
	assert.Equal(t, "beta", b.ToolCallInvocations[0].ToolName)
	require.NotNil(t, b.ToolCallInvocations[0].CallID)
	assert.Equal(t, "cb-1", *b.ToolCallInvocations[0].CallID)
	assert.Equal(t, map[string]any{"limit": float64(19)}, decodeReaderArgs(t, b.ToolCallInvocations[0].Arguments),
		"B's decoded argument belongs to B's invocation")
}

// TestToolFacts_LegacyCorrelationStillAttaches pins the legacy-safe
// fallback: rows and facts with no invocation identity keep exactly the
// pre-0030 behavior — a unique legacy correlation attaches its facts, a
// shared legacy correlation attributes to neither row.
func TestToolFacts_LegacyCorrelationStillAttaches(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newToolFactsReaderOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	uniq := "legacy-unique"
	insertReaderRow(t, pool, orgID, &uniq, nil, 5, stamp)
	insertReaderFact(t, pool, orgID, uniq, nil, "gamma")
	insertReaderOccurrence(t, pool, orgID, uniq, nil, 1, "cg-1", "gamma", `{"file":"legacy.txt"}`)

	amb := "legacy-ambiguous"
	insertReaderRow(t, pool, orgID, &amb, nil, 6, stamp)
	insertReaderRow(t, pool, orgID, &amb, nil, 8, stamp)
	insertReaderFact(t, pool, orgID, amb, nil, "delta")

	details, total, err := exportOrgDetails(t, New(pool, slog.Default(), nil), orgID,
		RequestPayloadAccess{Grant: true, OrgWideMetadata: true}, 10)
	require.NoError(t, err)
	require.Equal(t, 3, total)
	byToken := map[int64]*RequestDetail{}
	for _, d := range details {
		byToken[d.TokensIn] = d
	}
	assert.Equal(t, []string{"gamma"}, toolNames(byToken[5].ToolCalls), "unique legacy correlation keeps its facts")
	require.Len(t, byToken[5].ToolCallInvocations, 1)
	require.NotNil(t, byToken[5].ToolCallInvocations[0].CallID)
	assert.Equal(t, "cg-1", *byToken[5].ToolCallInvocations[0].CallID)
	assert.Equal(t, map[string]any{"file": "legacy.txt"}, decodeReaderArgs(t, byToken[5].ToolCallInvocations[0].Arguments))
	for _, tok := range []int64{6, 8} {
		assert.Empty(t, toolNames(byToken[tok].ToolCalls),
			"ambiguous legacy correlation attributes its facts to neither carrier (tokens %d)", tok)
	}
}

// TestToolFacts_ListColumnAndYQLFilterScope pins the list projection and the
// YQL tool filter to the same per-invocation scope, including across a page
// boundary: filtering and paging never mix one invocation's tools into
// another row.
func TestToolFacts_ListColumnAndYQLFilterScope(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newToolFactsReaderOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	shared := "list-ab"
	invA, invB, invC := "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"
	insertReaderRow(t, pool, orgID, &shared, &invA, 7, stamp)
	insertReaderRow(t, pool, orgID, &shared, &invB, 19, stamp)
	insertReaderRow(t, pool, orgID, &shared, &invC, 23, stamp)
	insertReaderFact(t, pool, orgID, shared, &invA, "alpha")
	insertReaderFact(t, pool, orgID, shared, &invB, "beta")
	legacy := "list-legacy"
	insertReaderRow(t, pool, orgID, &legacy, nil, 31, stamp)
	insertReaderFact(t, pool, orgID, legacy, nil, "gamma")

	store := New(pool, slog.Default(), nil)

	// Full list: each row's column carries exactly its own scope.
	rows, total, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, PageSize: 50})
	require.NoError(t, err)
	require.Equal(t, 4, total)
	byToken := map[int64]RequestListRow{}
	for _, r := range rows {
		byToken[r.TokensIn] = r
	}
	assert.ElementsMatch(t, []string{"alpha"}, byToken[7].ToolCalls)
	assert.ElementsMatch(t, []string{"beta"}, byToken[19].ToolCalls)
	assert.Empty(t, byToken[23].ToolCalls, "an invocation with no facts lists no tools")
	assert.ElementsMatch(t, []string{"gamma"}, byToken[31].ToolCalls)

	// Paging: page 1 and 2 of a 2-row page each keep their own names.
	p1, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Page: 1, PageSize: 2})
	require.NoError(t, err)
	p2, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Page: 2, PageSize: 2})
	require.NoError(t, err)
	paged := append(append([]RequestListRow{}, p1...), p2...)
	require.Len(t, paged, 4, "the two pages cover all four rows")
	for _, r := range paged {
		var want []string
		switch r.TokensIn {
		case 7:
			want = []string{"alpha"}
		case 19:
			want = []string{"beta"}
		case 31:
			want = []string{"gamma"}
		case 23:
			want = nil
		}
		assert.ElementsMatch(t, want, r.ToolCalls, "tokens %d keeps its own tool scope across pages", r.TokensIn)
	}

	// YQL filter: tool = alpha matches only A's row; tool is empty matches
	// only the fact-less invocation row.
	toolAlpha, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Query: mustParseYQL(t, "tool = alpha")})
	require.NoError(t, err)
	require.Len(t, toolAlpha, 1, "tool = alpha matches exactly invocation A's row")
	assert.Equal(t, int64(7), toolAlpha[0].TokensIn)

	toolEmpty, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Query: mustParseYQL(t, "tool is empty")})
	require.NoError(t, err)
	require.Len(t, toolEmpty, 1)
	assert.Equal(t, int64(23), toolEmpty[0].TokensIn, "only the fact-less invocation row is tool-empty")
}

// TestToolFacts_ReportCountsRequestIdentities pins the aggregate: the tool
// report's requests_using_tools counts physical request identities. Mix 1
// (collapse distinction): two invocation-bound rows sharing a correlation
// count as two, a unique legacy row as one, an orphaned fact as one — four
// where the old correlation count would give three.
func TestToolFacts_ReportCountsRequestIdentities(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newToolFactsReaderOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	shared := "report-ab"
	invA, invB := "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777"
	insertReaderRow(t, pool, orgID, &shared, &invA, 7, stamp)
	insertReaderRow(t, pool, orgID, &shared, &invB, 19, stamp)
	insertReaderFact(t, pool, orgID, shared, &invA, "alpha")
	insertReaderFact(t, pool, orgID, shared, &invB, "beta")
	legacy := "report-legacy"
	insertReaderRow(t, pool, orgID, &legacy, nil, 5, stamp)
	insertReaderFact(t, pool, orgID, legacy, nil, "gamma")
	insertReaderFact(t, pool, orgID, "report-orphan", nil, "epsilon") // no request_logs row at all

	rep, err := New(pool, slog.Default(), nil).GetToolCallsReport(context.Background(), orgID, 30)
	require.NoError(t, err)
	assert.Equal(t, 4, rep.TotalCalls, "four seeded facts in window: alpha, beta, gamma, epsilon")
	assert.Equal(t, 4, rep.DistinctTools, "alpha, beta, gamma, epsilon")
	assert.Equal(t, 4, rep.RequestsUsing, "A, B, legacy and the orphaned correlation each count once")

	// The distinction from the pre-0030 correlation count is real and
	// asserted, not assumed: the same org under the old semantics would
	// report three request ids.
	var naiveCorrelations int
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT COUNT(DISTINCT request_id) FROM tool_calls WHERE org_id = $1", orgID).Scan(&naiveCorrelations))
	assert.Equal(t, 3, naiveCorrelations)
}

// TestToolFacts_ReportAmbiguousLegacyAttributedToNone pins the report's
// mirror of the detail guard: a legacy fact whose correlation two legacy
// rows share is attributable to neither, so it must not count either row —
// and, the rows existing, it is not an orphan either.
func TestToolFacts_ReportAmbiguousLegacyAttributedToNone(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newToolFactsReaderOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	amb := "report-ambiguous"
	insertReaderRow(t, pool, orgID, &amb, nil, 6, stamp)
	insertReaderRow(t, pool, orgID, &amb, nil, 8, stamp)
	insertReaderFact(t, pool, orgID, amb, nil, "delta")

	rep, err := New(pool, slog.Default(), nil).GetToolCallsReport(context.Background(), orgID, 30)
	require.NoError(t, err)
	assert.Equal(t, 1, rep.TotalCalls)
	assert.Equal(t, 1, rep.DistinctTools)
	assert.Equal(t, 0, rep.RequestsUsing, "an ambiguous legacy fact counts no request")
}

// TestToolFacts_MintedSoleCarrierKeepsPre0030Facts is the positive control
// for the first independently-reported failing branch: a pre-0030 writer
// mode emits NULL-invocation facts for a MINTED request (request_logs row
// carries invocation identity). When that row is the org's sole carrier of
// the correlation, the facts are unambiguous and must associate — in the
// detail children, the list column, the YQL filter and the report count.
// The earlier NOT DISTINCT FROM predicate dropped these facts outright.
func TestToolFacts_MintedSoleCarrierKeepsPre0030Facts(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newToolFactsReaderOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	corr := "minted-sole-carrier"
	inv := "88888888-8888-4888-8888-888888888888"
	insertReaderRow(t, pool, orgID, &corr, &inv, 11, stamp)
	insertReaderFact(t, pool, orgID, corr, &inv, "minted-tool") // post-0030 fact
	insertReaderFact(t, pool, orgID, corr, nil, "pre0030-tool") // NULL fact, minted parent
	insertReaderOccurrence(t, pool, orgID, corr, &inv, 1, "cm-1", "minted-tool", `{"mode":"post"}`)
	insertReaderOccurrence(t, pool, orgID, corr, nil, 1, "cp-1", "pre0030-tool", `{"mode":"pre"}`)

	store := New(pool, slog.Default(), nil)

	details, total, err := exportOrgDetails(t, store, orgID, RequestPayloadAccess{Grant: true, OrgWideMetadata: true}, 10)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Len(t, details, 1)
	assert.ElementsMatch(t, []string{"minted-tool", "pre0030-tool"}, toolNames(details[0].ToolCalls),
		"the sole carrier keeps both its invocation-bound and its pre-0030 NULL facts")
	require.Len(t, details[0].ToolCallInvocations, 2)
	gotArgs := map[string]map[string]any{}
	for _, occ := range details[0].ToolCallInvocations {
		require.NotNil(t, occ.CallID)
		gotArgs[*occ.CallID] = decodeReaderArgs(t, occ.Arguments)
	}
	assert.Equal(t, map[string]any{"mode": "post"}, gotArgs["cm-1"],
		"the invocation-bound occurrence keeps its own decoded argument")
	assert.Equal(t, map[string]any{"mode": "pre"}, gotArgs["cp-1"],
		"the pre-0030 NULL occurrence keeps its own decoded argument")

	rows, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, PageSize: 10})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.ElementsMatch(t, []string{"minted-tool", "pre0030-tool"}, rows[0].ToolCalls, "list column carries the same association")

	for _, q := range []string{"tool = pre0030-tool", "tool = minted-tool"} {
		hit, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Query: mustParseYQL(t, q)})
		require.NoError(t, err)
		require.Len(t, hit, 1, "%s matches the sole carrier", q)
	}

	rep, err := store.GetToolCallsReport(context.Background(), orgID, 30)
	require.NoError(t, err)
	assert.Equal(t, 2, rep.TotalCalls)
	assert.Equal(t, 2, rep.DistinctTools)
	assert.Equal(t, 1, rep.RequestsUsing, "both facts attribute to the one sole carrier")
}

// TestToolFacts_NullFactsNeverMatchTwoCarriers is the negative control for
// the second independently-reported failing branch: two NULL-invocation
// parents sharing a correlation plus a NULL fact. The bare NOT DISTINCT
// FROM predicate matched BOTH rows in the list projection and the YQL
// filter; the association rule requires a unique carrier, so the fact
// associates with neither row anywhere — while the negated filter and
// is-empty forms stay consistent with that.
func TestToolFacts_NullFactsNeverMatchTwoCarriers(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newToolFactsReaderOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	amb := "null-parents-ambiguous"
	insertReaderRow(t, pool, orgID, &amb, nil, 6, stamp)
	insertReaderRow(t, pool, orgID, &amb, nil, 8, stamp)
	insertReaderFact(t, pool, orgID, amb, nil, "delta")

	store := New(pool, slog.Default(), nil)

	rows, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, PageSize: 10})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, r := range rows {
		assert.Empty(t, r.ToolCalls, "neither carrier lists the ambiguous NULL fact (tokens %d)", r.TokensIn)
	}

	pos, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Query: mustParseYQL(t, "tool = delta")})
	require.NoError(t, err)
	assert.Empty(t, pos, "tool = delta matches neither carrier")

	neg, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Query: mustParseYQL(t, "tool != delta")})
	require.NoError(t, err)
	require.Len(t, neg, 2, "the negated filter stays consistent: neither row used delta")

	empty, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Query: mustParseYQL(t, "tool is empty")})
	require.NoError(t, err)
	require.Len(t, empty, 2, "both carriers are tool-empty under the same rule")

	rep, err := store.GetToolCallsReport(context.Background(), orgID, 30)
	require.NoError(t, err)
	assert.Equal(t, 1, rep.TotalCalls)
	assert.Equal(t, 0, rep.RequestsUsing, "the report attributes the ambiguous fact to no request")
}

// TestToolFacts_CrossOrgCorrelationShadowing pins the org scoping of the
// association rule: the same correlation string carried by one row in each
// of two orgs stays two independent unique carriers. Each org sees exactly
// its own facts in detail, list, YQL and the report — the carrier count and
// every join are org-scoped, so a foreign org's row can neither steal facts
// nor inflate a carrier count into ambiguity.
func TestToolFacts_CrossOrgCorrelationShadowing(t *testing.T) {
	pool := openAdminTestPool(t)
	org1 := newToolFactsReaderOrg(t, pool)
	org2 := newToolFactsReaderOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	corr := "shadow-correlation"
	inv1 := "99999999-9999-4999-8999-999999999999"
	insertReaderRow(t, pool, org1, &corr, &inv1, 7, stamp)
	insertReaderFact(t, pool, org1, corr, &inv1, "org1-tool")
	insertReaderFact(t, pool, org1, corr, nil, "org1-legacy")
	insertReaderRow(t, pool, org2, &corr, nil, 19, stamp)
	insertReaderFact(t, pool, org2, corr, nil, "org2-legacy")

	store := New(pool, slog.Default(), nil)
	for _, org := range []struct {
		id    string
		want  []string
		other string
	}{{org1, []string{"org1-tool", "org1-legacy"}, "org2-legacy"}, {org2, []string{"org2-legacy"}, "org1-legacy"}} {
		details, total, err := exportOrgDetails(t, store, org.id, RequestPayloadAccess{Grant: true, OrgWideMetadata: true}, 10)
		require.NoError(t, err)
		require.Equal(t, 1, total, "org %s has exactly its own row", org.id)
		assert.ElementsMatch(t, org.want, toolNames(details[0].ToolCalls))

		rows, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: org.id, PageSize: 10})
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.ElementsMatch(t, org.want, rows[0].ToolCalls)

		foreign, _, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: org.id, Query: mustParseYQL(t, "tool = "+org.other)})
		require.NoError(t, err)
		assert.Empty(t, foreign, "org %s never matches the foreign org's tool", org.id)

		rep, err := store.GetToolCallsReport(context.Background(), org.id, 30)
		require.NoError(t, err)
		assert.Equal(t, len(org.want), rep.TotalCalls)
		assert.Equal(t, 1, rep.RequestsUsing, "org %s counts its own sole carrier once", org.id)
	}
}

// TestToolFacts_ReportMintedOrphanCountsPerInvocation pins retention
// semantics for minted facts whose request_logs rows are gone: the count
// must not drop them (the pre-0030 form only counted NULL orphans). Each
// surviving invocation identity counts once, regardless of how many facts
// it retained.
func TestToolFacts_ReportMintedOrphanCountsPerInvocation(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newToolFactsReaderOrg(t, pool)

	// Facts only — the request_logs parents are pruned (retention keeps
	// facts longer than rows). Two facts share one invocation, one more
	// belongs to a second invocation, one is a legacy NULL orphan.
	orphan1, orphan2 := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	insertReaderFact(t, pool, orgID, "gone-1", &orphan1, "one")
	insertReaderFact(t, pool, orgID, "gone-1", &orphan1, "two")
	insertReaderFact(t, pool, orgID, "gone-2", &orphan2, "three")
	insertReaderFact(t, pool, orgID, "gone-legacy", nil, "four")

	rep, err := New(pool, slog.Default(), nil).GetToolCallsReport(context.Background(), orgID, 30)
	require.NoError(t, err)
	assert.Equal(t, 4, rep.TotalCalls, "all retained facts still count as calls")
	assert.Equal(t, 4, rep.DistinctTools)
	assert.Equal(t, 3, rep.RequestsUsing, "per surviving invocation identity, plus the legacy orphan key")
}
