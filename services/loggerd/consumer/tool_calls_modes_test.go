package consumer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Review-2 and rollout controls for the tool-fact identity split (migration
// 0030). The writer under test selects statement bytes and probe domains
// from the live schema and the event's own identity — these tests pin the
// mode branches and the edges a coarse or over-caching design gets wrong:
//
//   - pre-0030 schema: exact legacy bytes and the coarse probe, verbatim
//     (the supported rolling-deployment mode);
//   - a single live consumer spanning the migration window: the negative
//     probe is revalidated, so the first paid call after the migrator ran
//     switches to invocation bytes (no permanently cached absence);
//   - 0030 + minted identity: invocation bytes, per-entry replay, no coarse
//     probe at all — a partially written prior attempt cannot suppress the
//     missing names or occurrences;
//   - 0030 + legacy identity: the NULL-domain probe — a minted sibling
//     sharing the client request-id never satisfies the legacy existence
//     check;
//   - existence is established only by a clean row or pgx.ErrNoRows: an
//     unexpected probe error fails the enrichment;
//   - a transient schema-probe failure fails the delivery and is never
//     cached.

// toolFactSampleTwoTools is a retained upstream sample with two distinct
// tool names, one occurrence each.
const toolFactSampleTwoTools = `{"choices":[{"message":{"tool_calls":[
	{"id":"call-a","type":"function","function":{"name":"list_projects","arguments":"{\"q\":\"a\"}"}},
	{"id":"call-b","type":"function","function":{"name":"list_labels","arguments":"{}"}}]}}]}`

// factCaptureTx is the smallest delivery-transaction double for direct
// writer calls: both surfaces delegate to the capturing mock.
type factCaptureTx struct{ db *retCaptureDB }

func (t *factCaptureTx) Exec(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	return t.db.Exec(ctx, q, args...)
}

func (t *factCaptureTx) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	return t.db.QueryRow(ctx, q, args...)
}

func (t *factCaptureTx) Commit(context.Context) error   { return nil }
func (t *factCaptureTx) Rollback(context.Context) error { return nil }

// schemaAwareAdmissionRow answers information_schema probes per table
// literal (settlement_jobs vs tool_calls may differ mid-rollout) and
// delegates everything else to the shared admissionRow router.
func schemaAwareAdmissionRow(cols map[string]int, admission *fakeRow, facts map[string]any) func(context.Context, string, ...any) pgx.Row {
	base := admissionRow(1, admission, facts)
	return func(ctx context.Context, query string, args ...any) pgx.Row {
		if strings.Contains(query, "information_schema.columns") {
			for table, n := range cols {
				if strings.Contains(query, "'"+table+"'") {
					return &fakeRow{vals: []any{n}}
				}
			}
		}
		return base(ctx, query, args...)
	}
}

// matchingFacts returns the canonical terminal facts bound to this
// delivery's identity (the wire-vs-facts equivalence check compares them).
func matchingFacts(rid, inv string) map[string]any {
	facts := chargedTerminalFacts()
	facts["request_id"] = rid
	if inv != "" {
		facts["invocation_id"] = inv
	} else {
		delete(facts, "invocation_id")
	}
	return facts
}

// toolFactEvent builds a request.completed message carrying the two-tool
// retained sample under the given identity.
func toolFactEvent(id, rid, inv string) redis.XMessage {
	msg := invocationChargedMsg(id)
	msg.Values["request_id"] = rid
	if inv != "" {
		msg.Values["invocation_id"] = inv
	} else {
		delete(msg.Values, "invocation_id")
	}
	msg.Values["upstream_response"] = toolFactSampleTwoTools
	return msg
}

// toolFactInserts returns every recorded tool-fact insert for one table.
func toolFactInserts(t *testing.T, db *retCaptureDB, table string) []retCall {
	t.Helper()
	var out []retCall
	for _, call := range db.calls {
		if strings.Contains(call.query, "INSERT INTO "+table+" ") {
			out = append(out, call)
		}
	}
	return out
}

// duplicateExecTags makes every request_logs insert conflict, routing the
// delivery through the duplicate-invocation enrichment path.
func duplicateExecTags(db *retCaptureDB, mu *sync.Mutex) {
	db.ExecFn = func(_ context.Context, q string, args ...any) (pgconn.CommandTag, error) {
		mu.Lock()
		defer mu.Unlock()
		db.calls = append(db.calls, retCall{query: q, args: args})
		switch {
		case strings.Contains(q, "INSERT INTO request_logs"):
			return pgconn.NewCommandTag("INSERT 0 0"), nil
		case strings.Contains(q, "UPDATE request_admissions"):
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}
}

// An invocation-bearing delivery against a pre-0030 schema keeps the exact
// legacy statement bytes and never binds the identity: there is no column to
// receive it, and no linkage is guessed after the fact.
func TestToolFactsPre0030SchemaKeepsExactLegacyBytes(t *testing.T) {
	const rid, inv = "rid-pre0030", "ac4243ad-e481-4194-bf32-000000000101"
	db := newRetCaptureDB()
	db.QueryRowFn = schemaAwareAdmissionRow(map[string]int{"settlement_jobs": 0, "tool_calls": 0},
		&fakeRow{vals: []any{"org-abc", "admitted"}}, matchingFacts(rid, inv))
	c := retConsumer(db, &retStubStore{found: true, effective: true})
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), toolFactEvent("121-1", rid, inv),
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true}))

	names := toolFactInserts(t, db, "tool_calls")
	require.Len(t, names, 2, "both distinct names recorded")
	for _, call := range names {
		assert.Equal(t, toolCallInsertLegacyQuery, call.query, "pre-0030 keeps the legacy bytes verbatim")
		assert.Len(t, call.args, 5, "no invocation bind on a schema without the column")
	}
	occ := toolFactInserts(t, db, "tool_call_invocations")
	require.Len(t, occ, 2, "both occurrences recorded")
	for _, call := range occ {
		assert.Equal(t, toolCallInvocationInsertLegacyQuery, call.query)
		assert.Len(t, call.args, 6)
	}
}

// One live consumer spans the migration window: its first paid call sees the
// column absent, the next one sees it present. The negative probe must be
// revalidated — a cached absence would keep unbound legacy inserts forever
// after the migrator ran.
func TestToolFactSchemaTransitionMidConsumerRevalidatesAbsence(t *testing.T) {
	const rid = "rid-transition"
	var mu sync.Mutex
	toolProbes := 0
	db := newRetCaptureDB()
	// The tool probe answers by call count: absent first, present after the
	// migrator ran; everything else routes through the shared admission
	// router bound to this delivery's facts.
	routerFor := func(facts map[string]any) func(context.Context, string, ...any) pgx.Row {
		wire := schemaAwareAdmissionRow(map[string]int{"settlement_jobs": 1},
			&fakeRow{vals: []any{"org-abc", "admitted"}}, facts)
		return func(ctx context.Context, q string, args ...any) pgx.Row {
			if strings.Contains(q, "information_schema.columns") && strings.Contains(q, "'tool_calls'") {
				mu.Lock()
				defer mu.Unlock()
				toolProbes++
				return &fakeRow{vals: []any{map[bool]int{true: 1}[toolProbes > 1]}}
			}
			return wire(ctx, q, args...)
		}
	}
	c := retConsumer(db, &retStubStore{found: true, effective: true})

	inv1 := "ac4243ad-e481-4194-bf32-000000000501"
	db.QueryRowFn = routerFor(matchingFacts(rid, inv1))
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), toolFactEvent("125-1", rid, inv1),
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true}))
	for _, call := range toolFactInserts(t, db, "tool_calls") {
		require.Equal(t, toolCallInsertLegacyQuery, call.query, "pre-migration call keeps legacy bytes")
	}

	inv2 := "ac4243ad-e481-4194-bf32-000000000502"
	db.QueryRowFn = routerFor(matchingFacts(rid, inv2))
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), toolFactEvent("125-2", rid, inv2),
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true}))

	mu.Lock()
	probes := toolProbes
	mu.Unlock()
	assert.Equal(t, 2, probes, "absence was revalidated, not cached")
	post := toolFactInserts(t, db, "tool_calls")
	require.Len(t, post, 4, "the second call wrote its two names as well")
	for _, call := range post[2:] {
		assert.Contains(t, call.query, "ON CONFLICT", "post-migration call picks the invocation bytes")
		assert.Len(t, call.args, 6)
		assert.Contains(t, call.args, inv2, "the identity is bound once the column exists")
	}
}

// Two paid invocations sharing one client request-id: the first delivers
// live, the second arrives as a duplicate (its request_logs insert conflicts)
// and enriches through the identity path. Both keep independent tool facts —
// the sibling's existing rows never suppress the second invocation's.
func TestToolFactsMixedSiblingsShareRequestIDThroughEnrich(t *testing.T) {
	const rid = "rid-shared"
	var mu sync.Mutex
	db := newRetCaptureDB()
	duplicateExecTags(db, &mu)
	c := retConsumer(db, &retStubStore{found: true, effective: true})
	for i := 0; i < 2; i++ {
		inv := fmt.Sprintf("ac4243ad-e481-4194-bf32-0000000002%02d", i)
		wire := schemaAwareAdmissionRow(map[string]int{"settlement_jobs": 1, "tool_calls": 1},
			&fakeRow{vals: []any{"org-abc", "admitted"}}, matchingFacts(rid, inv))
		db.QueryRowFn = wire
		require.NoError(t, c.handleRequestCompleteProfile(context.Background(), toolFactEvent(fmt.Sprintf("122-%d", i+1), rid, inv),
			deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true}))
	}
	bound := map[string]bool{}
	mu.Lock()
	defer mu.Unlock()
	for _, call := range append(toolFactInserts(t, db, "tool_calls"), toolFactInserts(t, db, "tool_call_invocations")...) {
		assert.Contains(t, call.query, "ON CONFLICT", "0030 schema picks the invocation bytes")
		for _, arg := range call.args {
			if s, ok := arg.(string); ok && strings.HasPrefix(s, "ac4243ad-") {
				bound[s] = true
			}
		}
	}
	assert.Len(t, bound, 2, "both sibling invocations keep independent tool facts")
}

// A duplicate invocation-bearing delivery post-0030 never issues the coarse
// existence probe: every entry replays under its own arbiter, so partially
// written prior attempts cannot suppress the missing names or occurrences.
func TestEnrichMintedSkipsProbeAndReplaysPerEntry(t *testing.T) {
	const rid, inv = "rid-partial", "ac4243ad-e481-4194-bf32-000000000301"
	var mu sync.Mutex
	db := newRetCaptureDB()
	duplicateExecTags(db, &mu)
	db.QueryRowFn = func(ctx context.Context, q string, args ...any) pgx.Row {
		mu.Lock()
		if strings.Contains(q, "FROM tool_calls") {
			mu.Unlock()
			t.Errorf("enrichment of an invocation-bearing delivery must not probe tool_calls existentially: %s", q)
		} else {
			mu.Unlock()
		}
		return schemaAwareAdmissionRow(map[string]int{"tool_calls": 1},
			&fakeRow{vals: []any{"org-abc", "admitted"}}, matchingFacts(rid, inv))(ctx, q, args...)
	}
	c := retConsumer(db, &retStubStore{found: true, effective: true})
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), toolFactEvent("123-1", rid, inv),
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true}))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, toolFactInserts(t, db, "tool_calls"), 2, "every distinct name replayed")
	require.Len(t, toolFactInserts(t, db, "tool_call_invocations"), 2, "every occurrence replayed")
}

// The legacy existence probe on a 0030 schema is scoped to the NULL domain:
// a minted sibling row sharing the client request-id must not satisfy it
// and suppress genuine legacy facts. The defense-in-depth branch is proven
// by direct call (the duplicate-invocation gate above it is
// identity-scoped); the coarse-probe failure mode is the built-in negative
// control — the sibling row WOULD satisfy it and yield zero inserts.
func TestEnrichLegacyProbeScopedToNullDomain(t *testing.T) {
	db := newRetCaptureDB()
	var sawNullDomainProbe bool
	db.QueryRowFn = func(_ context.Context, q string, _ ...any) pgx.Row {
		if strings.Contains(q, "information_schema.columns") && strings.Contains(q, "'tool_calls'") {
			return &fakeRow{vals: []any{1}} // 0030 live
		}
		if strings.Contains(q, "FROM tool_calls") {
			if strings.Contains(q, "invocation_id IS NULL") {
				sawNullDomainProbe = true
				return errRow{err: pgx.ErrNoRows} // no legacy rows: only the minted sibling exists
			}
			return &fakeRow{vals: []any{1}} // the coarse probe WOULD find the sibling
		}
		return errRow{err: pgx.ErrNoRows}
	}
	c := retConsumer(db, nil)
	tx := &factCaptureTx{db: db}
	ev := requestEvent{
		requestID: "rid-mixed", orgID: "org-abc",
		requestIDValue: "rid-mixed", orgIDValue: "org-uuid",
		modelUsed: "m", upstreamResponse: toolFactSampleTwoTools,
		invocationIDValue: nil, // legacy domain
	}
	require.NoError(t, c.enrichToolCallsIfAbsent(context.Background(), tx, ev))
	assert.True(t, sawNullDomainProbe, "the legacy probe ran scoped to the NULL domain")
	names := toolFactInserts(t, db, "tool_calls")
	require.Len(t, names, 2, "legacy facts are not suppressed by the minted sibling")
	for _, call := range names {
		assert.Equal(t, toolCallInsertLegacyQuery, call.query)
	}
}

// An unexpected existence-probe error is an enrichment failure, not
// "missing": only pgx.ErrNoRows establishes absence.
func TestEnrichProbeErrorIsNotAbsence(t *testing.T) {
	db := newRetCaptureDB()
	db.QueryRowFn = func(_ context.Context, q string, _ ...any) pgx.Row {
		if strings.Contains(q, "information_schema.columns") && strings.Contains(q, "'tool_calls'") {
			return &fakeRow{vals: []any{1}} // 0030 live
		}
		if strings.Contains(q, "FROM tool_calls") {
			return errRow{err: context.Canceled} // transport failure, not absence
		}
		return errRow{err: pgx.ErrNoRows}
	}
	c := retConsumer(db, nil)
	tx := &factCaptureTx{db: db}
	ev := requestEvent{
		requestID: "rid-probe-err", orgID: "org-abc",
		requestIDValue: "rid-probe-err", orgIDValue: "org-uuid",
		modelUsed: "m", upstreamResponse: toolFactSampleTwoTools,
		invocationIDValue: nil,
	}
	err := c.enrichToolCallsIfAbsent(context.Background(), tx, ev)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, toolFactInserts(t, db, "tool_calls"), "an errored probe must not fall through to inserts")
}

// A transient tool-fact schema-probe failure fails the delivery (retry
// later) and never resolves the schema: the retried delivery probes again
// and picks the invocation bytes once the probe succeeds.
func TestToolFactProbeFailurePropagatesUncached(t *testing.T) {
	const rid, inv = "rid-probe", "ac4243ad-e481-4194-bf32-000000000401"
	var mu sync.Mutex
	probes := 0
	db := newRetCaptureDB()
	base := schemaAwareAdmissionRow(map[string]int{"settlement_jobs": 1},
		&fakeRow{vals: []any{"org-abc", "admitted"}}, matchingFacts(rid, inv))
	db.QueryRowFn = func(ctx context.Context, q string, args ...any) pgx.Row {
		if strings.Contains(q, "information_schema.columns") && strings.Contains(q, "'tool_calls'") {
			mu.Lock()
			defer mu.Unlock()
			probes++
			if probes == 1 {
				return errRow{err: context.Canceled}
			}
			return &fakeRow{vals: []any{1}} // 0030 on the retry
		}
		return base(ctx, q, args...)
	}
	c := retConsumer(db, &retStubStore{found: true, effective: true})
	msg := toolFactEvent("124-1", rid, inv)

	err := c.handleRequestCompleteProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true})
	require.Error(t, err, "a transient probe failure fails the delivery")
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, errUnadmittedTerminal, "a probe failure is never a park")

	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true}))
	mu.Lock()
	assert.Equal(t, 2, probes, "the failed probe was not cached")
	mu.Unlock()
	names := toolFactInserts(t, db, "tool_calls")
	require.Len(t, names, 2)
	for _, call := range names {
		assert.Contains(t, call.query, "ON CONFLICT", "the successful retry picks the invocation bytes")
	}
}
