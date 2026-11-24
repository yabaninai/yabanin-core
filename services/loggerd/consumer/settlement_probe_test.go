package consumer

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// claimProbeDB wraps fakeSettlementDB with a programmable QueryRow so the
// schema-probe discipline of the claim path can be driven deterministically.
type claimProbeDB struct {
	*fakeSettlementDB

	mu         sync.Mutex
	answers    []pgx.Row // consumed in order by QueryRow
	queries    []string
	queryCalls int
}

func (f *claimProbeDB) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, query)
	f.queryCalls++
	if len(f.answers) > 0 {
		row := f.answers[0]
		f.answers = f.answers[1:]
		return row
	}
	return &intRow{n: 0}
}

// Query records the claim statement and returns no rows.
func (f *claimProbeDB) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, query)
	return &fakeRows{}, nil
}

// intRow scans a single *int destination.
type intRow struct{ n int }

func (r *intRow) Scan(dest ...any) error {
	if d, ok := dest[0].(*int); ok {
		*d = r.n
	}
	return nil
}

// A transient claim-probe failure is an error, never a silent legacy
// claim: with the schema unresolved, the worker must not claim anything —
// the legacy projection would settle invoked jobs under the shared request
// identity.
func TestClaimBatch_ProbeFailureIsErrorAndClaimsNothing(t *testing.T) {
	inner := &fakeSettlementDB{}
	db := &claimProbeDB{fakeSettlementDB: inner, answers: []pgx.Row{&errRow{err: context.Canceled}}}
	w := &SettlementWorker{db: db, cfg: SettlementConfig{BatchSize: 5, LeaseTTL: 60_000_000_000}, logger: silentLogger()}

	jobs, err := w.claimBatch(context.Background())
	require.Error(t, err, "the probe failure must fail the claim")
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, jobs)
	assert.Empty(t, inner.execs, "no claim statement ran")
}

// A failed probe is not cached as the old schema: the retried tick probes
// again, and once it observes the invocation column it claims through the
// invocation projection.
func TestClaimBatch_ProbeFailureThenSuccessUsesInvocationProjection(t *testing.T) {
	inner := &fakeSettlementDB{}
	db := &claimProbeDB{fakeSettlementDB: inner, answers: []pgx.Row{
		&errRow{err: context.Canceled}, // first tick: transient failure
		&intRow{n: 1},                  // second tick: 0028+ observed
	}}
	w := &SettlementWorker{db: db, cfg: SettlementConfig{BatchSize: 5, LeaseTTL: 60_000_000_000}, logger: silentLogger()}

	_, err := w.claimBatch(context.Background())
	require.ErrorIs(t, err, context.Canceled, "first tick fails loudly")

	jobs, err := w.claimBatch(context.Background())
	require.NoError(t, err, "second tick re-probes and claims")
	assert.Empty(t, jobs)
	db.mu.Lock()
	defer db.mu.Unlock()
	require.Len(t, db.queries, 3, "probe, failed claim's probe re-run, then the claim query")
	assert.Contains(t, db.queries[2], "invocation_id",
		"the successful probe selects the invocation-keyed claim projection")
}

// A successful probe is cached: subsequent claims run no probe and go
// straight to the projection.
func TestClaimBatch_ProbeSuccessIsCached(t *testing.T) {
	inner := &fakeSettlementDB{}
	db := &claimProbeDB{fakeSettlementDB: inner, answers: []pgx.Row{&intRow{n: 0}}}
	w := &SettlementWorker{db: db, cfg: SettlementConfig{BatchSize: 5, LeaseTTL: 60_000_000_000}, logger: silentLogger()}

	_, err := w.claimBatch(context.Background())
	require.NoError(t, err)
	_, err = w.claimBatch(context.Background())
	require.NoError(t, err)

	db.mu.Lock()
	defer db.mu.Unlock()
	assert.Equal(t, 1, db.queryCalls, "only the first claim probes; the cached result serves the rest")
	assert.NotContains(t, db.queries[len(db.queries)-1], "information_schema")
	assert.NotContains(t, db.queries[len(db.queries)-1], "invocation_id", "legacy projection on a pre-0028 schema")
}
