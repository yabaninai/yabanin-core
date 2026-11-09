package adminstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// canarySnapshotTx is the in-memory auditTx for the canary snapshot loader
// (snapshotAuditTx parity).
type canarySnapshotTx struct {
	queryFn   func(context.Context, string, ...interface{}) (pgx.Rows, error)
	execs     []string
	committed bool
	rollback  bool
}

func (tx *canarySnapshotTx) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return &mockPGXRow{err: errors.New("unexpected canary snapshot QueryRow")}
}
func (tx *canarySnapshotTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return tx.queryFn(ctx, sql, args...)
}
func (tx *canarySnapshotTx) Exec(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
	tx.execs = append(tx.execs, sql)
	return pgconn.NewCommandTag("OK"), nil
}
func (tx *canarySnapshotTx) Commit(context.Context) error   { tx.committed = true; return nil }
func (tx *canarySnapshotTx) Rollback(context.Context) error { tx.rollback = true; return nil }

func TestStore_LoadCanarySnapshot_AllOrError(t *testing.T) {
	now := time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)
	rolloutQueries := 0
	tx := &canarySnapshotTx{queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
		switch {
		case strings.Contains(sql, "FROM canary_rollouts") && !strings.Contains(sql, "JOIN"):
			rolloutQueries++
			return &mockPGXRows{data: [][]interface{}{
				{"r1", "org-a", "roll", true, 2, now, now},
			}}, nil
		case strings.Contains(sql, "FROM canary_rollout_versions"):
			return &mockPGXRows{data: [][]interface{}{
				{"v2", "r1", "org-a", 2, "base-m", "can-m", 25, CanaryLabelActive, "admin@x.test", now},
			}}, nil
		default:
			return nil, errors.New("unexpected query")
		}
	}}
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}
	store := newForTest(db, newTestLogger(), nil)

	snapshot, err := store.LoadCanarySnapshot(context.Background(), "org-a")
	require.NoError(t, err)
	require.True(t, tx.committed)
	require.False(t, tx.rollback)
	require.Equal(t, []string{"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", "SELECT set_config('app.current_org', $1, true)"}, tx.execs)
	require.Equal(t, 1, rolloutQueries, "one rollout-list query")
	require.Len(t, snapshot.Rollouts, 1)
	v, ok := snapshot.Versions["r1"]
	require.True(t, ok)
	require.Equal(t, 2, v.Version)
	require.Equal(t, "base-m", v.BaseModel)
	require.Equal(t, "can-m", v.CanaryModel)
	require.Equal(t, 25, v.Percent)
}

func TestStore_LoadCanarySnapshot_QueryFailureRollsBackWithoutPartialValue(t *testing.T) {
	wantErr := errors.New("version query failed")
	tx := &canarySnapshotTx{queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
		if strings.Contains(sql, "FROM canary_rollouts") && !strings.Contains(sql, "JOIN") {
			return &mockPGXRows{data: [][]interface{}{{"r1", "org-a", "roll", true, 1, time.Time{}, time.Time{}}}}, nil
		}
		return nil, wantErr
	}}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}, newTestLogger(), nil)

	snapshot, err := store.LoadCanarySnapshot(context.Background(), "org-a")
	require.ErrorIs(t, err, wantErr)
	require.True(t, tx.rollback)
	require.False(t, tx.committed)
	require.Empty(t, snapshot.Rollouts)
	require.Empty(t, snapshot.Versions)
}

// --- validation -----------------------------------------------------------------

func TestValidateCanaryContent(t *testing.T) {
	require.NoError(t, validateCanaryContent("gpt-old", "gpt-new", 1))
	require.NoError(t, validateCanaryContent("gpt-old", "gpt-new", 99))
	require.Error(t, validateCanaryContent("gpt-old", "gpt-new", 0), "percent 0 is a deactivated rollout, not a row")
	require.Error(t, validateCanaryContent("gpt-old", "gpt-new", 100), "percent 100 = canary gets ALL traffic (the packet's negative)")
	require.Error(t, validateCanaryContent("gpt-old", "gpt-new", -5))
	require.Error(t, validateCanaryContent("", "gpt-new", 10))
	require.Error(t, validateCanaryContent("gpt-old", "", 10))
	require.Error(t, validateCanaryContent("same", "same", 10), "base == canary is a no-op rollout")
}

// --- version bump contract --------------------------------------------------------

func TestStore_CanaryMutationsBumpVersion(t *testing.T) {
	// Every mutation path must end with exactly one bump for the mutated
	// org — the version-key contract the gateway cache depends on. The
	// happy paths are SQL; here we pin the bump wiring through the
	// withPolicyTx surface with a queryRow-answering mock (create path).
	now := time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)
	tx := &canaryMutationTx{now: now}
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil }}
	store := newForTest(db, newTestLogger(), nil)
	bumper := newRecordingCanaryBumper()
	store.SetCanaryVersionBumper(bumper)

	_, _, err := store.CreateCanaryRollout(context.Background(), "org-a", "roll", "base-m", "can-m", 10, "admin@x.test")
	require.NoError(t, err)
	require.Equal(t, 1, bumper.count("org-a"))
}

// canaryMutationTx answers the INSERT..RETURNING pairs of CreateCanaryRollout.
type canaryMutationTx struct {
	now time.Time
}

func (tx *canaryMutationTx) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	if strings.Contains(sql, "INSERT INTO canary_rollouts ") {
		return &mockPGXRow{data: [][]interface{}{{"r1", "org-a", "roll", false, 0, tx.now, tx.now}}}
	}
	if strings.Contains(sql, "INSERT INTO canary_rollout_versions ") {
		return &mockPGXRow{data: [][]interface{}{{"v1", "r1", "org-a", 1, "base-m", "can-m", 10, CanaryLabelDraft, "admin@x.test", tx.now}}}
	}
	return &mockPGXRow{err: errors.New("unexpected QueryRow: " + sql)}
}
func (tx *canaryMutationTx) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}
func (tx *canaryMutationTx) Exec(_ context.Context, _ string, _ ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("OK"), nil
}
func (tx *canaryMutationTx) Commit(context.Context) error   { return nil }
func (tx *canaryMutationTx) Rollback(context.Context) error { return nil }

// --- recommendation math (D3 evidence hook) ---------------------------------------

func TestCanaryRecommendation(t *testing.T) {
	// Insufficient data never recommends.
	require.Equal(t, "hold", canaryRecommendation(0, 0, 100, 1))
	require.Equal(t, "hold", canaryRecommendation(100, 50, 0, 0))
	// Equal error shares hold.
	require.Equal(t, "hold", canaryRecommendation(100, 2, 100, 2))
	// Canary error share 10pp above base recommends rollback.
	require.Equal(t, "rollback-recommended", canaryRecommendation(100, 10, 100, 5))
	// Just under the threshold holds.
	require.Equal(t, "hold", canaryRecommendation(1000, 50, 1000, 46))
}
