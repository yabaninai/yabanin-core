package batchstore

// Orphan-upload sweep pins: a purpose=batch upload unreferenced by any
// batch_jobs row is reclaimed after the grace window instead of riding the
// full 30-day retention. Referenced uploads (live AND terminal batches),
// uploads inside the grace window (upload→create race protection),
// executor-written purposes (batch.output / batch.error) and the 30-day
// expires_at path RetentionSweep owns are untouched — against the disposable
// fully-migrated Postgres stand (skips in -short; repo convention).

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// backdateFile moves a batch_files row's created_at into the past (the
// orphan sweep predicates on created_at; expires_at is deliberately left
// alone so the two reclamation paths stay independent).
func backdateFile(ctx context.Context, t *testing.T, store *Store, fileID string, age time.Duration) {
	t.Helper()
	_, err := store.pool.Exec(ctx,
		"UPDATE batch_files SET created_at = now() - make_interval(secs => $1) WHERE id = $2",
		age.Seconds(), fileID)
	require.NoError(t, err)
}

func TestSweepOrphanUploads_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("orphan")
	ctx := context.Background()

	line := []LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}}
	mkInput := func(name string) *File {
		t.Helper()
		f, err := store.CreateFile(ctx, orgA, name, PurposeBatchInput, jsonl(lineBody("c1", "hi")))
		require.NoError(t, err)
		return f
	}

	// (1) The orphan under test: unreferenced, aged past the grace window.
	orphan := mkInput("orphan.jsonl")
	backdateFile(ctx, t, store, orphan.ID, 25*time.Hour)

	// (2) Racing-create protection: unreferenced but inside the grace.
	fresh := mkInput("fresh.jsonl")
	backdateFile(ctx, t, store, fresh.ID, time.Hour)

	// (3) Referenced by a live (validating) batch.
	referenced := mkInput("referenced.jsonl")
	backdateFile(ctx, t, store, referenced.ID, 25*time.Hour)
	live, err := store.CreateBatch(ctx, orgA, "key", referenced.ID, EndpointChatCompletions, nil, line)
	require.NoError(t, err)

	// (4) Referenced by a terminal batch: the batch row keeps holding
	// input_file_id until RetentionSweep removes the row itself — the
	// predicate is status-agnostic.
	done := mkInput("done.jsonl")
	backdateFile(ctx, t, store, done.ID, 25*time.Hour)
	terminal, err := store.CreateBatch(ctx, orgA, "key", done.ID, EndpointChatCompletions, nil, line)
	require.NoError(t, err)
	_, err = store.CancelBatch(ctx, orgA, terminal.ID)
	require.NoError(t, err)

	// (5) Executor-written purposes are never orphan-swept.
	outFile, err := store.CreateFile(ctx, orgA, "out.jsonl", PurposeBatchOutput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	backdateFile(ctx, t, store, outFile.ID, 25*time.Hour)
	errFile, err := store.CreateFile(ctx, orgA, "err.jsonl", PurposeBatchError, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	backdateFile(ctx, t, store, errFile.ID, 25*time.Hour)

	reclaimed, err := store.SweepOrphanUploads(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), reclaimed, "exactly the aged unreferenced upload is reclaimed")

	_, err = store.GetFile(ctx, orgA, orphan.ID)
	require.ErrorIs(t, err, ErrNotFound, "orphan past the grace window is reclaimed")
	_, err = store.GetFile(ctx, orgA, fresh.ID)
	require.NoError(t, err, "upload inside the grace window survives (upload→create race protection)")
	_, err = store.GetFile(ctx, orgA, referenced.ID)
	require.NoError(t, err, "upload referenced by a live batch survives")
	_, err = store.GetFile(ctx, orgA, done.ID)
	require.NoError(t, err, "upload referenced by a terminal batch survives until the batch row is swept")
	_, err = store.GetFile(ctx, orgA, outFile.ID)
	require.NoError(t, err, "batch.output files keep the 30-day expires_at path")
	_, err = store.GetFile(ctx, orgA, errFile.ID)
	require.NoError(t, err, "batch.error files keep the 30-day expires_at path")

	// Idempotent: the second pass finds nothing left to reclaim.
	reclaimed, err = store.SweepOrphanUploads(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(0), reclaimed)

	// Shared-stand hygiene (shuffled order must not leak rows): terminalize
	// every batch this test created and remove its leftover files.
	_, err = store.CancelBatch(ctx, orgA, live.ID)
	require.NoError(t, err)
	for _, f := range []*File{fresh, referenced, done, outFile, errFile} {
		_, err := store.DeleteFile(ctx, orgA, f.ID)
		require.NoError(t, err)
	}
}

func TestSweepOrphanUploads_DisabledNoOp_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("orphandis")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "orphan.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	backdateFile(ctx, t, store, f.ID, 25*time.Hour)

	for _, grace := range []time.Duration{0, -time.Hour} {
		reclaimed, err := store.SweepOrphanUploads(ctx, grace)
		require.NoError(t, err)
		assert.Equal(t, int64(0), reclaimed, "grace %v must disable the sweep", grace)
	}
	_, err = store.GetFile(ctx, orgA, f.ID)
	require.NoError(t, err, "a disabled sweep never touches rows")

	_, err = store.DeleteFile(ctx, orgA, f.ID)
	require.NoError(t, err)
}

// TestSweepOrphanUploads_ClockInjectable_Integration: the cutoff rides the
// injectable store clock (SetClock parity with the retention tests) — no SQL
// backdating on the sweep side.
func TestSweepOrphanUploads_ClockInjectable_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("orphanclock")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "orphan.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)

	store.SetClock(func() time.Time { return time.Now().Add(25 * time.Hour) })
	reclaimed, err := store.SweepOrphanUploads(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, reclaimed, int64(1), "the advanced store clock ages the upload past the grace")
	_, err = store.GetFile(ctx, orgA, f.ID)
	require.ErrorIs(t, err, ErrNotFound)
	store.SetClock(time.Now)
}

// TestExecutor_OrphanSweep_Cadence_Integration: the executor runs the orphan
// sweep on the retention cadence (a fresh executor's first Tick always runs
// a cadence pass), the default grace reclaims aged orphans, the knob
// disables cleanly, and a custom grace applies.
func TestExecutor_OrphanSweep_Cadence_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("orphanexec")
	ctx := context.Background()

	mkAgedOrphan := func(t *testing.T) string {
		t.Helper()
		f, err := store.CreateFile(ctx, orgA, "orphan.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
		require.NoError(t, err)
		backdateFile(ctx, t, store, f.ID, 25*time.Hour)
		return f.ID
	}

	orphanA := mkAgedOrphan(t)
	require.NoError(t, NewExecutor(store, nil, nil).Tick(ctx))
	_, err := store.GetFile(ctx, orgA, orphanA)
	require.ErrorIs(t, err, ErrNotFound, "the default executor reclaims the aged orphan on cadence")

	// Knob disabled: exact pre-orphan-sweep behavior — the orphan keeps
	// riding the 30-day expires_at window.
	orphanB := mkAgedOrphan(t)
	require.NoError(t, NewExecutor(store, nil, nil).WithOrphanSweep(0).Tick(ctx))
	_, err = store.GetFile(ctx, orgA, orphanB)
	require.NoError(t, err, "WithOrphanSweep(0) disables reclamation")

	require.NoError(t, NewExecutor(store, nil, nil).WithOrphanSweep(time.Hour).Tick(ctx))
	_, err = store.GetFile(ctx, orgA, orphanB)
	require.ErrorIs(t, err, ErrNotFound, "an explicit grace shorter than the file's age reclaims it")
}
