package batchstore

// validation, claim/lease lifecycle, cancel semantics, crash resume and the
// retention sweep — against the disposable fully-migrated Postgres stand
// (skips in -short; repo convention).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// batchStoreMu serializes the package tests on the shared disposable stand.
var batchStoreMu sync.Mutex

// testStoreReal returns a store over the package-wide disposable, fully
// migrated Postgres stand (Docker required; skipped in -short).

// testOrg derives a unique org id per test (the disposable stand is shared
// by the whole package run; shuffled order must not leak rows between
// tests).
func testOrg(name string) string {
	return fmt.Sprintf("org-%s-%d", name, time.Now().UnixNano())
}

func testStoreReal(t *testing.T) *Store {
	t.Helper()
	pool := testdb.Postgres(t)
	batchStoreMu.Lock()
	t.Cleanup(batchStoreMu.Unlock)
	return NewStore(pool, nil)
}

func lineBody(customID, content string) string {
	return fmt.Sprintf(`{"custom_id":%q,"method":"POST","url":"/v1/chat/completions","body":{"model":"m","messages":[{"role":"user","content":%q}]}}`, customID, content)
}

func jsonl(lines ...string) []byte { return []byte(strings.Join(lines, "\n") + "\n") }

func TestFiles_CRUDAndOrgIsolation_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA, orgB := testOrg("a"), testOrg("b")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "requests.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi"), lineBody("c2", "yo")))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(f.ID, "file-"))
	assert.Equal(t, int64(len(jsonl(lineBody("c1", "hi"), lineBody("c2", "yo")))), f.Bytes)
	assert.WithinDuration(t, time.Now().Add(Retention), f.ExpiresAt, time.Minute)

	got, err := store.GetFile(ctx, orgA, f.ID)
	require.NoError(t, err)
	assert.Equal(t, f.ID, got.ID)

	content, meta, err := store.FileContent(ctx, orgA, f.ID)
	require.NoError(t, err)
	assert.Equal(t, f.Bytes, meta.Bytes)
	assert.Contains(t, string(content), `"custom_id":"c1"`)

	listed, err := store.ListFiles(ctx, orgA, 10)
	require.NoError(t, err)
	require.Len(t, listed, 1)

	// Foreign org: existence hidden — every read is a 404-equivalent miss.
	_, err = store.GetFile(ctx, orgB, f.ID)
	require.ErrorIs(t, err, ErrNotFound)
	_, _, err = store.FileContent(ctx, orgB, f.ID)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.ListFiles(ctx, orgB, 10)
	require.NoError(t, err)
	assert.Empty(t, listed[:0])

	deleted, err := store.DeleteFile(ctx, orgB, f.ID)
	require.NoError(t, err)
	assert.False(t, deleted, "foreign org delete must not remove the file")

	deleted, err = store.DeleteFile(ctx, orgA, f.ID)
	require.NoError(t, err)
	assert.True(t, deleted)
	_, err = store.GetFile(ctx, orgA, f.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFiles_SizeCap_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("cap")
	_, err := store.CreateFile(context.Background(), orgA, "big.bin", PurposeBatchInput, make([]byte, MaxFileSizeBytes+1))
	require.ErrorIs(t, err, ErrFileTooLarge)
}

func TestCreateBatch_Validation_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA, orgB := testOrg("a"), testOrg("b")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)

	// Foreign input file id: 404 semantics (org B referencing org A's file).
	_, err = store.CreateBatch(ctx, orgB, "key", f.ID, EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.ErrorIs(t, err, ErrNotFound)

	_, err = store.CreateBatch(ctx, orgA, "key", "file-doesnotexist", EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.ErrorIs(t, err, ErrNotFound)

	_, err = store.CreateBatch(ctx, orgA, "key", f.ID, "/v1/embeddings", nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.ErrorIs(t, err, ErrUnsupportedEndpoint)

	_, err = store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil, nil)
	require.ErrorIs(t, err, ErrBadLine)

	tooMany := make([]LineInput, MaxBatchLines+1)
	for i := range tooMany {
		tooMany[i] = LineInput{CustomID: fmt.Sprintf("c%d", i), RequestBody: json.RawMessage(`{"model":"m"}`)}
	}
	_, err = store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil, tooMany)
	require.ErrorIs(t, err, ErrTooManyLines)

	// Wrong-purpose file (executor output) cannot seed a batch.
	out, err := store.CreateFile(ctx, orgA, "o.jsonl", PurposeBatchOutput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	_, err = store.CreateBatch(ctx, orgA, "key", out.ID, EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.ErrorIs(t, err, ErrBadLine)
}

func TestBatch_ClaimProcessFinalize_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA, orgB := testOrg("a"), testOrg("b")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi"), lineBody("c2", "yo")))
	require.NoError(t, err)
	b, err := store.CreateBatch(ctx, orgA, "key-1", f.ID, EndpointChatCompletions,
		json.RawMessage(`{"env":"test"}`), []LineInput{
			{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)},
			{CustomID: "c2", RequestBody: json.RawMessage(`{"model":"m","messages":[{"role":"user","content":"yo"}]}`)},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusValidating, b.Status)
	assert.Equal(t, 2, b.TotalCount)

	// Foreign org cannot see the batch.
	_, err = store.GetBatch(ctx, orgB, b.ID)
	require.ErrorIs(t, err, ErrNotFound)

	claimed, err := store.ClaimBatch(ctx, time.Minute, 5)
	require.NoError(t, err)
	require.Equal(t, b.ID, claimed.ID)
	assert.Equal(t, StatusInProgress, claimed.Status)
	assert.Equal(t, 1, claimed.Attempts, "the claim is fencing token 1")

	// A second claim finds nothing (leased).
	_, err = store.ClaimBatch(ctx, time.Minute, 5)
	require.ErrorIs(t, err, ErrNotFound)

	lines, err := store.PendingLines(ctx, b.ID)
	require.NoError(t, err)
	require.Len(t, lines, 2)
	assert.Equal(t, RequestIDForLine(b.ID, 1), lines[0].RequestID)

	require.NoError(t, store.CompleteLine(ctx, b.ID, 1, LineDone, 200, []byte(`{"id":"cmpl-1"}`), nil))
	require.NoError(t, store.CompleteLine(ctx, b.ID, 2, LineFailed, 429, nil, []byte("rate limited")))

	// Double-complete is a no-op (idempotent terminal write).
	require.NoError(t, store.CompleteLine(ctx, b.ID, 1, LineDone, 200, []byte(`{"id":"cmpl-1"}`), nil))
	all, err := store.AllLines(ctx, b.ID)
	require.NoError(t, err)
	var want, gotLine map[string]any
	require.NoError(t, json.Unmarshal([]byte(`{"id":"cmpl-1"}`), &want))
	require.NoError(t, json.Unmarshal(all[0].ResponseBody, &gotLine))
	assert.Equal(t, want, gotLine, "re-completing a terminal line must not overwrite it")

	fin, err := store.FinalizeBatch(ctx, b.ID, claimed.Attempts, false, []byte("out\n"), []byte("err\n"))
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, fin.Status)
	assert.Equal(t, 1, fin.CompletedCount)
	assert.Equal(t, 1, fin.FailedCount)
	require.NotEmpty(t, fin.OutputFileID)
	require.NotEmpty(t, fin.ErrorFileID)

	// Result files are org-scoped like any file.
	outContent, outMeta, err := store.FileContent(ctx, orgA, fin.OutputFileID)
	require.NoError(t, err)
	assert.Equal(t, PurposeBatchOutput, outMeta.Purpose)
	assert.Equal(t, "out\n", string(outContent))
	_, _, err = store.FileContent(ctx, orgB, fin.OutputFileID)
	require.ErrorIs(t, err, ErrNotFound)

	// Terminal batch refuses cancel.
	_, err = store.CancelBatch(ctx, orgA, b.ID)
	require.ErrorIs(t, err, ErrBatchTerminal)
}

func TestBatch_CancelSemantics_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA, orgB := testOrg("a"), testOrg("b")
	ctx := context.Background()

	// Cancel of an unclaimed batch is terminal immediately, and idempotent.
	f, err := store.CreateFile(ctx, orgA, "b1.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	b1, err := store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.NoError(t, err)
	got, err := store.CancelBatch(ctx, orgA, b1.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCancelled, got.Status)
	got, err = store.CancelBatch(ctx, orgA, b1.ID)
	require.NoError(t, err, "repeated cancel on a cancelled batch is idempotent")
	assert.Equal(t, StatusCancelled, got.Status)
	// Cancelled batches are never claimed.
	_, err = store.ClaimBatch(ctx, time.Minute, 5)
	require.ErrorIs(t, err, ErrNotFound)

	// Cancel of an in-progress (leased) batch flips to cancelling; the
	// expired-lease recovery then finalizes it to cancelled.
	f2, err := store.CreateFile(ctx, orgA, "b2.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	b2, err := store.CreateBatch(ctx, orgA, "key", f2.ID, EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.NoError(t, err)
	claimed, err := store.ClaimBatch(ctx, time.Minute, 5)
	require.NoError(t, err)
	require.Equal(t, b2.ID, claimed.ID)
	got, err = store.CancelBatch(ctx, orgA, b2.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCancelling, got.Status)
	got, err = store.CancelBatch(ctx, orgA, b2.ID)
	require.NoError(t, err, "repeated cancel while cancelling is idempotent")
	assert.Equal(t, StatusCancelling, got.Status)

	// Simulate the executor dying: lease expires, recovery runs.
	require.NoError(t, expireLease(t, store, b2.ID))
	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))
	got, err = store.GetBatch(ctx, orgA, b2.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCancelled, got.Status)

	// Foreign org cancel is a plain miss.
	_, err = store.CancelBatch(ctx, orgB, b2.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestBatch_CrashResume_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("crash")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput,
		jsonl(lineBody("c1", "one"), lineBody("c2", "two"), lineBody("c3", "three")))
	require.NoError(t, err)
	b, err := store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil, []LineInput{
		{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)},
		{CustomID: "c2", RequestBody: json.RawMessage(`{"model":"m"}`)},
		{CustomID: "c3", RequestBody: json.RawMessage(`{"model":"m"}`)},
	})
	require.NoError(t, err)

	// First claim executes line 1, then the executor "crashes" (lease
	// expires without a terminal state).
	_, err = store.ClaimBatch(ctx, time.Minute, 5)
	require.NoError(t, err)
	require.NoError(t, store.CompleteLine(ctx, b.ID, 1, LineDone, 200, []byte(`{"ok":1}`), nil))
	require.NoError(t, expireLease(t, store, b.ID))
	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))

	got, err := store.GetBatch(ctx, orgA, b.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusValidating, got.Status, "crashed batch re-enters the queue")
	assert.Equal(t, 1, got.CompletedCount)

	// The second claim resumes at line 2 only, with the SAME deterministic
	// request ids (settlement idempotency on re-execution).
	claimed, err := store.ClaimBatch(ctx, time.Minute, 5)
	require.NoError(t, err)
	require.Equal(t, b.ID, claimed.ID)
	pending, err := store.PendingLines(ctx, b.ID)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assert.Equal(t, 2, pending[0].LineNo)
	assert.Equal(t, RequestIDForLine(b.ID, 2), pending[0].RequestID)

	require.NoError(t, store.CompleteLine(ctx, b.ID, 2, LineDone, 200, []byte(`{"ok":2}`), nil))
	require.NoError(t, store.CompleteLine(ctx, b.ID, 3, LineDone, 200, []byte(`{"ok":3}`), nil))
	fin, err := store.FinalizeBatch(ctx, b.ID, claimed.Attempts, false, []byte("out\n"), nil)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, fin.Status)
	assert.Equal(t, 3, fin.CompletedCount)
	assert.Empty(t, fin.ErrorFileID, "no error file when nothing failed")
}

func TestBatch_ExhaustedAttempts_Fail_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("exhaust")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	_, err = store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.NoError(t, err)

	// Burn the attempt budget with immediate crashes.
	for i := 0; i < 3; i++ {
		_, err := store.ClaimBatch(ctx, time.Minute, 3)
		require.NoError(t, err)
		require.NoError(t, expireLease(t, store, mustBatchID(t, store, orgA)))
		require.NoError(t, store.RecoverExpiredLeases(ctx, 3))
	}
	// attempts == 3 == max: claim refuses, recovery fails it explicitly.
	_, err = store.ClaimBatch(ctx, time.Minute, 3)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, store.RecoverExpiredLeases(ctx, 3))
	got, err := store.GetBatch(ctx, orgA, mustBatchID(t, store, orgA))
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, got.Status)
	assert.NotEmpty(t, got.LastError)
}

func TestRetentionSweep_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("retention")
	ctx := context.Background()

	oldFile, err := store.CreateFile(ctx, orgA, "old.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	oldBatchInput, err := store.CreateFile(ctx, orgA, "oldb.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	oldBatch, err := store.CreateBatch(ctx, orgA, "key", oldBatchInput.ID, EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.NoError(t, err)
	// The batch is processed while inside its window (the claim refuses
	// past-expiry rows), then the retention window elapses.
	claimed, err := store.ClaimBatch(ctx, time.Minute, 5)
	require.NoError(t, err)
	require.Equal(t, oldBatch.ID, claimed.ID)
	fin, err := store.FinalizeBatch(ctx, oldBatch.ID, claimed.Attempts, false, []byte("out\n"), nil)
	require.NoError(t, err)
	_, err = store.pool.Exec(ctx,
		"UPDATE batch_jobs SET expires_at = now() - interval '1 second' WHERE id = $1", oldBatch.ID)
	require.NoError(t, err)
	_, err = store.pool.Exec(ctx,
		"UPDATE batch_files SET expires_at = now() - interval '1 second' WHERE id = $1", oldFile.ID)
	require.NoError(t, err)

	fresh, err := store.CreateFile(ctx, orgA, "fresh.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)

	require.NoError(t, store.RetentionSweep(ctx))

	_, err = store.GetFile(ctx, orgA, oldFile.ID)
	require.ErrorIs(t, err, ErrNotFound, "expired file must not outlive the retention window")
	_, err = store.GetFile(ctx, orgA, fin.OutputFileID)
	require.ErrorIs(t, err, ErrNotFound, "expired batch result file is swept with its batch")
	_, err = store.GetBatch(ctx, orgA, oldBatch.ID)
	require.ErrorIs(t, err, ErrNotFound, "expired batch is swept (lines cascade)")
	_, err = store.GetFile(ctx, orgA, fresh.ID)
	require.NoError(t, err, "fresh file survives the sweep")
}

func TestExecutor_TickEndToEnd_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("tick")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput,
		jsonl(lineBody("c1", "one"), lineBody("c2", "two")))
	require.NoError(t, err)
	_, err = store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil, []LineInput{
		{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m","messages":[]}`)},
		{CustomID: "c2", RequestBody: json.RawMessage(`{"model":"m","messages":[]}`)},
	})
	require.NoError(t, err)

	runCount := 0
	exec := NewExecutor(store, func(ctx context.Context, b *Batch, ln Line) LineResult {
		runCount++
		if ln.CustomID == "c2" {
			return LineResult{Status: 500, Err: errors.New("upstream boom")}
		}
		return LineResult{Status: 200, Body: []byte(`{"id":"cmpl","choices":[]}`)}
	}, nil)
	require.NoError(t, exec.Tick(ctx))
	assert.Equal(t, 2, runCount)

	id := mustBatchID(t, store, orgA)
	got, err := store.GetBatch(ctx, orgA, id)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, got.Status)
	assert.Equal(t, 1, got.CompletedCount)
	assert.Equal(t, 1, got.FailedCount)

	outContent, _, err := store.FileContent(ctx, orgA, got.OutputFileID)
	require.NoError(t, err)
	assert.Contains(t, string(outContent), `"custom_id":"c1"`)
	assert.NotContains(t, string(outContent), `"custom_id":"c2"`)
	errContent, _, err := store.FileContent(ctx, orgA, got.ErrorFileID)
	require.NoError(t, err)
	assert.Contains(t, string(errContent), "upstream boom")

	// The queue is drained.
	require.NoError(t, exec.Tick(ctx))
	_, err = store.ClaimBatch(ctx, time.Minute, 5)
	require.ErrorIs(t, err, ErrNotFound)
}

// expireLease forces the batch's lease into the past (crash simulation).
func expireLease(t *testing.T, store *Store, batchID string) error {
	t.Helper()
	_, err := store.pool.Exec(context.Background(),
		"UPDATE batch_jobs SET lease_until = now() - interval '1 second' WHERE id = $1", batchID)
	return err
}

// expireBatchWindow forces BOTH the lease and the retention window into the
// past: the executor died after the batch should have expired (the recovery
// sweep must then pick the expiry verdict, not the re-queue).
func expireBatchWindow(t *testing.T, store *Store, batchID string) error {
	t.Helper()
	_, err := store.pool.Exec(context.Background(),
		"UPDATE batch_jobs SET lease_until = now() - interval '1 second', expires_at = now() - interval '1 second' WHERE id = $1", batchID)
	return err
}

// leaseUntil reads the raw lease column (fencing assertions).
func leaseUntil(t *testing.T, store *Store, batchID string) *time.Time {
	t.Helper()
	var lu *time.Time
	require.NoError(t, store.pool.QueryRow(context.Background(),
		"SELECT lease_until FROM batch_jobs WHERE id = $1", batchID).Scan(&lu))
	return lu
}

// TestBatch_Expiry_Queued_Integration: a queued batch whose 30-day retention
// window passed is terminalized as 'expired' by the recovery pass — never
// claimed, never cancellable, client-visible instead of a silent late
// execution between sweep cadences.
func TestBatch_Expiry_Queued_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("expq")
	ctx := context.Background()

	past := time.Now().Add(-31 * 24 * time.Hour)
	store.SetClock(func() time.Time { return past })
	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	b, err := store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.NoError(t, err)
	store.SetClock(time.Now)

	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))
	got, err := store.GetBatch(ctx, orgA, b.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, got.Status)
	assert.False(t, got.CompletedAt.IsZero(), "expiry records when the verdict landed")

	// Never claimable, never re-cancellable (terminal), attempts untouched.
	_, err = store.ClaimBatch(ctx, time.Minute, 5)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.CancelBatch(ctx, orgA, b.ID)
	require.ErrorIs(t, err, ErrBatchTerminal)
	assert.Equal(t, 0, got.Attempts)
}

// TestBatch_Expiry_ClaimRefusesBeforeRecovery_Integration: the claim queue
// itself refuses a past-expiry batch even before the recovery/sweep pass ran
// (the sweep is cadence-gated; the claim must not execute-and-bill inside
// that window).
func TestBatch_Expiry_ClaimRefusesBeforeRecovery_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("expc")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi")))
	require.NoError(t, err)
	b, err := store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil,
		[]LineInput{{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)}})
	require.NoError(t, err)
	_, err = store.pool.Exec(ctx,
		"UPDATE batch_jobs SET expires_at = now() - interval '1 second' WHERE id = $1", b.ID)
	require.NoError(t, err)

	_, err = store.ClaimBatch(ctx, time.Minute, 5)
	require.ErrorIs(t, err, ErrNotFound, "past-expiry batch is not claimable before the sweep deletes it")

	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))
	got, err := store.GetBatch(ctx, orgA, b.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, got.Status)
}

// TestBatch_Expiry_InFlight_Integration: lease death past the retention
// window expires the batch (never re-queued), unless a cancel request
// outlived the lease — cancel wins over expiry.
func TestBatch_Expiry_InFlight_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("expf")
	ctx := context.Background()

	mkBatch := func(t *testing.T) *Batch {
		t.Helper()
		f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi"), lineBody("c2", "yo")))
		require.NoError(t, err)
		b, err := store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil, []LineInput{
			{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)},
			{CustomID: "c2", RequestBody: json.RawMessage(`{"model":"m"}`)},
		})
		require.NoError(t, err)
		_, err = store.ClaimBatch(ctx, time.Minute, 5)
		require.NoError(t, err)
		require.NoError(t, store.CompleteLine(ctx, b.ID, 1, LineDone, 200, []byte(`{"ok":1}`), nil))
		return b
	}

	// (a) lease died past expiry, no cancel → expired, executed prefix kept.
	b := mkBatch(t)
	require.NoError(t, expireBatchWindow(t, store, b.ID))
	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))
	got, err := store.GetBatch(ctx, orgA, b.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, got.Status, "expired beats re-queue when the window passed")
	assert.Equal(t, 1, got.CompletedCount, "the executed prefix stays durable")
	assert.Empty(t, got.OutputFileID, "expiry never fabricates result files")
	_, err = store.ClaimBatch(ctx, time.Minute, 5)
	require.ErrorIs(t, err, ErrNotFound, "expired batch never re-enters the queue")

	// (b) lease died past expiry WITH a pending cancel → cancelled wins.
	b2 := mkBatch(t)
	got, err = store.CancelBatch(ctx, orgA, b2.ID)
	require.NoError(t, err)
	require.Equal(t, StatusCancelling, got.Status)
	require.NoError(t, expireBatchWindow(t, store, b2.ID))
	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))
	got, err = store.GetBatch(ctx, orgA, b2.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCancelled, got.Status, "cancel wins over expiry")
	assert.False(t, got.CompletedAt.IsZero())

	// (c) a NOT-expired batch with a dead lease still re-queues (the
	// original crash-resume contract is untouched by the expiry verdicts).
	// It is cancelled afterwards: the stand is shared by the whole package
	// run and a leftover validating batch would leak into another test's
	// claim queue (shuffled order must not matter).
	b3 := mkBatch(t)
	require.NoError(t, expireLease(t, store, b3.ID))
	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))
	got, err = store.GetBatch(ctx, orgA, b3.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusValidating, got.Status)
	_, err = store.CancelBatch(ctx, orgA, b3.ID)
	require.NoError(t, err)
}

// TestBatch_StaleOwner_Fenced_Integration: a claim generation that lost its
// lease to recovery + re-claim cannot finalize, fail or release the batch —
// the current owner's token owns every terminal write.
func TestBatch_StaleOwner_Fenced_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("fence")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput, jsonl(lineBody("c1", "hi"), lineBody("c2", "yo")))
	require.NoError(t, err)
	b, err := store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil, []LineInput{
		{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)},
		{CustomID: "c2", RequestBody: json.RawMessage(`{"model":"m"}`)},
	})
	require.NoError(t, err)

	// Generation 1 executes line 1 and dies.
	stale, err := store.ClaimBatch(ctx, time.Minute, 5)
	require.NoError(t, err)
	require.Equal(t, b.ID, stale.ID)
	require.NoError(t, store.CompleteLine(ctx, b.ID, 1, LineDone, 200, []byte(`{"ok":1}`), nil))
	require.NoError(t, expireLease(t, store, b.ID))
	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))

	// Generation 2 claims (token bumps).
	cur, err := store.ClaimBatch(ctx, time.Minute, 5)
	require.NoError(t, err)
	require.Equal(t, b.ID, cur.ID)
	require.Equal(t, stale.Attempts+1, cur.Attempts)

	// Stale generation: every terminal write is rejected or a no-op —
	// the batch stays the current owner's.
	_, err = store.FinalizeBatch(ctx, b.ID, stale.Attempts, false, []byte("stale\n"), nil)
	require.Error(t, err, "stale finalize is fenced")
	require.ErrorContains(t, err, "lease lost or superseded")
	got, err := store.GetBatch(ctx, orgA, b.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusInProgress, got.Status, "stale finalize must not terminalize")

	require.NoError(t, store.MarkBatchFailed(ctx, b.ID, stale.Attempts, "stale poison"))
	got, err = store.GetBatch(ctx, orgA, b.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusInProgress, got.Status, "stale failure marking must not kill the owner's run")

	require.NoError(t, store.ReleaseLease(ctx, b.ID, stale.Attempts))
	got, err = store.GetBatch(ctx, orgA, b.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusInProgress, got.Status, "stale release must not strip the owner's lease")
	assert.NotNil(t, leaseUntil(t, store, b.ID), "the current lease survives the stale release")

	// Current owner finishes: line 2, then the fenced finalize wins.
	require.NoError(t, store.CompleteLine(ctx, b.ID, 2, LineDone, 200, []byte(`{"ok":2}`), nil))
	fin, err := store.FinalizeBatch(ctx, b.ID, cur.Attempts, false, []byte("out\n"), nil)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, fin.Status)
	assert.Equal(t, 2, fin.CompletedCount)
	assert.Empty(t, fin.ErrorFileID)
	assert.Nil(t, leaseUntil(t, store, b.ID), "finalize clears the lease")
}

// TestExecutor_CrashRestart_NoDuplicates_Integration (card acceptance): a
// batch interrupted by a worker crash resumes at the first unexecuted line
// and every line executes and settles EXACTLY once — no duplicate work, no
// duplicate result entries, despite the interrupted generation.
func TestExecutor_CrashRestart_NoDuplicates_Integration(t *testing.T) {
	store := testStoreReal(t)
	orgA := testOrg("crashnd")
	ctx := context.Background()

	f, err := store.CreateFile(ctx, orgA, "b.jsonl", PurposeBatchInput,
		jsonl(lineBody("c1", "one"), lineBody("c2", "two"), lineBody("c3", "three")))
	require.NoError(t, err)
	b, err := store.CreateBatch(ctx, orgA, "key", f.ID, EndpointChatCompletions, nil, []LineInput{
		{CustomID: "c1", RequestBody: json.RawMessage(`{"model":"m"}`)},
		{CustomID: "c2", RequestBody: json.RawMessage(`{"model":"m"}`)},
		{CustomID: "c3", RequestBody: json.RawMessage(`{"model":"m"}`)},
	})
	require.NoError(t, err)

	// Generation 1: executes line 1, then "crashes" (no terminal state,
	// no lease release — the row just keeps a dead lease).
	crashed, err := store.ClaimBatch(ctx, time.Minute, 5)
	require.NoError(t, err)
	require.Equal(t, b.ID, crashed.ID)
	require.NoError(t, store.CompleteLine(ctx, b.ID, 1, LineDone, 200, []byte(`{"ok":1}`), nil))
	require.NoError(t, expireLease(t, store, b.ID))
	require.NoError(t, store.RecoverExpiredLeases(ctx, 5))

	// Generation 2 (fresh executor) resumes and completes the batch.
	runs := map[string]int{}
	exec := NewExecutor(store, func(ctx context.Context, b *Batch, ln Line) LineResult {
		runs[ln.CustomID]++
		return LineResult{Status: 200, Body: []byte(fmt.Sprintf(`{"ok":%q}`, ln.CustomID))}
	}, nil)
	require.NoError(t, exec.Tick(ctx))

	assert.Equal(t, map[string]int{"c2": 1, "c3": 1}, runs,
		"resume executes exactly the unexecuted lines, exactly once each")

	got, err := store.GetBatch(ctx, orgA, b.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, got.Status)
	assert.Equal(t, 3, got.CompletedCount)
	assert.Equal(t, 0, got.FailedCount)
	assert.Equal(t, crashed.Attempts+1, got.Attempts, "two claim generations total")

	all, err := store.AllLines(ctx, b.ID)
	require.NoError(t, err)
	require.Len(t, all, 3)
	for _, ln := range all {
		assert.Equal(t, LineDone, ln.Status, "line %d", ln.LineNo)
		assert.Equal(t, RequestIDForLine(b.ID, ln.LineNo), ln.RequestID,
			"deterministic request id survives the restart (settlement dedupes)")
	}

	out, _, err := store.FileContent(ctx, orgA, got.OutputFileID)
	require.NoError(t, err)
	for _, custom := range []string{"c1", "c2", "c3"} {
		assert.Equal(t, 1, strings.Count(string(out), fmt.Sprintf(`"custom_id":%q`, custom)),
			"output carries %s exactly once", custom)
	}
}

// mustBatchID returns the single batch of the org (test helper).
func mustBatchID(t *testing.T, store *Store, orgID string) string {
	t.Helper()
	batches, err := store.ListBatches(context.Background(), orgID, 1)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	return batches[0].ID
}
