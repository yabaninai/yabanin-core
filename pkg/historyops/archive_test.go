package historyops

// ENT-HIST-05 coverage: the archive_copy runner's deterministic objects,
// exactly-once counting, export-completeness and checksum gates, destination
// refusals and the engine wiring. Unit tests run everywhere; the integration
// pins share the real PostgreSQL stand (skipped under -short).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// ---- cold-storage fakes (names chosen against the existing helper
// inventory: no fakeClock/scriptedRunner/testHarness collisions) ----

// mapStore is the in-memory cold store with a read side: the read-back
// checksum gate runs against exactly what Write captured.
type mapStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	writes  int
	// corrupt mutates every written object before storing it — the
	// bit-rot/silent-corruption simulation for the read-back gate.
	corrupt bool
	// onWrite, when set, observes every successful Write with its key —
	// the export-before-delete ordering pin runs its DB probes here.
	onWrite func(key string)
}

func newMapStore() *mapStore {
	return &mapStore{objects: make(map[string][]byte)}
}

func (s *mapStore) Write(_ context.Context, key string, data []byte) error {
	s.mu.Lock()
	s.writes++
	stored := append([]byte(nil), data...)
	if s.corrupt {
		stored = append([]byte("CORRUPTED"), stored...)
	}
	s.objects[key] = stored
	s.mu.Unlock()
	if s.onWrite != nil {
		s.onWrite(key)
	}
	return nil
}

func (s *mapStore) Read(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[key]
	if !ok {
		return nil, fmt.Errorf("object %q not found", key)
	}
	return append([]byte(nil), data...), nil
}

func (s *mapStore) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.objects[key]
	return ok
}

func (s *mapStore) bytes(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.objects[key]...)
}

func (s *mapStore) totalWrites() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

// writeOnlyStore models the production FSStore: Write only, no Read — the
// read-back gate must degrade to the Write-error discipline, not refuse.
type writeOnlyStore struct {
	inner *mapStore
}

func (s writeOnlyStore) Write(ctx context.Context, key string, data []byte) error {
	return s.inner.Write(ctx, key, data)
}

// ---- fixtures ----

// archiveJob builds a runner-direct job over the given selection with a
// digest computed against the live DB stamp (seeded head 16).
func archiveJob(t *testing.T, ctx context.Context, pool testPGPool, orgID string, sel Selection, dest string) *Job {
	t.Helper()
	seedSchemaMigrations(t, ctx, pool, 16)
	stamp, err := SchemaStampFromDB(ctx, pool)
	require.NoError(t, err)
	digest, err := SelectionDigest(OpArchiveCopy, sel, stamp)
	require.NoError(t, err)
	return &Job{
		ID:              fmt.Sprintf("job-archive-%d", time.Now().UnixNano()),
		OrgID:           orgID,
		Op:              OpArchiveCopy,
		Selection:       sel,
		SelectionDigest: digest,
		Stamp:           stamp,
		Destination:     dest,
		CreatedAt:       time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC),
		Confirmed:       FamilyCounts{},
	}
}

func archiveCopyRunner(db HistoryDB, store ColdStorage) *ArchiveCopyRunner {
	return &ArchiveCopyRunner{
		DB:                 db,
		ResolveDestination: func(string) (ColdStorage, error) { return store, nil },
	}
}

// archiveObjectKeys returns every stored object key of one family batch.
func archiveObjectKeys(orgID, digest, jobID string, batchIndex int, family Family) (string, string) {
	key := archiveObjectKey(orgID, digest, jobID, batchIndex, family)
	return key, key + ".manifest.json"
}

// ---- unit tests ----

func TestDecodeBatchMarkerRules(t *testing.T) {
	family, ids, err := decodeBatch(encodeBatch(FamilyRequestLogs, []string{"1", "2"}))
	require.NoError(t, err)
	assert.Equal(t, FamilyRequestLogs, family)
	assert.Equal(t, []string{"1", "2"}, ids)

	// An id that looks like a marker cannot exist by construction — but a
	// batch whose FIRST element is not a marker is a corrupt checkpoint.
	_, _, err = decodeBatch([]string{"42"})
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, _, err = decodeBatch(nil)
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, _, err = decodeBatch([]string{"prefix:not-the-marker", "1"})
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestBatchCountDeltaMatrix(t *testing.T) {
	plan := [][]string{
		encodeBatch(FamilyRequestLogs, []string{"1", "2", "3"}),
		encodeBatch(FamilyRequestLogs, []string{"4"}),
		encodeBatch(FamilySessions, []string{"s1"}),
	}

	// Fresh execution: the family has no confirmed counts yet.
	delta, err := batchCountDelta(plan, 0, FamilyCounts{})
	require.NoError(t, err)
	assert.EqualValues(t, 3, delta)
	// Second batch of the same family, first one already confirmed.
	delta, err = batchCountDelta(plan, 1, FamilyCounts{FamilyRequestLogs: 3})
	require.NoError(t, err)
	assert.EqualValues(t, 1, delta)
	// Other families never interfere.
	delta, err = batchCountDelta(plan, 2, FamilyCounts{FamilyRequestLogs: 4})
	require.NoError(t, err)
	assert.EqualValues(t, 1, delta)

	// Crash-window replay of an already-checkpointed batch: zero.
	delta, err = batchCountDelta(plan, 0, FamilyCounts{FamilyRequestLogs: 3})
	require.NoError(t, err)
	assert.EqualValues(t, 0, delta)

	// Count drift is a corrupt checkpoint, not a guess.
	_, err = batchCountDelta(plan, 1, FamilyCounts{FamilyRequestLogs: 2})
	require.ErrorIs(t, err, ErrInvalidRequest)

	// Index and marker corruption.
	_, err = batchCountDelta(plan, 3, FamilyCounts{})
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, err = batchCountDelta([][]string{{"no-marker"}}, 0, FamilyCounts{})
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestArchiveObjectKeyLayout(t *testing.T) {
	key := archiveObjectKey("org-1", "digest-abc", "018f0000-0000-7000-8000-000000000001", 2, FamilyRequestLogs)
	assert.Equal(t,
		"historyops/org-1/digest-abc/job-018f0000-0000-7000-8000-000000000001/batch-2/request_logs.jsonl",
		key, "the key scopes objects to one job (HIST-03)")
	assert.Equal(t, key,
		archiveObjectKey("org-1", "digest-abc", "018f0000-0000-7000-8000-000000000001", 2, FamilyRequestLogs),
		"deterministic: a re-run must rewrite, not duplicate")
	assert.NotEqual(t, key,
		archiveObjectKey("org-1", "digest-abc", "018f0000-0000-7000-8000-000000000002", 2, FamilyRequestLogs),
		"different jobs of the same selection produce disjoint objects")
	assert.NotContains(t, key, "..")
	assert.True(t, strings.HasPrefix(key, "historyops/"), "inside the historyops namespace")

	// Free-form job ids cannot change the key's path shape. The literal is
	// j / . . \ o b (7 chars); every non-alphanumeric becomes one '_'.
	weird := archiveObjectKey("org-1", "digest-abc", "j/..\\ob", 0, FamilyRequestLogs)
	assert.NotContains(t, weird, "..", "path-unsafe job-id characters are neutralized")
	assert.Contains(t, weird, "job-j____ob/", "unsafe characters are replaced, structure kept")
}

func TestArchiveManifestContractFields(t *testing.T) {
	ctx := context.Background()
	store := newMapStore()
	key := "historyops/org-1/digest-abc/batch-0/request_logs.jsonl"
	payloads := [][]byte{[]byte(`{"id":1}`), []byte(`{"id":2}`)}
	manifest := archiveManifest{
		Table:         string(FamilyRequestLogs),
		Scope:         "org-1",
		Rows:          len(payloads),
		Redacted:      false,
		ExportedAt:    time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		SchemaVersion: FamiliesSchemaVersion,
		Op:            string(OpArchiveCopy),
		OrgID:         "org-1",
		Digest:        "digest-abc",
		JobID:         "job-test-1",
		PeriodFrom:    previewPeriod.From.UTC().Format(time.RFC3339Nano),
		PeriodTo:      previewPeriod.To.UTC().Format(time.RFC3339Nano),
		Batch:         0,
	}
	_, err := writeArchiveObject(ctx, store, key, manifest, payloads)
	require.NoError(t, err)

	// JSONL: each payload verbatim + newline.
	jsonl := store.bytes(key)
	require.Equal(t,
		bytes.Join([][]byte{[]byte(`{"id":1}`), []byte(`{"id":2}`)}, []byte("\n")),
		bytes.TrimSuffix(jsonl, []byte("\n")))
	require.True(t, bytes.HasSuffix(jsonl, []byte("\n")))

	// Manifest: contract fields + the sha256 over exactly the JSONL bytes.
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(store.bytes(key+".manifest.json"), &decoded))
	for _, k := range []string{"table", "scope", "rows", "sha256", "redacted",
		"cutoff_days", "exported_at", "schema_version", "op", "org_id",
		"selection_digest", "job_id", "period_from", "period_to", "batch"} {
		require.Contains(t, decoded, k, "manifest contract key %s", k)
	}
	sum := sha256.Sum256(jsonl)
	assert.Equal(t, hex.EncodeToString(sum[:]), decoded["sha256"])
	assert.InDelta(t, float64(2), decoded["rows"], 0.001)
	assert.InDelta(t, float64(0), decoded["cutoff_days"], 0.001, "retention-window semantics do not apply")
	assert.Equal(t, false, decoded["redacted"])
	assert.InDelta(t, float64(FamiliesSchemaVersion), decoded["schema_version"], 0.001)
	assert.Equal(t, "digest-abc", decoded["selection_digest"])
	assert.Equal(t, "job-test-1", decoded["job_id"],
		"the manifest carries the durable job identity (HIST-03)")
}

// TestArchiveWriteNeverOverwrites pins HIST-03's non-overwriting write: a
// byte-identical re-execution (the engine's at-least-once replay) writes
// nothing, and DIFFERENT content at an existing key refuses instead of
// replacing an earlier archive.
func TestArchiveWriteNeverOverwrites(t *testing.T) {
	ctx := context.Background()
	store := newMapStore()
	key := "historyops/org-1/digest-abc/job-j1/batch-0/request_logs.jsonl"
	m := archiveManifest{Table: string(FamilyRequestLogs), Scope: "org-1", Rows: 1}

	_, err := writeArchiveObject(ctx, store, key, m, [][]byte{[]byte(`{"id":1}`)})
	require.NoError(t, err)
	first := store.bytes(key)

	// Byte-identical replay: no new writes at all.
	_, err = writeArchiveObject(ctx, store, key, m, [][]byte{[]byte(`{"id":1}`)})
	require.NoError(t, err)
	assert.Equal(t, first, store.bytes(key))
	assert.Equal(t, 2, store.totalWrites(), "identical replay writes nothing")

	// Different content at the same key: refuse, archive untouched.
	_, err = writeArchiveObject(ctx, store, key, m, [][]byte{[]byte(`{"id":1,"changed":true}`)})
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "conflicting content must refuse, not overwrite: %v", err)
	assert.Equal(t, RefusalArchiveChecksum, refusal.Code)
	assert.Equal(t, first, store.bytes(key), "the earlier archive is never replaced")
}

// TestArchiveWriteOverwriteRefusalViaRunner pins the runner-level path: the
// copy runner re-executing a batch whose rows CHANGED since the first
// execution (same key, different exported bytes) refuses fail-closed instead
// of overwriting the first archive.
func TestArchiveWriteOverwriteRefusalViaRunner_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	insertRequestLog(t, ctx, pool, orgID, "req-ow1",
		time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), strptr(`{"v":1}`))

	store := newMapStore()
	runner := archiveCopyRunner(pool, store)
	job := archiveJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"file:///cold/historyops/"+orgID+"/cycle/")
	require.NoError(t, runner.VerifySnapshot(ctx, job))
	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1)
	job.Checkpoint.Plan = plan

	_, err = runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.NoError(t, err)
	key := archiveObjectKey(orgID, job.SelectionDigest, job.ID, 0, FamilyRequestLogs)
	first := store.bytes(key)

	// The row changes after the first execution but before the checkpoint
	// (the crash-window replay shape): the replay's export differs.
	_, err = pool.Exec(ctx,
		"UPDATE request_logs SET response = $1::jsonb WHERE org_id = $2::uuid AND request_id = $3",
		`{"v":2,"mutated":"after-archive"}`, orgID, "req-ow1")
	require.NoError(t, err)

	_, err = runner.ExecuteBatch(ctx, job, 0, plan[0])
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "a conflicting replay must refuse, got %v", err)
	assert.Equal(t, RefusalArchiveChecksum, refusal.Code)
	assert.Equal(t, first, store.bytes(key),
		"the first archive survives the conflicting execution untouched")
}

// refusalCodeOf extracts the typed refusal code from err (fails the test
// when err is not a refusal).
func refusalCodeOf(t *testing.T, err error) RefusalCode {
	t.Helper()
	require.Error(t, err)
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "expected a typed refusal, got: %v", err)
	return refusal.Code
}

func TestVerifyArchiveCompletenessGate(t *testing.T) {
	planned := []string{"1", "2", "3"}
	ok := [][]byte{[]byte(`{}`), []byte(`{}`), []byte(`{}`)}

	require.NoError(t, verifyArchiveCompleteness(FamilyRequestLogs, planned, []string{"1", "2", "3"}, ok))
	require.NoError(t, verifyArchiveSubset(FamilyRequestLogs, planned, []string{"1", "2", "3"}, ok))

	// Short / reordered / unplanned exports refuse (copy runner).
	err := verifyArchiveCompleteness(FamilyRequestLogs, planned, []string{"1", "2"}, ok[:2])
	assert.Equal(t, RefusalArchiveChecksum, refusalCodeOf(t, err))
	err = verifyArchiveCompleteness(FamilyRequestLogs, planned, []string{"1", "3", "2"}, ok)
	assert.Equal(t, RefusalArchiveChecksum, refusalCodeOf(t, err))

	// The destructive runner accepts subsets (crash-window replays) but
	// never unplanned ids or empty serializations.
	require.NoError(t, verifyArchiveSubset(FamilyRequestLogs, planned, []string{"1"}, ok[:1]))
	require.NoError(t, verifyArchiveSubset(FamilyRequestLogs, planned, nil, nil))
	err = verifyArchiveSubset(FamilyRequestLogs, planned, []string{"1", "9"}, append(ok[:1], []byte(`{}`)))
	assert.Equal(t, RefusalArchiveChecksum, refusalCodeOf(t, err))
	err = verifyArchiveSubset(FamilyRequestLogs, planned, []string{"1"}, [][]byte{nil})
	assert.Equal(t, RefusalArchiveChecksum, refusalCodeOf(t, err))
}

func TestValidateArchiveDestinationMatrix(t *testing.T) {
	org := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	cases := []struct {
		name string
		dest string
		want RefusalCode // empty = valid
	}{
		{"inside-namespace", "file:///cold/historyops/" + org + "/2026/03/", ""},
		{"namespace-suffix", "file:///cold/historyops/" + org, ""},
		{"empty", "", RefusalNoDestination},
		{"http", "http://cold.example/historyops/" + org + "/", RefusalUnsupportedDestination},
		{"s3", "s3://bucket/historyops/" + org + "/", RefusalUnsupportedDestination},
		{"traversal", "file:///cold/historyops/" + org + "/../../etc/", RefusalUnsupportedDestination},
		{"foreign-org", "file:///cold/historyops/other-org/2026/03/", RefusalForeignDestination},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateArchiveDestination(OpArchiveCopy, org, tc.dest)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			assert.Equal(t, tc.want, refusalCodeOf(t, err))
		})
	}
}

// ---- integration pins (real PostgreSQL stand) ----

// TestArchiveCopyArchivesExactlyOnce_Integration drives the runner directly:
// export discipline, verbatim row serialization, byte-identical rewrites and
// the checkpoint-derived exactly-once counting gate.
func TestArchiveCopyArchivesExactlyOnce_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	foreign := seedPreviewOrg(t, ctx, pool)

	inPeriod := []string{"req-a1", "req-a2", "req-a3"}
	for i, req := range inPeriod {
		insertRequestLog(t, ctx, pool, orgID, req,
			time.Date(2026, 3, 2, 0, i, 0, 0, time.UTC),
			strptr(fmt.Sprintf(`{"v":1,"kind":"model_response","content":"row-%d"}`, i)))
	}
	// Out of period and foreign-org rows must not be archived.
	insertRequestLog(t, ctx, pool, orgID, "req-outside", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), nil)
	insertRequestLog(t, ctx, pool, foreign, "req-foreign", time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), nil)

	store := newMapStore()
	runner := archiveCopyRunner(pool, store)
	job := archiveJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"file:///cold/historyops/"+orgID+"/cycle/")

	require.NoError(t, runner.VerifySnapshot(ctx, job))
	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1, "3 in-window rows fit one batch")
	family, ids, err := decodeBatch(plan[0])
	require.NoError(t, err)
	require.Equal(t, FamilyRequestLogs, family)
	require.Len(t, ids, 3)
	job.Checkpoint.Plan = plan

	key, mkey := archiveObjectKeys(orgID, job.SelectionDigest, job.ID, 0, FamilyRequestLogs)

	// First execution: counts the batch; the object carries exactly the
	// planned rows, verbatim.
	counts, err := runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.NoError(t, err)
	require.EqualValues(t, 3, counts[FamilyRequestLogs])
	require.True(t, store.has(key))
	firstBytes := store.bytes(key)
	var line map[string]any
	require.NoError(t, json.Unmarshal(bytes.Split(firstBytes, []byte("\n"))[0], &line))
	assert.Equal(t, "req-a1", line["request_id"])
	// row_to_json travels verbatim — jsonb's normalized form (spaces after
	// colons) is preserved byte-for-byte into the JSONL.
	assert.Contains(t, string(firstBytes), `"content": "row-0"`)
	assert.NotContains(t, string(firstBytes), "req-outside")

	// Crash-window replay BEFORE the checkpoint saved (confirmed empty):
	// re-archives byte-identical and counts again (checkpoint still
	// advances by delta — that execution is the one that gets recorded).
	counts, err = runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.NoError(t, err)
	require.EqualValues(t, 3, counts[FamilyRequestLogs])
	require.Equal(t, firstBytes, store.bytes(key), "re-run leaves byte-identical objects")
	require.Equal(t, 2, store.totalWrites(),
		"object + manifest once; the byte-identical replay writes nothing (non-overwrite gate, HIST-03)")

	// Replay AFTER the checkpoint saved: delta gate skips — zero counts,
	// zero writes.
	job.Confirmed = FamilyCounts{FamilyRequestLogs: 3}
	counts, err = runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.NoError(t, err)
	require.Empty(t, counts)
	assert.Equal(t, 2, store.totalWrites(), "skipped batches do not touch the store")
	assert.True(t, store.has(mkey))

	// The exported set was exactly the plan (completeness held): 4 rows
	// remain — the archived 3 + the out-of-period one; the foreign row is
	// untouched.
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid", orgID).Scan(&n))
	require.Equal(t, 4, n, "archive_copy never deletes")
}

// TestArchiveCopyChecksumRefusalOnCorruptReadback_Integration pins the
// backlog AC: a corrupted archive write refuses the batch (fail-closed).
func TestArchiveCopyChecksumRefusalOnCorruptReadback_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	insertRequestLog(t, ctx, pool, orgID, "req-c1",
		time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), strptr(`{"ok":true}`))

	store := newMapStore()
	store.corrupt = true
	runner := archiveCopyRunner(pool, store)
	job := archiveJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"file:///cold/historyops/"+orgID+"/cycle/")
	require.NoError(t, runner.VerifySnapshot(ctx, job))
	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1)
	job.Checkpoint.Plan = plan

	_, err = runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.Error(t, err)
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "corruption must refuse, not error-retry: %v", err)
	assert.Equal(t, RefusalArchiveChecksum, refusal.Code)
}

// TestArchiveCopyWriteOnlyStoreDegradesGracefully_Integration: a store
// without Read (the retention FSStore shape) still completes — the
// verification degrades to the Write-error discipline + completeness gate.
func TestArchiveCopyWriteOnlyStoreDegradesGracefully_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	insertRequestLog(t, ctx, pool, orgID, "req-w1",
		time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), strptr(`{"ok":true}`))

	inner := newMapStore()
	runner := archiveCopyRunner(pool, writeOnlyStore{inner: inner})
	job := archiveJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"file:///cold/historyops/"+orgID+"/cycle/")
	require.NoError(t, runner.VerifySnapshot(ctx, job))
	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1)
	job.Checkpoint.Plan = plan

	counts, err := runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.NoError(t, err)
	require.EqualValues(t, 1, counts[FamilyRequestLogs])
	require.True(t, inner.has(archiveObjectKey(orgID, job.SelectionDigest, job.ID, 0, FamilyRequestLogs)))
}

// TestArchiveCopyDestinationRefusalZeroWrites_Integration: every run-time
// destination failure mode refuses before the store is touched.
func TestArchiveCopyDestinationRefusalZeroWrites_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	insertRequestLog(t, ctx, pool, orgID, "req-d1",
		time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), nil)

	store := newMapStore()
	job := archiveJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"s3://bucket/historyops/"+orgID+"/")

	err := archiveCopyRunner(pool, store).VerifySnapshot(ctx, job)
	assert.Equal(t, RefusalUnsupportedDestination, refusalCodeOf(t, err))

	err = archiveCopyRunner(pool, store).VerifySnapshot(ctx, archiveJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"file:///cold/historyops/other-org/"))
	assert.Equal(t, RefusalForeignDestination, refusalCodeOf(t, err))

	// No resolver wired: no_destination, zero writes.
	noResolver := &ArchiveCopyRunner{}
	err = noResolver.VerifySnapshot(ctx, archiveJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"file:///cold/historyops/"+orgID+"/cycle/"))
	assert.Equal(t, RefusalNoDestination, refusalCodeOf(t, err))

	assert.Zero(t, store.totalWrites(), "destination refusals never write")
}

// TestArchiveCopyEngineWiring_Integration: the full engine path — enqueue,
// claim, verify, plan, execute, checkpoint, finalize — against the real
// stand, with the journal recording the lifecycle.
func TestArchiveCopyEngineWiring_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	insertRequestLog(t, ctx, pool, orgID, "req-e1",
		time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), strptr(`{"v":1}`))
	insertRequestLog(t, ctx, pool, orgID, "req-e2",
		time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC), strptr(`{"v":2}`))

	seedSchemaMigrations(t, ctx, pool, 16)
	stampFn := func(ctx context.Context) (SchemaStamp, error) { return SchemaStampFromDB(ctx, pool) }

	store := newMapStore()
	engine := NewEngine(NewMemoryJobStore(previewNow), &MemoryJournaler{}, EngineConfig{
		LeaseTTL:    30 * time.Second,
		MaxAttempts: 3,
		Now:         previewNow,
		Stamp:       stampFn,
	})
	engine.RegisterRunner(OpArchiveCopy, archiveCopyRunner(pool, store))

	sel := previewSelection(orgID, FamilyRequestLogs)
	stamp, err := stampFn(ctx)
	require.NoError(t, err)
	digest, err := SelectionDigest(OpArchiveCopy, sel, stamp)
	require.NoError(t, err)
	dest := "file:///cold/historyops/" + orgID + "/engine/"
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID:           orgID,
		Op:              OpArchiveCopy,
		Selection:       sel,
		PresentedDigest: digest,
		IdempotencyKey:  "engine-archive-1",
		Destination:     dest,
		Actor:           JobActor{Type: ActorUser, Author: "u-admin-1"},
		Caller:          adminCaller(),
	})
	require.NoError(t, err)

	// Idempotent replay returns the same job.
	replay, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgID, Op: OpArchiveCopy, Selection: sel, PresentedDigest: digest,
		IdempotencyKey: "engine-archive-1", Destination: dest,
		Actor: JobActor{Type: ActorUser, Author: "u-admin-1"}, Caller: adminCaller(),
	})
	require.NoError(t, err)
	require.Equal(t, job.ID, replay.ID)

	more, err := engine.ExecuteNext(ctx, "worker-archive-1")
	require.NoError(t, err)
	require.True(t, more)

	final, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCompleted, final.Status,
		"job failed: last_error=%q refusal=%+v confirmed=%+v checkpoint=%+v",
		final.LastError, final.Refusal, final.Confirmed, final.Checkpoint)
	require.EqualValues(t, 2, final.Confirmed[FamilyRequestLogs])

	key, mkey := archiveObjectKeys(orgID, digest, job.ID, 0, FamilyRequestLogs)
	require.True(t, store.has(key))
	require.True(t, store.has(mkey))

	// Hot rows untouched by archive_copy.
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid", orgID).Scan(&n))
	require.Equal(t, 2, n)
}

// TestArchiveCopySnapshotDrift_Integration pins the archive path's
// execute-time snapshot-digest gate (verifyArchiveSnapshot) against the real
// runner: schema drift between enqueue and execute (a migration landing
// mid-flight, simulated by a schema_migrations row the enqueue never saw)
// must fail the whole job with digest_mismatch, zero rows archived and the
// hot rows untouched. The redact path has the same pin
// (TestRedactContentSnapshotDrift_Integration); the engine-level scripted
// pin (TestSnapshotDriftRefuses) exercises only the engine's refusal
// handling and cannot reach this real digest computation, so without this
// test the gate has no direct regression pin.
func TestArchiveCopySnapshotDrift_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	insertRequestLog(t, ctx, pool, orgID, "req-drift-a1",
		time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), strptr(`{"v":1}`))
	insertRequestLog(t, ctx, pool, orgID, "req-drift-a2",
		time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC), strptr(`{"v":2}`))

	seedSchemaMigrations(t, ctx, pool, 16)
	stampFn := func(ctx context.Context) (SchemaStamp, error) { return SchemaStampFromDB(ctx, pool) }

	store := newMapStore()
	engine := NewEngine(NewMemoryJobStore(previewNow), &MemoryJournaler{}, EngineConfig{
		LeaseTTL:    30 * time.Second,
		MaxAttempts: 3,
		Now:         previewNow,
		Stamp:       stampFn,
	})
	engine.RegisterRunner(OpArchiveCopy, archiveCopyRunner(pool, store))

	sel := previewSelection(orgID, FamilyRequestLogs)
	stamp, err := stampFn(ctx)
	require.NoError(t, err)
	digest, err := SelectionDigest(OpArchiveCopy, sel, stamp)
	require.NoError(t, err)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID:           orgID,
		Op:              OpArchiveCopy,
		Selection:       sel,
		PresentedDigest: digest,
		IdempotencyKey:  "engine-archive-drift",
		Destination:     "file:///cold/historyops/" + orgID + "/engine-drift/",
		Actor:           JobActor{Type: ActorUser, Author: "u-admin-1"},
		Caller:          adminCaller(),
	})
	require.NoError(t, err)

	// A migration lands between enqueue and execute: the live stamp head
	// moves 16 -> 17, so the presented digest no longer matches.
	_, err = pool.Exec(ctx, `INSERT INTO schema_migrations (version, dirty) VALUES (17, false)`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 17`) })

	more, err := engine.ExecuteNext(ctx, "worker-archive-drift")
	require.NoError(t, err)
	require.True(t, more)

	final, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobFailed, final.Status, "schema drift must fail the job, not retry it")
	require.NotNil(t, final.Refusal)
	assert.Equal(t, RefusalDigestMismatch, final.Refusal.Code)

	// Fail-closed: nothing archived, nothing destroyed.
	require.Empty(t, store.objects,
		"a drift-refused job must not archive any object")
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid", orgID).Scan(&n))
	require.Equal(t, 2, n, "a drift-refused job touches zero rows")
}
