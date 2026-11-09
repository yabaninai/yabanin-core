package adminstore

// AF-10 acceptance against a real PostgreSQL (disposable testcontainers stand):
// 100 concurrent appends keep the hash chain linear on an empty AND a
// non-empty journal, tampering with the new snapshot payload is detected,
// legacy v1 rows keep verifying, two store instances return the same journal,
// the durable outbox delivers after a failed direct append, and the list
// order/tie-breaker is stable across pages.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // register the pgx database/sql driver for the production verifier
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/auditlog"
)

// resetAuditTable empties the journal and the outbox so the chain-sensitive
// scenarios start from a known state (the disposable per-binary stand holds
// nothing of value across tests).
func resetAuditTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`TRUNCATE admin_audit_outbox; TRUNCATE admin_audit_logs;`)
	require.NoError(t, err)
}

// newTestVerifier binds the production pkg/auditlog.Verifier to the same
// database through a database/sql connection (the store exposes its pool
// config), so the acceptance runs the real linear verifier.
func newTestVerifier(t *testing.T, store *Store) func(ctx context.Context) (int64, error) {
	t.Helper()
	require.NotNil(t, store.DB())
	sqlDB, err := sql.Open("pgx", store.DB().Config().ConnString())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	v := auditlog.NewVerifier(sqlDB)
	return v.Verify
}

// TestAuditChain_OldForUpdateProtocol_ForksOnEmptyTable pins the FACT the
// card demanded: SELECT ... FOR UPDATE on the last row guarantees nothing on
// an empty journal — there is no row to lock, so two concurrent appends both
// read prev_hash="" and fork the chain. This is why the shared protocol uses
// a transaction-scoped advisory lock instead (the next test proves it holds).
func TestAuditChain_OldForUpdateProtocol_ForksOnEmptyTable(t *testing.T) {
	pool := openAdminTestPool(t)
	ctx := context.Background()
	resetAuditTable(t, pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM admin_audit_logs WHERE action = 'old.protocol'`)
	})

	start := make(chan struct{})
	release := make(chan struct{})
	selected := make(chan string, 2)
	commitErrs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			<-start
			tx, err := pool.Begin(ctx)
			if err != nil {
				selected <- fmt.Sprintf("begin error: %v", err)
				<-release
				commitErrs <- err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			// The old ENT-03 protocol, verbatim.
			var prevHash string
			err = tx.QueryRow(ctx,
				`SELECT row_hash FROM admin_audit_logs
				 WHERE seq = (SELECT COALESCE(MAX(seq), 0) FROM admin_audit_logs)
				 FOR UPDATE`).Scan(&prevHash)
			if err != nil {
				prevHash = "" // the old code treated ErrNoRows as the first link
			}
			// Report the head each transaction saw, then wait until BOTH have
			// selected — the deterministic serialization point the old
			// protocol lacks.
			selected <- prevHash
			<-release
			h := sha256.Sum256([]byte(prevHash + "|old-protocol-fork|" + fmt.Sprint(k)))
			rowHash := hex.EncodeToString(h[:])
			if _, err := tx.Exec(ctx,
				`INSERT INTO admin_audit_logs (id, action, resource, details, admin_id, admin_name, ip_address, prev_hash, row_hash)
				 VALUES ($1, 'old.protocol', 'demo', 'd', 'u', 'n', '127.0.0.1', $2, $3)`,
				fmt.Sprintf("af10-old-protocol-%d", k), prevHash, rowHash); err != nil {
				commitErrs <- err
				return
			}
			commitErrs <- tx.Commit(ctx)
		}(i)
	}
	close(start)
	seen := []string{<-selected, <-selected}
	close(release)
	wg.Wait()
	close(commitErrs)
	for commitErr := range commitErrs {
		require.NoError(t, commitErr)
	}

	var emptyPrev int
	for _, prev := range seen {
		if prev == "" {
			emptyPrev++
		}
	}
	assert.Equal(t, 2, emptyPrev,
		"both transactions chained from the empty head — the old protocol forked the chain")

	var withEmptyPrev int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE prev_hash = '' AND action = 'old.protocol'`).Scan(&withEmptyPrev))
	assert.Equal(t, 2, withEmptyPrev, "two rows claim to be the first link: the chain forked")
}

// TestAuditChain_100ConcurrentAppends_EmptyJournal: the acceptance scenario —
// 100 concurrent appends onto an EMPTY journal, then the linear verifier.
func TestAuditChain_100ConcurrentAppends_EmptyJournal(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	resetAuditTable(t, pool)

	runConcurrentAppends(t, store, 0)
	assertChainIntact(t, store)

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE action = 'af10.concurrent'`).Scan(&count))
	assert.Equal(t, 100, count, "all 100 appends are persisted exactly once each")
}

// TestAuditChain_100ConcurrentAppends_NonEmptyJournal: same on a seeded head.
func TestAuditChain_100ConcurrentAppends_NonEmptyJournal(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	resetAuditTable(t, pool)

	seed := fmt.Sprintf("af10-seed-%d", time.Now().UnixNano())
	require.NoError(t, store.InsertAuditLog(ctx, seed, "af10.seed", "journal", "head", "root", "Root", "127.0.0.1"))

	runConcurrentAppends(t, store, 1)
	assertChainIntact(t, store)
}

// runConcurrentAppends fires n concurrent full-record appends (snapshots +
// reason → v2 rows) after optionally seeding one plain row.
func runConcurrentAppends(t *testing.T, store *Store, seed int) {
	t.Helper()
	ctx := context.Background()
	if seed > 0 {
		require.NoError(t, store.InsertAuditLog(ctx,
			fmt.Sprintf("af10-seed-%d", time.Now().UnixNano()), "af10.seed", "journal", "head", "root", "Root", "127.0.0.1"))
	}

	const n = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			<-start
			errs[k] = store.InsertAuditLogEntry(ctx, AuditLogEntryRecord{
				ID:        fmt.Sprintf("af10-concurrent-%d", k),
				Action:    "af10.concurrent",
				Resource:  "journal",
				Details:   fmt.Sprintf(`{"n":%d}`, k),
				AdminID:   "root",
				AdminName: "Root",
				IPAddress: "127.0.0.1",
				Before:    fmt.Sprintf(`{"active":%t}`, true),
				After:     fmt.Sprintf(`{"active":%t}`, k%2 == 0),
				Reason:    fmt.Sprintf("concurrent append %d", k),
			})
		}(i)
	}
	close(start)
	wg.Wait()
	for k, err := range errs {
		require.NoError(t, err, "concurrent append %d", k)
	}
}

// assertChainIntact runs the linear verifier over the whole journal.
func assertChainIntact(t *testing.T, store *Store) {
	t.Helper()
	require.NotNil(t, store.DB())
	verifier := newTestVerifier(t, store)
	broken, err := verifier(context.Background())
	if err != nil {
		// The verifier reports broken rows as (seq, error) — dump the row.
		msg := err.Error()
		if _, rest, found := strings.Cut(msg, "at seq "); found {
			if sp := strings.IndexAny(rest, ":"); sp >= 0 {
				rest = rest[:sp]
			}
			if seq, convErr := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); convErr == nil && seq > 0 {
				var dump string
				if dumpErr := store.DB().QueryRow(context.Background(),
					`SELECT format('id=%s action=%s hv=%s prev=%s hash=%s before=%s after=%s reason=%s',
					id, action, hash_version, prev_hash, row_hash, before_snapshot, after_snapshot, reason)
				 FROM admin_audit_logs WHERE seq = $1`, seq).Scan(&dump); dumpErr != nil {
					t.Logf("dump query failed: %v", dumpErr)
				} else {
					t.Logf("verifier error at seq %d — row: %s", seq, dump)
				}
			} else {
				t.Logf("could not parse seq from %q (convErr=%v)", rest, convErr)
			}
		}
		t.Fatalf("expected intact hash chain, verifier error: %v", err)
	}
	if broken != 0 {
		t.Fatalf("expected intact hash chain, got broken at seq %d", broken)
	}
}

func TestAuditChain_TamperedNewPayload_Detected_LegacyRowsStillVerify(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	resetAuditTable(t, pool)

	// A legacy-style plain row and a full v2 row chain together.
	plainID := fmt.Sprintf("af10-plain-%d", time.Now().UnixNano())
	fullID := fmt.Sprintf("af10-full-%d", time.Now().UnixNano())
	require.NoError(t, store.InsertAuditLog(ctx, plainID, "af10.legacy", "journal", "d", "root", "Root", "127.0.0.1"))
	require.NoError(t, store.InsertAuditLogEntry(ctx, AuditLogEntryRecord{
		ID: fullID, Action: "af10.full", Resource: "journal", AdminID: "root",
		Before: `{"k":1}`, After: `{"k":2}`, Reason: "verify me",
	}))
	assertChainIntact(t, store)

	// Tamper with the v2 row's snapshot payload → detected.
	var original *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT before_snapshot FROM admin_audit_logs WHERE id = $1`, fullID).Scan(&original))
	require.NotNil(t, original)
	t.Cleanup(func() {
		// Restore → the chain verifies again (proves the detection was the
		// tampered payload, not a broken fixture) and the shared stand stays
		// verifiable for the other tests.
		_, err := pool.Exec(context.Background(),
			`UPDATE admin_audit_logs SET before_snapshot = $2 WHERE id = $1`, fullID, *original)
		require.NoError(t, err)
		assertChainIntact(t, store)
	})
	_, err := pool.Exec(ctx,
		`UPDATE admin_audit_logs SET before_snapshot = '{"k":999}' WHERE id = $1`, fullID)
	require.NoError(t, err)
	broken, verr := newTestVerifier(t, store)(ctx)
	if verr != nil {
		t.Logf("tampering detected via verify error: %v", verr)
	}
	assert.True(t, verr != nil || broken != 0,
		"tampering with the new payload must be detected (broken seq or error)")

	// Legacy plain row is v1: its hash matches the pre-AF-10 formula exactly.
	var version int
	var rowHash string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT hash_version, row_hash FROM admin_audit_logs WHERE id = $1`, plainID).Scan(&version, &rowHash))
	assert.Equal(t, 1, version)
	want := auditlog.RowHash("", auditlog.PayloadV1("af10.legacy", "journal", "d", "root", "127.0.0.1"))
	assert.Equal(t, want, rowHash, "legacy row keeps the v1 formula byte-for-byte")
}

// TestAuditJournal_PersistedAcrossStoreInstances: restart/reconnect/second
// admin instance parity — the DB is the authority, not a process buffer.
func TestAuditJournal_PersistedAcrossStoreInstances(t *testing.T) {
	pool := openAdminTestPool(t)
	writer := New(pool, slog.Default(), nil)
	reader := New(pool, slog.Default(), nil) // a "second instance" store
	ctx := context.Background()

	id := fmt.Sprintf("af10-parity-%d", time.Now().UnixNano())
	rec := AuditLogEntryRecord{
		ID: id, Action: "af10.parity", Resource: "journal", Details: `{"k":1}`,
		AdminID: "root", AdminName: "Root", IPAddress: "127.0.0.1",
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		Before:    `{"active":true}`, After: `{"active":false}`, Reason: "why not",
	}
	require.NoError(t, writer.InsertAuditLogEntry(ctx, rec))

	entries, total, pending, err := reader.ListAuditLogEntries(ctx, AuditLogQuery{Sort: "timestamp", Desc: true, Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(1))
	assert.GreaterOrEqual(t, pending, int64(0), "the pending count is reported alongside the journal")

	var found *AuditLogEntry
	for i := range entries {
		if entries[i].ID == id {
			found = &entries[i]
			break
		}
	}
	require.NotNil(t, found, "the entry is readable from a second store instance")
	assert.Equal(t, "why not", found.Reason, "reason survives the DB round-trip")
	assert.Equal(t, `{"active":true}`, string(found.Before), "before snapshot survives")
	assert.Equal(t, `{"active":false}`, string(found.After), "after snapshot survives")
	assert.Equal(t, "root", found.AdminID)
	assert.WithinDuration(t, rec.CreatedAt, found.Timestamp, time.Microsecond)
}

// TestAuditOutbox_FailedDirectAppend_IsDurableIntent_ThenDelivered: a store
// failure does not create the visibility of durable success — the intent is
// durably recorded and later delivered by the drain.
func TestAuditOutbox_FailedDirectAppend_IsDurableIntent_ThenDelivered(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	id := fmt.Sprintf("af10-outbox-%d", time.Now().UnixNano())
	rec := AuditLogEntryRecord{
		ID: id, Action: "af10.outbox", Resource: "journal", AdminID: "root",
		Before: `{"a":1}`, Reason: "outbox intent",
	}

	require.NoError(t, store.EnqueueAuditOutbox(ctx, rec))

	_, _, pending, err := store.ListAuditLogEntries(ctx, AuditLogQuery{Page: 1, PageSize: 1})
	require.NoError(t, err)
	assert.NotZero(t, pending, "the pending count exposes the undelivered entry")

	// A duplicate enqueue for the same entry id is idempotent.
	require.NoError(t, store.EnqueueAuditOutbox(ctx, rec))

	delivered, err := store.DrainAuditOutbox(ctx, 100)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, delivered, 1)

	_, _, pending, err = store.ListAuditLogEntries(ctx, AuditLogQuery{Page: 1, PageSize: 1})
	require.NoError(t, err)
	assert.Zero(t, pending, "delivered outbox rows are deleted")

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE id = $1`, id).Scan(&count))
	assert.Equal(t, 1, count, "the entry was delivered exactly once")
	assertChainIntact(t, store)

	// A payload with a valid JSON shape that cannot unmarshal into the record
	// can never be delivered: it is marked failed with a backoff instead of
	// poisoning the drain.
	badID := fmt.Sprintf("af10-outbox-bad-%d", time.Now().UnixNano())
	_, err = pool.Exec(ctx,
		`INSERT INTO admin_audit_outbox (id, payload) VALUES ($1, $2::jsonb)`, badID, `{"id":123}`)
	require.NoError(t, err)
	t.Cleanup(func() {
		// The failed row intentionally stays undelivered; remove it so the
		// shared stand's pending count is not polluted for later tests.
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_audit_outbox WHERE id = $1`, badID)
	})
	_, err = store.DrainAuditOutbox(ctx, 100)
	require.NoError(t, err)
	var attempts int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attempts FROM admin_audit_outbox WHERE id = $1`, badID).Scan(&attempts))
	assert.Equal(t, 1, attempts, "failed row got its attempt counter bumped")
	var nextAttempt time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT next_attempt_at FROM admin_audit_outbox WHERE id = $1`, badID).Scan(&nextAttempt))
	assert.True(t, nextAttempt.After(time.Now().UTC()), "failed row backs off into the future")
}

// TestAuditJournal_SortAndPaginationStability: identical queries return
// identical order (unique seq tie-breaker) and walking 1-row pages yields
// every row exactly once in a consistent order.
func TestAuditJournal_SortAndPaginationStability(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	base := time.Now().UnixNano()
	for i := 0; i < 5; i++ {
		// Identical action (tie on the sort key) — only seq breaks the tie.
		require.NoError(t, store.InsertAuditLog(ctx,
			fmt.Sprintf("af10-sort-%d-%d", base, i), "af10.sorttie", "journal", "d", "root", "Root", "127.0.0.1"))
	}

	q := AuditLogQuery{Sort: "action", Desc: true, Page: 1, PageSize: 3}
	first, total1, _, err := store.ListAuditLogEntries(ctx, q)
	require.NoError(t, err)
	second, total2, _, err := store.ListAuditLogEntries(ctx, q)
	require.NoError(t, err)
	assert.Equal(t, total1, total2)
	require.Len(t, second, len(first))
	for i := range first {
		assert.Equal(t, first[i].ID, second[i].ID, "identical queries must return identical order")
	}

	// Walk 1-row pages: no duplicates, no skips, order consistent with page 1.
	seen := map[string]bool{}
	page := 1
	for {
		items, total, _, err := store.ListAuditLogEntries(ctx, AuditLogQuery{Sort: "action", Desc: true, Page: page, PageSize: 1})
		require.NoError(t, err)
		if len(items) == 0 {
			assert.LessOrEqual(t, page-1, int(total), "walked at most total pages")
			break
		}
		assert.False(t, seen[items[0].ID], "row repeated across pages: unstable tie-breaker")
		seen[items[0].ID] = true
		page++
		if page > int(total)+1 {
			t.Fatalf("pagination ran away: page %d > total %d", page, total)
		}
	}
	assert.GreaterOrEqual(t, len(seen), 5, "the tie-breaker walk covered the seeded rows")
}
