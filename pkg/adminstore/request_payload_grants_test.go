package adminstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

type payloadGrantFakeDB struct {
	mu      sync.Mutex
	grants  map[[32]byte]RequestPayloadGrant
	audited []string
	// auditDetails captures the details column of each audit INSERT (same
	// order as audited; column 4 of the append statement).
	auditDetails []string
	// consumeErr fails the consume UPDATE itself.
	consumeErr error
	// auditErr fails the durable audit INSERT (the T08 interruption seam:
	// the grant row has already committed when the audit write runs).
	auditErr error
	// requestLogs models the issuance target resolution (0031): how many
	// physical request_logs rows carry the correlation and the lowest row
	// key among them.
	requestLogCarriers int
	requestLogMinKey   int64
	// snapshots stack per open transaction so Rollback restores state (the
	// consume couples UPDATE + audit in one commit).
	snapshots []map[[32]byte]RequestPayloadGrant
}

// newPayloadGrantFakeDB returns the fake with its default physical target:
// exactly one carrier row under key 4242.
func newPayloadGrantFakeDB() *payloadGrantFakeDB {
	return &payloadGrantFakeDB{grants: make(map[[32]byte]RequestPayloadGrant), requestLogCarriers: 1, requestLogMinKey: 4242}
}

func (db *payloadGrantFakeDB) BeginAuditTx(context.Context) (auditTx, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	snapshot := make(map[[32]byte]RequestPayloadGrant, len(db.grants))
	for k, v := range db.grants {
		snapshot[k] = v
	}
	db.snapshots = append(db.snapshots, snapshot)
	return &payloadGrantFakeTx{db: db}, nil
}

func (db *payloadGrantFakeDB) Exec(_ context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	return db.exec(query, args...)
}

func (db *payloadGrantFakeDB) QueryRow(_ context.Context, query string, args ...interface{}) pgx.Row {
	return db.queryRow(query, args...)
}

func (db *payloadGrantFakeDB) Query(_ context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	if !strings.Contains(query, "FROM request_payload_grants") {
		return nil, errors.New("unexpected query")
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	rootID := args[0].(string)
	rows := &mockPGXRows{}
	for _, grant := range db.grants {
		if grant.RootID == rootID {
			rows.data = append(rows.data, []interface{}{grant.ID, grant.OrgID, grant.RequestID, grant.RootID, grant.RowKey, grant.ExpiresAt, grant.Scope})
		}
	}
	return rows, nil
}

// queryRow routes one-row queries by SQL shape to focused handlers; each
// handler owns its locking.
func (db *payloadGrantFakeDB) queryRow(query string, args ...interface{}) pgx.Row {
	switch {
	case strings.Contains(query, "SELECT count(*) FROM request_payload_grants"):
		return db.queryRowActiveGrantCount(args...)
	case strings.Contains(query, "FROM request_logs"):
		return db.queryRowRequestLogTarget()
	case strings.Contains(query, "SELECT request_row_key"):
		return db.queryRowPeekTarget(args...)
	case strings.Contains(query, "SELECT row_hash FROM admin_audit_logs"):
		return &mockPGXRow{err: pgx.ErrNoRows}
	case strings.Contains(query, "UPDATE request_payload_grants SET consumed_at"):
		return db.queryRowConsume(args...)
	case strings.Contains(query, "UPDATE request_payload_grants SET revoked_at"):
		return db.queryRowRevoke(args...)
	default:
		return &mockPGXRow{err: errors.New("unexpected query row")}
	}
}

// queryRowActiveGrantCount answers the per-root active-cap count with the
// same predicate as the durable store: revoked, consumed and expired grants
// never count.
func (db *payloadGrantFakeDB) queryRowActiveGrantCount(args ...interface{}) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	var count int
	rootID, now := args[0].(string), args[1].(time.Time)
	for _, grant := range db.grants {
		if grant.RootID == rootID && now.Before(grant.ExpiresAt) && !grantConsumed(grant) && !grantRevoked(grant) {
			count++
		}
	}
	return &mockPGXRow{data: [][]interface{}{{count}}}
}

// queryRowRequestLogTarget answers issuance target resolution (0031):
// carrier count + MIN(id).
func (db *payloadGrantFakeDB) queryRowRequestLogTarget() pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	return &mockPGXRow{data: [][]interface{}{{db.requestLogCarriers, db.requestLogMinKey}}}
}

// queryRowPeekTarget answers peek target resolution: the issuance-time
// bound row key, NULL for a legacy pre-binding grant.
func (db *payloadGrantFakeDB) queryRowPeekTarget(args ...interface{}) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	grant, ok := db.grants[hashArg(args[0])]
	orgID, requestID, rootID := args[1].(string), args[2].(string), args[3].(string)
	now := args[4].(time.Time)
	if !ok || grant.OrgID != orgID || grant.RequestID != requestID || grant.RootID != rootID || !now.Before(grant.ExpiresAt) || grantConsumed(grant) || grantRevoked(grant) {
		return &mockPGXRow{err: pgx.ErrNoRows}
	}
	if grant.RowKey <= 0 {
		return &mockPGXRow{data: [][]interface{}{{nil}}}
	}
	return &mockPGXRow{data: [][]interface{}{{grant.RowKey}}}
}

// queryRowConsume answers the keyed consume UPDATE — RETURNING the grant
// row on success, no rows when any predicate denies.
func (db *payloadGrantFakeDB) queryRowConsume(args ...interface{}) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.consumeErr != nil {
		return &mockPGXRow{err: db.consumeErr}
	}
	hash := hashArg(args[0])
	grant, ok := db.grants[hash]
	orgID, requestID, rootID := args[1].(string), args[2].(string), args[3].(string)
	now, scope, rowKey := args[4].(time.Time), args[5].(string), args[6].(int64)
	if rowKey <= 0 || grant.RowKey != rowKey {
		return &mockPGXRow{err: pgx.ErrNoRows}
	}
	if !ok || grant.OrgID != orgID || grant.RequestID != requestID || grant.RootID != rootID || grant.Scope != scope || !now.Before(grant.ExpiresAt) || grant.Scope == "" || grantConsumed(grant) {
		return &mockPGXRow{err: pgx.ErrNoRows}
	}
	grant.Scope = "consumed:" + grant.Scope
	db.grants[hash] = grant
	return &mockPGXRow{data: [][]interface{}{{grant.ID, grant.OrgID, grant.RequestID, grant.RootID, grant.RowKey, grant.ExpiresAt, strings.TrimPrefix(grant.Scope, "consumed:")}}}
}

// queryRowRevoke answers the revoke UPDATE (RETURNING the grant row).
func (db *payloadGrantFakeDB) queryRowRevoke(args ...interface{}) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	hash := hashArg(args[0])
	grant, ok := db.grants[hash]
	rootID := args[1].(string)
	if !ok || grant.RootID != rootID || grantConsumed(grant) {
		return &mockPGXRow{err: pgx.ErrNoRows}
	}
	grant.Scope = "revoked:" + grant.Scope
	db.grants[hash] = grant
	return &mockPGXRow{data: [][]interface{}{{grant.ID, grant.OrgID, grant.RequestID, grant.RootID, grant.RowKey, grant.ExpiresAt, strings.TrimPrefix(grant.Scope, "revoked:")}}}
}

func (db *payloadGrantFakeDB) exec(query string, args ...interface{}) (pgconn.CommandTag, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch {
	case strings.Contains(query, "INSERT INTO request_payload_grants"):
		id, hash, rootID := args[0].(string), hashArg(args[1]), args[2].(string)
		orgID, requestID, rowKey := args[3].(string), args[4].(string), args[5].(int64)
		scope, expiresAt := args[6].(string), args[7].(time.Time)
		db.grants[hash] = RequestPayloadGrant{ID: id, OrgID: orgID, RequestID: requestID, RootID: rootID, RowKey: rowKey, Scope: scope, ExpiresAt: expiresAt}
	case strings.Contains(query, "INSERT INTO admin_audit_logs"):
		if db.auditErr != nil {
			return pgconn.CommandTag{}, db.auditErr
		}
		db.audited = append(db.audited, args[1].(string))
		if len(args) > 3 {
			db.auditDetails = append(db.auditDetails, args[3].(string))
		}
	case strings.Contains(query, "UPDATE request_payload_grants SET revoked_at"):
		id := args[0].(string)
		for hash, grant := range db.grants {
			if grant.ID == id && !grantRevoked(grant) {
				grant.Scope = "revoked:" + grant.Scope
				db.grants[hash] = grant
			}
		}
	}
	return pgconn.NewCommandTag("OK"), nil
}

// payloadGrantFakeTx models transactional commit/rollback over the fake map:
// mutations land immediately but Rollback restores the BEGIN snapshot.
type payloadGrantFakeTx struct {
	db   *payloadGrantFakeDB
	done bool
}

func (tx *payloadGrantFakeTx) QueryRow(_ context.Context, query string, args ...interface{}) pgx.Row {
	return tx.db.queryRow(query, args...)
}
func (tx *payloadGrantFakeTx) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	return tx.db.Query(ctx, query, args...)
}
func (tx *payloadGrantFakeTx) Exec(_ context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	return tx.db.exec(query, args...)
}
func (tx *payloadGrantFakeTx) Commit(context.Context) error {
	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()
	tx.done = true
	if n := len(tx.db.snapshots); n > 0 {
		tx.db.snapshots = tx.db.snapshots[:n-1]
	}
	return nil
}
func (tx *payloadGrantFakeTx) Rollback(context.Context) error {
	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()
	if tx.done {
		return nil
	}
	tx.done = true
	if n := len(tx.db.snapshots); n > 0 {
		tx.db.grants = tx.db.snapshots[n-1]
		tx.db.snapshots = tx.db.snapshots[:n-1]
	}
	return nil
}

func hashArg(value interface{}) [32]byte {
	return [sha256.Size]byte(value.([]byte))
}

func grantConsumed(grant RequestPayloadGrant) bool {
	return strings.HasPrefix(grant.Scope, "consumed:")
}

func grantRevoked(grant RequestPayloadGrant) bool {
	return strings.HasPrefix(grant.Scope, "revoked:")
}

func TestRequestPayloadGrant_FailsClosedWithoutDurableStore(t *testing.T) {
	store := &Store{}
	if _, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, time.Now()); err != ErrRequestPayloadGrantUnavailable {
		t.Fatalf("CreateRequestPayloadGrant() error = %v, want unavailable", err)
	}
	if store.ConsumeRequestPayloadGrant("token", "org-a", "request-a", "root-a", time.Now()) {
		t.Fatal("grant accepted without durable storage")
	}
	if err := store.RevokeRequestPayloadGrant("token", "root-a"); err != ErrRequestPayloadGrantUnavailable {
		t.Fatalf("RevokeRequestPayloadGrant() error = %v, want unavailable", err)
	}
	if _, err := store.ListRequestPayloadGrants(t.Context(), "root-a"); err != ErrRequestPayloadGrantUnavailable {
		t.Fatalf("ListRequestPayloadGrants() error = %v, want unavailable", err)
	}
}

func TestRequestPayloadGrant_RejectsUnboundedTTL(t *testing.T) {
	_, err := (&Store{}).CreateRequestPayloadGrant("org-a", "request-a", "root-a", MaxRequestPayloadGrantTTL+time.Second, time.Now())
	if !errors.Is(err, ErrInvalidRequestPayloadGrant) {
		t.Fatalf("CreateRequestPayloadGrant() error = %v, want %v", err, ErrInvalidRequestPayloadGrant)
	}
}

// TestRequestPayloadGrant_DurableIssueConsumeRevokeAndList walks the durable
// grant lifecycle over one fake: issue (bound to the seeded carrier row),
// keyed redemption with denials for cross-org/wrong-row/replay, metadata
// listing without bearer leakage, and revocation semantics for consumed and
// active grants. The subtests run in order and share the lifecycle state on
// purpose.
func TestRequestPayloadGrant_DurableIssueConsumeRevokeAndList(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := newPayloadGrantFakeDB()
	store := newForTest(db, newTestLogger(), nil)
	grant, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now)
	require.NoError(t, err)
	t.Run("issue binds the carrier row and journals", func(t *testing.T) {
		require.Equal(t, int64(4242), grant.RowKey)
		require.Equal(t, []string{"request_payload.grant_issued"}, db.audited)
	})
	t.Run("consume honors binding, party and single use", func(t *testing.T) {
		consume := func(org string, rowKey int64) error {
			_, err := store.ConsumeRequestPayloadGrantScope(grant.Token, org, "request-a", rowKey, "root-a", RequestPayloadScopeRead, now)
			return err
		}
		require.Error(t, consume("org-b", 4242))
		require.Error(t, consume("org-a", 4243))
		require.NoError(t, consume("org-a", 4242))
		require.Error(t, consume("org-a", 4242))
	})
	t.Run("list exposes metadata without tokens", func(t *testing.T) {
		listed, err := store.ListRequestPayloadGrants(t.Context(), "root-a")
		require.NoError(t, err)
		require.Len(t, listed, 1)
		require.Empty(t, listed[0].Token)
	})
	t.Run("revocation", func(t *testing.T) {
		require.Error(t, store.RevokeRequestPayloadGrant(grant.Token, "root-other"))
		require.Error(t, store.RevokeRequestPayloadGrant(grant.Token, "root-a"))
		require.Equal(t, []string{"request_payload.grant_issued", "request_payload.grant_used"}, db.audited)
		revokable, err := store.CreateRequestPayloadGrant("org-a", "request-b", "root-a", time.Minute, now)
		require.NoError(t, err)
		require.NoError(t, store.RevokeRequestPayloadGrant(revokable.Token, "root-a"))
		require.False(t, store.ConsumeRequestPayloadGrant(revokable.Token, "org-a", "request-b", "root-a", now))
		require.Equal(t, "request_payload.grant_revoked", db.audited[len(db.audited)-1])
	})
}

func TestRequestPayloadGrant_DatabaseConsumeFailureFailsClosed(t *testing.T) {
	db := newPayloadGrantFakeDB()
	db.consumeErr = errors.New("database connection lost")
	store := newForTest(db, newTestLogger(), nil)
	if store.ConsumeRequestPayloadGrant("unavailable-token", "org-a", "request-a", "root-a", time.Now().UTC()) {
		t.Fatal("payload grant accepted while durable database operation failed")
	}
}

// TestRequestPayloadGrant_IssuanceBindsExactlyOnePhysicalRow pins the 0031
// issuance contract: a grant is minted only when exactly one physical
// request_logs row carries the correlation in the org — no carrier is a 404
// (missing target), several carriers are a 409 (ambiguous target) — and the
// minted grant carries that row's key, which the consume then requires.
func TestRequestPayloadGrant_IssuanceBindsExactlyOnePhysicalRow(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

	db := newPayloadGrantFakeDB()
	db.requestLogCarriers = 0
	store := newForTest(db, newTestLogger(), nil)
	if _, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now); !errors.Is(err, ErrRequestPayloadGrantTargetMissing) {
		t.Fatalf("issuance without a carrier row = %v, want %v", err, ErrRequestPayloadGrantTargetMissing)
	}

	db.requestLogCarriers = 2
	if _, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now); !errors.Is(err, ErrRequestPayloadGrantTargetAmbiguous) {
		t.Fatalf("issuance over an ambiguous correlation = %v, want %v", err, ErrRequestPayloadGrantTargetAmbiguous)
	}

	db.requestLogCarriers, db.requestLogMinKey = 1, 777
	grant, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if grant.RowKey != 777 {
		t.Fatalf("grant bound to row %d, want the sole carrier 777", grant.RowKey)
	}
	if _, err := store.ConsumeRequestPayloadGrantScope(grant.Token, "org-a", "request-a", 778, "root-a", RequestPayloadScopeRead, now); err == nil {
		t.Fatal("consume addressed a row the grant is not bound to")
	}
	if _, err := store.ConsumeRequestPayloadGrantScope(grant.Token, "org-a", "request-a", 777, "root-a", RequestPayloadScopeRead, now); err != nil {
		t.Fatalf("consume of the bound row failed: %v", err)
	}
}

// TestRequestPayloadGrant_LifecycleAuditDetailsDecode pins the store-side
// journal contract for hostile request ids: every issue/consume lifecycle
// details blob is valid JSON (encoding/json, never %q escaping, which emits
// invalid-JSON \x.. escapes for control bytes), round-trips the bound row
// key and the request id (invalid UTF-8 marshals as the U+FFFD replacement
// rune), and never contains the bearer token. The handler decision journal
// is a different record, covered by the hostile-ID detail handler test.
func TestRequestPayloadGrant_LifecycleAuditDetailsDecode(t *testing.T) {
	db := newPayloadGrantFakeDB()
	store := &Store{db: db}

	hostile := "req\x01\x1b\xff"
	grant, err := store.CreateRequestPayloadGrantScope("org-1", hostile, "root-1", RequestPayloadScopeRead, time.Minute, time.Now().UTC())
	require.NoError(t, err)
	require.Equal(t, int64(4242), grant.RowKey)
	_, err = store.ConsumeRequestPayloadGrantScope(grant.Token, "org-1", hostile, grant.RowKey, "root-1", RequestPayloadScopeRead, time.Now().UTC())
	require.NoError(t, err)
	require.Equal(t, []string{"request_payload.grant_issued", "request_payload.grant_used"}, db.audited)
	require.Len(t, db.auditDetails, len(db.audited))
	for _, raw := range db.auditDetails {
		var detail requestPayloadGrantAuditDetail
		require.NoError(t, json.Unmarshal([]byte(raw), &detail))
		require.Equal(t, "req\x01\x1b\ufffd", detail.RequestID)
		require.Equal(t, int64(4242), detail.RowKey)
		require.Equal(t, grant.ID, detail.GrantID)
		require.NotEmpty(t, detail.GrantID)
		require.Equal(t, "org-1", detail.OrgID)
		require.Equal(t, RequestPayloadScopeRead, detail.Scope)
		_, err := time.Parse(time.RFC3339Nano, detail.ExpiresAt)
		require.NoError(t, err)
		require.NotContains(t, raw, grant.Token)
	}
}

// TestRequestPayloadGrant_ConsumeAuditFailureRollsBackAndRetrySucceeds pins
// the single-commit coupling: the consume UPDATE and its mandatory use-audit
// row commit together, so a journal outage denies the redemption WITHOUT
// destroying the token — retrying the same token once the journal recovers
// succeeds, and exactly one use-audit row exists afterwards.
func TestRequestPayloadGrant_ConsumeAuditFailureRollsBackAndRetrySucceeds(t *testing.T) {
	now := time.Date(2026, 11, 21, 11, 0, 0, 0, time.UTC)
	db := newPayloadGrantFakeDB()
	store := newForTest(db, newTestLogger(), nil)
	grant, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}

	db.auditErr = errors.New("audit journal unavailable")
	if _, err := store.ConsumeRequestPayloadGrantScope(grant.Token, "org-a", "request-a", 4242, "root-a", RequestPayloadScopeRead, now.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "audit payload grant use") {
		t.Fatalf("consume with a failed mandatory audit = %v, want audit failure", err)
	}
	if store.ConsumeRequestPayloadGrant(grant.Token, "org-a", "request-a", "root-a", now.Add(time.Second)) {
		t.Fatal("token must stay redeemable-or-denied, never silently consumed, while its audit fails")
	}

	db.auditErr = nil
	consumed, err := store.ConsumeRequestPayloadGrantScope(grant.Token, "org-a", "request-a", 4242, "root-a", RequestPayloadScopeRead, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("retry on the same token after audit recovery failed: %v", err)
	}
	if consumed.RowKey != 4242 {
		t.Fatalf("consumed grant reports row %d, want 4242", consumed.RowKey)
	}
	if _, err := store.ConsumeRequestPayloadGrantScope(grant.Token, "org-a", "request-a", 4242, "root-a", RequestPayloadScopeRead, now.Add(3*time.Second)); err == nil {
		t.Fatal("token redeemed twice after retry")
	}
	used := 0
	for _, action := range db.audited {
		if action == "request_payload.grant_used" {
			used++
		}
	}
	if used != 1 {
		t.Fatalf("grant_used audit rows = %d, want exactly 1 (the rolled-back attempt must leave none)", used)
	}
}

// TestRequestPayloadGrant_LegacyUnboundGrantIsPermanentlyUnusable pins the
// conservative legacy treatment: a grant issued before the 0031 binding has
// NULL request_row_key, its original row is not provable, and it can never be
// redeemed against whatever row the correlation currently names — not via
// peek resolution and not via a direct keyed consume.
func TestRequestPayloadGrant_LegacyUnboundGrantIsPermanentlyUnusable(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	db := newPayloadGrantFakeDB()
	store := newForTest(db, newTestLogger(), nil)
	hash := sha256.Sum256([]byte("legacy-token"))
	db.grants[hash] = RequestPayloadGrant{ID: "legacy-grant", OrgID: "org-a", RequestID: "request-a", RootID: "root-a", Scope: RequestPayloadScopeRead, ExpiresAt: now.Add(time.Minute)}

	if _, err := store.PeekRequestPayloadGrantTarget(context.Background(), "legacy-token", "org-a", "request-a", "root-a", now); !errors.Is(err, ErrInvalidRequestPayloadGrant) {
		t.Fatalf("legacy unbound grant peek = %v, want the generic invalid error", err)
	}
	if _, err := store.ConsumeRequestPayloadGrantScope("legacy-token", "org-a", "request-a", 4242, "root-a", RequestPayloadScopeRead, now); err == nil {
		t.Fatal("legacy unbound grant was redeemed by key")
	}
	if store.ConsumeRequestPayloadGrant("legacy-token", "org-a", "request-a", "root-a", now) {
		t.Fatal("legacy unbound grant was redeemed")
	}
	db.mu.Lock()
	grant := db.grants[hash]
	db.mu.Unlock()
	if grantConsumed(grant) {
		t.Fatal("denied legacy grant must not be burned")
	}
	// Control: changing only the binding makes this same seeded row reachable.
	grant.RowKey = 4242
	db.grants[hash] = grant
	row, err := store.PeekRequestPayloadGrantTarget(t.Context(), "legacy-token", "org-a", "request-a", "root-a", now)
	require.NoError(t, err)
	require.Equal(t, int64(4242), row)
	require.True(t, store.ConsumeRequestPayloadGrant("legacy-token", "org-a", "request-a", "root-a", now))

}

func TestRequestPayloadDenyOwnHistoryPolicy(t *testing.T) {
	ctx := WithRequestPayloadDenyOwnHistory(t.Context(), true)
	if !RequestPayloadDenyOwnHistoryFromContext(ctx) {
		t.Fatal("explicit own-history deny policy was not carried to payload authorization")
	}
	decision := ResolveRequestPayloadDecision(RequestPayloadDenyOwnHistoryFromContext(ctx), true, true)
	if decision != RequestPayloadDenied {
		t.Fatalf("own-history deny lost to grant: got %q", decision)
	}
}

// TestRequestPayloadGrantAuditInterruptionCompensatesAndRetryConverges pins
// the T08 interruption seam: grant issuance commits the grant row first and
// writes the mandatory audit second. When the audit write fails after the
// commit, the compensating revoke must retire the grant (an unaudited grant
// must never be redeemable), and the retry must converge to exactly one
// usable grant — no double grant, no cap consumed by the compensated row.
func TestRequestPayloadGrantAuditInterruptionCompensatesAndRetryConverges(t *testing.T) {
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	db := newPayloadGrantFakeDB()
	store := newForTest(db, newTestLogger(), nil)

	// Attempt 1: the audit write fails after the grant row committed.
	db.auditErr = errors.New("audit journal unavailable")
	interrupted, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now)
	require.ErrorContains(t, err, "audit payload grant")
	require.Empty(t, interrupted.Token)
	require.Empty(t, db.audited)
	require.Len(t, db.grants, 1)
	var retiredHash [32]byte
	var retired RequestPayloadGrant
	for retiredHash, retired = range db.grants {
		require.True(t, grantRevoked(retired), "the committed row must be revoked after the journal write fails")
	}
	t.Run("retry converges to one usable grant", func(t *testing.T) {
		db.auditErr = nil
		retried, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now.Add(time.Second))
		require.NoError(t, err)
		require.NotEqual(t, retired.ID, retried.ID)
		require.NotEmpty(t, retried.Token)
		require.Len(t, db.grants, 2)
		require.True(t, grantRevoked(db.grants[retiredHash]))
		require.True(t, store.ConsumeRequestPayloadGrant(retried.Token, "org-a", "request-a", "root-a", now.Add(2*time.Second)))
		require.False(t, store.ConsumeRequestPayloadGrant(retried.Token, "org-a", "request-a", "root-a", now.Add(2*time.Second)))
		require.Equal(t, []string{"request_payload.grant_issued", "request_payload.grant_used"}, db.audited)
	})

	t.Run("compensated row does not consume the active cap", func(t *testing.T) {
		// The retried grant was consumed above, so the quota is free again:
		// root-a can still fill the full quota and the next grant over it
		// is rejected.
		for i := 0; i < MaxActiveRequestGrants; i++ {
			if _, err := store.CreateRequestPayloadGrant("org-a", fmt.Sprintf("request-cap-%d", i), "root-a", time.Minute, now.Add(2*time.Second)); err != nil {
				t.Fatalf("active grant %d rejected: %v", i+1, err)
			}
		}
		if _, err := store.CreateRequestPayloadGrant("org-a", "request-over-cap", "root-a", time.Minute, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidRequestPayloadGrant) {
			t.Fatalf("grant beyond the active cap = %v, want %v", err, ErrInvalidRequestPayloadGrant)
		}
	})
}

// TestRequestPayloadGrantIssueBoundarySemantics pins the issuance input
// edges: TTL is bounded (0, negative and >15m rejected; the exact 15m bound
// passes validation), scope is an exact-match enum, and identity fields are
// mandatory. A nil-durable-store error after validation proves the input
// passed the boundary checks.
func TestRequestPayloadGrantIssueBoundarySemantics(t *testing.T) {
	now := time.Now()
	store := &Store{}

	cases := []struct {
		name    string
		org     string
		request string
		root    string
		ttl     time.Duration
		scope   string
		wantErr error
	}{
		{"exact max ttl passes validation", "org-a", "request-a", "root-a", MaxRequestPayloadGrantTTL, RequestPayloadScopeRead, ErrRequestPayloadGrantUnavailable},
		{"just under max ttl passes validation", "org-a", "request-a", "root-a", MaxRequestPayloadGrantTTL - time.Millisecond, RequestPayloadScopeOriginals, ErrRequestPayloadGrantUnavailable},
		{"ttl one nanosecond over the bound is invalid", "org-a", "request-a", "root-a", MaxRequestPayloadGrantTTL + time.Nanosecond, RequestPayloadScopeRead, ErrInvalidRequestPayloadGrant},
		{"zero ttl is invalid", "org-a", "request-a", "root-a", 0, RequestPayloadScopeRead, ErrInvalidRequestPayloadGrant},
		{"negative ttl is invalid", "org-a", "request-a", "root-a", -time.Second, RequestPayloadScopeRead, ErrInvalidRequestPayloadGrant},
		{"originals scope is exact", "org-a", "request-a", "root-a", time.Minute, RequestPayloadScopeOriginals, ErrRequestPayloadGrantUnavailable},
		{"unknown scope is invalid", "org-a", "request-a", "root-a", time.Minute, "payload.write", ErrInvalidRequestPayloadGrant},
		{"scope is case sensitive", "org-a", "request-a", "root-a", time.Minute, "PAYLOAD.READ", ErrInvalidRequestPayloadGrant},
		{"scope with trailing space is invalid", "org-a", "request-a", "root-a", time.Minute, "payload.read ", ErrInvalidRequestPayloadGrant},
		{"empty org is invalid", "", "request-a", "root-a", time.Minute, RequestPayloadScopeRead, ErrInvalidRequestPayloadGrant},
		{"empty request is invalid", "org-a", "", "root-a", time.Minute, RequestPayloadScopeRead, ErrInvalidRequestPayloadGrant},
		{"empty root is invalid", "org-a", "request-a", "", time.Minute, RequestPayloadScopeRead, ErrInvalidRequestPayloadGrant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.CreateRequestPayloadGrantScope(tc.org, tc.request, tc.root, tc.scope, tc.ttl, now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CreateRequestPayloadGrantScope() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
