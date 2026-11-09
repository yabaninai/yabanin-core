package adminstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

type payloadGrantFakeDB struct {
	mu         sync.Mutex
	grants     map[[32]byte]RequestPayloadGrant
	audited    []string
	consumeErr error
	// auditErr fails the durable audit INSERT (the T08 interruption seam:
	// the grant row has already committed when the audit write runs).
	auditErr error
}

func (db *payloadGrantFakeDB) BeginAuditTx(context.Context) (auditTx, error) {
	return payloadGrantFakeTx{db: db}, nil
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
			rows.data = append(rows.data, []interface{}{grant.ID, grant.OrgID, grant.RequestID, grant.RootID, grant.ExpiresAt, grant.Scope})
		}
	}
	return rows, nil
}

func (db *payloadGrantFakeDB) queryRow(query string, args ...interface{}) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch {
	case strings.Contains(query, "SELECT count(*) FROM request_payload_grants"):
		var count int
		rootID, now := args[0].(string), args[1].(time.Time)
		for _, grant := range db.grants {
			// Same predicate as the durable store: revoked, consumed and
			// expired grants never count toward the per-root active cap.
			if grant.RootID == rootID && now.Before(grant.ExpiresAt) && !grantConsumed(grant) && !grantRevoked(grant) {
				count++
			}
		}
		return &mockPGXRow{data: [][]interface{}{{count}}}
	case strings.Contains(query, "SELECT row_hash FROM admin_audit_logs"):
		return &mockPGXRow{err: pgx.ErrNoRows}
	case strings.Contains(query, "UPDATE request_payload_grants SET consumed_at"):
		if db.consumeErr != nil {
			return &mockPGXRow{err: db.consumeErr}
		}
		hash := hashArg(args[0])
		grant, ok := db.grants[hash]
		orgID, requestID, rootID := args[1].(string), args[2].(string), args[3].(string)
		now, scope := args[4].(time.Time), args[5].(string)
		if !ok || grant.OrgID != orgID || grant.RequestID != requestID || grant.RootID != rootID || grant.Scope != scope || !now.Before(grant.ExpiresAt) || grant.Scope == "" || grantConsumed(grant) {
			return &mockPGXRow{err: pgx.ErrNoRows}
		}
		grant.Scope = "consumed:" + grant.Scope
		db.grants[hash] = grant
		return &mockPGXRow{data: [][]interface{}{{grant.ID, grant.OrgID, grant.RequestID, grant.RootID, grant.ExpiresAt, strings.TrimPrefix(grant.Scope, "consumed:")}}}
	case strings.Contains(query, "UPDATE request_payload_grants SET revoked_at"):
		hash := hashArg(args[0])
		grant, ok := db.grants[hash]
		rootID := args[1].(string)
		if !ok || grant.RootID != rootID || grantConsumed(grant) {
			return &mockPGXRow{err: pgx.ErrNoRows}
		}
		grant.Scope = "revoked:" + grant.Scope
		db.grants[hash] = grant
		return &mockPGXRow{data: [][]interface{}{{grant.ID, grant.OrgID, grant.RequestID, grant.RootID, grant.ExpiresAt, strings.TrimPrefix(grant.Scope, "revoked:")}}}
	default:
		return &mockPGXRow{err: errors.New("unexpected query row")}
	}
}

func (db *payloadGrantFakeDB) exec(query string, args ...interface{}) (pgconn.CommandTag, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch {
	case strings.Contains(query, "INSERT INTO request_payload_grants"):
		id, hash, rootID := args[0].(string), hashArg(args[1]), args[2].(string)
		orgID, requestID, scope := args[3].(string), args[4].(string), args[5].(string)
		expiresAt := args[6].(time.Time)
		db.grants[hash] = RequestPayloadGrant{ID: id, OrgID: orgID, RequestID: requestID, RootID: rootID, Scope: scope, ExpiresAt: expiresAt}
	case strings.Contains(query, "INSERT INTO admin_audit_logs"):
		if db.auditErr != nil {
			return pgconn.CommandTag{}, db.auditErr
		}
		db.audited = append(db.audited, args[1].(string))
	case strings.Contains(query, "UPDATE request_payload_grants SET revoked_at"):
		id, now := args[0].(string), args[1].(time.Time)
		for hash, grant := range db.grants {
			if grant.ID == id {
				grant.ExpiresAt = minTime(grant.ExpiresAt, now)
				db.grants[hash] = grant
			}
		}
	}
	return pgconn.NewCommandTag("OK"), nil
}

type payloadGrantFakeTx struct{ db *payloadGrantFakeDB }

func (tx payloadGrantFakeTx) QueryRow(_ context.Context, query string, args ...interface{}) pgx.Row {
	return tx.db.queryRow(query, args...)
}
func (tx payloadGrantFakeTx) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	return tx.db.Query(ctx, query, args...)
}
func (tx payloadGrantFakeTx) Exec(_ context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	return tx.db.exec(query, args...)
}
func (payloadGrantFakeTx) Commit(context.Context) error   { return nil }
func (payloadGrantFakeTx) Rollback(context.Context) error { return nil }

func hashArg(value interface{}) [32]byte {
	return sha256.Sum256(value.([]byte))
}

func grantConsumed(grant RequestPayloadGrant) bool {
	return strings.HasPrefix(grant.Scope, "consumed:")
}

func grantRevoked(grant RequestPayloadGrant) bool {
	return strings.HasPrefix(grant.Scope, "revoked:")
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
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
	if err != ErrInvalidRequestPayloadGrant {
		t.Fatalf("CreateRequestPayloadGrant() error = %v, want %v", err, ErrInvalidRequestPayloadGrant)
	}
}

func TestRequestPayloadGrant_DurableIssueConsumeRevokeAndList(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	db := &payloadGrantFakeDB{grants: make(map[[32]byte]RequestPayloadGrant)}
	store := newForTest(db, newTestLogger(), nil)
	grant, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.audited) != 1 || db.audited[0] != "request_payload.grant_issued" {
		t.Fatalf("issue must be audited before returning token; actions=%v", db.audited)
	}
	if err := store.ConsumeRequestPayloadGrantScope(grant.Token, "org-b", "request-a", "root-a", RequestPayloadScopeRead, now); err == nil {
		t.Fatal("cross-organization grant redemption succeeded")
	}
	if err := store.ConsumeRequestPayloadGrantScope(grant.Token, "org-a", "request-a", "root-a", RequestPayloadScopeRead, now); err != nil {
		t.Fatalf("valid grant consumption failed: %v", err)
	}
	if err := store.ConsumeRequestPayloadGrantScope(grant.Token, "org-a", "request-a", "root-a", RequestPayloadScopeRead, now); err == nil {
		t.Fatal("consumed grant was reusable")
	}
	listed, err := store.ListRequestPayloadGrants(context.Background(), "root-a")
	if err != nil || len(listed) != 1 || listed[0].Token != "" {
		t.Fatalf("metadata list leaked/missed grant: grants=%+v err=%v", listed, err)
	}
	if err := store.RevokeRequestPayloadGrant(grant.Token, "root-other"); err == nil {
		t.Fatal("another root revoked the grant")
	}
	if err := store.RevokeRequestPayloadGrant(grant.Token, "root-a"); err == nil {
		t.Fatal("consumed grant was revocable")
	}
	if len(db.audited) != 2 || db.audited[1] != "request_payload.grant_used" {
		t.Fatalf("consume audit missing or unexpected: %v", db.audited)
	}

	revokable, err := store.CreateRequestPayloadGrant("org-a", "request-b", "root-a", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeRequestPayloadGrant(revokable.Token, "root-a"); err != nil {
		t.Fatalf("active grant revocation failed: %v", err)
	}
	if store.ConsumeRequestPayloadGrant(revokable.Token, "org-a", "request-b", "root-a", now) {
		t.Fatal("revoked grant was consumable")
	}
	if db.audited[len(db.audited)-1] != "request_payload.grant_revoked" {
		t.Fatalf("revoke audit missing: %v", db.audited)
	}
}

func TestRequestPayloadGrant_DatabaseConsumeFailureFailsClosed(t *testing.T) {
	db := &payloadGrantFakeDB{
		grants:     make(map[[32]byte]RequestPayloadGrant),
		consumeErr: errors.New("database connection lost"),
	}
	store := newForTest(db, newTestLogger(), nil)
	if store.ConsumeRequestPayloadGrant("unavailable-token", "org-a", "request-a", "root-a", time.Now().UTC()) {
		t.Fatal("payload grant accepted while durable database operation failed")
	}
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
	db := &payloadGrantFakeDB{grants: make(map[[32]byte]RequestPayloadGrant)}
	store := newForTest(db, newTestLogger(), nil)

	// Attempt 1: the audit write fails after the grant row committed.
	db.auditErr = errors.New("audit journal unavailable")
	interrupted, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now)
	if err == nil {
		t.Fatal("issuance succeeded without its mandatory audit write")
	}
	if !strings.Contains(err.Error(), "audit payload grant") {
		t.Fatalf("audit failure not surfaced: %v", err)
	}
	db.mu.Lock()
	if len(db.audited) != 0 {
		t.Fatalf("failed issuance left audit rows: %v", db.audited)
	}
	db.mu.Unlock()

	// The compensating revoke retired the unaudited grant: not consumable.
	if store.ConsumeRequestPayloadGrant(interrupted.Token, "org-a", "request-a", "root-a", now.Add(time.Second)) {
		t.Fatal("unaudited (compensated) grant was redeemable")
	}

	// Attempt 2 (retry after the journal recovers): grants cleanly.
	db.auditErr = nil
	retried, err := store.CreateRequestPayloadGrant("org-a", "request-a", "root-a", time.Minute, now.Add(time.Second))
	if err != nil {
		t.Fatalf("retry after audit recovery failed: %v", err)
	}
	if retried.ID == interrupted.ID || retried.Token == interrupted.Token {
		t.Fatal("retry must mint a fresh grant, not resurrect the compensated row")
	}

	// Convergence: exactly one usable grant. The interrupted token stays
	// dead (no double grant) and the retried token redeems once.
	if store.ConsumeRequestPayloadGrant(interrupted.Token, "org-a", "request-a", "root-a", now.Add(2*time.Second)) {
		t.Fatal("compensated grant resurrected by the retry")
	}
	if !store.ConsumeRequestPayloadGrant(retried.Token, "org-a", "request-a", "root-a", now.Add(2*time.Second)) {
		t.Fatal("retried grant must redeem cleanly")
	}
	if store.ConsumeRequestPayloadGrant(retried.Token, "org-a", "request-a", "root-a", now.Add(2*time.Second)) {
		t.Fatal("retried grant redeemed twice")
	}
	db.mu.Lock()
	issued := 0
	for _, action := range db.audited {
		if action == "request_payload.grant_issued" {
			issued++
		}
	}
	db.mu.Unlock()
	if issued != 1 {
		t.Fatalf("grant_issued audit rows = %d, want exactly 1", issued)
	}

	// The compensated row must not consume the per-root active cap: root-a
	// can still fill the full quota and the next grant over it is rejected.
	// (The retried grant was consumed above, so the quota is free again.)
	for i := 0; i < MaxActiveRequestGrants; i++ {
		if _, err := store.CreateRequestPayloadGrant("org-a", fmt.Sprintf("request-cap-%d", i), "root-a", time.Minute, now.Add(2*time.Second)); err != nil {
			t.Fatalf("active grant %d rejected: %v", i+1, err)
		}
	}
	if _, err := store.CreateRequestPayloadGrant("org-a", "request-over-cap", "root-a", time.Minute, now.Add(2*time.Second)); err != ErrInvalidRequestPayloadGrant {
		t.Fatalf("grant beyond the active cap = %v, want %v", err, ErrInvalidRequestPayloadGrant)
	}
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
