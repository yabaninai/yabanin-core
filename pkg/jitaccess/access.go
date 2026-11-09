package jitaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// expired} machine for new code. Existing fragmented vocabularies elsewhere
// (finance "rejected", controller "awaiting_review") are deliberately left
// alone. denied and expired are terminal: no further decision applies.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
)

// Decision windows: a pending request auto-expires after 24h; an
// approved elevation stays active for 1h from the approval decision.
const (
	PendingTTL  = 24 * time.Hour
	ApprovedTTL = time.Hour
)

// Sentinel decision outcomes. Callers should match with errors.Is; the
// inactive.
var (
	ErrNotFound        = errors.New("jit request not found")
	ErrNotPending      = errors.New("jit request is not pending (already decided or unknown)")
	ErrSelfApproval    = errors.New("cannot self-approve a JIT elevation (different human required)")
	ErrApproverNotRoot = errors.New("approver is not an active root operator")
	ErrDigestMismatch  = errors.New("request digest mismatch (arguments changed or stale review view)")
	ErrNoPool          = errors.New("jit access manager has no database pool")
)

// RootChecker reports whether an admin identity is an active root operator.
// Any failure to establish root status must return false plus the error —
// decisions fail closed on the error path.
type RootChecker func(ctx context.Context, approverID string) (bool, error)

// ApprovalBinds pins an approval decision to the immutable request content
// ApprovalBinds, ReviewRecord.StateSHA). For JIT elevations Org is the
// requesting principal (the scope the elevation elevates), Entity the
// requested role, EntityVersion the request creation stamp and ParamsDigest
// the SHA-256 over the pending request tuple. A decision whose binds do not
// equal the stored row's binds is rejected — replaying an approval after
// changed arguments (or from a stale view) fails closed.
type ApprovalBinds struct {
	Org           string `json:"org"`
	Entity        string `json:"entity"`
	EntityVersion string `json:"entity_version"`
	ParamsDigest  string `json:"params_digest"`
}

// Manager handles JIT elevation requests and decisions.
type Manager struct {
	pool       *pgxpool.Pool
	ttl        time.Duration // approved elevation window (D6, default 1h)
	pendingTTL time.Duration // pending auto-expire window (D6, default 24h)
	rootCheck  RootChecker   // nil disables every decision (fail closed)
	// queryRow/exec are the storage surfaces the fetch projection and the
	// terminal UPDATE go through. Production wires them to the pool in
	// NewManager; same-package tests may swap in failing doubles to pin the
	// ready() fails closed before any call.
	queryRow func(ctx context.Context, query string, args ...any) pgx.Row
	exec     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// NewManager creates a new JIT access manager bound to the given DB pool,
// with the Postgres-backed root check wired.
func NewManager(pool *pgxpool.Pool) *Manager {
	m := &Manager{
		pool:       pool,
		ttl:        ApprovedTTL,
		pendingTTL: PendingTTL,
		rootCheck:  PostgresRootCheck(pool),
	}
	if pool != nil {
		m.queryRow = pool.QueryRow
		m.exec = pool.Exec
	}
	return m
}

// WithRootCheck replaces the approver root check. A nil checker disables all
// decisions (fail closed); tests use this to stub authorization.
func (m *Manager) WithRootCheck(rc RootChecker) *Manager {
	m.rootCheck = rc
	return m
}

// PostgresRootCheck reports from admin_users whether the approver is an
// active root operator. Unknown ids, inactive accounts and lookup failures
// all answer the error path (the caller fails closed).
func PostgresRootCheck(pool *pgxpool.Pool) RootChecker {
	return func(ctx context.Context, approverID string) (bool, error) {
		if pool == nil {
			return false, ErrNoPool
		}
		var isRoot bool
		err := pool.QueryRow(ctx,
			`SELECT is_root FROM admin_users WHERE id=$1::uuid AND active`,
			approverID).Scan(&isRoot)
		if err != nil {
			return false, fmt.Errorf("root check for approver: %w", err)
		}
		return isRoot, nil
	}
}

// Request creates a pending JIT elevation. The pending window is policy
// (D6): it expires 24h after creation unless decided. The returned record
// carries the binds (including the request digest) the approver must quote.
func (m *Manager) Request(ctx context.Context, adminID, role, reason string) (*JITRecord, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(adminID) == "" {
		return nil, errors.New("requesting admin id is required")
	}
	if strings.TrimSpace(role) == "" {
		return nil, errors.New("requested role is required")
	}
	var id string
	var createdAt, expiresAt time.Time
	err := m.pool.QueryRow(ctx,
		`INSERT INTO jit_access (id, admin_id, requested_role, reason, status, expires_at)
		 VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
		 RETURNING id, created_at, expires_at`,
		uuid.NewString(), adminID, role, reason, StatusPending, m.pendingTTL.Seconds(),
	).Scan(&id, &createdAt, &expiresAt)
	if err != nil {
		return nil, fmt.Errorf("create jit request: %w", err)
	}
	r := &JITRecord{
		ID:        id,
		AdminID:   adminID,
		Role:      role,
		Reason:    reason,
		Status:    StatusPending,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
	}
	r.Binds = bindsFor(r)
	return r, nil
}

// Get loads a request in any status, with its computed binds.
func (m *Manager) Get(ctx context.Context, requestID string) (*JITRecord, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	r, err := m.fetch(ctx, requestID)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Approve elevates a pending request (D1+D3). The decision is rejected
// unless the approver is an active root operator other than the requester
// and the supplied binds equal the stored request's binds. On success the
// elevation is active for the approved TTL (D6).
func (m *Manager) Approve(ctx context.Context, requestID, approverID string, saw ApprovalBinds) (*JITRecord, error) {
	return m.decide(ctx, requestID, approverID, saw, StatusApproved)
}

// Deny rejects a pending request under the same authorization and binding
// rules as Approve (D1+D3). denied is terminal.
func (m *Manager) Deny(ctx context.Context, requestID, approverID string, saw ApprovalBinds) (*JITRecord, error) {
	return m.decide(ctx, requestID, approverID, saw, StatusDenied)
}

// decide is the shared decision core. Ordering is deliberate: cheap checks
// first, authorization before binds — a non-root or self approver never
// learns whether the digest matched.
func (m *Manager) decide(ctx context.Context, requestID, approverID string, saw ApprovalBinds, decision string) (*JITRecord, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(approverID) == "" {
		return nil, errors.New("approver id is required")
	}
	if decision != StatusApproved && decision != StatusDenied {
		return nil, fmt.Errorf("unknown decision %q", decision)
	}
	if m.rootCheck == nil {
		// Fail closed before touching storage: without a way to establish
		// root authorization, no decision may proceed.
		return nil, fmt.Errorf("%w: no root checker wired", ErrApproverNotRoot)
	}
	cur, err := m.fetch(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if cur.Status != StatusPending {
		return nil, ErrNotPending
	}
	if cur.AdminID == approverID {
		return nil, ErrSelfApproval
	}
	isRoot, err := m.rootCheck(ctx, approverID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApproverNotRoot, err)
	}
	if !isRoot {
		return nil, ErrApproverNotRoot
	}
	if cur.Binds != saw {
		return nil, ErrDigestMismatch
	}

	// Terminal transition. The immutable tuple rides in the WHERE clause so
	// a concurrent decision (status flip) or content mutation fails closed
	// instead of overwriting a decision that already happened.
	expires := time.Now().UTC().Add(m.ttl)
	if decision == StatusDenied {
		expires = time.Now().UTC() // terminal stamp; a denial is never active
	}
	tag, err := m.exec(ctx,
		`UPDATE jit_access SET status=$1, approver_id=$2, expires_at=$3
		 WHERE id=$4 AND status=$5 AND admin_id=$6 AND requested_role=$7 AND reason=$8 AND created_at=$9`,
		decision, approverID, expires, requestID,
		StatusPending, cur.AdminID, cur.Role, cur.Reason, cur.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("record jit %s: %w", decision, err)
	}
	if tag.RowsAffected() == 0 {
		// Lost a race or the row changed underneath: re-read to report the
		// honest reason rather than a blind failure.
		after, gerr := m.fetch(ctx, requestID)
		if gerr != nil {
			return nil, gerr
		}
		if after.Status != StatusPending {
			return nil, ErrNotPending
		}
		return nil, ErrDigestMismatch
	}
	return m.fetch(ctx, requestID)
}

// IsActive checks if admin currently has an approved, non-expired elevation.
// Fail-closed (D7): any lookup error answers false.
func (m *Manager) IsActive(ctx context.Context, adminID, role string) bool {
	if m.pool == nil {
		return false
	}
	var n int
	err := m.queryRow(ctx,
		`SELECT count(*) FROM jit_access
		 WHERE admin_id=$1 AND requested_role=$2 AND status='approved' AND expires_at > now()`,
		adminID, role).Scan(&n)
	return err == nil && n > 0
}

// ExpirePast runs the planned sweep (D6): pending requests past their 24h
// window and approved elevations past their TTL flip to the terminal
// 'expired' status. Expire is a recorded terminal decision, not a silent
// delete. Returns the number of rows flipped.
func (m *Manager) ExpirePast(ctx context.Context) (int64, error) {
	if err := m.ready(); err != nil {
		return 0, err
	}
	tag, err := m.exec(ctx,
		`UPDATE jit_access SET status=$1 WHERE status IN ($2, $3) AND expires_at <= now()`,
		StatusExpired, StatusPending, StatusApproved)
	if err != nil {
		return 0, fmt.Errorf("expire jit requests: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PendingRequests returns the undecided queue (operator surface for the
// approval flow), oldest first.
func (m *Manager) PendingRequests(ctx context.Context) ([]JITRecord, error) {
	return m.query(ctx, `SELECT id, admin_id, requested_role, reason, approver_id, status, expires_at, created_at
		FROM jit_access WHERE status=$1 ORDER BY created_at`, StatusPending)
}

// ActiveRequests returns all non-expired active elevations.
func (m *Manager) ActiveRequests(ctx context.Context) ([]JITRecord, error) {
	return m.query(ctx, `SELECT id, admin_id, requested_role, reason, approver_id, status, expires_at, created_at
		FROM jit_access WHERE status='approved' AND expires_at > now()`)
}

func (m *Manager) query(ctx context.Context, sql string, args ...any) ([]JITRecord, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	rows, err := m.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query jit requests: %w", err)
	}
	defer rows.Close()

	var result []JITRecord
	for rows.Next() {
		var r JITRecord
		if err := rows.Scan(&r.ID, &r.AdminID, &r.Role, &r.Reason, &r.ApproverID, &r.Status, &r.ExpiresAt, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan jit request: %w", err)
		}
		r.Binds = bindsFor(&r)
		result = append(result, r)
	}
	return result, rows.Err()
}

func (m *Manager) fetch(ctx context.Context, requestID string) (*JITRecord, error) {
	var r JITRecord
	err := m.queryRow(ctx,
		`SELECT id, admin_id, requested_role, reason, approver_id, status, expires_at, created_at
		 FROM jit_access WHERE id=$1`, requestID).
		Scan(&r.ID, &r.AdminID, &r.Role, &r.Reason, &r.ApproverID, &r.Status, &r.ExpiresAt, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load jit request: %w", err)
	}
	r.Binds = bindsFor(&r)
	return &r, nil
}

func (m *Manager) ready() error {
	if m.pool == nil {
		return ErrNoPool
	}
	return nil
}

// bindsFor derives the immutable bind tuple from the stored request fields.
// Only fields that never change after creation feed the digest: the pending
// expires_at is deliberately excluded because approval legitimately rewrites
// it (approved TTL).
func bindsFor(r *JITRecord) ApprovalBinds {
	version := r.CreatedAt.UTC().Format(time.RFC3339Nano)
	return ApprovalBinds{
		Org:           r.AdminID,
		Entity:        r.Role,
		EntityVersion: version,
		ParamsDigest:  requestDigest(r.AdminID, r.Role, r.Reason, version),
	}
}

// requestDigest is the SHA-256 over the pending request tuple, joined with
// the ASCII unit separator so field values cannot bleed into each other.
func requestDigest(adminID, role, reason, entityVersion string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{adminID, role, reason, entityVersion}, "\x1f")))
	return hex.EncodeToString(h[:])
}

// JITRecord represents a single JIT access request with its computed binds.
type JITRecord struct {
	ID         string        `json:"id"`
	AdminID    string        `json:"admin_id"`
	Role       string        `json:"requested_role"`
	Reason     string        `json:"reason"`
	ApproverID *string       `json:"approver_id,omitempty"`
	Status     string        `json:"status"`
	ExpiresAt  time.Time     `json:"expires_at"`
	CreatedAt  time.Time     `json:"created_at"`
	Binds      ApprovalBinds `json:"binds"`
}
