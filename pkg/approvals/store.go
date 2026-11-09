// Package approvals provides the durable approval-operation store for
// human-approved tool executions (packet N05-P04 «Durable подтверждения
// через UI и API», card N05-P04-T02): a Postgres-backed implementation of the
// frozen pkg/agentloop ApprovalSPI seam (spi.go:575-606).
//
// The store composes the SPI contract — it does not extend or reinterpret
// it. In particular it inherits, and is bound by:
//
//   - The five-state durable vocabulary from agentloop.ApprovalState:
//     pending / approved / rejected / expired / cancelled (spi.go:523-544).
//     approved and rejected are decision outcomes; expiry resolves
//     pending → expired; cancelled records an operation-level cancellation
//     while pending. No parallel vocabulary is defined here.
//   - Exact binding: every stored operation pins the concrete invocation —
//     initiating subject (+ authenticated subject kind), server, tool,
//     canonical-JSON ArgsDigest and the PolicyRef it was made under — as
//     immutable columns. The terminal UPDATE re-asserts the whole tuple in
//     its WHERE clause, so concurrent content mutation fails closed instead
//     of overwriting a decision (the jitaccess precedent shape, with this
//     packet's vocabulary: rejected and cancelled, never denied).
//   - TTL rules (I59): a zero TTL means agentloop.DefaultApprovalTTL (15
//     minutes); a negative TTL is invalid configuration and is rejected with
//     a validation error at Request time — never clamped, never an
//     already-expired deadline. The absolute deadline is persisted with the
//     request so enforcement survives restart and HA failover; ExpirePast
//     materializes it, and a decision racing the deadline is resolved by one
//     atomic UPDATE guarded on expires_at > now() (single DB clock).
//   - Late decisions: a decision arriving after expiry returns an error
//     wrapping agentloop.ErrApprovalExpired together with the resulting
//     record; an expired approval never revives and never executes (I59).
//     A duplicate decision on an already-resolved operation resolves once:
//     the resolved record is returned unchanged with ErrNotPending.
//   - No self-approval invariants that the seam itself fixes (I57): when the
//     stored request mandates RequiresDifferentHuman, or the initiator is an
//     agent/CI subject, a decision whose approver equals the initiator is
//     rejected with ErrSelfApproval.
//
// Deliberate scope boundaries (later packet cards, not defects): approver
// eligibility (users/groups/roles permission, absent-approver routing) is
// N05-P04-T03; policy-side TTL configuration surfaces are N05-P04-T04; the
// UI/API decision + status surfaces and their access control (OperationID
// possession is not authorization, spi.go:92-97) are N05-P04-T06; the
// post-approval rights/policy/credentials recheck and autoresume engine are
// N05-P04-T05. For a human initiator without RequiresDifferentHuman this
// store therefore does NOT yet police self-approval beyond the seam
// invariants above — approver permission checks arrive with T03.
package approvals

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/agentloop"
)

// Compile-time pin: Store satisfies the frozen ApprovalSPI seam with exactly
// the documented semantics (build-enforced, like the pkg/agentloop
// spi_test.go stub pin).
var _ agentloop.ApprovalSPI = (*Store)(nil)

// Sentinel errors. Callers classify with errors.Is; storage errors are
// wrapped with %w underneath these.
var (
	// ErrNoPool reports a store constructed without a database pool.
	// Fail-closed: every operation answers it, nothing is decided on an
	// unverifiable store.
	ErrNoPool = errors.New("approvals: store has no database pool")
	// ErrNotFound reports that the referenced approval operation does not
	// exist.
	ErrNotFound = errors.New("approval operation not found")
	// ErrNotPending reports that the approval operation is already resolved
	// (approved, rejected or cancelled). A duplicate decision resolves once:
	// the resolved record is returned unchanged alongside this error.
	ErrNotPending = errors.New("approval operation is not pending")
	// ErrInvalidRequest reports a Request the contract forbids creating:
	// missing binding fields, unknown subject kind, or a negative TTL
	// (invalid configuration per spi.go:512-517 — rejected at request
	// creation, never clamped to the default).
	ErrInvalidRequest = errors.New("invalid approval request")
	// ErrInvalidDecision reports a Decision the contract forbids recording:
	// empty approval id, empty approver, or an outcome outside
	// approved/rejected.
	ErrInvalidDecision = errors.New("invalid approval decision")
	// ErrSelfApproval reports a decision whose approver equals the initiator
	// while the seam forbids it (agent/CI initiators, or a request with
	// RequiresDifferentHuman). I57: the different-human mandate overrides
	// any self-approval permission.
	ErrSelfApproval = errors.New("approver equals the initiator (self-approval forbidden)")
)

// approvalColumns is the projection every scan shares (single-row fetch and
// the pending-by-operation list) so record reconstruction cannot drift
// between read paths.
const approvalColumns = `id, operation_id, org_id, project_id, step_index, turn_id,
	initiator, initiator_kind, server_name, tool_name, args_digest,
	policy_ref, ttl_secs, requires_different_human, state,
	outcome, approver, decided_at, recheck_required,
	expires_at, created_at`

// row is the raw stored shape; recordFromRow is the only converter to the
// agentloop.ApprovalRecord surface.
type row struct {
	ID                     string
	OperationID            string
	OrgID                  string
	ProjectID              string
	StepIndex              int32
	TurnID                 string
	Initiator              string
	InitiatorKind          string
	Server                 string
	Tool                   string
	ArgsDigest             string
	PolicyRef              string
	TTLSecs                float64
	RequiresDifferentHuman bool
	State                  agentloop.ApprovalState
	Outcome                *string
	Approver               *string
	DecidedAt              *time.Time
	RecheckRequired        bool
	ExpiresAt              time.Time
	CreatedAt              time.Time
}

// Store is the Postgres-backed durable approval-operation store implementing
// agentloop.ApprovalSPI. It is safe for concurrent use: after construction it
// holds no mutable state, and every lifecycle change is a single guarded SQL
// statement.
type Store struct {
	pool *pgxpool.Pool
	// queryRow/exec are the storage surfaces. Production wires them to the
	// pool in NewStore; same-package hermetic tests swap in doubles to pin
	// the fail-closed posture before any call.
	queryRow func(ctx context.Context, sql string, args ...any) pgx.Row
	exec     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// NewStore creates a store bound to the given pool. A nil pool constructs a
// store whose every operation fails with ErrNoPool (fail closed), mirroring
// the jitaccess posture.
func NewStore(pool *pgxpool.Pool) *Store {
	s := &Store{pool: pool}
	if pool != nil {
		s.queryRow = pool.QueryRow
		s.exec = pool.Exec
	}
	return s
}

// ready fails closed before any storage call when no pool is wired.
func (s *Store) ready() error {
	if s.pool == nil || s.queryRow == nil || s.exec == nil {
		return ErrNoPool
	}
	return nil
}

// Request implements agentloop.ApprovalSPI.Request: it validates the request,
// resolves the effective TTL (zero → agentloop.DefaultApprovalTTL; negative →
// ErrInvalidRequest), records a durable pending operation with its absolute
// deadline and returns it with the generated ApprovalID.
//
// All clock decisions live inside single SQL statements (now() for created_at
// and expires_at), so the persisted deadline and every later comparison use
// one clock. Changed args (a different ArgsDigest) or a changed PolicyRef
// never match this row: each Request is a new binding, and an approval can
// never be derived across operations. The returned record carries the
// RESOLVED TTL (the default substituted), not the zero the caller passed.
func (s *Store) Request(ctx context.Context, op agentloop.Operation, req agentloop.ApprovalRequest) (agentloop.ApprovalRecord, error) {
	if err := s.ready(); err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	if err := validateRequest(op, req); err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = agentloop.DefaultApprovalTTL
	}

	id := uuid.NewString()
	var expiresAt time.Time
	err := s.queryRow(ctx,
		`INSERT INTO approval_operations
		     (id, operation_id, org_id, project_id, step_index, turn_id,
		      initiator, initiator_kind, server_name, tool_name, args_digest,
		      policy_ref, ttl_secs, requires_different_human, state, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
		         'pending', now() + make_interval(secs => $13))
		 RETURNING expires_at`,
		id, string(op.ID), op.OrgID, op.ProjectID, req.StepIndex, req.TurnID,
		req.Initiator, string(req.InitiatorKind), req.Server, req.Tool, req.ArgsDigest,
		req.PolicyRef, ttl.Seconds(), req.RequiresDifferentHuman,
	).Scan(&expiresAt)
	if err != nil {
		return agentloop.ApprovalRecord{}, fmt.Errorf("record approval operation: %w", err)
	}

	rec := agentloop.ApprovalRecord{
		ApprovalID: id,
		Request:    req,
		State:      agentloop.ApprovalPending,
		ExpiresAt:  expiresAt,
	}
	rec.Request.TTL = ttl
	return rec, nil
}

// Decision implements agentloop.ApprovalSPI.Decision: it records the human
// decision through one atomic guarded UPDATE that resolves the
// decision-versus-expiry race (I59).
//
// Outcomes:
//   - pending within TTL → approved/rejected, decision recorded once;
//   - already expired (swept, or racing the deadline) → the row materializes
//     terminal expired and an error wrapping agentloop.ErrApprovalExpired is
//     returned together with the resulting record;
//   - already decided or cancelled → the resolved record plus ErrNotPending;
//   - unknown id → ErrNotFound.
//
// The guard re-asserts the stored binding tuple, so a decision can never
// land on mutated content; binding fields have no UPDATE path, and any drift
// fails closed to the lost-race classification instead of overwriting.
func (s *Store) Decision(ctx context.Context, dec agentloop.ApprovalDecision) (agentloop.ApprovalRecord, error) {
	if err := s.ready(); err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	if strings.TrimSpace(dec.ApprovalID) == "" {
		return agentloop.ApprovalRecord{}, fmt.Errorf("%w: approval id is required", ErrInvalidDecision)
	}
	if dec.Outcome != agentloop.DecisionApproved && dec.Outcome != agentloop.DecisionRejected {
		return agentloop.ApprovalRecord{}, fmt.Errorf("%w: unknown outcome %q", ErrInvalidDecision, dec.Outcome)
	}
	if strings.TrimSpace(dec.Approver) == "" {
		return agentloop.ApprovalRecord{}, fmt.Errorf("%w: approver is required", ErrInvalidDecision)
	}

	cur, err := s.fetchRow(ctx, dec.ApprovalID)
	if err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	if cur.State != agentloop.ApprovalPending {
		return recordFromRow(cur), classifyResolved(cur.State)
	}
	// Cheap checks first, authorization last (jitaccess ordering): a
	// self-approving caller learns nothing about the stored binding.
	if dec.Approver == cur.Initiator && selfApprovalForbidden(cur) {
		return recordFromRow(cur), ErrSelfApproval
	}

	// Terminal transition. One statement owns the race: state + deadline +
	// full binding tuple in the WHERE clause, DB clock deciding expiry.
	state := string(dec.Outcome)
	tag, err := s.exec(ctx, decisionUpdateSQL,
		state, dec.Approver, dec.RecheckRequired, dec.ApprovalID,
		cur.OperationID, cur.OrgID, cur.Initiator,
		cur.InitiatorKind, cur.Server, cur.Tool,
		cur.ArgsDigest, cur.PolicyRef, cur.RequiresDifferentHuman)
	if err != nil {
		return agentloop.ApprovalRecord{}, fmt.Errorf("record approval decision: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return s.classifyLostRace(ctx, dec.ApprovalID)
	}
	after, err := s.fetchRow(ctx, dec.ApprovalID)
	if err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	return recordFromRow(after), nil
}

// Cancel records an operation-level cancellation of a pending approval
// (store-level extension; the v1 ApprovalSPI surface is Request+Decision).
// Cancelled is terminal. A row whose deadline has already passed cannot
// become cancelled — the honest terminal state for it is expired — so the
// same deadline guard applies and ErrApprovalExpired is returned for it.
// Cancelled carries no human decision (approver/outcome stay NULL); actor
// audit belongs to pkg/auditlog, not to the approval record.
func (s *Store) Cancel(ctx context.Context, approvalID string) (agentloop.ApprovalRecord, error) {
	if err := s.ready(); err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	if strings.TrimSpace(approvalID) == "" {
		return agentloop.ApprovalRecord{}, fmt.Errorf("%w: approval id is required", ErrInvalidDecision)
	}

	cur, err := s.fetchRow(ctx, approvalID)
	if err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	if cur.State != agentloop.ApprovalPending {
		return recordFromRow(cur), classifyResolved(cur.State)
	}
	tag, err := s.exec(ctx,
		`UPDATE approval_operations
		 SET state = 'cancelled', updated_at = now()
		 WHERE id = $1 AND state = 'pending' AND expires_at > now()`,
		approvalID)
	if err != nil {
		return agentloop.ApprovalRecord{}, fmt.Errorf("cancel approval operation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return s.classifyLostRace(ctx, approvalID)
	}
	return s.fetchRecord(ctx, approvalID)
}

// ExpirePast materializes the persisted deadline: every pending operation
// past its expires_at flips to terminal expired. Sweep and decision-time
// materialization are idempotent with each other. Returns the number of rows
// flipped. Enforcement survives restart and failover because the deadline is
// absolute and persisted (I59). Approved and rejected rows are decision
// records, not active windows — the sweep deliberately does not touch them.
func (s *Store) ExpirePast(ctx context.Context) (int64, error) {
	if err := s.ready(); err != nil {
		return 0, err
	}
	tag, err := s.exec(ctx,
		`UPDATE approval_operations
		 SET state = 'expired', updated_at = now()
		 WHERE state = 'pending' AND expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("expire approval operations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Get loads the durable record in any state (the status surface later packet
// cards expose; loading it here is what makes the stored operation ID and
// state observable after restart or disconnect).
func (s *Store) Get(ctx context.Context, approvalID string) (agentloop.ApprovalRecord, error) {
	if err := s.ready(); err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	return s.fetchRecord(ctx, approvalID)
}

// PendingByOperation returns the still-pending approvals of one loop
// operation, oldest first. After a restart or failover the engine (later
// packet cards) resumes waiting operations from this projection instead of
// client state.
func (s *Store) PendingByOperation(ctx context.Context, operationID agentloop.OperationID) ([]agentloop.ApprovalRecord, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+approvalColumns+`
		 FROM approval_operations
		 WHERE operation_id = $1 AND state = 'pending'
		 ORDER BY created_at`, string(operationID))
	if err != nil {
		return nil, fmt.Errorf("query pending approvals: %w", err)
	}
	defer rows.Close()

	var out []agentloop.ApprovalRecord
	for rows.Next() {
		var r row
		if err := scanInto(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, recordFromRow(r))
	}
	return out, rows.Err()
}

// approvalRowScanner is the minimal scan surface shared by single-row fetch
// (pgx.Row) and the pending list (pgx.Rows), so the projection column order
// has exactly one definition site.
type approvalRowScanner interface {
	Scan(dest ...any) error
}

// scanInto scans one approvalColumns projection row into r.
func scanInto(src approvalRowScanner, r *row) error {
	return src.Scan(&r.ID, &r.OperationID, &r.OrgID, &r.ProjectID, &r.StepIndex, &r.TurnID,
		&r.Initiator, &r.InitiatorKind, &r.Server, &r.Tool, &r.ArgsDigest,
		&r.PolicyRef, &r.TTLSecs, &r.RequiresDifferentHuman, &r.State,
		&r.Outcome, &r.Approver, &r.DecidedAt, &r.RecheckRequired,
		&r.ExpiresAt, &r.CreatedAt)
}

// fetchRow loads the raw row; fetchRecord converts it. Unknown ids answer
// ErrNotFound (fail loud, never a fabricated record).
func (s *Store) fetchRow(ctx context.Context, id string) (row, error) {
	var r row
	err := scanInto(s.queryRow(ctx,
		`SELECT `+approvalColumns+` FROM approval_operations WHERE id = $1`, id), &r)
	if errors.Is(err, pgx.ErrNoRows) {
		return row{}, ErrNotFound
	}
	if err != nil {
		return row{}, fmt.Errorf("load approval operation: %w", err)
	}
	return r, nil
}

func (s *Store) fetchRecord(ctx context.Context, id string) (agentloop.ApprovalRecord, error) {
	r, err := s.fetchRow(ctx, id)
	if err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	return recordFromRow(r), nil
}

// decisionUpdateSQL is the terminal decision transition and the single
// write path for a human decision. Its WHERE clause is the enforcement:
// the row must still be pending, inside its persisted deadline (DB clock),
// AND byte-identical to the binding tuple the store just read — so content
// drift inside the read→write window matches zero rows and folds into
// classifyLostRace (fail closed) instead of stamping the decision onto
// mutated content. The full statement is pinned hermetically by
// TestDecisionUpdateSQL_GuardShape and probed live per binding column by
// TestIntApprovals_BindingTamperFailsClosed.
const decisionUpdateSQL = `UPDATE approval_operations
		 SET state = $1, outcome = $1, approver = $2, decided_at = now(),
		     recheck_required = $3, updated_at = now()
		 WHERE id = $4 AND state = 'pending' AND expires_at > now()
		   AND operation_id = $5 AND org_id = $6 AND initiator = $7
		   AND initiator_kind = $8 AND server_name = $9 AND tool_name = $10
		   AND args_digest = $11 AND policy_ref = $12 AND requires_different_human = $13`

// materializeExpiredSQL folds a still-pending row to terminal expired (the
// lost-race classification path). Its state='pending' guard is load-bearing:
// the fold must never demote a decided or cancelled row.
const materializeExpiredSQL = `UPDATE approval_operations
			 SET state = 'expired', updated_at = now()
			 WHERE id = $1 AND state = 'pending'`

// classifyLostRace reports WHY a guarded transition matched zero rows: the
// row moved (decided/cancelled by a concurrent caller) or its deadline
// passed between the read and the write. A row still pending at this point
// expired in that window and is materialized terminal expired (idempotent
// with ExpirePast) before the honest ErrApprovalExpired answer.
func (s *Store) classifyLostRace(ctx context.Context, id string) (agentloop.ApprovalRecord, error) {
	after, err := s.fetchRow(ctx, id)
	if err != nil {
		return agentloop.ApprovalRecord{}, err
	}
	if after.State == agentloop.ApprovalPending {
		if _, uerr := s.exec(ctx, materializeExpiredSQL, id); uerr != nil {
			return agentloop.ApprovalRecord{}, fmt.Errorf("materialize approval expiry: %w", uerr)
		}
		after, err = s.fetchRow(ctx, id)
		if err != nil {
			return agentloop.ApprovalRecord{}, err
		}
	}
	return recordFromRow(after), classifyResolved(after.State)
}

// classifyResolved maps an already-resolved state to its decision-path
// error: expired answers agentloop.ErrApprovalExpired (the SPI-mandated
// classification for late decisions), every other terminal state answers
// ErrNotPending. The record is returned either way, so callers always see
// the resulting ApprovalState.
func classifyResolved(state agentloop.ApprovalState) error {
	if state == agentloop.ApprovalExpired {
		return fmt.Errorf("%w: deadline passed; a late or repeated decision never revives the operation",
			agentloop.ErrApprovalExpired)
	}
	return fmt.Errorf("%w: state %q", ErrNotPending, state)
}

// selfApprovalForbidden reports whether the stored binding forbids an
// initiator-equal approver outright: a request with RequiresDifferentHuman
// (the different-human mandate overrides any self-approval permission,
// I57), or an agent/CI initiator (agents and CI never approve their own
// calls). Human/service initiators without the mandate are left to the T03
// approver-permission layer.
func selfApprovalForbidden(r row) bool {
	if r.RequiresDifferentHuman {
		return true
	}
	switch agentloop.SubjectKind(r.InitiatorKind) {
	case agentloop.SubjectAgent, agentloop.SubjectCI:
		return true
	default:
		return false
	}
}

// validateRequest enforces the Request-time contract: every binding field
// present, a known authenticated subject kind, and no negative TTL (a
// negative TTL is invalid configuration per spi.go:512-517 — rejected here,
// never clamped to the default, never an already-expired deadline).
func validateRequest(op agentloop.Operation, req agentloop.ApprovalRequest) error {
	if strings.TrimSpace(string(op.ID)) == "" {
		return fmt.Errorf("%w: operation id is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(op.OrgID) == "" {
		return fmt.Errorf("%w: operation org is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(req.Initiator) == "" {
		return fmt.Errorf("%w: initiator subject is required", ErrInvalidRequest)
	}
	switch req.InitiatorKind {
	case agentloop.SubjectHuman, agentloop.SubjectAgent, agentloop.SubjectService, agentloop.SubjectCI:
	default:
		return fmt.Errorf("%w: unknown initiator kind %q", ErrInvalidRequest, req.InitiatorKind)
	}
	if strings.TrimSpace(req.Server) == "" {
		return fmt.Errorf("%w: server binding is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(req.Tool) == "" {
		return fmt.Errorf("%w: tool binding is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(req.ArgsDigest) == "" {
		return fmt.Errorf("%w: args digest binding is required", ErrInvalidRequest)
	}
	if req.TTL < 0 {
		return fmt.Errorf("%w: negative TTL %v is invalid configuration (spi.go: zero means the default, negative is rejected)", ErrInvalidRequest, req.TTL)
	}
	return nil
}

// recordFromRow is the only converter from the stored shape to the
// agentloop.ApprovalRecord surface. A decided row reconstructs its
// ApprovalDecision; decided_at non-NULL with a NULL outcome/approver would
// be a schema violation and scans as an empty decision rather than a
// fabricated one.
func recordFromRow(r row) agentloop.ApprovalRecord {
	rec := agentloop.ApprovalRecord{
		ApprovalID: r.ID,
		Request: agentloop.ApprovalRequest{
			OperationID:            agentloop.OperationID(r.OperationID),
			StepIndex:              int(r.StepIndex),
			TurnID:                 r.TurnID,
			Initiator:              r.Initiator,
			InitiatorKind:          agentloop.SubjectKind(r.InitiatorKind),
			Server:                 r.Server,
			Tool:                   r.Tool,
			ArgsDigest:             r.ArgsDigest,
			PolicyRef:              r.PolicyRef,
			TTL:                    time.Duration(r.TTLSecs * float64(time.Second)),
			RequiresDifferentHuman: r.RequiresDifferentHuman,
		},
		State:     agentloop.ApprovalState(r.State),
		ExpiresAt: r.ExpiresAt,
	}
	if r.DecidedAt != nil {
		var outcome agentloop.ApprovalOutcome
		if r.Outcome != nil {
			outcome = agentloop.ApprovalOutcome(*r.Outcome)
		}
		approver := ""
		if r.Approver != nil {
			approver = *r.Approver
		}
		rec.Decision = &agentloop.ApprovalDecision{
			ApprovalID:      r.ID,
			Outcome:         outcome,
			Approver:        approver,
			DecidedAt:       *r.DecidedAt,
			RecheckRequired: r.RecheckRequired,
		}
	}
	return rec
}
