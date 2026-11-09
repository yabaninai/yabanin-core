// file objects (Postgres bytea payloads, ratified D2) and batch jobs drained
// by a claim/lease worker over the settlement_jobs pattern (ratified D1).
//
// Ratified limits (D3, 2026-10-18): 100 MiB per file, 1000 requests per
// batch, 30-day retention enforced by expires_at columns and the executor's
// retention sweep. One documented tightening: a purpose=batch
// upload never referenced by any batch is reclaimed after a grace window
// (SweepOrphanUploads, executor cadence) instead of riding the full window.
// Tenant isolation: every query is org_id-scoped; a foreign
// id is indistinguishable from a missing one (the endpoints answer 404).
package batchstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Ratified D3 limits.
const (
	// MaxFileSizeBytes is the per-file upload cap (413 above it).
	MaxFileSizeBytes int64 = 100 << 20
	// MaxBatchLines is the maximum number of requests in one batch.
	MaxBatchLines = 1000
	// Retention is how long files and batches outlive their creation.
	Retention = 30 * 24 * time.Hour
)

// EndpointChatCompletions is the only supported batch endpoint (explicit
// unsupported indication for anything else).
const EndpointChatCompletions = "/v1/chat/completions"

// Store errors mapped by the endpoints to HTTP states.
var (
	// ErrNotFound is the org-scoped miss: wrong org OR unknown id.
	ErrNotFound = errors.New("not found")
	// ErrFileTooLarge is the D3 size cap (HTTP 413).
	ErrFileTooLarge = errors.New("file exceeds the maximum size")
	// ErrFilePurpose marks an upload purpose outside the supported set.
	ErrFilePurpose = errors.New("unsupported file purpose")
	// ErrTooManyLines is the D3 batch line cap.
	ErrTooManyLines = errors.New("batch exceeds the maximum number of requests")
	// ErrBadLine marks a JSONL line that violates the batch request shape.
	ErrBadLine = errors.New("invalid batch request line")
	// ErrUnsupportedEndpoint marks a batch endpoint other than chat.
	ErrUnsupportedEndpoint = errors.New("unsupported batch endpoint")
	// ErrBatchTerminal marks a cancel against an already-finished batch
	// (completed/failed/expired) — never restarted, never double-freed.
	ErrBatchTerminal = errors.New("batch is already in a terminal state")
)

// File is a stored file object (content fetched separately).
type File struct {
	ID        string
	OrgID     string
	Filename  string
	Purpose   string
	Bytes     int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Batch is a batch job row. Attempts doubles as the lease fencing token:
// claimBatch increments it, so it identifies the current claim generation —
// executor writes scoped to a stale generation are rejected by the store.
type Batch struct {
	ID             string
	OrgID          string
	APIKeyID       string
	InputFileID    string
	Endpoint       string
	Model          string
	Metadata       json.RawMessage
	Status         string
	Attempts       int
	TotalCount     int
	CompletedCount int
	FailedCount    int
	OutputFileID   string
	ErrorFileID    string
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CompletedAt    time.Time
	ExpiresAt      time.Time
}

// Line is one batch request row.
type Line struct {
	BatchID      string
	LineNo       int
	CustomID     string
	RequestID    string
	RequestBody  []byte
	Status       string
	ResponseCode int
	ResponseBody []byte
	Error        string
}

// Line statuses.
const (
	LinePending = "pending"
	LineDone    = "done"
	LineFailed  = "failed"
)

// Batch statuses (OpenAI-compatible lifecycle).
const (
	StatusValidating = "validating"
	StatusInProgress = "in_progress"
	StatusFinalizing = "finalizing"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
	StatusCancelling = "cancelling"
	StatusCancelled  = "cancelled"
	StatusExpired    = "expired"
)

// File purposes: client uploads use "batch"; the executor writes result
// files with the two internal purposes.
const (
	PurposeBatchInput  = "batch"
	PurposeBatchOutput = "batch.output"
	PurposeBatchError  = "batch.error"
)

// Store is the batch/files persistence surface over one pgx pool.
type Store struct {
	pool *pgxpool.Pool
	log  *slog.Logger
	now  func() time.Time
}

// NewStore builds the store; now is injectable for retention tests.
func NewStore(pool *pgxpool.Pool, l *slog.Logger) *Store {
	if l == nil {
		l = slog.Default()
	}
	return &Store{pool: pool, log: l, now: time.Now}
}

// SetClock pins the store clock (tests only).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func newID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano())
	}
	return prefix + hex.EncodeToString(b[:])
}

// CreateFile stores an org-scoped file (D2: bytea payload). The D3 size cap
// is enforced here so every ingestion path (HTTP upload, executor output)
// shares it.
func (s *Store) CreateFile(ctx context.Context, orgID, filename, purpose string, content []byte) (*File, error) {
	if int64(len(content)) > MaxFileSizeBytes {
		return nil, ErrFileTooLarge
	}
	switch purpose {
	case PurposeBatchInput, PurposeBatchOutput, PurposeBatchError:
	default:
		return nil, ErrFilePurpose
	}
	now := s.now()
	f := &File{
		ID:        newID("file-"),
		OrgID:     orgID,
		Filename:  filename,
		Purpose:   purpose,
		Bytes:     int64(len(content)),
		CreatedAt: now,
		ExpiresAt: now.Add(Retention),
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO batch_files (id, org_id, filename, purpose, bytes, content, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, expires_at`,
		f.ID, f.OrgID, f.Filename, f.Purpose, f.Bytes, content, now, f.ExpiresAt).
		Scan(&f.CreatedAt, &f.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("insert batch_files: %w", err)
	}
	return f, nil
}

const fileColumns = "id, org_id, filename, purpose, bytes, created_at, expires_at"

func scanFile(row pgx.Row) (*File, error) {
	var f File
	if err := row.Scan(&f.ID, &f.OrgID, &f.Filename, &f.Purpose, &f.Bytes, &f.CreatedAt, &f.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan batch_files: %w", err)
	}
	return &f, nil
}

// GetFile resolves a file for the org (foreign org → ErrNotFound).
func (s *Store) GetFile(ctx context.Context, orgID, id string) (*File, error) {
	return scanFile(s.pool.QueryRow(ctx,
		"SELECT "+fileColumns+" FROM batch_files WHERE id = $1 AND org_id = $2", id, orgID))
}

// ListFiles lists the org's newest files first.
func (s *Store) ListFiles(ctx context.Context, orgID string, limit int) ([]*File, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		"SELECT "+fileColumns+" FROM batch_files WHERE org_id = $1 ORDER BY created_at DESC, id LIMIT $2", orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("list batch_files: %w", err)
	}
	defer rows.Close()
	var out []*File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.OrgID, &f.Filename, &f.Purpose, &f.Bytes, &f.CreatedAt, &f.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan batch_files row: %w", err)
		}
		out = append(out, &f)
	}
	return out, rows.Err()
}

// FileContent returns the payload bytes for the org's file.
func (s *Store) FileContent(ctx context.Context, orgID, id string) ([]byte, *File, error) {
	var content []byte
	var f File
	err := s.pool.QueryRow(ctx,
		"SELECT id, org_id, filename, purpose, bytes, created_at, expires_at, content FROM batch_files WHERE id = $1 AND org_id = $2",
		id, orgID).
		Scan(&f.ID, &f.OrgID, &f.Filename, &f.Purpose, &f.Bytes, &f.CreatedAt, &f.ExpiresAt, &content)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("read batch_files content: %w", err)
	}
	return content, &f, nil
}

// DeleteFile removes the org's file row (payload included). Idempotent per
// OpenAI semantics is NOT offered: deleting a missing id reports false so
// the endpoint can distinguish "just deleted" from "never existed here".
func (s *Store) DeleteFile(ctx context.Context, orgID, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		"DELETE FROM batch_files WHERE id = $1 AND org_id = $2", id, orgID)
	if err != nil {
		return false, fmt.Errorf("delete batch_files: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// LineInput is one validated JSONL request body from the submit endpoint.
type LineInput struct {
	CustomID    string
	RequestBody json.RawMessage
}

// RequestIDForLine derives the deterministic per-line request id: identical
// across crash-retries, so settlement's (org_id, request_id, charge_kind)
// identity makes a re-executed line bill exactly once (E4).
func RequestIDForLine(batchID string, lineNo int) string {
	return fmt.Sprintf("%s-l%06d", batchID, lineNo)
}

// CreateBatch validates the input file (owned by the org, purpose=batch)
// and materializes every JSONL line as a batch_lines row in ONE transaction:
// after submit, execution never needs the input file again, and a crash
// resumes from the durable per-line statuses.
func (s *Store) CreateBatch(ctx context.Context, orgID, apiKeyID, inputFileID, endpoint string, metadata json.RawMessage, bodies []LineInput) (*Batch, error) {
	if endpoint != EndpointChatCompletions {
		return nil, ErrUnsupportedEndpoint
	}
	if len(bodies) == 0 {
		return nil, ErrBadLine
	}
	if len(bodies) > MaxBatchLines {
		return nil, ErrTooManyLines
	}
	now := s.now()
	b := &Batch{
		ID:          newID("batch-"),
		OrgID:       orgID,
		APIKeyID:    apiKeyID,
		InputFileID: inputFileID,
		Endpoint:    endpoint,
		Status:      StatusValidating,
		TotalCount:  len(bodies),
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   now.Add(Retention),
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create batch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var purpose string
	err = tx.QueryRow(ctx,
		"SELECT purpose FROM batch_files WHERE id = $1 AND org_id = $2 FOR UPDATE",
		inputFileID, orgID).Scan(&purpose)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lock input file: %w", err)
	}
	if purpose != PurposeBatchInput {
		return nil, ErrBadLine
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO batch_jobs (id, org_id, api_key_id, input_file_id, endpoint, metadata, status, total_count, created_at, updated_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'validating', $7, $8, $8, $9)
		RETURNING created_at, updated_at, expires_at`,
		b.ID, b.OrgID, b.APIKeyID, b.InputFileID, b.Endpoint, metadata, b.TotalCount, now, b.ExpiresAt).
		Scan(&b.CreatedAt, &b.UpdatedAt, &b.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("insert batch_jobs: %w", err)
	}
	for i, in := range bodies {
		if _, err := tx.Exec(ctx, `
			INSERT INTO batch_lines (batch_id, line_no, custom_id, request_id, request_body, status)
			VALUES ($1, $2, $3, $4, $5, 'pending')`,
			b.ID, i+1, in.CustomID, RequestIDForLine(b.ID, i+1), in.RequestBody); err != nil {
			return nil, fmt.Errorf("insert batch_lines: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create batch: %w", err)
	}
	return b, nil
}

const batchColumns = `id, org_id, api_key_id, input_file_id, endpoint, metadata, status, attempts, total_count,
	completed_count, failed_count, output_file_id, error_file_id, last_error,
	created_at, updated_at, completed_at, expires_at`

func scanBatch(row pgx.Row) (*Batch, error) {
	var b Batch
	var completedAt *time.Time
	var outputID, errorID, lastErr *string
	err := row.Scan(&b.ID, &b.OrgID, &b.APIKeyID, &b.InputFileID, &b.Endpoint, &b.Metadata, &b.Status, &b.Attempts, &b.TotalCount,
		&b.CompletedCount, &b.FailedCount, &outputID, &errorID, &lastErr,
		&b.CreatedAt, &b.UpdatedAt, &completedAt, &b.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan batch_jobs: %w", err)
	}
	if completedAt != nil {
		b.CompletedAt = *completedAt
	}
	if outputID != nil {
		b.OutputFileID = *outputID
	}
	if errorID != nil {
		b.ErrorFileID = *errorID
	}
	if lastErr != nil {
		b.LastError = *lastErr
	}
	return &b, nil
}

// GetBatch resolves a batch for the org (foreign org → ErrNotFound).
func (s *Store) GetBatch(ctx context.Context, orgID, id string) (*Batch, error) {
	return scanBatch(s.pool.QueryRow(ctx,
		"SELECT "+batchColumns+" FROM batch_jobs WHERE id = $1 AND org_id = $2", id, orgID))
}

// getBatchInternal is the executor-side lookup by id alone — the executor
// runs server-side on already-claimed rows and never resolves client input
// here (all HTTP paths stay org-scoped via GetBatch).
func (s *Store) getBatchInternal(ctx context.Context, id string) (*Batch, error) {
	return scanBatch(s.pool.QueryRow(ctx,
		"SELECT "+batchColumns+" FROM batch_jobs WHERE id = $1", id))
}

// ListBatches lists the org's newest batches first.
func (s *Store) ListBatches(ctx context.Context, orgID string, limit int) ([]*Batch, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		"SELECT "+batchColumns+" FROM batch_jobs WHERE org_id = $1 ORDER BY created_at DESC, id LIMIT $2", orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("list batch_jobs: %w", err)
	}
	defer rows.Close()
	var out []*Batch
	for rows.Next() {
		b, err := scanBatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// CancelBatch is the «повтор cancel» contract: cancelling and already-
// cancelling batches are idempotent (the same object returns, no second side
// effect); terminal completed/failed/expired batches refuse with
// ErrBatchTerminal. A validating batch (no executor lease can exist) goes
// straight to cancelled; an in_progress batch flips to cancelling and the
// executor finalizes it as cancelled between lines.
func (s *Store) CancelBatch(ctx context.Context, orgID, id string) (*Batch, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin cancel batch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	if err := tx.QueryRow(ctx,
		"SELECT status FROM batch_jobs WHERE id = $1 AND org_id = $2 FOR UPDATE",
		id, orgID).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lock batch for cancel: %w", err)
	}
	switch status {
	case StatusCompleted, StatusFailed, StatusExpired:
		return nil, ErrBatchTerminal
	case StatusCancelling, StatusCancelled:
		// Idempotent: fall through to the plain read below.
	case StatusValidating:
		if _, err := tx.Exec(ctx, `
			UPDATE batch_jobs SET status = 'cancelled', completed_at = $2, updated_at = $2 WHERE id = $1`,
			id, s.now()); err != nil {
			return nil, fmt.Errorf("cancel validating batch: %w", err)
		}
	case StatusInProgress, StatusFinalizing:
		if _, err := tx.Exec(ctx, `
			UPDATE batch_jobs SET status = 'cancelling', cancel_requested_at = $2, updated_at = $2 WHERE id = $1`,
			id, s.now()); err != nil {
			return nil, fmt.Errorf("request batch cancel: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown batch status %q", status)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit cancel batch: %w", err)
	}
	return s.GetBatch(ctx, orgID, id)
}

// claimQuery leases one due batch: SKIP LOCKED lets replicas share the
// queue; the subquery locks exactly the rows the UPDATE takes (the
// settlement_jobs claim shape). expires_at > now() keeps the retention sweep
// window honest: a batch past its 30-day window is never claimed and billed
// while it waits for the (hourly) sweep to delete it.
const claimQuery = `WITH claimed AS (
		UPDATE batch_jobs SET
			status = 'in_progress',
			attempts = attempts + 1,
			lease_until = now() + make_interval(secs => $1),
			updated_at = now()
		WHERE id IN (
			SELECT id FROM batch_jobs
			WHERE status = 'validating' AND next_attempt_at <= now()
			  AND attempts < $2 AND expires_at > now()
			ORDER BY created_at, id
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id
	)
	SELECT id FROM claimed`

// ClaimBatch leases the next due batch for execution. Returns ErrNotFound
// when the queue is empty.
func (s *Store) ClaimBatch(ctx context.Context, lease time.Duration, maxAttempts int) (*Batch, error) {
	var id string
	if err := s.pool.QueryRow(ctx, claimQuery, lease.Seconds(), maxAttempts).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("claim batch_jobs: %w", err)
	}
	return s.getBatchInternal(ctx, id)
}

// recoverExpiredLeasesQuery is the crash-resume contract (E4): a processing
// lease that expired means the executor died. Verdict order: a cancel request
// that outlived its lease finalizes straight to cancelled; a batch whose
// retention window (expires_at) passed expires instead of re-executing past
// deletion; everything else re-enters the queue — already-executed lines stay
// terminal and the deterministic per-line request_id keeps settlement
// idempotent on re-execution (E4).
const recoverExpiredLeasesQuery = `UPDATE batch_jobs SET
		status = CASE
			WHEN cancel_requested_at IS NOT NULL THEN 'cancelled'
			WHEN expires_at <= now() THEN 'expired'
			ELSE 'validating'
		END,
		completed_at = CASE
			WHEN cancel_requested_at IS NOT NULL OR expires_at <= now() THEN now()
			ELSE completed_at
		END,
		next_attempt_at = now(),
		lease_until = NULL,
		updated_at = now()
	WHERE status IN ('in_progress', 'cancelling')
	  AND lease_until IS NOT NULL AND lease_until < now()`

// expireQueuedQuery terminalizes queued (never claimed or just recovered)
// batches whose retention window passed. The retention sweep deletes them
// within its cadence; until then 'expired' is the client-visible verdict
// instead of a silent late execution (claimQuery also refuses these rows).
const expireQueuedQuery = `UPDATE batch_jobs SET
		status = 'expired',
		completed_at = now(),
		lease_until = NULL,
		updated_at = now()
	WHERE status = 'validating' AND expires_at <= now()`

const failExhaustedQuery = `UPDATE batch_jobs SET
		status = 'failed',
		last_error = 'batch exceeded the maximum execution attempts',
		completed_at = now(),
		lease_until = NULL,
		updated_at = now()
	WHERE status = 'validating' AND attempts >= $1`

// RecoverExpiredLeases is the executor's periodic recovery pass: expired
// leases resolve (cancel > expire > re-queue), queued batches past their
// retention window expire, exhausted batches fail explicitly. The order
// matters: expiry verdicts run before the exhaustion pass so a batch past
// its retention window reads 'expired', not 'failed'.
func (s *Store) RecoverExpiredLeases(ctx context.Context, maxAttempts int) error {
	if _, err := s.pool.Exec(ctx, recoverExpiredLeasesQuery); err != nil {
		return fmt.Errorf("recover expired batch leases: %w", err)
	}
	if _, err := s.pool.Exec(ctx, expireQueuedQuery); err != nil {
		return fmt.Errorf("expire queued batches: %w", err)
	}
	if _, err := s.pool.Exec(ctx, failExhaustedQuery, maxAttempts); err != nil {
		return fmt.Errorf("fail exhausted batches: %w", err)
	}
	return nil
}

// ReleaseLease drops the lease without a terminal state (shutdown between
// lines): the batch re-enters the queue via the normal recovery path. The
// attempts token fences it: a releasing worker whose lease already died and
// whose batch was re-claimed must not strip the new owner's lease.
func (s *Store) ReleaseLease(ctx context.Context, batchID string, leaseToken int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE batch_jobs SET status = 'validating', next_attempt_at = now(), lease_until = NULL, updated_at = now()
		WHERE id = $1 AND attempts = $2 AND status IN ('in_progress', 'cancelling')`, batchID, leaseToken)
	if err != nil {
		return fmt.Errorf("release batch lease: %w", err)
	}
	return nil
}

// PendingLines returns the batch's unexecuted lines in order.
func (s *Store) PendingLines(ctx context.Context, batchID string) ([]Line, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT batch_id, line_no, custom_id, request_id, request_body FROM batch_lines
		WHERE batch_id = $1 AND status = 'pending' ORDER BY line_no`, batchID)
	if err != nil {
		return nil, fmt.Errorf("list pending batch_lines: %w", err)
	}
	defer rows.Close()
	var out []Line
	for rows.Next() {
		var ln Line
		var body []byte
		if err := rows.Scan(&ln.BatchID, &ln.LineNo, &ln.CustomID, &ln.RequestID, &body); err != nil {
			return nil, fmt.Errorf("scan pending batch_lines row: %w", err)
		}
		ln.RequestBody = body
		ln.Status = LinePending
		out = append(out, ln)
	}
	return out, rows.Err()
}

// AllLines returns every line with its terminal state (result assembly).
func (s *Store) AllLines(ctx context.Context, batchID string) ([]Line, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT batch_id, line_no, custom_id, request_id, status, response_code, response_body, error FROM batch_lines
		WHERE batch_id = $1 ORDER BY line_no`, batchID)
	if err != nil {
		return nil, fmt.Errorf("list batch_lines: %w", err)
	}
	defer rows.Close()
	var out []Line
	for rows.Next() {
		var ln Line
		var code *int
		var body []byte
		var errMsg *string
		if err := rows.Scan(&ln.BatchID, &ln.LineNo, &ln.CustomID, &ln.RequestID, &ln.Status, &code, &body, &errMsg); err != nil {
			return nil, fmt.Errorf("scan batch_lines row: %w", err)
		}
		if code != nil {
			ln.ResponseCode = *code
		}
		ln.ResponseBody = body
		if errMsg != nil {
			ln.Error = *errMsg
		}
		out = append(out, ln)
	}
	return out, rows.Err()
}

// CompleteLine records one line's terminal result and refreshes the batch
// counters from the lines (one transaction; the conditional line update
// makes a re-executed line after lease recovery a no-op).
func (s *Store) CompleteLine(ctx context.Context, batchID string, lineNo int, status string, responseCode int, responseBody, errMsg []byte) error {
	if status != LineDone && status != LineFailed {
		return fmt.Errorf("invalid line terminal status %q", status)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin complete line: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE batch_lines SET status = $3, response_code = $4, response_body = $5, error = $6
		WHERE batch_id = $1 AND line_no = $2 AND status = 'pending'`,
		batchID, lineNo, status, responseCode, responseBody, errMsg)
	if err != nil {
		return fmt.Errorf("complete batch_lines: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil // already terminal (crash-recovery re-execution)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE batch_jobs SET
			completed_count = (SELECT count(*) FROM batch_lines WHERE batch_id = $1 AND status = 'done'),
			failed_count = (SELECT count(*) FROM batch_lines WHERE batch_id = $1 AND status = 'failed'),
			updated_at = now()
		WHERE id = $1`, batchID); err != nil {
		return fmt.Errorf("refresh batch counts: %w", err)
	}
	return tx.Commit(ctx)
}

// FinalizeBatch writes the result files and the terminal state in ONE
// transaction. cancelled=true records the cancel requested by the org; the
// output still contains everything executed before the cancel. The update is
// fenced on the lease token (the attempts value read at claim time) and on a
// live lease: a finalize from a claim generation that lost its batch to
// recovery + re-claim must not terminalize (or double-finalize) a batch the
// current owner is still running.
func (s *Store) FinalizeBatch(ctx context.Context, batchID string, leaseToken int, cancelled bool, outputJSONL, errorJSONL []byte) (*Batch, error) {
	b, err := s.getBatchInternal(ctx, batchID)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin finalize batch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := s.now()
	outputID := newID("file-")
	// A batch whose every line failed (or that was cancelled before any
	// line ran) has an empty output file — still a real (zero-byte) file,
	// never a NULL payload.
	if outputJSONL == nil {
		outputJSONL = []byte{}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO batch_files (id, org_id, filename, purpose, bytes, content, created_at, expires_at)
		VALUES ($1, $2, $3, 'batch.output', $4, $5, $6, $7)`,
		outputID, b.OrgID, batchID+".jsonl", len(outputJSONL), outputJSONL, now, now.Add(Retention)); err != nil {
		return nil, fmt.Errorf("write batch output file: %w", err)
	}
	var errorID *string
	if len(errorJSONL) > 0 {
		eid := newID("file-")
		if _, err := tx.Exec(ctx, `
			INSERT INTO batch_files (id, org_id, filename, purpose, bytes, content, created_at, expires_at)
			VALUES ($1, $2, $3, 'batch.error', $4, $5, $6, $7)`,
			eid, b.OrgID, batchID+"_errors.jsonl", len(errorJSONL), errorJSONL, now, now.Add(Retention)); err != nil {
			return nil, fmt.Errorf("write batch error file: %w", err)
		}
		errorID = &eid
	}
	status := StatusCompleted
	if cancelled {
		status = StatusCancelled
	}
	tag, err := tx.Exec(ctx, `
		UPDATE batch_jobs SET
			status = $2, output_file_id = $3, error_file_id = $4,
			completed_at = $5, lease_until = NULL, updated_at = $5
		WHERE id = $1 AND attempts = $6 AND status IN ('in_progress', 'cancelling')
		  AND lease_until IS NOT NULL AND lease_until >= $5`,
		batchID, status, outputID, errorID, now, leaseToken)
	if err != nil {
		return nil, fmt.Errorf("finalize batch_jobs: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("finalize batch %s: lease lost or superseded (token %d)", batchID, leaseToken)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit finalize batch: %w", err)
	}
	return s.getBatchInternal(ctx, batchID)
}

// MarkBatchFailed terminalizes a batch the executor could not progress
// (poison input, unrecoverable store state). Fenced on the lease token and
// the live lease, like FinalizeBatch: a failed worker from a dead generation
// must not terminalize the batch's current owner's run.
func (s *Store) MarkBatchFailed(ctx context.Context, batchID string, leaseToken int, reason string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE batch_jobs SET status = 'failed', last_error = $2, completed_at = now(), lease_until = NULL, updated_at = now()
		WHERE id = $1 AND attempts = $3 AND status IN ('in_progress', 'cancelling')
		  AND lease_until IS NOT NULL AND lease_until >= now()`, batchID, reason, leaseToken)
	if err != nil {
		return fmt.Errorf("fail batch_jobs: %w", err)
	}
	return nil
}

// RetentionSweep enforces the D3 30-day window: expired batches (lines
// cascade) and their result files go first, then every expired file row.
// Cadence-gated by the executor (bounded, batched deletes).
func (s *Store) RetentionSweep(ctx context.Context) error {
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin retention sweep: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		DELETE FROM batch_files WHERE id IN (
			SELECT COALESCE(output_file_id, '') FROM batch_jobs WHERE expires_at < $1
			UNION ALL
			SELECT COALESCE(error_file_id, '') FROM batch_jobs WHERE expires_at < $1
		)`, now); err != nil {
		return fmt.Errorf("delete expired batch result files: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM batch_jobs WHERE expires_at < $1", now); err != nil {
		return fmt.Errorf("delete expired batch_jobs: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM batch_files WHERE expires_at < $1", now); err != nil {
		return fmt.Errorf("delete expired batch_files: %w", err)
	}
	return tx.Commit(ctx)
}

// SweepOrphanUploads reclaims client uploads (purpose="batch") that no
// batch_jobs row references and that have waited out the grace window: the
// grace protects an upload raced against a concurrent CreateBatch, a
// referenced upload keeps the full D3 30-day retention (the batch row holds
// input_file_id until the retention sweep removes it), and executor-written
// purposes (batch.output / batch.error) plus the expires_at path are never
// touched here — RetentionSweep owns those. One transaction in the
// RetentionSweep style; returns the reclaimed row count. grace <= 0 is a
// no-op (the executor knob treats it as "disabled").
func (s *Store) SweepOrphanUploads(ctx context.Context, grace time.Duration) (int64, error) {
	if grace <= 0 {
		return 0, nil
	}
	cutoff := s.now().Add(-grace)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin orphan upload sweep: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		DELETE FROM batch_files
		WHERE purpose = $1 AND created_at < $2 AND id NOT IN (
			SELECT input_file_id FROM batch_jobs WHERE input_file_id IS NOT NULL)`,
		PurposeBatchInput, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete orphan batch_files: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit orphan upload sweep: %w", err)
	}
	return tag.RowsAffected(), nil
}
