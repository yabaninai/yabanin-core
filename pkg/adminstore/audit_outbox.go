package adminstore

// N10-P04-T04: strict commit/outbox/dedup rules for audit (and, by
// construction, rights and accounting records that share the same Postgres
// durability class) must be observable: the durability GAP between a durable
// outbox intent and its hash-chained journal row, the DEAD LETTERS that keep
// failing delivery, and the RECOVERY that drains them once the outage ends.
//
// This file adds the read model and the operator recovery primitive on top
// of the existing admin_audit_outbox mechanics (audit.go). It deliberately
// needs NO schema change: classification is derived from the existing
// attempts/next_attempt_at/last_error columns, so a schema rollback stays
// safe and the outbox keeps working for pre-card binaries.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditOutboxDeadLetterAttempts is the failed-delivery count at which an
// outbox row is classified as a dead letter. Under failOutboxRow's capped
// exponential backoff (2s doubling, 3600s cap) twelve consecutive failures
// amount to more than two hours of continuous undeliverability — well past
// any transient blip the drain is expected to ride out.
//
// The classification is observability and operator surface ONLY: mandatory
// audit is RPO=0 (owner decision I44), so the drain NEVER stops retrying
// dead-letter rows. A dead letter means "operator attention required", not
// "give up" — dropping a mandatory audit entry is never an option.
const AuditOutboxDeadLetterAttempts = 12

// AuditOutboxStatusReport is the durability read model for the audit outbox.
//
// Pending is the GAP: durable intents committed to the outbox that have not
// reached the hash-chained journal yet. While Pending > 0 the journal is
// missing rows that ARE durably recorded elsewhere — a reader comparing only
// the journal sees a gap that this number makes explicit. Due is the subset
// the drain will pick up on its next pass; Retrying counts rows that already
// failed at least once and are inside their backoff window; DeadLetters is
// the subset at or beyond AuditOutboxDeadLetterAttempts.
type AuditOutboxStatusReport struct {
	// Pending is the total number of undelivered outbox rows (the gap).
	Pending int64
	// Due counts rows whose backoff expired: the drain delivers them next.
	Due int64
	// Retrying counts failed rows still inside their backoff window below
	// the dead-letter threshold.
	Retrying int64
	// DeadLetters counts rows with attempts >= AuditOutboxDeadLetterAttempts.
	// The drain keeps retrying them (RPO=0); operators must intervene.
	DeadLetters int64
	// OldestPendingAge is how long the oldest pending intent has waited —
	// the age of the open gap (0 when the outbox is empty).
	OldestPendingAge time.Duration
	// LastError is the most recent persisted failure reason (the dead-letter
	// row with the most attempts, newest first), empty when nothing failed.
	LastError string
	// LastErrorID is the outbox row id LastError belongs to.
	LastErrorID string
}

// AuditOutboxStatus reports the outbox durability state (gaps, dead letters)
// for the journal readers and operator runbooks. A nil-db store (audit
// disabled) reports an empty, healthy status.
func (s *Store) AuditOutboxStatus(ctx context.Context) (AuditOutboxStatusReport, error) {
	var report AuditOutboxStatusReport
	if s.db == nil {
		return report, nil
	}

	var oldestPending time.Time
	err := s.db.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE next_attempt_at <= now()),
		       count(*) FILTER (WHERE attempts > 0 AND attempts < $1),
		       count(*) FILTER (WHERE attempts >= $1),
		       COALESCE(MIN(created_at), now())
		FROM admin_audit_outbox`, AuditOutboxDeadLetterAttempts).Scan(
		&report.Pending,
		&report.Due,
		&report.Retrying,
		&report.DeadLetters,
		&oldestPending)
	if err != nil {
		return AuditOutboxStatusReport{}, fmt.Errorf("read audit outbox status: %w", err)
	}
	if report.Pending > 0 {
		report.OldestPendingAge = time.Since(oldestPending)
	}

	// Sample the loudest persisted failure: the row closest to the
	// dead-letter threshold, newest first on ties. A pure read-model sample,
	// never an authority on any single row's state.
	err = s.db.QueryRow(ctx, `
		SELECT id, last_error
		FROM admin_audit_outbox
		WHERE last_error IS NOT NULL
		ORDER BY attempts DESC, created_at DESC, id
		LIMIT 1`).Scan(&report.LastErrorID, &report.LastError)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return AuditOutboxStatusReport{}, fmt.Errorf("read audit outbox last error: %w", err)
	}

	return report, nil
}

// RequeueAuditOutboxDeadLetter is the operator recovery primitive for a dead
// letter: it resets the attempt counter and backoff so the very next drain
// pass retries the row immediately. Only dead-letter rows (attempts >=
// AuditOutboxDeadLetterAttempts) may be requeued — a healthy backoff is
// never eaten, and unknown ids report false rather than pretending recovery
// happened. The payload is untouched: if it is permanently undecodable the
// row will fail back into the dead-letter state loudly.
func (s *Store) RequeueAuditOutboxDeadLetter(ctx context.Context, id string) (bool, error) {
	if s.db == nil {
		return false, nil
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE admin_audit_outbox
		SET attempts = 0, last_error = NULL, next_attempt_at = now()
		WHERE id = $1 AND attempts >= $2`, id, AuditOutboxDeadLetterAttempts)
	if err != nil {
		return false, fmt.Errorf("requeue audit outbox dead letter: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
