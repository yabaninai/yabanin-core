package consumer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
)

const (
	recoveryBatchSize    = 128
	recoveryInterval     = 15 * time.Second
	recoveryGraceSeconds = 15 * 60
)

const staleWithoutFacts = `a.state='admitted' AND a.admitted_at < now() - make_interval(secs => $1)
 AND NOT EXISTS (SELECT 1 FROM request_terminal_facts f WHERE f.invocation_id=a.invocation_id AND f.org_id=a.org_id)`
const staleAdmissionIDs = `SELECT a.invocation_id::text FROM request_admissions a WHERE ` + staleWithoutFacts +
	` AND a.invocation_id > $2::uuid ORDER BY a.invocation_id LIMIT $3`
const expireAdmissionSQL = `UPDATE request_admissions SET state='unresolved',resolved_at=now(),resolve_reason='grace_elapsed_no_terminal_facts'
 WHERE invocation_id=(SELECT a.invocation_id FROM request_admissions a WHERE a.invocation_id=$2::uuid AND ` + staleWithoutFacts + ` FOR UPDATE SKIP LOCKED)`

const factColumns = `a.invocation_id::text,a.org_id,a.kind,f.kind,coalesce(a.client_request_id,''),coalesce(f.client_request_id,''),f.event`
const pendingSource = ` FROM request_admissions a JOIN request_terminal_facts f USING(invocation_id,org_id)
WHERE a.state IN ('admitted','unresolved')`
const afterCursor = ` AND a.invocation_id > $1::uuid ORDER BY a.invocation_id LIMIT $2`
const pendingFactsSQL = "SELECT " + factColumns + pendingSource + afterCursor
const pendingIDsSQL = "SELECT a.invocation_id::text" + pendingSource + afterCursor
const pendingFactSQL = "SELECT " + factColumns + pendingSource + ` AND a.invocation_id=$1::uuid`

const initialRecoveryCursor = "00000000-0000-0000-0000-000000000000"

type recoveryFact struct {
	id, orgID, admittedKind, terminalKind, correlation, terminalCorrelation string
	data                                                                    []byte
}

func readRecoveryFact(row pgx.Row) (recoveryFact, error) {
	var fact recoveryFact
	err := row.Scan(&fact.id, &fact.orgID, &fact.admittedKind, &fact.terminalKind, &fact.correlation, &fact.terminalCorrelation, &fact.data)
	return fact, err
}

// RunAdmissionRecovery reconciles durable provider facts without dispatching
// upstream or depending on Redis delivery. Its context owns one leadership term.
func (c *StreamConsumer) RunAdmissionRecovery(ctx context.Context, db SettlementDB) {
	cursor := initialRecoveryCursor
	expiryCursor := initialRecoveryCursor
	var nextExpiry time.Time
	for ctx.Err() == nil {
		if !time.Now().Before(nextExpiry) {
			expiryCursor, nextExpiry = c.expireAdmissionBatch(ctx, db, expiryCursor)
		}
		next, more, err := c.recoverAdmissionBatch(ctx, db, cursor)
		cursor = next
		if err != nil && ctx.Err() == nil {
			c.logger.Error("cannot scan admission recovery queue", "error", err)
		}
		if err == nil && (more || nextExpiry.IsZero()) {
			continue
		}
		if !sleepCtx(ctx, recoveryInterval) {
			return
		}
	}
}

// Expiry runs once per stale invocation. One failed transition leaves its
// admission retryable without rolling back its neighbors.
func (c *StreamConsumer) expireAdmissionBatch(ctx context.Context, db SettlementDB, cursor string) (string, time.Time) {
	expiryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	retry := time.Now().Add(recoveryInterval)
	rows, err := db.Query(expiryCtx, staleAdmissionIDs, recoveryGraceSeconds, cursor, recoveryBatchSize)
	if err != nil {
		c.logger.Error("cannot list stale admissions", "error", err)
		return cursor, retry
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		c.logger.Error("cannot read stale admissions", "error", err)
		return cursor, retry
	}
	for _, id := range ids {
		if expiryCtx.Err() != nil {
			return cursor, retry
		}
		tag, err := db.Exec(expiryCtx, expireAdmissionSQL, recoveryGraceSeconds, id)
		switch {
		case err != nil:
			c.logger.Error("could not expire stale admission", "invocation_id", id, "error", err)
		case tag.RowsAffected() > 0:
			c.logger.Warn("admission has no terminal usage evidence", "invocation_id", id)
		}
		cursor = id
	}
	if len(ids) == recoveryBatchSize {
		return cursor, time.Time{}
	}
	return initialRecoveryCursor, retry
}

func (c *StreamConsumer) recoverAdmissionBatch(ctx context.Context, db SettlementDB, cursor string) (string, bool, error) {
	rows, err := db.Query(ctx, pendingFactsSQL, cursor, recoveryBatchSize)
	if err != nil {
		return cursor, false, err
	}
	// Release the scanning connection before per-invocation transactions, even
	// on a single-connection pool. One bad fact must not block later pages.
	facts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (recoveryFact, error) { return readRecoveryFact(row) })
	if err != nil {
		c.logger.Warn("cannot read admission recovery page; checking individual facts", "error", err)
		return c.recoverIndividualFacts(ctx, db, cursor)
	}
	for _, fact := range facts {
		if err := ctx.Err(); err != nil {
			return cursor, false, err
		}
		if err := c.recoverAdmission(ctx, fact); err != nil {
			c.logger.Error("terminal facts could not be reconciled", "invocation_id", fact.id, "error", err)
		}
		cursor = fact.id
	}
	if len(facts) == recoveryBatchSize {
		return cursor, true, nil
	}
	return initialRecoveryCursor, false, nil
}

// A row-specific decode or scan error must not strand subsequent UUIDs.
func (c *StreamConsumer) recoverIndividualFacts(ctx context.Context, db SettlementDB, cursor string) (string, bool, error) {
	rows, err := db.Query(ctx, pendingIDsSQL, cursor, recoveryBatchSize)
	if err != nil {
		return cursor, false, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return cursor, false, fmt.Errorf("read pending invocation IDs: %w", err)
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return cursor, false, err
		}
		fact, err := readRecoveryFact(db.QueryRow(ctx, pendingFactSQL, id))
		if err == nil {
			err = c.recoverAdmission(ctx, fact)
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			c.logger.Error("cannot recover individual invocation", "invocation_id", id, "error", err)
		}
		cursor = id
	}
	if len(ids) == recoveryBatchSize {
		return cursor, true, nil
	}
	return initialRecoveryCursor, false, nil
}

func (c *StreamConsumer) recoverAdmission(ctx context.Context, fact recoveryFact) error {
	if fact.admittedKind != fact.terminalKind || fact.correlation != fact.terminalCorrelation {
		return errors.New("terminal identity does not match admission")
	}
	fields, err := eventpublisher.DecodeTerminalAccounting(fact.data, fact.id, fact.orgID)
	if err != nil {
		return err
	}
	if fields["request_id"] != fact.correlation {
		return errors.New("terminal request correlation differs from admission")
	}
	policy := factsDeliveryPolicy()
	policy.recoveredFromFacts = true
	// No stream delivery occurred. An empty ID deliberately bypasses the
	// Redis inbox claim; the locked admission and invocation uniqueness govern replay.
	return c.deliverEventPolicy(ctx, redis.XMessage{Values: fields}, fields["event_type"].(string), policy)
}
