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

const expireAdmissionsSQL = `WITH stale AS (
 SELECT a.invocation_id FROM request_admissions a
 WHERE a.state='admitted' AND a.admitted_at < now() - make_interval(secs => $1)
 AND NOT EXISTS (SELECT 1 FROM request_terminal_facts f WHERE f.invocation_id=a.invocation_id)
 ORDER BY a.admitted_at, a.invocation_id LIMIT $2 FOR UPDATE OF a SKIP LOCKED
)
UPDATE request_admissions a SET state='unresolved',resolved_at=now(),resolve_reason='grace_elapsed_no_terminal_facts'
FROM stale WHERE a.invocation_id=stale.invocation_id AND a.state='admitted'
AND NOT EXISTS (SELECT 1 FROM request_terminal_facts f WHERE f.invocation_id=a.invocation_id)`

const pendingFactsSQL = `SELECT a.invocation_id::text,a.org_id,a.kind,f.kind,coalesce(a.client_request_id,''),coalesce(f.client_request_id,''),f.event
FROM request_admissions a JOIN request_terminal_facts f USING(invocation_id,org_id)
WHERE a.state IN ('admitted','unresolved') AND a.invocation_id > $1::uuid
ORDER BY a.invocation_id LIMIT $2`

const initialRecoveryCursor = "00000000-0000-0000-0000-000000000000"

type recoveryFact struct {
	id, orgID, admittedKind, terminalKind, correlation, terminalCorrelation string
	data                                                                    []byte
}

func readRecoveryFact(row pgx.CollectableRow) (recoveryFact, error) {
	var fact recoveryFact
	err := row.Scan(&fact.id, &fact.orgID, &fact.admittedKind, &fact.terminalKind, &fact.correlation, &fact.terminalCorrelation, &fact.data)
	return fact, err
}

// RunAdmissionRecovery reconciles durable provider facts without dispatching
// upstream or depending on Redis delivery. Its context owns one leadership term.
func (c *StreamConsumer) RunAdmissionRecovery(ctx context.Context, db SettlementDB) {
	cursor := initialRecoveryCursor
	for ctx.Err() == nil {
		next, more, err := c.recoverAdmissionBatch(ctx, db, cursor)
		if err != nil && ctx.Err() == nil {
			c.logger.Error("cannot scan admission recovery queue", "error", err)
		}
		if err == nil && more {
			cursor = next
			continue
		}
		cursor = initialRecoveryCursor
		timer := time.NewTimer(recoveryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (c *StreamConsumer) recoverAdmissionBatch(ctx context.Context, db SettlementDB, cursor string) (string, bool, error) {
	tag, err := db.Exec(ctx, expireAdmissionsSQL, recoveryGraceSeconds, recoveryBatchSize)
	if err != nil {
		return cursor, false, fmt.Errorf("expire unconfirmed provider usage: %w", err)
	}
	if n := tag.RowsAffected(); n > 0 {
		c.logger.Warn("admissions have no terminal usage evidence", "count", n)
	}
	rows, err := db.Query(ctx, pendingFactsSQL, cursor, recoveryBatchSize)
	if err != nil {
		return cursor, false, err
	}
	// Release the scanning connection before per-invocation transactions, even
	// on a single-connection pool. One bad fact must not block later pages.
	facts, err := pgx.CollectRows(rows, readRecoveryFact)
	if err != nil {
		return cursor, false, err
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
	return initialRecoveryCursor, tag.RowsAffected() == recoveryBatchSize, nil
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
