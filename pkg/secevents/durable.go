// Durable sink (AUD-EVENT-01, owner audit 2026-11-02).
//
// The in-memory Ingester deduplication (ingest.go) is per-instance: it
// survives neither a process restart nor a second ingester instance, so a
// sink that simply appends double-records redelivered events (reproduced on
// the unmodified baseline; see the audit record). The sink therefore owns
// the durable exactly-once decision: DurableSink commits the document and
// the dedup decision in one statement (INSERT ... ON CONFLICT DO NOTHING),
// so persist-then-error retries, redeliveries after a restart and
// concurrent ingester instances all converge to exactly one durable JSON
// document per (org, event_id).
//
// Error semantics: a true storage failure returns an error so the Ingester
// leaves the event unseen and the delivery loop retries; a conflict with an
// already-durable document is success (nil), never an error that would
// stall a healthy redelivery. First write wins — a recorded document is
// never mutated by redeliveries.
//
// Wiring note: pkg/secevents is the additive enterprise SPI and has no
// production caller yet (integrations plug in through the Adapter/Ingester
// surface). The production home of the table DDL is migration
// 0021_secevents_documents (migrations/ and pkg/migrate/migrations/);
// EnsureSchema below is the idempotent bootstrap for SPI and test stands
// and is a no-op once the migration has run (its DDL mirrors migration
// 0021 plus IF NOT EXISTS).

package secevents

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// DurableDB is the minimal database surface DurableSink needs. It is
// satisfied directly by *pgxpool.Pool, *pgxpool.Conn and *pgx.Tx (the
// production connection surfaces) without a wrapper.
type DurableDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	// QueryRow and Begin carry the W04 §5.2 writer GUC-pin law: the pin and
	// the insert must share one transaction (see RecordContext).
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// durableSchemaSQL creates the security-event store. document is the
// canonical wire encoding at record time; recorded_at is server-side
// delivery bookkeeping and never rebases OccurredAt (skew semantics stay
// with the Ingester).
const durableSchemaSQL = `CREATE TABLE IF NOT EXISTS secevents_documents (
	org_id         TEXT        NOT NULL,
	event_id       TEXT        NOT NULL,
	schema_version INT         NOT NULL,
	event_type     TEXT        NOT NULL,
	occurred_at    TIMESTAMPTZ NOT NULL,
	document       JSONB       NOT NULL,
	recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (org_id, event_id)
)`

// durableNeedsPinSQL reports whether the current session is actually
// constrained by row-level security: superusers and BYPASSRLS roles bypass
// RLS (migration 0026 posture), so a pin would be inert for them — and, on
// PostgreSQL 14+, ANY set_config of a custom GUC leaves its session
// placeholder as ” for the rest of the connection's life (verified on the
// PG16 stand: autocommit, in-tx and post-commit RESET variants all leave
// ”). The pin is therefore skipped entirely for bypass sessions: the
// migration/superuser posture keeps pristine GUC-less connections, and the
// ” residue is fail-closed under the decided NULLIF policy anyway (an
// empty binding must match nothing). Table owners WITHOUT bypass are still
// constrained (0026 uses FORCE), and they get the pin.
const durableNeedsPinSQL = `SELECT EXISTS (
	SELECT 1 FROM pg_roles
	WHERE rolname = current_user AND (rolsuper OR rolbypassrls)
) AS bypass`

// durablePinSQL is the W04 §5.2 writer GUC-pin law: bind app.current_org
// transaction-locally so the org_isolation policy (migration 0026) admits
// the write. Inside the explicit transaction of RecordContext the is_local
// binding is truly transaction-local — cleared at commit/rollback, never
// carried into another org's transaction on a pooled connection.
const durablePinSQL = `SELECT set_config('app.current_org', $1, true)`

// durableInsertSQL is the exactly-once write: one statement, one row, a
// redelivery is a no-op. The durable exactly-once decision stays inside
// this statement (unique index arbitration), independent of the
// transaction around it.
const durableInsertSQL = `INSERT INTO secevents_documents
	(org_id, event_id, schema_version, event_type, occurred_at, document)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (org_id, event_id) DO NOTHING`

// DurableStatus reports what RecordContext did. It is only meaningful when
// RecordContext returned a nil error.
type DurableStatus int

const (
	// DurableInserted means this call wrote the durable document.
	DurableInserted DurableStatus = iota
	// DurableAlreadyPresent means the event was already durable (a
	// redelivery after a restart, a concurrent twin write, or a retry
	// after a lost acknowledgment); the existing document is untouched.
	DurableAlreadyPresent
)

// DurableSink persists every event exactly once into Postgres. It
// implements Sink; use it as the Ingester's sink so durability does not
// depend on any single ingester instance. Safe for concurrent use when the
// DurableDB is (pools and transactions are).
type DurableSink struct {
	db DurableDB
}

// NewDurableSink wraps db with exactly-once durable recording.
func NewDurableSink(db DurableDB) *DurableSink {
	return &DurableSink{db: db}
}

// EnsureSchema creates the store table if it is missing. In production the
// table comes from migration 0021_secevents_documents; this bootstrap is for
// SPI and test stands (see the package wiring note above).
func (s *DurableSink) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.Exec(ctx, durableSchemaSQL); err != nil {
		return fmt.Errorf("secevents: durable sink: ensure schema: %w", err)
	}
	return nil
}

// Record implements Sink: it establishes the durability of e — inserting
// the document or finding it already durable — and returns an error only
// when durability could not be established.
func (s *DurableSink) Record(e Event) error {
	_, err := s.RecordContext(context.Background(), e)
	return err
}

// RecordContext is Record with an explicit context (production callers with
// a request/deadline context should prefer it).
//
// Transaction shape (W04 §5.2): the pin — when the session needs it — and
// the insert run in ONE transaction, so the org_isolation policy of
// migration 0026 sees the binding at insert time and the binding cannot
// outlive the write. A same-statement CTE pin was tried and rejected: on
// PostgreSQL 14+ any set_config of a custom GUC (even transaction-local,
// even in autocommit) leaves the GUC's session placeholder as ” on the
// connection, and the dataflow guarantee the CTE relies on does not
// compensate for that residue on shared pools.
func (s *DurableSink) RecordContext(ctx context.Context, e Event) (DurableStatus, error) {
	if e.OrgID == "" || e.EventID == "" {
		// org_id/event_id key the store; Ingest validates them before the
		// sink runs, this guard keeps direct sink users from writing
		// null-key rows.
		return DurableAlreadyPresent, fmt.Errorf("secevents: durable sink: org_id and event_id are required")
	}
	doc, err := e.Encode()
	if err != nil {
		return DurableAlreadyPresent, fmt.Errorf("secevents: durable sink: encode: %w", err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return DurableAlreadyPresent, fmt.Errorf("secevents: durable sink: begin %s/%s: %w", e.OrgID, e.EventID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	var bypass bool
	if err := tx.QueryRow(ctx, durableNeedsPinSQL).Scan(&bypass); err != nil {
		return DurableAlreadyPresent, fmt.Errorf("secevents: durable sink: pin check %s/%s: %w", e.OrgID, e.EventID, err)
	}
	if !bypass {
		if _, err := tx.Exec(ctx, durablePinSQL, e.OrgID); err != nil {
			return DurableAlreadyPresent, fmt.Errorf("secevents: durable sink: pin org %s: %w", e.OrgID, err)
		}
	}
	tag, err := tx.Exec(ctx, durableInsertSQL,
		e.OrgID, e.EventID, e.SchemaVersion, e.EventType, e.OccurredAt, string(doc))
	if err != nil {
		return DurableAlreadyPresent, fmt.Errorf("secevents: durable sink: record %s/%s: %w", e.OrgID, e.EventID, err)
	}
	inserted := tag.RowsAffected() == 1
	if err := tx.Commit(ctx); err != nil {
		return DurableAlreadyPresent, fmt.Errorf("secevents: durable sink: commit %s/%s: %w", e.OrgID, e.EventID, err)
	}
	if !inserted {
		return DurableAlreadyPresent, nil
	}
	return DurableInserted, nil
}
