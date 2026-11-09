// Incident store for the unified security inbox (E06-P01 W01-C02).
//
// The store owns every security_inbox statement. It follows the two GUC
// laws landed by W01-C01, applied to the inbox's own table:
//
//   - writes mirror the secevents writer law: Begin → bypass check →
//     (pin only when the session is RLS-bound) → statement → Commit, so
//     superuser/rolbypassrls stands keep pristine GUC-less connections
//     (on PG14+ any set_config of a custom GUC leaves a '' session
//     placeholder for the connection's life — see durable.go);
//   - reads mirror the Reader law: Begin → pin → select → Commit, with
//     the explicit org_id predicate kept as defense-in-depth (RLS is the
//     boundary, the WHERE is the second lock).
//
// The upsert never writes status/assignee — operator state (W04) survives
// every projection fold — and first_seen/first_event_id only ever move
// down the LEAST side, so the group's origin survives too. A replayed or
// late event advances counts and last_seen and nothing else.

package inbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// IncidentDB is the surface the store needs. Satisfied by *pgxpool.Pool,
// *pgxpool.Conn and *pgx.Tx — same shape as ReaderDB plus QueryRow.
type IncidentDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}

// storeNeedsPinSQL is the inbox twin of the secevents writer's bypass
// check (durableNeedsPinSQL): superuser/rolbypassrls sessions skip the
// GUC pin entirely — for them it is inert residue, and keeping their
// connections GUC-less is a standing test invariant (the W05 probe).
const storeNeedsPinSQL = `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolbypassrls)) AS bypass`

// ErrStoreOrgRequired mirrors the reader law: the store never operates
// without a concrete org — an empty scope is refused, never "all rows".
var ErrStoreOrgRequired = errors.New("inbox: store: org id required (uuid.Nil refused)")

// storeUpsertSQL folds one draft into the incident table. The UNIQUE
// (org_id, group_key) constraint is the replay/collision lock: a
// concurrent or repeated fold merges into the existing row (counts++ /
// last_seen forward), never a second incident. first_seen/first_event_id
// take the LEAST and last_seen/last_event_id/evidence take the GREATEST
// side, so out-of-order delivery folds identically to in-order; ties
// resolve to the incoming event — deterministic under the reader's
// (occurred_at, event_id) total order.
const storeUpsertSQL = `
INSERT INTO security_inbox
  (org_id, group_key, summary, severity, confidence, first_seen, last_seen,
   event_count, first_event_id, last_event_id, evidence)
VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9, $10)
ON CONFLICT (org_id, group_key) DO UPDATE SET
  summary = EXCLUDED.summary,
  severity = EXCLUDED.severity,
  confidence = EXCLUDED.confidence,
  first_seen = LEAST(security_inbox.first_seen, EXCLUDED.first_seen),
  first_event_id = CASE WHEN EXCLUDED.first_seen < security_inbox.first_seen
    THEN EXCLUDED.first_event_id ELSE security_inbox.first_event_id END,
  last_seen = GREATEST(security_inbox.last_seen, EXCLUDED.last_seen),
  event_count = security_inbox.event_count + 1,
  last_event_id = CASE WHEN EXCLUDED.last_seen >= security_inbox.last_seen
    THEN EXCLUDED.last_event_id ELSE security_inbox.last_event_id END,
  evidence = CASE WHEN EXCLUDED.last_seen >= security_inbox.last_seen
    THEN EXCLUDED.evidence ELSE security_inbox.evidence END,
  updated_at = now()
RETURNING id, org_id, group_key, summary, severity, confidence, status,
  assignee, first_seen, last_seen, event_count, first_event_id,
  last_event_id, evidence, created_at, updated_at`

// storeListSQL is the W01 read surface (and the W05-C02 keyset order):
// newest activity first, (last_seen DESC, id) is the stable total order
// served by the 0027 index.
const storeListSQL = `
SELECT id, org_id, group_key, summary, severity, confidence, status,
  assignee, first_seen, last_seen, event_count, first_event_id,
  last_event_id, evidence, created_at, updated_at
FROM security_inbox
WHERE org_id = $1
ORDER BY last_seen DESC, id`

// storeGetSQL fetches one incident inside the org scope (the W01-C03
// detail endpoint's read).
const storeGetSQL = `
SELECT id, org_id, group_key, summary, severity, confidence, status,
  assignee, first_seen, last_seen, event_count, first_event_id,
  last_event_id, evidence, created_at, updated_at
FROM security_inbox
WHERE org_id = $1 AND id = $2`

// Store reads and writes security_inbox incidents for exactly one org
// per call.
type Store struct {
	db IncidentDB
}

// NewStore wraps a database handle.
func NewStore(db IncidentDB) *Store {
	return &Store{db: db}
}

// IncidentDraft is the projection's per-event contribution to an
// incident: everything the fold may set. Operator fields
// (status/assignee) are deliberately absent — the upsert never writes
// them; the draft's OccurredAt/EventID reach first_seen/first_event_id
// only through the upsert's LEAST side.
type IncidentDraft struct {
	GroupKey   string
	Summary    string
	Severity   string
	Confidence float64
	OccurredAt time.Time
	EventID    string
	Evidence   []secevents.EvidenceRef
}

// Upsert folds one draft into the org's inbox and returns the resulting
// row (post-fold state, deterministic).
func (s *Store) Upsert(ctx context.Context, orgID uuid.UUID, d IncidentDraft) (Incident, error) {
	if orgID == uuid.Nil {
		return Incident{}, ErrStoreOrgRequired
	}
	draft := Incident{
		OrgID:        orgID,
		GroupKey:     d.GroupKey,
		Summary:      d.Summary,
		Severity:     d.Severity,
		Confidence:   d.Confidence,
		Status:       StatusNew,
		FirstSeen:    d.OccurredAt,
		LastSeen:     d.OccurredAt,
		EventCount:   1,
		FirstEventID: d.EventID,
		LastEventID:  d.EventID,
	}
	if err := draft.Validate(); err != nil {
		return Incident{}, err
	}
	if d.Evidence == nil {
		d.Evidence = []secevents.EvidenceRef{} // column contract is an array, never JSON null
	}
	evJSON, err := json.Marshal(d.Evidence)
	if err != nil {
		return Incident{}, fmt.Errorf("inbox: store: marshal evidence: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Incident{}, fmt.Errorf("inbox: store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// Writer law: pin only when the session is RLS-bound.
	var bypass bool
	if err := tx.QueryRow(ctx, storeNeedsPinSQL).Scan(&bypass); err != nil {
		return Incident{}, fmt.Errorf("inbox: store: pin probe: %w", err)
	}
	if !bypass {
		if _, err := tx.Exec(ctx, readerPinSQL, orgID.String()); err != nil {
			return Incident{}, fmt.Errorf("inbox: store: pin: %w", err)
		}
	}

	var inc Incident
	var evidence []byte
	if err := tx.QueryRow(ctx, storeUpsertSQL,
		orgID, d.GroupKey, d.Summary, d.Severity, d.Confidence,
		d.OccurredAt, d.OccurredAt, d.EventID, d.EventID, evJSON,
	).Scan(
		&inc.ID, &inc.OrgID, &inc.GroupKey, &inc.Summary, &inc.Severity,
		&inc.Confidence, &inc.Status, &inc.Assignee, &inc.FirstSeen,
		&inc.LastSeen, &inc.EventCount, &inc.FirstEventID, &inc.LastEventID,
		&evidence, &inc.CreatedAt, &inc.UpdatedAt,
	); err != nil {
		return Incident{}, fmt.Errorf("inbox: store: upsert: %w", err)
	}
	if err := json.Unmarshal(evidence, &inc.Evidence); err != nil {
		return Incident{}, fmt.Errorf("inbox: store: unmarshal evidence: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Incident{}, fmt.Errorf("inbox: store: commit: %w", err)
	}
	return inc, nil
}

// List returns the org's incidents, newest activity first. An org with
// no incidents is an empty slice, never an error (the W01-C03 "200 []"
// contract).
func (s *Store) List(ctx context.Context, orgID uuid.UUID) ([]Incident, error) {
	if orgID == uuid.Nil {
		return nil, ErrStoreOrgRequired
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("inbox: store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// Reader law: pin + explicit predicate in one transaction.
	if _, err := tx.Exec(ctx, readerPinSQL, orgID.String()); err != nil {
		return nil, fmt.Errorf("inbox: store: pin: %w", err)
	}
	rows, err := tx.Query(ctx, storeListSQL, orgID)
	if err != nil {
		return nil, fmt.Errorf("inbox: store: list: %w", err)
	}
	incs, err := scanIncidents(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inbox: store: list rows: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("inbox: store: commit: %w", err)
	}
	return incs, nil
}

// Get fetches one incident by id inside the org scope. ok=false (no
// error) when the incident does not exist in this org.
func (s *Store) Get(ctx context.Context, orgID, incidentID uuid.UUID) (Incident, bool, error) {
	if orgID == uuid.Nil {
		return Incident{}, false, ErrStoreOrgRequired
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Incident{}, false, fmt.Errorf("inbox: store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	if _, err := tx.Exec(ctx, readerPinSQL, orgID.String()); err != nil {
		return Incident{}, false, fmt.Errorf("inbox: store: pin: %w", err)
	}
	var inc Incident
	var evidence []byte
	err = tx.QueryRow(ctx, storeGetSQL, orgID, incidentID).Scan(
		&inc.ID, &inc.OrgID, &inc.GroupKey, &inc.Summary, &inc.Severity,
		&inc.Confidence, &inc.Status, &inc.Assignee, &inc.FirstSeen,
		&inc.LastSeen, &inc.EventCount, &inc.FirstEventID, &inc.LastEventID,
		&evidence, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, false, nil
	}
	if err != nil {
		return Incident{}, false, fmt.Errorf("inbox: store: get: %w", err)
	}
	if err := json.Unmarshal(evidence, &inc.Evidence); err != nil {
		return Incident{}, false, fmt.Errorf("inbox: store: unmarshal evidence: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Incident{}, false, fmt.Errorf("inbox: store: commit: %w", err)
	}
	return inc, true, nil
}

func scanIncidents(rows pgx.Rows) ([]Incident, error) {
	out := []Incident{}
	for rows.Next() {
		var inc Incident
		var evidence []byte
		if err := rows.Scan(
			&inc.ID, &inc.OrgID, &inc.GroupKey, &inc.Summary, &inc.Severity,
			&inc.Confidence, &inc.Status, &inc.Assignee, &inc.FirstSeen,
			&inc.LastSeen, &inc.EventCount, &inc.FirstEventID, &inc.LastEventID,
			&evidence, &inc.CreatedAt, &inc.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("inbox: store: scan incident: %w", err)
		}
		if err := json.Unmarshal(evidence, &inc.Evidence); err != nil {
			return nil, fmt.Errorf("inbox: store: unmarshal evidence: %w", err)
		}
		out = append(out, inc)
	}
	return out, nil
}
