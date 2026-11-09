// Fleet caps store (E03-P01, batch B, card W03-C03): the persistent home
// of the installation registry behind migration 0024_fleet_registry.
//
// The store owns every fleet_installations statement and follows the E06
// inbox store law (pkg/inbox/store.go) applied to this table:
//
//   - writes: Begin → bypass check → (pin only when the session is
//     RLS-bound) → statement → Commit, so superuser/rolbypassrls stands
//     keep pristine GUC-less connections;
//   - reads: Begin → pin → select → Commit, with the explicit org_id
//     predicate kept as defense-in-depth (RLS is the boundary, the WHERE
//     is the second lock);
//   - the store never operates without a concrete org: an empty scope is
//     refused BEFORE any statement, never "all rows" (the reader law);
//   - timestamps are caller-injected (package determinism law): no now()
//     in any statement — the clock arrives as a parameter.
//
// Lifecycle law at the persistence layer: the store never transitions
// states (that is ValidateTransition's law, identity.go — revocation,
// enrollment and health own their transitions); UpsertCaps only writes
// the caps document of an existing installation or creates a row in the
// enrolled state, and a REVOKED row is terminal — a caps refresh on it is
// refused with ErrRevoked, never a silent overwrite.
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// DB is the surface the store needs. Satisfied by *pgxpool.Pool,
// *pgxpool.Conn and *pgx.Tx (the IncidentDB shape).
type DB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}

// fleetNeedsPinSQL is the fleet twin of the secevents writer's bypass
// check (durable.go / inbox store.go): superuser/rolbypassrls sessions
// skip the GUC pin entirely — for them it is inert residue, and keeping
// their connections GUC-less is a standing test invariant.
const fleetNeedsPinSQL = `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolbypassrls)) AS bypass`

// fleetPinSQL pins the org scope for this transaction (the reader law;
// transaction-local, mirrors the house GUC app.current_org of 0002/0026).
const fleetPinSQL = `SELECT set_config('app.current_org', $1, true)`

// ErrFleetStoreOrgRequired mirrors the reader law: the store never
// operates without a concrete org — an empty scope is refused BEFORE any
// statement, never "all rows".
var ErrFleetStoreOrgRequired = errors.New("fleet: store: org id required (empty refused)")

// fleetUpsertSQL writes one installation's caps document. New rows are
// born enrolled (the registry's first sight of a contour IS its verified
// enrollment record); existing rows keep their lifecycle state — only the
// caps document and its stamp move, and the WHERE state <> 'revoked'
// clause keeps revoked terminal at the SQL layer too (belt beside the
// store's own refusal).
const fleetUpsertSQL = `
INSERT INTO fleet_installations
  (org_id, deployment_id, state, caps, enrolled_at, caps_updated_at)
VALUES ($1, $2, $3, $4, $5, $5)
ON CONFLICT (org_id, deployment_id) DO UPDATE SET
  caps = EXCLUDED.caps,
  caps_updated_at = EXCLUDED.caps_updated_at
WHERE fleet_installations.state <> 'revoked'`

// fleetGetSQL fetches one installation inside the org scope.
const fleetGetSQL = `
SELECT org_id, deployment_id, state, caps, enrolled_at, caps_updated_at,
  last_heartbeat_at, revoked_at, revocation_reason
FROM fleet_installations
WHERE org_id = $1 AND deployment_id = $2`

// fleetListSQL is the org-scan read surface (the W04-C03 list endpoint):
// deterministic (deployment_id) order inside the org.
const fleetListSQL = `
SELECT org_id, deployment_id, state, caps, enrolled_at, caps_updated_at,
  last_heartbeat_at, revoked_at, revocation_reason
FROM fleet_installations
WHERE org_id = $1
ORDER BY deployment_id`

// CapsStore reads and writes fleet_installations rows for exactly one
// org per call.
type CapsStore struct {
	db DB
}

// NewCapsStore wraps a database handle.
func NewCapsStore(db DB) *CapsStore { return &CapsStore{db: db} }

// StoredInstallation is one registry row: the identity pair, the
// lifecycle state and its stamps, and the persisted caps document. It
// carries no secrets (the packet law — identity-model.md §2); Caps is
// the document exactly as negotiated (and persisted) at caps_updated_at.
type StoredInstallation struct {
	Identity
	State            State
	Caps             NegotiatedCaps
	EnrolledAt       time.Time
	CapsUpdatedAt    time.Time
	LastHeartbeatAt  *time.Time
	RevokedAt        *time.Time
	RevocationReason string
}

// UpsertCaps persists the negotiated caps document for one installation
// (orgID, deploymentID), creating the row in the enrolled state on first
// sight or refreshing the document of an existing row. now is the
// caller-injected clock (determinism law). Refused: empty/invalid org or
// deployment coordinates (before any statement), a caps document whose
// version is outside the supported matrix (the store persists only
// negotiable documents), and a revoked installation (terminal — never a
// silent overwrite).
func (s *CapsStore) UpsertCaps(ctx context.Context, orgID, deploymentID string, caps NegotiatedCaps, now time.Time) error {
	if orgID == "" {
		return ErrFleetStoreOrgRequired
	}
	if err := ValidateOrgID(orgID); err != nil {
		return err
	}
	if err := ValidateDeploymentID(deploymentID); err != nil {
		return err
	}
	if err := validateCapsVersionToken("caps format_version", caps.FormatVersion); err != nil {
		return err
	}
	if !supportedCapsVersion(caps.FormatVersion) {
		return fmt.Errorf("%w: refusing to persist %q", ErrUnknownCapsVersion, caps.FormatVersion)
	}
	capsJSON, err := json.Marshal(caps)
	if err != nil {
		return fmt.Errorf("fleet: store: marshal caps: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("fleet: store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// Writer law: pin only when the session is RLS-bound.
	var bypass bool
	if err := tx.QueryRow(ctx, fleetNeedsPinSQL).Scan(&bypass); err != nil {
		return fmt.Errorf("fleet: store: pin probe: %w", err)
	}
	if !bypass {
		if _, err := tx.Exec(ctx, fleetPinSQL, orgID); err != nil {
			return fmt.Errorf("fleet: store: pin: %w", err)
		}
	}

	tag, err := tx.Exec(ctx, fleetUpsertSQL,
		orgID, deploymentID, string(StateEnrolled), capsJSON, now,
	)
	if err != nil {
		return fmt.Errorf("fleet: store: upsert: %w", err)
	}
	// One row written or refreshed; zero rows means the target exists in
	// the revoked state (the upsert's WHERE refused it) — the terminality
	// law surfaces as ErrRevoked, not as a silent no-op. The state is
	// probed INSIDE the same transaction, so the verdict matches the
	// refused write's snapshot.
	if tag.RowsAffected() == 0 {
		var existingState State
		err := tx.QueryRow(ctx,
			`SELECT state FROM fleet_installations WHERE org_id = $1 AND deployment_id = $2`,
			orgID, deploymentID,
		).Scan(&existingState)
		if err != nil {
			return fmt.Errorf("fleet: store: upsert refused, state probe failed: %w", err)
		}
		if existingState == StateRevoked {
			return fmt.Errorf("%w: caps refresh on %q refused", ErrRevoked, deploymentID)
		}
		return fmt.Errorf("fleet: store: upsert affected no rows for %q", deploymentID)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("fleet: store: commit: %w", err)
	}
	return nil
}

// Get fetches one installation by identity inside the org scope.
// ok=false (no error) when the installation does not exist in this org.
func (s *CapsStore) Get(ctx context.Context, orgID, deploymentID string) (StoredInstallation, bool, error) {
	if orgID == "" {
		return StoredInstallation{}, false, ErrFleetStoreOrgRequired
	}
	if err := ValidateOrgID(orgID); err != nil {
		return StoredInstallation{}, false, err
	}
	if err := ValidateDeploymentID(deploymentID); err != nil {
		return StoredInstallation{}, false, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return StoredInstallation{}, false, fmt.Errorf("fleet: store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// Reader law: pin + explicit predicate in one transaction.
	if _, err := tx.Exec(ctx, fleetPinSQL, orgID); err != nil {
		return StoredInstallation{}, false, fmt.Errorf("fleet: store: pin: %w", err)
	}
	rec, err := scanInstallation(tx.QueryRow(ctx, fleetGetSQL, orgID, deploymentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredInstallation{}, false, nil
	}
	if err != nil {
		return StoredInstallation{}, false, fmt.Errorf("fleet: store: get: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return StoredInstallation{}, false, fmt.Errorf("fleet: store: commit: %w", err)
	}
	return rec, true, nil
}

// List returns the org's installations in deterministic deployment_id
// order. An org with no installations is an empty slice, never an error.
func (s *CapsStore) List(ctx context.Context, orgID string) ([]StoredInstallation, error) {
	if orgID == "" {
		return nil, ErrFleetStoreOrgRequired
	}
	if err := ValidateOrgID(orgID); err != nil {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("fleet: store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	if _, err := tx.Exec(ctx, fleetPinSQL, orgID); err != nil {
		return nil, fmt.Errorf("fleet: store: pin: %w", err)
	}
	rows, err := tx.Query(ctx, fleetListSQL, orgID)
	if err != nil {
		return nil, fmt.Errorf("fleet: store: list: %w", err)
	}
	out := []StoredInstallation{}
	for rows.Next() {
		rec, err := scanInstallation(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("fleet: store: scan installation: %w", err)
		}
		out = append(out, rec)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("fleet: store: list rows: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("fleet: store: commit: %w", err)
	}
	return out, nil
}

// rowScanner is the pgx scan surface shared by QueryRow results and Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanInstallation decodes one registry row. The caps document is read
// back TOLERANTLY: a stored document naming a future version (written by
// a newer core, read by this one) decodes as-is and stays visible to the
// drift layer (W04-C02) — the read path never refuses what the registry
// honestly holds; unknown NAMES equally survive the round-trip.
func scanInstallation(row rowScanner) (StoredInstallation, error) {
	var rec StoredInstallation
	var capsJSON []byte
	if err := row.Scan(
		&rec.OrgID, &rec.DeploymentID, &rec.State, &capsJSON,
		&rec.EnrolledAt, &rec.CapsUpdatedAt,
		&rec.LastHeartbeatAt, &rec.RevokedAt, &rec.RevocationReason,
	); err != nil {
		return StoredInstallation{}, err
	}
	if err := json.Unmarshal(capsJSON, &rec.Caps); err != nil {
		return StoredInstallation{}, fmt.Errorf("fleet: store: unmarshal caps: %w", err)
	}
	return rec, nil
}
