package policystore

// Durable guard detector-pack policy state: the Postgres adapter for the
// guardhooks.PolicyVersionCAS port. This adapter is THE
// coordination point whenever a DB pool exists: the gateway startup
// (pkg/gateway loadGuardHooks → guardpack_durable.go) and the admin API
// surface both CAS through this one singleton row (guard_pack_state,
// migration 0013) — exactly one concurrent winner among all replicas and
// processes, every loser reads the winner's version from the same row.
// Without a DB pool the gateway falls back to the local no-op store:
// env-based activation keeps working and there is nothing to coordinate.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

// ErrGuardPackConflict is the CAS precondition mismatch: the durable active
// version is not the expected one. Nothing was written; the caller must
// re-read ActiveGuardPackState and rebase (adminstore.ErrPreconditionFailed
// parity — the handler maps it to 409 with the live state).
var ErrGuardPackConflict = errors.New("policystore: guard pack version conflict (durable state moved)")

// GuardPackState is the durable activation record (single row; the zero
// value means "no durable activation recorded yet" — e.g. a deployment that
// only ever used env-based startup activation).
type GuardPackState struct {
	ActiveVersion   string    `json:"active_version"`
	PreviousVersion string    `json:"previous_version"`
	UpdatedBy       string    `json:"updated_by"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// compile pin: the durable adapter implements the lifecycle's policy port.
var _ guardhooks.PolicyVersionCAS = (*GuardPolicyCAS)(nil)

// GuardPolicyCAS performs compare-and-swap on the durable guard-pack policy
// version. The zero value is feature-off: every call fails closed with
// ErrNoDB (pack state unchanged — never a silent local-only activation).
type GuardPolicyCAS struct {
	pool *pgxpool.Pool
}

// NewGuardPolicyCAS builds the durable CAS over a Postgres pool. A nil pool
// is accepted (feature-off; every CAS fails closed).
func NewGuardPolicyCAS(pool *pgxpool.Pool) *GuardPolicyCAS {
	return &GuardPolicyCAS{pool: pool}
}

// CompareAndSwap transitions the durable active version from → to in one
// statement. Semantics:
//
//   - row absent (no durable activation yet): the INSERT arm bootstraps the
//     row with active=to, previous=from — the first recorded transition;
//   - row present with active_version == from: the UPDATE arm wins and the
//     old active moves to previous_version;
//   - row present with any other active_version (including a concurrent
//     winner between our read and write, or from == to): nothing is written
//     and ErrGuardPackConflict is returned.
//
// from/to must be non-empty: the lifecycle's version identity ("core", a
// single "pack@version", or the joined multi-pack form) is never empty.
func (c *GuardPolicyCAS) CompareAndSwap(ctx context.Context, from, to string) error {
	if from == "" || to == "" {
		return fmt.Errorf("policystore: guard pack CAS requires non-empty from/to versions")
	}
	if from == to {
		return ErrGuardPackConflict
	}
	if c == nil || c.pool == nil {
		return ErrNoDB
	}
	tag, err := c.pool.Exec(ctx, `
		INSERT INTO guard_pack_state (id, active_version, previous_version)
		VALUES (1, $2, $1)
		ON CONFLICT (id) DO UPDATE SET
			active_version = EXCLUDED.active_version,
			previous_version = guard_pack_state.active_version,
			updated_at = now()
		WHERE guard_pack_state.active_version = $1
	`, from, to)
	if err != nil {
		return fmt.Errorf("guard pack policy CAS: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrGuardPackConflict
	}
	return nil
}

// ActiveGuardPackState reads the durable activation record. A missing row is
// the zero value with a nil error (no durable activation yet), matching the
// "missing version key reads as 0" convention of the other version stores.
func (c *GuardPolicyCAS) ActiveGuardPackState(ctx context.Context) (GuardPackState, error) {
	if c == nil || c.pool == nil {
		return GuardPackState{}, ErrNoDB
	}
	var state GuardPackState
	err := c.pool.QueryRow(ctx, `
		SELECT active_version, previous_version, updated_by, updated_at
		FROM guard_pack_state WHERE id = 1
	`).Scan(&state.ActiveVersion, &state.PreviousVersion, &state.UpdatedBy, &state.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return GuardPackState{}, nil
		}
		return GuardPackState{}, fmt.Errorf("read guard pack state: %w", err)
	}
	return state, nil
}
