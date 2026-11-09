package adminstore

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Reservations modes (ADR-0001 rev. 3 §9). off = admission unchanged
// (CheckBalance); shadow = reservations run, admission unchanged; enforce =
// a failed reservation rejects admission with 402. Switching back to off is
// immediate — the mode is read per decision, nothing to drain.
const (
	ReservationsOff     = "off"
	ReservationsShadow  = "shadow"
	ReservationsEnforce = "enforce"
)

// GraceFloorMinCents / GraceFloorMaxCents bound the per-org grace floor
// (§8): -$1000.00 … 0. NULL (nil) means "platform default"; an explicit 0
// is a valid, distinct value (AF-01 zero preserved — it forbids overdraft).
const (
	GraceFloorMinCents int64 = -100000
	GraceFloorMaxCents int64 = 0
)

// ValidGraceFloorCents reports whether v is a settable per-org grace floor.
// nil (reset to the platform default) is decided by the caller — this only
// validates an explicit value.
func ValidGraceFloorCents(v int64) bool {
	return v >= GraceFloorMinCents && v <= GraceFloorMaxCents
}

// ValidReservationsMode reports whether mode is one of the three §9 modes.
func ValidReservationsMode(mode string) bool {
	switch mode {
	case ReservationsOff, ReservationsShadow, ReservationsEnforce:
		return true
	}
	return false
}

// OrgBudgetSettings is the per-org budget policy block administered by the
// NEXT-18f admin API. GraceFloorCents and DefaultOutputCapTokens are nil
// when unset (platform default); ReservationsMode is always present
// (DB default 'off').
type OrgBudgetSettings struct {
	OrgID                  string `json:"org_id"`
	GraceFloorCents        *int64 `json:"grace_floor_cents"`
	ReservationsMode       string `json:"reservations_mode"`
	DefaultOutputCapTokens *int64 `json:"default_output_cap_tokens"`
}

// orgUUID parses the org id or reports ErrNotFound: organizations.id is
// uuid, so a non-UUID id can never match a row — answer not-found instead
// of letting a cast error escape (AF-14 typed UUID predicate).
func orgUUID(orgID string) (uuid.UUID, error) {
	id, err := uuid.Parse(orgID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	return id, nil
}

// GetOrgBudgetSettings returns the budget settings block for an organization.
// A missing org is ErrNotFound; a missing wallet row leaves the floor nil
// (the wallet is created lazily by the first top-up).
func (s *Store) GetOrgBudgetSettings(ctx context.Context, orgID string) (*OrgBudgetSettings, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	oid, err := orgUUID(orgID)
	if err != nil {
		return nil, err
	}
	var out OrgBudgetSettings
	err = s.db.QueryRow(ctx, `
		SELECT o.id::text,
		       oc.grace_floor_cents,
		       COALESCE(o.reservations_mode, 'off'),
		       o.default_output_cap_tokens
		FROM organizations o
		LEFT JOIN org_credits oc ON oc.org_id = o.id::text
		WHERE o.id = $1`,
		oid,
	).Scan(&out.OrgID, &out.GraceFloorCents, &out.ReservationsMode, &out.DefaultOutputCapTokens)
	if IsNotFound(err) {
		return nil, fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get org budget settings: %w", err)
	}
	return &out, nil
}

// UpdateOrgGraceFloor sets or clears (nil) the per-org grace floor. The
// wallet row is created on demand for an existing org so a setting can be
// stored before the first top-up; an unknown org is ErrNotFound.
func (s *Store) UpdateOrgGraceFloor(ctx context.Context, orgID string, floorCents *int64) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	oid, err := orgUUID(orgID)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, grace_floor_cents, updated_at)
		SELECT o.id, 0, $2, now() FROM organizations o WHERE o.id = $1
		ON CONFLICT (org_id) DO UPDATE
		    SET grace_floor_cents = EXCLUDED.grace_floor_cents,
		        updated_at = now()`,
		oid, floorCents,
	)
	if err != nil {
		// A set value outside the CHECK range is a caller bug (the handler
		// validates); surface it as a plain error either way.
		return fmt.Errorf("update org grace floor: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	return nil
}

// UpdateOrgReservationsMode switches the org's reservations mode (§9). The
// change takes effect on the next admission decision — there is nothing to
// drain when rolling back to off.
func (s *Store) UpdateOrgReservationsMode(ctx context.Context, orgID, mode string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if !ValidReservationsMode(mode) {
		return fmt.Errorf("update org reservations mode: invalid mode %q", mode)
	}
	oid, err := orgUUID(orgID)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE organizations SET reservations_mode = $2, updated_at = now() WHERE id = $1`,
		oid, mode,
	)
	if err != nil {
		return fmt.Errorf("update org reservations mode: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	return nil
}

// UpdateOrgDefaultOutputCap sets or clears (nil) the org override of the
// reserve-sizing output-token fallback. Values must be > 0 (validated here
// too — the DB CHECK is the last line of defense).
func (s *Store) UpdateOrgDefaultOutputCap(ctx context.Context, orgID string, capTokens *int64) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if capTokens != nil && *capTokens <= 0 {
		return fmt.Errorf("update org output cap: default_output_cap_tokens must be positive")
	}
	oid, err := orgUUID(orgID)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE organizations SET default_output_cap_tokens = $2, updated_at = now() WHERE id = $1`,
		oid, capTokens,
	)
	if err != nil {
		return fmt.Errorf("update org output cap: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	return nil
}
