package adminstore

// NEXT-18f: DB-gated round-trip for the org budget settings block (grace
// floor, reservations mode, default output cap) against the shared dev
// Postgres. Skips when the database is unavailable so offline unit runs stay
// green (repo convention: orgs_int_test.go).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_OrgBudgetSettings_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	// Defaults: no floor, mode off, no output cap.
	settings, err := store.GetOrgBudgetSettings(ctx, orgID)
	require.NoError(t, err)
	assert.Nil(t, settings.GraceFloorCents)
	assert.Equal(t, ReservationsOff, settings.ReservationsMode)
	assert.Nil(t, settings.DefaultOutputCapTokens)

	// Grace floor: set → change → NULL vs 0 are distinct (AF-01).
	floor := int64(-500)
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, orgID, &floor))
	settings, err = store.GetOrgBudgetSettings(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, settings.GraceFloorCents)
	assert.Equal(t, int64(-500), *settings.GraceFloorCents)

	zero := int64(0)
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, orgID, &zero))
	settings, err = store.GetOrgBudgetSettings(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, settings.GraceFloorCents, "explicit 0 is preserved, never coerced to NULL")
	assert.Equal(t, int64(0), *settings.GraceFloorCents)

	require.NoError(t, store.UpdateOrgGraceFloor(ctx, orgID, nil))
	settings, err = store.GetOrgBudgetSettings(ctx, orgID)
	require.NoError(t, err)
	assert.Nil(t, settings.GraceFloorCents, "nil resets to the platform default")

	// The wallet row is created on demand by the floor write if absent.
	walletOrg := qaOrg(t, store, ctx)
	_, err = pool.Exec(ctx, "DELETE FROM org_credits WHERE org_id = $1", walletOrg)
	require.NoError(t, err)
	bigFloor := int64(-100000)
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, walletOrg, &bigFloor))
	settings, err = store.GetOrgBudgetSettings(ctx, walletOrg)
	require.NoError(t, err)
	require.NotNil(t, settings.GraceFloorCents)
	assert.Equal(t, int64(-100000), *settings.GraceFloorCents)

	// Reservations mode: switch through every legal value; invalid is an error.
	for _, mode := range []string{ReservationsShadow, ReservationsEnforce, ReservationsOff} {
		require.NoError(t, store.UpdateOrgReservationsMode(ctx, orgID, mode))
		settings, err = store.GetOrgBudgetSettings(ctx, orgID)
		require.NoError(t, err)
		assert.Equal(t, mode, settings.ReservationsMode)
	}
	require.Error(t, store.UpdateOrgReservationsMode(ctx, orgID, "enforce_now"))

	// Output cap: set, reject non-positive, clear.
	capTokens := int64(4096)
	require.NoError(t, store.UpdateOrgDefaultOutputCap(ctx, orgID, &capTokens))
	settings, err = store.GetOrgBudgetSettings(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, settings.DefaultOutputCapTokens)
	assert.Equal(t, int64(4096), *settings.DefaultOutputCapTokens)

	badCap := int64(0)
	require.Error(t, store.UpdateOrgDefaultOutputCap(ctx, orgID, &badCap))

	require.NoError(t, store.UpdateOrgDefaultOutputCap(ctx, orgID, nil))
	settings, err = store.GetOrgBudgetSettings(ctx, orgID)
	require.NoError(t, err)
	assert.Nil(t, settings.DefaultOutputCapTokens, "nil clears the override")
}

// TestStore_GraceFloorDecreaseBelowLiveSpend_Allowed_Integration verifies the behavior.
// Tightening the grace floor below the wallet's
// live reserve is ALLOWED at the settings store: no guard, no rejection.
// The denial happens on the next admission (free < 0 refuses the grant),
// pinned in pkg/budget (TestR040_WalletFloorShrunkBelowLiveEscrow_...).
func TestStore_GraceFloorDecreaseBelowLiveSpend_Allowed_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	// $10 balance, −$50 floor → wallet capacity $60; all $60 of it
	// reserved (a live escrow beyond the balance alone).
	floor := int64(-5000)
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, orgID, &floor))
	_, err := pool.Exec(ctx, `
		UPDATE org_credits SET balance_cents = 1000, reserved_micro_usd = 60_000_000
		WHERE org_id = $1`, orgID)
	require.NoError(t, err)

	// Tighten to 0 (no overdraft): capacity $10 < $60 reserved — still
	// accepted (D2 allow + deny-next).
	zero := int64(0)
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, orgID, &zero), "a decrease below live spend is allowed (D2)")
	settings, err := store.GetOrgBudgetSettings(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, settings.GraceFloorCents)
	assert.Equal(t, int64(0), *settings.GraceFloorCents)
}

// the settings paths is an explicit wrapped error, never a silent success
// and never a not-found verdict (unknown ≠ missing; partial/unknown states
// do not count as applied).
func TestStore_OrgBudgetSettings_DBErrorPropagates(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{err: errors.New("injected read outage")}
		},
		execFn: func(_ context.Context, _ string, _ ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("injected write outage")
		},
	}
	s := &Store{db: db}
	ctx := context.Background()
	orgID := uuid.NewString()

	floor := int64(-100)
	err := s.UpdateOrgGraceFloor(ctx, orgID, &floor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update org grace floor")
	require.NotErrorIs(t, err, ErrNotFound, "an outage is not the unknown-org verdict")

	_, err = s.GetOrgBudgetSettings(ctx, orgID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get org budget settings")
	assert.NotErrorIs(t, err, ErrNotFound)
}

// TestStore_TeamBudgetDecrease_CASRollbackRace_Integration verifies the CAS rollback race.
// concurrent-limit-change face of D2 at the settings layer. The audited
// decrease (allowed below live spend by D2) may need an audit rollback
// replay while a NEWER operator decision has already moved the limit: the
// CAS precondition must refuse the stale rollback (ErrPreconditionFailed
// with the current state) so the newer ratified limit survives — the
// journal can never silently revert a newer operator choice.
func TestStore_TeamBudgetDecrease_CASRollbackRace_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	var teamID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1, 'r040-cas', $2)
		RETURNING id::text`,
		orgID, fmt.Sprintf("r040-cas-%d", time.Now().UnixNano())).Scan(&teamID))

	// The audited change: the D2 decrease 200 → 100 (below live spend).
	_, err := store.UpsertTeamBudgetPreconditioned(ctx, teamID, 100, true, &TeamBudgetExpectation{Absent: true})
	require.NoError(t, err)

	// A newer operator decision raises the limit to 300.
	require.NoError(t, store.UpsertTeamBudget(ctx, teamID, 300, true))

	// The stale rollback of the audited decrease (recorded after = 100,
	// replays the pre-change 200) must lose; 300 survives.
	current, err := store.UpsertTeamBudgetPreconditioned(ctx, teamID, 200, true,
		&TeamBudgetExpectation{MonthlyLimitUSD: 100, HardLimit: true})
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.NotNil(t, current)
	assert.InDelta(t, 300.0, current.MonthlyLimitUSD, 1e-9, "the conflict reports the newer limit")

	tb, err := store.GetTeamBudget(ctx, teamID)
	require.NoError(t, err)
	assert.InDelta(t, 300.0, tb.MonthlyLimitUSD, 1e-9, "the newer limit survives the stale rollback")

	// A rollback whose expectation matches the CURRENT state applies.
	_, err = store.UpsertTeamBudgetPreconditioned(ctx, teamID, 200, true,
		&TeamBudgetExpectation{MonthlyLimitUSD: 300, HardLimit: true})
	require.NoError(t, err)
	tb, err = store.GetTeamBudget(ctx, teamID)
	require.NoError(t, err)
	assert.InDelta(t, 200.0, tb.MonthlyLimitUSD, 1e-9)
}

func TestStore_OrgBudgetSettings_UnknownOrg_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	_, err := store.GetOrgBudgetSettings(ctx, "no-such-org-18f")
	require.ErrorIs(t, err, ErrNotFound)

	floor := int64(-100)
	require.ErrorIs(t, store.UpdateOrgGraceFloor(ctx, "no-such-org-18f", &floor), ErrNotFound)
	require.ErrorIs(t, store.UpdateOrgReservationsMode(ctx, "no-such-org-18f", ReservationsShadow), ErrNotFound)
	capTokens := int64(16)
	require.ErrorIs(t, store.UpdateOrgDefaultOutputCap(ctx, "no-such-org-18f", &capTokens), ErrNotFound)
}

func TestStore_OrgBudgetSettings_DBCHECKConstraints_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	// The DB CHECK is the last line of defense behind the handler/store
	// validation: outside the §8 range must fail at the storage layer too.
	// The grace range has no Go-side guard in the store (the handler
	// validates), so this exercises the CHECK directly; the output-cap
	// CHECK is probed via raw SQL (the store refuses non-positive early).
	outOfRange := int64(-100001)
	require.Error(t, store.UpdateOrgGraceFloor(ctx, orgID, &outOfRange))
	zeroCap := int64(0)
	require.Error(t, store.UpdateOrgDefaultOutputCap(ctx, orgID, &zeroCap))
	_, err := pool.Exec(ctx,
		`UPDATE organizations SET default_output_cap_tokens = 0 WHERE id = $1`, orgID)
	require.Error(t, err, "DB CHECK must reject a non-positive output cap")

	// The orgs list surfaces the floor for root tables.
	org, err := store.GetOrganizationByID(ctx, orgID)
	require.NoError(t, err)
	assert.Nil(t, org.GraceFloorCents)
	floor := int64(-250)
	require.NoError(t, store.UpdateOrgGraceFloor(ctx, orgID, &floor))
	org, err = store.GetOrganizationByID(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, org.GraceFloorCents)
	assert.Equal(t, int64(-250), *org.GraceFloorCents)
}
