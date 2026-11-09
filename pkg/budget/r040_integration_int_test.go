//go:build integration

// the REAL consumer boundaries on one real Postgres stand — the settings
// write goes through the admin consumer entry (adminstore.Store, the store
// behind PUT /api/orgs/{id}/credits/grace) and the allowance enforcement
// goes through the admission consumer entry (ReservationStore + Admission
// enforce mode, what the gateway calls), including the 402-wallet Denial
// mapping and the v2-hash audit row the handler's persistAudit writes via
// Store.InsertAuditLogEntry. Stub pricers only; no live/paid model calls.
package budget

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// r040SeedOrg inserts a fresh organization and returns its uuid string.
func r040SeedOrg(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`, id, name, name)
	require.NoError(t, err)
	return id.String()
}

// TestR040_Integration_SettingsToEnforcement_ThroughRealPostgres: contract
// acceptance example 1 end to end on one stand — root-equivalent settings
// write of grace_floor_cents −$50 on a $10 wallet, probe free =
// 10−(−50)−reserved, an enforce request with bound $70 refused with the
// wallet-scope Denial (the 402 mapping), bound $45 admitted, and the
// v2-hash audit row carrying before null / after −5000 / reason.
func TestR040_Integration_SettingsToEnforcement_ThroughRealPostgres(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := r040SeedOrg(t, pool, "r040-integ-"+uuid.NewString()[:8])

	// The settings consumer entry: the store behind PutOrgGraceFloor.
	adminStore := adminstore.New(pool, slog.Default(), nil)
	setWallet(t, pool, org, 1000, nil) // $10 balance, NULL per-org floor

	// The allowance consumer entry with §14 defaults (D1: NULL floor →
	// platform default −$1.00 until the per-org setting overrides it).
	store := NewReservationStore(pool, nil)
	free, err := store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 11_000_000, free, "D1 before the override: $10 + $1 platform-default floor")

	// The operator's choice: −$50 overdraft allowance (allowed range, the
	// same single mutation UpdateOrgGraceFloor performs for the PUT).
	floor := int64(-5000)
	require.NoError(t, adminStore.UpdateOrgGraceFloor(ctx, org, &floor))

	free, err = store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 60_000_000, free, "probe free = 10 − (−50) − reserved")

	// Enforce mode through the admission controller (the gateway entry):
	// bound $70 > $60 free → *Denial{wallet} wrapping
	// ErrInsufficientCapacity — the surface the gateway maps to 402.
	adm := NewAdmission(store, ScopedRateSource{
		Base:   BaseRateSource{Pricer: stubPricer{in: 2, out: 2}},
		Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(pool, stubPricer{in: 2.3, out: 2.3}, nil)},
	}, nil, "int-r040-"+uuid.NewString()[:8], ModeEnforce,
		func(context.Context, string) (OrgSettings, error) { return OrgSettings{Mode: ModeEnforce}, nil },
		AdmissionConfig{})
	plan := &Plan{Mode: ModeEnforce, OrgID: org, Scopes: []ScopeBound{
		{Scope: ScopeWallet, Key: org, Bound: 70_000_000},
	}}
	_, err = adm.Reserve(ctx, plan)
	var denial *Denial
	require.ErrorAs(t, err, &denial)
	require.ErrorIs(t, err, ErrInsufficientCapacity)
	assert.Equal(t, ScopeWallet, denial.Scope, "the 402-wallet mapping")

	// Bound $45 ≤ $60 free → admitted; the escrow reserves exactly it.
	plan = &Plan{Mode: ModeEnforce, OrgID: org, Scopes: []ScopeBound{
		{Scope: ScopeWallet, Key: org, Bound: 45_000_000},
	}}
	rsv, err := adm.Reserve(ctx, plan)
	require.NoError(t, err)
	require.Len(t, rsv.Scopes, 1)
	assert.EqualValues(t, 45_000_000, walletState(t, pool, org))

	// The settings read side (the GET behind the same route): NULL →
	// explicit −5000 now.
	settings, err := adminStore.GetOrgBudgetSettings(ctx, org)
	require.NoError(t, err)
	require.NotNil(t, settings.GraceFloorCents)
	assert.EqualValues(t, -5000, *settings.GraceFloorCents)

	// The audit half of example 1: the v2-hash row the handler's
	// persistAudit writes through Store.InsertAuditLogEntry — before
	// {"grace_floor_cents":null}, after −5000, mandatory reason.
	before, err := json.Marshal(map[string]any{"org_id": org, "grace_floor_cents": nil})
	require.NoError(t, err)
	after, err := json.Marshal(map[string]any{"org_id": org, "grace_floor_cents": -5000})
	require.NoError(t, err)
	rec := adminstore.AuditLogEntryRecord{
		ID: "r040-audit-" + uuid.NewString()[:8], Action: "update",
		Resource: "org_grace_floor", Details: "org=" + org,
		AdminID: "admin-root", AdminName: "Root", IPAddress: "127.0.0.1",
		CreatedAt: time.Now().UTC(), Before: string(before), After: string(after),
		Reason: "pilot overdraft",
	}
	require.NoError(t, adminStore.InsertAuditLogEntry(ctx, rec))

	var hashVersion int16
	var gotBefore, gotAfter, gotReason string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT hash_version, COALESCE(before_snapshot, ''), COALESCE(after_snapshot, ''), reason
		FROM admin_audit_logs WHERE id = $1`, rec.ID).
		Scan(&hashVersion, &gotBefore, &gotAfter, &gotReason))
	assert.EqualValues(t, 2, hashVersion, "snapshot+reason rows are v2-hash chained")
	assert.Contains(t, gotBefore, `"grace_floor_cents":null`)
	assert.Contains(t, gotAfter, "-5000")
	assert.Equal(t, "pilot overdraft", gotReason)
}

// TestR040_Integration_NoSettingFaces_ThroughRealPostgres: the negative
// scenarios through the same real boundaries — «нет настройки» on the grace
// floor means the platform default −$1.00 (D1 stays; probe = balance + $1),
// and «нет настройки» on a team budget row fails closed in enforce mode
// (Denial wrapping ErrNoCapacitySource), never an unlimited admit.
func TestR040_Integration_NoSettingFaces_ThroughRealPostgres(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := r040SeedOrg(t, pool, "r040-noset-"+uuid.NewString()[:8])
	setWallet(t, pool, org, 10_000, nil) // $100 balance, NULL floor

	// D1: the NULL per-org floor probes as the platform default.
	store := NewReservationStore(pool, nil)
	free, err := store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 101_000_000, free, "$100 + $1 platform-default floor")

	// D14 fail-closed: a team attribution without a team_budgets row.
	adm := NewAdmission(store, ScopedRateSource{
		Base:   BaseRateSource{Pricer: stubPricer{in: 2, out: 2}},
		Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(pool, stubPricer{in: 2.3, out: 2.3}, nil)},
	}, nil, "int-r040n-"+uuid.NewString()[:8], ModeEnforce,
		func(context.Context, string) (OrgSettings, error) { return OrgSettings{Mode: ModeEnforce}, nil },
		AdmissionConfig{})
	plan := &Plan{Mode: ModeEnforce, OrgID: org, Scopes: []ScopeBound{
		{Scope: ScopeTeamMonth, Key: uuid.NewString(), Period: time.Now().UTC().Format("2006-01"), Bound: 1_000_000},
	}}
	_, err = adm.Reserve(ctx, plan)
	var denial *Denial
	require.ErrorAs(t, err, &denial)
	require.ErrorIs(t, err, ErrNoCapacitySource, "missing budget row denies, never unlimited")
	assert.Equal(t, ScopeTeamMonth, denial.Scope)
	assert.False(t, errors.Is(err, ErrInsufficientCapacity))
}
