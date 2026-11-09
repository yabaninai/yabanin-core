//go:build integration

// NEXT-18a acceptance tests on a disposable live Postgres (ADR-0001 §10,
// heavy runs under the machine semaphore): grant/renew/settle/return/
// reconcile primitives, the admission invariant reserved + Δ ≤ L, atomic
// multi-scope refusal, late-settle-after-release, 100-goroutine grant
// stress without deadlock or capacity overrun, and the reservation schema
// shipped by the consolidated 0001_init baseline.
package budget

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newReservationStore builds a store with §14 defaults for live tests.
func newReservationStore(pool *pgxpool.Pool) *ReservationStore {
	return NewReservationStore(pool, nil)
}

// setWallet seeds an org wallet with an explicit balance and optional grace
// floor (nil → per-org NULL, meaning the store's global default applies),
// resetting every allowance the org may hold so tests are repeatable and
// order-independent on the shared container.
func setWallet(t *testing.T, pool *pgxpool.Pool, org string, balanceCents int64, floor *int64) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `DELETE FROM budget_allowances WHERE org_id = $1`, org)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd, grace_floor_cents, reserved_micro_usd)
		 VALUES ($1, $2, 0, $3, 0)
		 ON CONFLICT (org_id) DO UPDATE SET
			balance_cents = $2, remainder_micro_usd = 0,
			grace_floor_cents = $3, reserved_micro_usd = 0, updated_at = now()`,
		org, balanceCents, floor)
	require.NoError(t, err)
}

// walletState reads the wallet's reserve for invariant assertions.
func walletState(t *testing.T, pool *pgxpool.Pool, org string) (reserved int64) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, org).Scan(&reserved)
	require.NoError(t, err)
	return reserved
}

// allowanceRow reads one allowance by natural key.
func allowanceRow(t *testing.T, pool *pgxpool.Pool, replica string, scope ScopeKind, key, period string) (
	id, granted, returned int64, status string, lease time.Time) {
	t.Helper()
	err := pool.QueryRow(context.Background(), `
		SELECT id, granted_micro_usd, returned_micro_usd, status, lease_until
		FROM budget_allowances
		WHERE replica_id = $1 AND scope_kind = $2 AND scope_key = $3 AND period = $4`,
		replica, string(scope), key, period).Scan(&id, &granted, &returned, &status, &lease)
	require.NoError(t, err)
	return id, granted, returned, status, lease
}

func scopeReserve(t *testing.T, pool *pgxpool.Pool, scope ScopeKind, key, period string) int64 {
	t.Helper()
	ctx := context.Background()
	var q string
	var args []any
	switch scope {
	case ScopeTeamMonth:
		q = `SELECT reserved_micro_usd FROM team_spend_monthly WHERE team_id = $1::uuid AND period = $2`
		args = []any{key, period}
	case ScopeAgentDay:
		q = `SELECT reserved_micro_usd FROM agent_spend_daily WHERE agent_id = $1::uuid AND day = $2::date`
		args = []any{key, period}
	case ScopeSession:
		q = `SELECT reserved_micro_usd FROM session_spend WHERE session_key_id = $1::uuid`
		args = []any{key}
	default:
		t.Fatalf("unexpected scope %s", scope)
	}
	var reserved int64
	err := pool.QueryRow(ctx, q, args...).Scan(&reserved)
	require.NoError(t, err)
	return reserved
}

// seedOrgTeam creates an organization with one team (FK targets for
// team_budgets and api_keys) and returns both uuids.
func seedOrgTeam(t *testing.T, pool *pgxpool.Pool, name string) (string, string) {
	t.Helper()
	ctx := context.Background()
	orgUUID := uuid.New()
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`, orgUUID, name, name)
	require.NoError(t, err)
	teamID := uuid.New()
	_, err = pool.Exec(ctx,
		`INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		teamID, orgUUID, name, name)
	require.NoError(t, err)
	return orgUUID.String(), teamID.String()
}

// seedTeamBudget creates a hard monthly team budget and returns its uuid.
func seedTeamBudget(t *testing.T, pool *pgxpool.Pool, limitUSD float64) string {
	t.Helper()
	_, teamID := seedOrgTeam(t, pool, "team-"+uuid.NewString()[:8])
	_, err := pool.Exec(context.Background(),
		`INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit) VALUES ($1, $2, true)`, teamID, limitUSD)
	require.NoError(t, err)
	return teamID
}

func setTeamSpend(t *testing.T, pool *pgxpool.Pool, teamID, period string, spendMicro int64) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO team_spend_monthly (team_id, period, spend_usd, spend_micro_usd)
		VALUES ($1::uuid, $2, $3::bigint / 1000000.0, $3)
		ON CONFLICT (team_id, period) DO UPDATE SET spend_micro_usd = $3`,
		teamID, period, spendMicro)
	require.NoError(t, err)
}

func seedAgentBudget(t *testing.T, pool *pgxpool.Pool, dailyLimitCents int64) string {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO agent_budgets (agent_id, daily_limit_cents) VALUES ($1, $2)`, id, dailyLimitCents)
	require.NoError(t, err)
	return id.String()
}

// seedSessionKey creates org → team → api_key → session_key with a money
// cap (limitUSD ≤ 0 → NULL cap) and returns the session key uuid.
func seedSessionKey(t *testing.T, pool *pgxpool.Pool, org string, limitUSD float64) string {
	t.Helper()
	ctx := context.Background()
	orgID, teamID := seedOrgTeam(t, pool, "skorg-"+uuid.NewString()[:8])
	orgUUID, err := uuid.Parse(orgID)
	require.NoError(t, err)
	teamUUID, err := uuid.Parse(teamID)
	require.NoError(t, err)
	keyID := uuid.New()
	_, err = pool.Exec(ctx,
		`INSERT INTO api_keys (id, key_hash, org_id, name, team_id) VALUES ($1, $2, $3, $4, $5)`,
		keyID, "resv-hash-"+uuid.NewString(), orgUUID, org, teamUUID)
	require.NoError(t, err)
	skID := uuid.New()
	var limit any
	if limitUSD > 0 {
		limit = limitUSD
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO session_keys (id, key_hash, org_id, parent_api_key_id, name, max_cost_usd, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now() + interval '1 hour')`,
		skID, "sk-resv-"+uuid.NewString(), orgUUID, keyID, org, limit)
	require.NoError(t, err)
	return skID.String()
}

const testReplica = "test-host:resv-boot"

// TestGrant_WalletCreatesExtendsAndReservesExactly: a grant creates the
// allowance and reserves exactly Δ; a second grant extends the SAME
// allocation row (natural-key upsert) and renews the lease.
func TestGrant_WalletCreatesExtendsAndReservesExactly(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	org := "org-resv-extends"
	setWallet(t, pool, org, 100_000, nil) // $1000, per-org floor NULL → −$1 global

	g1, err := store.Grant(context.Background(), testReplica, org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 100_000}, // $0.10, rate 0 → Δ = bound
	})
	require.NoError(t, err)
	require.Len(t, g1, 1)
	require.Equal(t, int64(100_000), int64(g1[0].Delta))
	require.Equal(t, int64(100_000), walletState(t, pool, org))

	id, granted, returned, status, lease := allowanceRow(t, pool, testReplica, ScopeWallet, org, "")
	require.Equal(t, g1[0].AllowanceID, id)
	require.Equal(t, int64(100_000), granted)
	require.Equal(t, int64(0), returned)
	require.Equal(t, AllowanceActive, status)
	require.True(t, time.Until(lease) > 9*time.Minute, "lease ≈ now + ReservationTTL(10m), got %v", time.Until(lease))

	// Second grant on the same scope: same row, cumulative granted.
	g2, err := store.Grant(context.Background(), testReplica, org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 50_000},
	})
	require.NoError(t, err)
	require.Equal(t, id, g2[0].AllowanceID, "natural-key upsert extends the allocation")

	_, granted, _, status, lease2 := allowanceRow(t, pool, testReplica, ScopeWallet, org, "")
	require.Equal(t, int64(150_000), granted)
	require.Equal(t, AllowanceActive, status)
	require.True(t, lease2.After(lease) || lease2.Equal(lease), "lease renewed")
	require.Equal(t, int64(150_000), walletState(t, pool, org))
}

// TestGrant_EscrowSizingAndLowWater: with a spend rate the grant sizes to
// rate × EscrowHorizon; near exhaustion it degrades to exactly one bound.
func TestGrant_EscrowSizingAndLowWater(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	org := "org-resv-escrow"
	setWallet(t, pool, org, 1_000_000, nil) // $10_000 → free ≈ 10_001_000_000µ

	g, err := store.Grant(context.Background(), testReplica, org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 100_000, RatePerSecond: 1_000_000}, // $1/s
	})
	require.NoError(t, err)
	require.Equal(t, int64(5_000_000), int64(g[0].Delta), "Δ = rate($1/s) × EscrowHorizon(5s)")
	require.Equal(t, int64(5_000_000), walletState(t, pool, org))

	// Near exhaustion: free < 20 × bound → exactly bound.
	small := "org-resv-lowwater"
	setWallet(t, pool, small, 1_000, nil) // $10 → free = 10M + 1M(floor) = 11M < 20×1M
	g2, err := store.Grant(context.Background(), testReplica, small, []GrantRequest{
		{Scope: ScopeWallet, Key: small, Bound: 1_000_000, RatePerSecond: 100_000_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(1_000_000), int64(g2[0].Delta), "low water issues exactly the bound")
}

// TestGrant_InvariantReservedPlusDeltaUnderCapacity: repeated grants can
// never push the reserve past the wallet capacity L (balance − grace floor).
func TestGrant_InvariantReservedPlusDeltaUnderCapacity(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	org := "org-resv-invariant"
	zero := int64(0)
	setWallet(t, pool, org, 1_000, &zero) // $10, no overdraft → L = 10_000_000µ

	total := int64(0)
	for i := 0; i < 12; i++ { // 12 × $1 bounds vs $10 capacity: 10 fit
		g, err := store.Grant(context.Background(), fmt.Sprintf("replica-%d", i), org, []GrantRequest{
			{Scope: ScopeWallet, Key: org, Bound: 1_000_000},
		})
		if err != nil {
			require.ErrorIs(t, err, ErrInsufficientCapacity, "iteration %d", i)
			continue
		}
		total += int64(g[0].Delta)
	}
	require.Equal(t, int64(10_000_000), total, "grants stop exactly at capacity")
	require.Equal(t, total, walletState(t, pool, org))
	require.LessOrEqual(t, walletState(t, pool, org), int64(10_000_000), "reserved ≤ L")
}

// TestGrant_MultiScopeAllOrNothing: one TX grants every scope; a refusal of
// any scope rolls back the whole grant (ADR §10.2).
func TestGrant_MultiScopeAllOrNothing(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()

	org := "org-resv-multi"
	team := seedTeamBudget(t, pool, 100)              // $100
	agent := seedAgentBudget(t, pool, 5_000)          // $50
	session := seedSessionKey(t, pool, org+"-ok", 25) // $25 cap
	period := time.Now().UTC().Format("2006-01")
	day := time.Now().UTC().Format("2006-01-02")
	setWallet(t, pool, org, 500_000, nil)

	g, err := store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeSession, Key: session, Bound: 300_000},
		{Scope: ScopeAgentDay, Key: agent, Period: day, Bound: 400_000},
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 200_000},
		{Scope: ScopeWallet, Key: org, Bound: 100_000},
	})
	require.NoError(t, err)
	require.Len(t, g, 4)
	// Fixed lock order in the applied sequence: wallet → team → agent → session.
	require.Equal(t, []ScopeKind{ScopeWallet, ScopeTeamMonth, ScopeAgentDay, ScopeSession},
		[]ScopeKind{g[0].Scope, g[1].Scope, g[2].Scope, g[3].Scope})
	require.Equal(t, int64(100_000), walletState(t, pool, org))
	require.Equal(t, int64(200_000), scopeReserve(t, pool, ScopeTeamMonth, team, period))
	require.Equal(t, int64(400_000), scopeReserve(t, pool, ScopeAgentDay, agent, day))
	require.Equal(t, int64(300_000), scopeReserve(t, pool, ScopeSession, session, ""))

	// Now the team scope cannot cover its bound: nothing may be applied.
	setTeamSpend(t, pool, team, period, 99_800_000) // $99.80 spent, free $0.20 < $1 bound
	reservedBefore := walletState(t, pool, org)
	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 100_000},
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1_000_000},
	})
	require.ErrorIs(t, err, ErrInsufficientCapacity)
	require.Equal(t, reservedBefore, walletState(t, pool, org), "wallet part rolled back with the team refusal")
}

// TestGrant_RefusesWithoutCapacitySource: missing wallet/budget/limit rows
// fail closed (D14) instead of granting unlimited.
func TestGrant_RefusesWithoutCapacitySource(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()

	_, err := store.Grant(ctx, testReplica, "org-resv-no-wallet", []GrantRequest{
		{Scope: ScopeWallet, Key: "org-resv-no-wallet", Bound: 1},
	})
	require.ErrorIs(t, err, ErrNoCapacitySource)

	_, err = store.Grant(ctx, testReplica, "org-resv-x", []GrantRequest{
		{Scope: ScopeTeamMonth, Key: uuid.NewString(), Period: "2026-10", Bound: 1},
	})
	require.ErrorIs(t, err, ErrNoCapacitySource)

	// Session key without max_cost_usd: hard scope requested, no cap → refuse.
	sessionNoCap := seedSessionKey(t, pool, "org-resv-nocap", 0)
	_, err = store.Grant(ctx, testReplica, "org-resv-nocap", []GrantRequest{
		{Scope: ScopeSession, Key: sessionNoCap, Bound: 1},
	})
	require.ErrorIs(t, err, ErrNoCapacitySource)
}

// TestGrant_TeamAgentSessionCapacities: per-scope capacity enforcement with
// exact µUSD limit conversion (ADR §13).
func TestGrant_TeamAgentSessionCapacities(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	period := time.Now().UTC().Format("2006-01")
	day := time.Now().UTC().Format("2006-01-02")

	team := seedTeamBudget(t, pool, 10) // $10 = 10_000_000µ
	setTeamSpend(t, pool, team, period, 0)
	g, err := store.Grant(ctx, testReplica, "org-resv-team", []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 4_000_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(4_000_000), int64(g[0].Delta))
	require.Equal(t, int64(4_000_000), scopeReserve(t, pool, ScopeTeamMonth, team, period))
	_, err = store.Grant(ctx, testReplica, "org-resv-team", []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 6_000_001},
	})
	require.ErrorIs(t, err, ErrInsufficientCapacity)

	agent := seedAgentBudget(t, pool, 1_000) // $10 = 10_000_000µ
	g, err = store.Grant(ctx, testReplica, "org-resv-agent", []GrantRequest{
		{Scope: ScopeAgentDay, Key: agent, Period: day, Bound: 2_500_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(2_500_000), scopeReserve(t, pool, ScopeAgentDay, agent, day))
	_, err = store.Grant(ctx, testReplica, "org-resv-agent", []GrantRequest{
		{Scope: ScopeAgentDay, Key: agent, Period: day, Bound: 7_500_001},
	})
	require.ErrorIs(t, err, ErrInsufficientCapacity)

	session := seedSessionKey(t, pool, "org-resv-session", 5) // $5 = 5_000_000µ
	g, err = store.Grant(ctx, testReplica, "org-resv-session", []GrantRequest{
		{Scope: ScopeSession, Key: session, Bound: 1_250_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(1_250_000), scopeReserve(t, pool, ScopeSession, session, ""))
	_, err = store.Grant(ctx, testReplica, "org-resv-session", []GrantRequest{
		{Scope: ScopeSession, Key: session, Bound: 3_750_001},
	})
	require.ErrorIs(t, err, ErrInsufficientCapacity)
}

// TestGrant_SoftTeamBudgetIsAdvisory: hard_limit=false grants without a
// capacity check (I6) but keeps the reserve accounting.
func TestGrant_SoftTeamBudgetIsAdvisory(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	team := seedTeamBudget(t, pool, 1) // $1 nominal limit, advisory
	_, err := pool.Exec(ctx, `UPDATE team_budgets SET hard_limit = false WHERE team_id = $1::uuid`, team)
	require.NoError(t, err)
	period := time.Now().UTC().Format("2006-01")

	// Bound far beyond the $1 nominal limit: admitted, accounting kept.
	g, err := store.Grant(ctx, testReplica, "org-resv-soft", []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 50_000_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(50_000_000), scopeReserve(t, pool, ScopeTeamMonth, team, period))
	require.NotZero(t, g[0].AllowanceID)
}

// (ratified 2026-10-16) — decreasing a hard team limit below live
// spend+reserved is ALLOWED (the settings path carries no below-spend
// guard; the UPDATE mirrors adminstore.UpsertTeamBudget's ON CONFLICT DO
// UPDATE) and the NEXT grant is denied with free < 0. The live escrow is
// neither clamped nor drained: the in-flight reserve keeps its money until
// the limit is raised again or the allowance settles.
func TestR040_TeamLimitDecreasedBelowSpend_AllowThenDenyNext(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	period := time.Now().UTC().Format("2006-01")

	team := seedTeamBudget(t, pool, 200) // $200 hard limit
	setTeamSpend(t, pool, team, period, 120_000_000)

	// Pre-decrease: free = $200 − $120 = $80 → a $10 bound reserves fine.
	_, err := store.Grant(ctx, testReplica, "org-r040-team", []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 10_000_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(10_000_000), scopeReserve(t, pool, ScopeTeamMonth, team, period))

	// D2 allow: $100 < $120 spend + $10 reserved — accepted anyway.
	_, err = pool.Exec(ctx,
		`UPDATE team_budgets SET monthly_limit_usd = 100 WHERE team_id = $1::uuid`, team)
	require.NoError(t, err)

	// Deny-next: free = $100 − $120 − $10 = −$30 → every bound is refused
	// (grantDelta's free < 0 guard), and the probe reports the negative
	// free capacity explicitly.
	free, err := store.ProbeFreeCapacity(ctx, "org-r040-team", GrantRequest{
		Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1,
	})
	require.NoError(t, err)
	require.Equal(t, int64(-30_000_000), int64(free), "free capacity is explicitly negative")

	_, err = store.Grant(ctx, testReplica, "org-r040-team", []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1},
	})
	require.ErrorIs(t, err, ErrInsufficientCapacity, "deny-next after the decrease")

	// The live escrow is untouched: no silent clamp, no drain.
	require.Equal(t, int64(10_000_000), scopeReserve(t, pool, ScopeTeamMonth, team, period))
}

// TestR040_WalletFloorShrunkBelowLiveEscrow_AllowThenDenyNext: the wallet
// face of D2 — tightening the grace floor (toward 0, less overdraft) under
// a live escrow is allowed (PutOrgGraceFloor/UpdateOrgGraceFloor have no
// below-spend guard) and the next grant denies with free < 0. The reserve
// itself is not rewound; only new admissions stop.
func TestR040_WalletFloorShrunkBelowLiveEscrow_AllowThenDenyNext(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-r040-wallet"

	// $10 balance with a −$50 floor: free = 10M + 50M = 60M µ.
	floor := int64(-5000)
	setWallet(t, pool, org, 1000, &floor)
	_, err := store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 50_000_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(50_000_000), walletState(t, pool, org))

	// D2 allow: shrink the floor to 0 (no overdraft) under the live escrow
	// — the same single-column UPDATE UpdateOrgGraceFloor performs.
	_, err = pool.Exec(ctx, `UPDATE org_credits SET grace_floor_cents = 0 WHERE org_id = $1`, org)
	require.NoError(t, err)

	// Deny-next: free = 10M − 0 − 50M = −40M µ.
	free, err := store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
	require.NoError(t, err)
	require.Equal(t, int64(-40_000_000), int64(free))

	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 1}})
	require.ErrorIs(t, err, ErrInsufficientCapacity, "deny-next after the floor shrink")

	// The live escrow keeps its claim until settle/return — no clamp.
	require.Equal(t, int64(50_000_000), walletState(t, pool, org))
}

// TestRenewal_FromExpiredToActive: renewal returns a lapsed allowance to
// active until it is released (ADR §5.3); released rows stay released.
func TestRenewal_FromExpiredToActive(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-resv-renew"
	setWallet(t, pool, org, 100_000, nil)

	g, err := store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 100_000}})
	require.NoError(t, err)
	id := g[0].AllowanceID

	// Simulate a lapsed lease.
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET status = 'expired', lease_until = now() - interval '1 min' WHERE id = $1`, id)
	require.NoError(t, err)

	n, err := store.Renewal(ctx, testReplica)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(1))

	_, _, _, status, lease := allowanceRow(t, pool, testReplica, ScopeWallet, org, "")
	require.Equal(t, AllowanceActive, status, "renewal returns expired → active")
	require.True(t, time.Until(lease) > 9*time.Minute)

	// A released allowance is never resurrected by renewal.
	_, err = pool.Exec(ctx, `UPDATE budget_allowances SET status = 'released' WHERE id = $1`, id)
	require.NoError(t, err)
	_, err = store.Renewal(ctx, testReplica)
	require.NoError(t, err)
	_, _, _, status, _ = allowanceRow(t, pool, testReplica, ScopeWallet, org, "")
	require.Equal(t, AllowanceReleased, status)
}

// TestSettleDecrement_MinActualBound: settle releases exactly
// min(actual, bound) from the scope reserve; after release the reserve is
// never decremented again (late settle, ADR §5.3).
func TestSettleDecrement_MinActualBound(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-resv-settle"
	setWallet(t, pool, org, 100_000, nil)

	g, err := store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 1_000_000}})
	require.NoError(t, err)
	require.Equal(t, int64(1_000_000), walletState(t, pool, org))

	// actual ≤ bound → reserve drops by actual.
	res, err := store.SettleDecrement(ctx, org, g[0].AllowanceID, 300_000, 1_000_000)
	require.NoError(t, err)
	require.True(t, res.Applied)
	require.Equal(t, int64(300_000), int64(res.Amount))
	require.Equal(t, int64(700_000), walletState(t, pool, org))

	// actual > bound → reserve drops by bound (the granted envelope's
	// remainder), never beyond.
	res, err = store.SettleDecrement(ctx, org, g[0].AllowanceID, 5_000_000, 700_000)
	require.NoError(t, err)
	require.True(t, res.Applied)
	require.Equal(t, int64(700_000), int64(res.Amount))
	require.Equal(t, int64(0), walletState(t, pool, org))

	// Late settle after release: ledger-only, reserve untouched.
	_, err = pool.Exec(ctx, `UPDATE budget_allowances SET status = 'released' WHERE id = $1`, g[0].AllowanceID)
	require.NoError(t, err)
	res, err = store.SettleDecrement(ctx, org, g[0].AllowanceID, 100_000, 1_000_000)
	require.NoError(t, err)
	require.False(t, res.Applied, "released allowance: settle is ledger-only")
	require.Equal(t, int64(0), int64(res.Amount))
	require.Equal(t, int64(0), walletState(t, pool, org), "no double decrement")
}

// TestReturn_UnusedEscrow: idle return lowers the scope reserve and
// accumulates returned_micro_usd; over-return is an invariant error.
func TestReturn_UnusedEscrow(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-resv-return"
	setWallet(t, pool, org, 100_000, nil)

	_, err := store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 1_000_000}})
	require.NoError(t, err)

	require.NoError(t, store.Return(ctx, org, testReplica, []ReturnRequest{
		{Scope: ScopeWallet, Key: org, Amount: 400_000},
	}))
	require.Equal(t, int64(600_000), walletState(t, pool, org))
	_, granted, returned, status, _ := allowanceRow(t, pool, testReplica, ScopeWallet, org, "")
	require.Equal(t, int64(1_000_000), granted)
	require.Equal(t, int64(400_000), returned)
	require.Equal(t, AllowanceActive, status)

	err = store.Return(ctx, org, testReplica, []ReturnRequest{{Scope: ScopeWallet, Key: org, Amount: 700_000}})
	require.ErrorIs(t, err, ErrAllowanceUnderflow)
}

// TestMarkDraining_ReconcileZeroRemainder: a drained-out allowance with
// zero remainder is released by reconcile without waiting for the safety
// window (§7.1.2).
func TestMarkDraining_ReconcileZeroRemainder(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-resv-drain"
	setWallet(t, pool, org, 100_000, nil)

	_, err := store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 1_000_000}})
	require.NoError(t, err)
	n, err := store.MarkDraining(ctx, testReplica)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(1))
	require.NoError(t, store.Return(ctx, org, testReplica, []ReturnRequest{{Scope: ScopeWallet, Key: org, Amount: 1_000_000}}))

	summary, err := store.ReconcileRelease(ctx, ReservationSafetyWindow)
	require.NoError(t, err)
	require.GreaterOrEqual(t, summary.Released, int64(1))
	_, _, _, status, _ := allowanceRow(t, pool, testReplica, ScopeWallet, org, "")
	require.Equal(t, AllowanceReleased, status)
}

// TestReconcile_ReleasesExpiredAfterSafetyWindow: expired allowances past
// the safety window release their remainder (granted − returned − settled)
// back to the scope; young expirations and active leases stay untouched.
func TestReconcile_ReleasesExpiredAfterSafetyWindow(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-resv-reconcile"
	setWallet(t, pool, org, 1_000_000, nil)

	// Allowance 1: expired 3h ago with one settled job (200k already taken
	// from the reserve by the settlement worker).
	g1, err := store.Grant(ctx, "reconcile-replica-1", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 1_000_000},
	})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, allowance_id, payload, status)
		VALUES ($1, $2, 'wallet', $3, $4::jsonb, 'settled')`,
		org, fmt.Sprintf("req-reconcile-%d", time.Now().UnixNano()), g1[0].AllowanceID,
		`{"settle_decrement_micro_usd": 200000}`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET status = 'expired', lease_until = now() - interval '3 hours' WHERE id = $1`,
		g1[0].AllowanceID)
	require.NoError(t, err)

	// Allowance 2: expired only 10 minutes ago — inside the safety window.
	g2, err := store.Grant(ctx, "reconcile-replica-2", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 500_000},
	})
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET status = 'expired', lease_until = now() - interval '10 min' WHERE id = $1`,
		g2[0].AllowanceID)
	require.NoError(t, err)

	reservedBefore := walletState(t, pool, org) // 1.5M
	require.Equal(t, int64(1_500_000), reservedBefore)

	summary, err := store.ReconcileRelease(ctx, ReservationSafetyWindow)
	require.NoError(t, err)
	require.Equal(t, int64(1), summary.Released)
	require.Equal(t, int64(800_000), summary.ReturnedMicroUSD, "remainder = granted − returned − settled(200k)")

	require.Equal(t, int64(700_000), walletState(t, pool, org), "1.5M − 800k released back")
	_, _, returned, status, _ := allowanceRow(t, pool, "reconcile-replica-1", ScopeWallet, org, "")
	require.Equal(t, AllowanceReleased, status)
	require.Equal(t, int64(800_000), returned)

	// The young expired allowance is untouched, its money still reserved.
	_, _, _, status, _ = allowanceRow(t, pool, "reconcile-replica-2", ScopeWallet, org, "")
	require.Equal(t, AllowanceExpired, status)
	require.Equal(t, int64(700_000), walletState(t, pool, org))
}

// TestConcurrentGrantStress_NoDeadlockNoOverrun: 100 goroutines grant on
// ONE scope; the run finishes (no deadlock), the refusals happen only when
// the capacity is genuinely exhausted, and Σ grants ≤ L always.
func TestConcurrentGrantStress_NoDeadlockNoOverrun(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-resv-stress"
	zero := int64(0)
	const capacity = int64(1_000_000_000) // $1000, no overdraft
	const bound = 15_000_000              // $15 → ⌊1000/15⌋ = 66 can fit
	setWallet(t, pool, org, 100_000, &zero)

	const goroutines = 100
	var ok, refused, otherErr atomic.Int64
	var sumGrants atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			g, err := store.Grant(ctx, fmt.Sprintf("stress-replica-%02d", n), org, []GrantRequest{
				{Scope: ScopeWallet, Key: org, Bound: bound},
			})
			switch {
			case err == nil:
				ok.Add(1)
				sumGrants.Add(int64(g[0].Delta))
			case err != nil && isInsufficient(err):
				refused.Add(1)
			default:
				otherErr.Add(1)
			}
		}(i)
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		t.Fatal("grant stress deadlocked")
	}

	require.Zero(t, otherErr.Load(), "unexpected errors: no deadlock, no serialization failures")
	require.Positive(t, ok.Load())
	require.Positive(t, refused.Load(), "capacity exhaustion must refuse late grants")
	require.LessOrEqual(t, sumGrants.Load(), capacity, "Σ grants ≤ L (admission invariant)")
	require.Equal(t, sumGrants.Load(), walletState(t, pool, org), "reserved == Σ grants")
	require.Equal(t, capacity/bound, ok.Load(), "⌊1000M/15M⌋ = 66 grants fit; the rest refuse")
}

func isInsufficient(err error) bool {
	return errors.Is(err, ErrInsufficientCapacity)
}

// TestBudgetReservations_ConsolidatedSchemaPresent: the reservation surface
// the 0023 migration used to ship (budget_allowances, session_spend, the
// reserved/grace columns, the org reservations_mode knob) now lives in the
// consolidated 0001_init baseline. The historical up/down file-cycle test
// died with that consolidation; what must keep holding is that the schema
// is present, insertable and starts from inert defaults.
func TestBudgetReservations_ConsolidatedSchemaPresent(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	// Schema presence.
	require.True(t, tableExists(t, pool, "budget_allowances"))
	require.True(t, tableExists(t, pool, "session_spend"))
	require.True(t, columnExists(t, pool, "org_credits", "reserved_micro_usd"))
	require.True(t, columnExists(t, pool, "org_credits", "grace_floor_cents"))
	require.True(t, columnExists(t, pool, "team_spend_monthly", "reserved_micro_usd"))
	require.True(t, columnExists(t, pool, "team_spend_monthly", "spend_micro_usd"), "pre-reservation spend column stays")
	require.True(t, columnExists(t, pool, "agent_spend_daily", "reserved_micro_usd"))
	require.True(t, columnExists(t, pool, "organizations", "reservations_mode"))
	require.True(t, columnExists(t, pool, "organizations", "default_output_cap_tokens"))
	require.True(t, columnExists(t, pool, "settlement_jobs", "allowance_id"))

	// Insertability of the whole surface (seed across the objects).
	org := "org-resv-migration"
	setWallet(t, pool, org, 50_000, nil)
	migOrg := uuid.New()
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, reservations_mode)
		VALUES ($1, 'migration-org', $2, 'shadow')`, migOrg, "migration-org-"+uuid.NewString()[:8])
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, status, lease_until)
		VALUES ('mig-replica', 'wallet', 'org-resv-migration', '', 'org-resv-migration', 123, 'active', now() + interval '10 min')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO session_spend (session_key_id, spent_micro_usd, reserved_micro_usd)
		VALUES (gen_random_uuid(), 7, 11)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, amount_cents, allowance_id)
		VALUES ('org-resv-migration', $1, 'wallet', 5, 42)`,
		fmt.Sprintf("req-mig-%d", time.Now().UnixNano()))
	require.NoError(t, err)

	// Inert defaults on a fresh wallet/org.
	plainOrg := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'defaults-org', $2)`, plainOrg, "defaults-org-"+uuid.NewString()[:8])
	require.NoError(t, err)

	var mode string
	err = pool.QueryRow(ctx, `SELECT reservations_mode FROM organizations WHERE id = $1`, plainOrg).Scan(&mode)
	require.NoError(t, err)
	require.Equal(t, "off", mode, "reservations_mode defaults to 'off'")

	setWallet(t, pool, "org-resv-defaults", 50_000, nil)
	var reserved int64
	err = pool.QueryRow(ctx, `SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, "org-resv-defaults").Scan(&reserved)
	require.NoError(t, err)
	require.Zero(t, reserved, "fresh wallet starts with reserved_micro_usd = 0")
}

func tableExists(t *testing.T, pool *pgxpool.Pool, table string) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1`,
		table).Scan(&n)
	require.NoError(t, err)
	return n == 1
}

func columnExists(t *testing.T, pool *pgxpool.Pool, table, column string) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`,
		table, column).Scan(&n)
	require.NoError(t, err)
	return n == 1
}

// TestN06P05Live_CloseAbandonedReplicaClosesOrphansSafely: the
// permanently-lost-replica verdict sorts an abandoned replica's rows by
// lifecycle shape — it closes a hard-crashed orphan (active, lease beyond
// the §14 safety window) with its full remainder, releases a finished
// drain (zero remainder) immediately, spares a mid-drain crash and a live
// renewing sibling (negative criterion), falls back to the §14 safety
// window when the caller passes no window, is idempotent, and leaves no
// lapsed non-released rows behind.
func TestN06P05Live_CloseAbandonedReplicaClosesOrphansSafely(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-orph-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	grant := func(replica string, bound money.MicroUSD) {
		_, err := store.Grant(ctx, replica, org, []GrantRequest{
			{Scope: ScopeWallet, Key: org, Bound: bound},
		})
		require.NoError(t, err)
	}

	// Four orphan shapes for one verdict to sort:
	//   dead     — crashed replica: active, lease lapsed 3h (beyond window)
	//   drained  — graceful drain that finished: zero remainder, young lease
	//   middrain — crashed mid-drain: draining, remainder held, young lease
	//   live     — alive and renewing: active, fresh lease
	grant("n06p5-orph-dead", 600_000)
	grant("n06p5-orph-drained", 100_000)
	grant("n06p5-orph-middrain", 300_000)
	grant("n06p5-orph-live", 200_000)
	n06p5ForceState(t, pool, "n06p5-orph-dead", org, AllowanceActive, 3*time.Hour)
	drained, err := store.MarkDraining(ctx, "n06p5-orph-middrain")
	require.NoError(t, err)
	require.Equal(t, int64(1), drained)
	sum, err := store.ReturnRemaining(ctx, org, "n06p5-orph-drained", []RemainingRequest{
		{Scope: ScopeWallet, Key: org, Holdback: 0},
	})
	require.NoError(t, err)
	require.Equal(t, int64(100_000), sum.ReturnedMicroUSD)
	require.Equal(t, int64(1_100_000), walletState(t, pool, org))

	// 1) Live renewing sibling: skipped, escrow untouched.
	s, err := store.CloseAbandonedReplica(ctx, "n06p5-orph-live", 0)
	require.NoError(t, err)
	require.Zero(t, s.Closed)
	require.Zero(t, s.ReturnedMicroUSD)
	require.Equal(t, int64(1), s.SkippedLive)
	require.Zero(t, s.AlreadyReleased)
	require.Equal(t, int64(1_100_000), walletState(t, pool, org))

	// 2) Mid-drain crash on a young lease: §7.1.1 safety skips it too —
	// money still owned must not move on a young lease, verdict or not.
	s, err = store.CloseAbandonedReplica(ctx, "n06p5-orph-middrain", 0)
	require.NoError(t, err)
	require.Zero(t, s.Closed)
	require.Equal(t, int64(1), s.SkippedLive)
	require.Equal(t, int64(1_100_000), walletState(t, pool, org))
	_, _, _, status, _ := allowanceRow(t, pool, "n06p5-orph-middrain", ScopeWallet, org, "")
	assert.Equal(t, AllowanceDraining, status)

	// 3) Finished drain (zero remainder): releasable immediately (§7.1.2),
	// with no money returned.
	s, err = store.CloseAbandonedReplica(ctx, "n06p5-orph-drained", 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), s.Closed)
	require.Zero(t, s.ReturnedMicroUSD)
	require.Zero(t, s.SkippedLive)
	_, _, _, status, _ = allowanceRow(t, pool, "n06p5-orph-drained", ScopeWallet, org, "")
	assert.Equal(t, AllowanceReleased, status)

	// 4) Hard-crashed orphan: closed with its full remainder. Window 0 →
	// the §14 ReservationSafetyWindow fallback admits the 3h-lapsed lease.
	s, err = store.CloseAbandonedReplica(ctx, "n06p5-orph-dead", 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), s.Closed)
	require.Equal(t, int64(600_000), s.ReturnedMicroUSD)
	require.Equal(t, int64(500_000), walletState(t, pool, org))
	_, granted, ret, status, _ := allowanceRow(t, pool, "n06p5-orph-dead", ScopeWallet, org, "")
	assert.Equal(t, int64(600_000), granted)
	assert.Equal(t, int64(600_000), ret)
	assert.Equal(t, AllowanceReleased, status)

	// 5) Recent crash inside the default window: the fallback fails
	// closed — the caller must assert the replica is gone for good (via
	// an explicit window) before the verdict moves young-lapsed money.
	grant("n06p5-orph-recent", 50_000)
	n06p5ForceState(t, pool, "n06p5-orph-recent", org, AllowanceActive, 1*time.Hour)
	s, err = store.CloseAbandonedReplica(ctx, "n06p5-orph-recent", 0)
	require.NoError(t, err)
	require.Zero(t, s.Closed)
	require.Equal(t, int64(1), s.SkippedLive)
	require.Equal(t, int64(550_000), walletState(t, pool, org))
	// N06-P05-T04: the explicit short window is the deliberate override —
	// but only under the fencing lease. Unfenced, any window shorter than
	// the §14 default is floored back up (fail-closed: a stale or
	// mis-configured caller can never release a renewing reserve), so 30m
	// still skips the 1h-lapsed row.
	s, err = store.CloseAbandonedReplica(ctx, "n06p5-orph-recent", 30*time.Minute)
	require.NoError(t, err)
	require.Zero(t, s.Closed)
	require.Equal(t, int64(1), s.SkippedLive)
	require.Equal(t, int64(550_000), walletState(t, pool, org))
	// The same verdict under a held fence closes: the serialized,
	// TTL-bounded override is the one authority allowed to accelerate.
	fence := NewRecoveryFence(pool, nil)
	lease, err := fence.Acquire(ctx, "n06p5-orph-recent", "verdict-t04", time.Hour)
	require.NoError(t, err)
	s, err = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), s.Closed)
	require.Equal(t, int64(50_000), s.ReturnedMicroUSD)
	require.Equal(t, int64(500_000), walletState(t, pool, org))
	require.NoError(t, lease.Release(ctx))

	// 6) Idempotent: re-verdicting closed replicas observes the
	// exactly-once losing side, moves nothing.
	s, err = store.CloseAbandonedReplica(ctx, "n06p5-orph-dead", 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), s.AlreadyReleased)
	require.Zero(t, s.Closed)
	require.Zero(t, s.ReturnedMicroUSD)
	require.Equal(t, int64(500_000), walletState(t, pool, org))

	// 7) Unknown replica: a clean, all-zero summary — no error, no rows.
	s, err = store.CloseAbandonedReplica(ctx, "n06p5-orph-nobody", time.Hour)
	require.NoError(t, err)
	require.Zero(t, s.Closed)
	require.Zero(t, s.ReturnedMicroUSD)
	require.Zero(t, s.SkippedLive)
	require.Zero(t, s.AlreadyReleased)

	// The verdict leaves no lapsed non-released rows: no eternal
	// reservations for the abandoned replica.
	assert.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations")
}
