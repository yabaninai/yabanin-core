package adminstore

// AF-09: DB-level proof of the atomic precondition (CAS) contract for the
// audited rollback families. The expectation is part of the same SQL
// statement as the write, so a concurrent mutation between "check" and
// "write" is impossible by construction; here the statement semantics are
// verified against real PostgreSQL (disposable container, repo convention),
// including the 10→20→100 rollback race from audit finding F07: the stale
// rollback must lose with ErrPreconditionFailed while the newer value
// survives.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_CAS_APIKeyActive_Integration(t *testing.T) {
	store, orgID, pool := casTestEnv(t)
	ctx := context.Background()

	key := casSeedKey(t, pool, orgID)

	// Baseline: the key starts deactivated (the newer decision's effect).
	require.NoError(t, store.UpdateAPIKeyActive(ctx, key.ID, false))

	// The audited change enables the key (expects the recorded pre-state).
	current, err := store.UpdateAPIKeyActivePreconditioned(ctx, key.ID, true, boolPtr(false))
	require.NoError(t, err)
	require.NotNil(t, current)
	assert.True(t, *current, "success returns the new state")

	// A newer security decision deactivates the key again.
	require.NoError(t, store.UpdateAPIKeyActive(ctx, key.ID, false))

	// Stale rollback of the audited enable (expects active=true) must
	// conflict with the current state and change nothing.
	current, err = store.UpdateAPIKeyActivePreconditioned(ctx, key.ID, true, boolPtr(true))
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.NotNil(t, current)
	assert.False(t, *current, "conflict reports the newer state")

	got, err := store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.False(t, got.Active, "the newer deactivation survives")

	// Matching expectation applies; a vanished row is ErrNotFound.
	current, err = store.UpdateAPIKeyActivePreconditioned(ctx, key.ID, true, boolPtr(false))
	require.NoError(t, err)
	assert.True(t, *current)

	require.NoError(t, store.DeleteAPIKey(ctx, key.ID))
	_, err = store.UpdateAPIKeyActivePreconditioned(ctx, key.ID, true, boolPtr(false))
	assert.True(t, IsNotFound(err), "missing row → 404 semantics")
}

func TestStore_CAS_RoutingRuleEnabled_Integration(t *testing.T) {
	store, orgID, _ := casTestEnv(t)
	ctx := context.Background()

	rule, err := store.CreateRoutingRule(ctx, orgID, "model == 'm'", "m", 1)
	require.NoError(t, err)

	// Audited change: the rule is disabled (created enabled by default).
	current, err := store.UpdateRoutingRuleEnabledPreconditioned(ctx, rule.ID, false, boolPtr(true))
	require.NoError(t, err)
	assert.False(t, *current, "success returns the new state")

	// A newer decision re-enables the rule.
	require.NoError(t, store.UpdateRoutingRuleEnabled(ctx, rule.ID, true))

	// Stale rollback of the disable (expects enabled=false) conflicts and
	// does not cancel the newer enable decision.
	current, err = store.UpdateRoutingRuleEnabledPreconditioned(ctx, rule.ID, false, boolPtr(false))
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.NotNil(t, current)
	assert.True(t, *current)

	got, err := store.GetRoutingRuleByID(ctx, rule.ID)
	require.NoError(t, err)
	assert.True(t, got.Enabled, "the newer enable survives")
}

func TestStore_CAS_Labels_Integration(t *testing.T) {
	store, orgID, pool := casTestEnv(t)
	ctx := context.Background()

	key := casSeedKey(t, pool, orgID)

	expect := &APIKeyLabelsState{Labels: map[string]string{}, LabelsLocked: false, CanMintSessions: false, CanReadUsage: false}
	current, err := store.UpdateAPIKeyLabelsPreconditioned(ctx, key.ID, map[string]string{"team": "payments"}, true, false, true, expect)
	require.NoError(t, err)
	assert.Equal(t, "payments", current.Labels["team"])

	// Stale rollback expecting the pre-change set conflicts (jsonb equality).
	current, err = store.UpdateAPIKeyLabelsPreconditioned(ctx, key.ID, map[string]string{}, false, false, false, expect)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.NotNil(t, current)
	assert.Equal(t, "payments", current.Labels["team"], "conflict reports the current labels")
	assert.True(t, current.LabelsLocked)

	got, err := store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.Equal(t, "payments", got.Labels["team"], "newer labels survive")
}

func TestStore_CAS_TeamBudget_RollbackRace_Integration(t *testing.T) {
	store, orgID, pool := casTestEnv(t)
	ctx := context.Background()

	teamID := casSeedTeam(t, pool, orgID)

	// The F07 scenario: first change records after={20}, then the limit
	// moves to 100. The rollback of the first change expects 20 and must
	// lose; the 100 survives.
	_, err := store.UpsertTeamBudgetPreconditioned(ctx, teamID, 20, true, &TeamBudgetExpectation{Absent: true})
	require.NoError(t, err)

	_, err = store.UpsertTeamBudgetPreconditioned(ctx, teamID, 100, true, &TeamBudgetExpectation{MonthlyLimitUSD: 20, HardLimit: true})
	require.NoError(t, err)

	current, err := store.UpsertTeamBudgetPreconditioned(ctx, teamID, 10, true, &TeamBudgetExpectation{MonthlyLimitUSD: 20, HardLimit: true})
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.NotNil(t, current)
	assert.InDelta(t, 100.0, current.MonthlyLimitUSD, 1e-9, "409 body carries the current limit")

	tb, err := store.GetTeamBudget(ctx, teamID)
	require.NoError(t, err)
	assert.InDelta(t, 100.0, tb.MonthlyLimitUSD, 1e-9, "100 survives the stale rollback")

	// Matching rollback applies; restore-after-delete requires absence.
	_, err = store.UpsertTeamBudgetPreconditioned(ctx, teamID, 10, true, &TeamBudgetExpectation{MonthlyLimitUSD: 100, HardLimit: true})
	require.NoError(t, err)

	deleted, _, err := store.DeleteTeamBudgetPreconditioned(ctx, teamID, TeamBudgetExpectation{MonthlyLimitUSD: 10, HardLimit: true})
	require.NoError(t, err)
	assert.True(t, deleted)

	_, err = store.UpsertTeamBudgetPreconditioned(ctx, teamID, 10, true, &TeamBudgetExpectation{Absent: true})
	require.NoError(t, err)

	// A newer row appears; the expected-absent restore now conflicts.
	require.NoError(t, store.UpsertTeamBudget(ctx, teamID, 75, false))
	_, err = store.UpsertTeamBudgetPreconditioned(ctx, teamID, 10, true, &TeamBudgetExpectation{Absent: true})
	require.ErrorIs(t, err, ErrPreconditionFailed)

	_, current, err = store.DeleteTeamBudgetPreconditioned(ctx, teamID, TeamBudgetExpectation{MonthlyLimitUSD: 10, HardLimit: true})
	require.ErrorIs(t, err, ErrPreconditionFailed)
	assert.NotNil(t, current, "conflict reports the newer row")
}

func TestStore_CAS_TeamBudget_ConcurrentHammer_Integration(t *testing.T) {
	store, orgID, pool := casTestEnv(t)
	ctx := context.Background()

	teamID := casSeedTeam(t, pool, orgID)
	require.NoError(t, store.UpsertTeamBudget(ctx, teamID, 100, true))

	// Writers keep moving the limit while a stale rollback (expects 20)
	// hammers the same row: the compare is part of the write statement, so
	// there is no window between check and write — the stale value must
	// NEVER land no matter the interleaving. The hammer is iteration-bounded
	// (not time-bounded): the WaitGroup join is the deterministic end signal.
	const hammerIters = 100
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		v := 100.0
		for i := 0; i < hammerIters; i++ {
			_ = store.UpsertTeamBudget(ctx, teamID, v, true)
			if v == 100.0 {
				v = 101.0
			} else {
				v = 100.0
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < hammerIters; i++ {
			_, _ = store.UpsertTeamBudgetPreconditioned(ctx, teamID, 10, true, &TeamBudgetExpectation{MonthlyLimitUSD: 20, HardLimit: true})
		}
	}()
	wg.Wait()

	tb, err := store.GetTeamBudget(ctx, teamID)
	require.NoError(t, err)
	assert.Contains(t, []float64{100, 101}, tb.MonthlyLimitUSD,
		"only the plain writers' values survive; the stale rollback never landed")
}

func TestStore_CAS_AgentBudget_Integration(t *testing.T) {
	store, orgID, _ := casTestEnv(t)
	ctx := context.Background()

	agentID := casSeedAgentKey(t, store, orgID)

	current, err := store.UpsertAgentBudgetPreconditioned(ctx, agentID, 7000, &AgentBudgetExpectation{Absent: true})
	require.NoError(t, err)
	assert.EqualValues(t, 7000, current.DailyLimitCents)

	_, err = store.UpsertAgentBudgetPreconditioned(ctx, agentID, 5000, &AgentBudgetExpectation{DailyLimitCents: 7000})
	require.NoError(t, err)

	current, err = store.UpsertAgentBudgetPreconditioned(ctx, agentID, 5000, &AgentBudgetExpectation{DailyLimitCents: 7000})
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.NotNil(t, current)
	assert.EqualValues(t, 5000, current.DailyLimitCents)

	b, err := store.GetAgentBudget(ctx, agentID)
	require.NoError(t, err)
	assert.EqualValues(t, 5000, b.DailyLimitCents)

	_, current, err = store.DeleteAgentBudgetPreconditioned(ctx, agentID, 9999)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	assert.EqualValues(t, 5000, current.DailyLimitCents)
	deleted, _, err := store.DeleteAgentBudgetPreconditioned(ctx, agentID, 5000)
	require.NoError(t, err)
	assert.True(t, deleted)
}

func TestStore_CAS_Whitelist_Integration(t *testing.T) {
	store, orgID, pool := casTestEnv(t)
	ctx := context.Background()

	key := casSeedKey(t, pool, orgID)

	// Restore-add requires absence, then conflicts on a second restore.
	entry, err := store.AddKeyWhitelistPreconditioned(ctx, key.ID, "m-1", true)
	require.NoError(t, err)
	assert.True(t, entry.Allowed)

	current, err := store.AddKeyWhitelistPreconditioned(ctx, key.ID, "m-1", true)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.NotNil(t, current)
	assert.True(t, current.Allowed)

	// Conditional delete matches only the recorded allowed value.
	var deleted bool
	_, current, err = store.DeleteKeyWhitelistPreconditioned(ctx, key.ID, "m-1", false)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	assert.True(t, current.Allowed)
	deleted, _, err = store.DeleteKeyWhitelistPreconditioned(ctx, key.ID, "m-1", true)
	require.NoError(t, err)
	assert.True(t, deleted)

	_, current, err = store.DeleteKeyWhitelistPreconditioned(ctx, key.ID, "m-1", true)
	require.ErrorIs(t, err, ErrPreconditionFailed, "already-removed entry is a mismatch, not a success")
	assert.Nil(t, current)

	// Team allowlist mirrors the contract.
	teamID := casSeedTeam(t, pool, orgID)
	_, err = store.AddTeamWhitelistPreconditioned(ctx, teamID, "m-1", false)
	require.NoError(t, err)
	_, _, err = store.DeleteTeamWhitelistPreconditioned(ctx, teamID, "m-1", true)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	deleted, _, err = store.DeleteTeamWhitelistPreconditioned(ctx, teamID, "m-1", false)
	require.NoError(t, err)
	assert.True(t, deleted)
}

// --- shared seeds -----------------------------------------------------------

func casTestEnv(t *testing.T) (*Store, string, *pgxpool.Pool) {
	t.Helper()
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	slug := fmt.Sprintf("af09-cas-%d", time.Now().UnixNano())
	_, err := pool.Exec(ctx, `INSERT INTO organizations (name, slug) VALUES ('AF09 CAS', $1)`, slug)
	require.NoError(t, err)
	var orgID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT id::text FROM organizations WHERE slug = $1`, slug).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return store, orgID, pool
}

func casSeedKey(t *testing.T, pool *pgxpool.Pool, orgID string) *APIKey {
	t.Helper()
	teamID := casSeedTeam(t, pool, orgID)
	hash := sha256.Sum256([]byte(fmt.Sprintf("af09-%d", time.Now().UnixNano())))
	key, err := New(pool, slog.Default(), nil).CreateAPIKey(context.Background(), hex.EncodeToString(hash[:]), "af09-key", &orgID, &teamID)
	require.NoError(t, err)
	return key
}

func casSeedTeam(t *testing.T, pool *pgxpool.Pool, orgID string) string {
	t.Helper()
	var teamID string
	require.NoError(t, pool.QueryRow(context.Background(), `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1, 'af09-team', $2)
		RETURNING id::text`,
		orgID, fmt.Sprintf("af09-team-%d", time.Now().UnixNano())).Scan(&teamID))
	return teamID
}

func casSeedAgentKey(t *testing.T, store *Store, orgID string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(fmt.Sprintf("af09-agent-%d", time.Now().UnixNano())))
	key, err := store.CreateAgentKey(context.Background(), hex.EncodeToString(hash[:]), "af09-agent", orgID)
	require.NoError(t, err)
	return key.ID
}

func boolPtr(b bool) *bool { return &b }
