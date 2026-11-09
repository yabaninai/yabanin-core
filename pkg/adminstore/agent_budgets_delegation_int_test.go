package adminstore

// AUDIT-P1-03: the delegation-budget invariant runs against real Postgres
// (testdb.Postgres). Unit fakes mirror the SQL, so row shapes, NULL parent
// semantics, the advisory-lock serialization and the FOR UPDATE headroom
// read were never exercised. This suite drives the production store:
//   - a child cap must fit the parent's remaining headroom
//     (parent limit − parent spend today − Σ active non-expired sibling
//     caps, excluding the child's own current cap on updates),
//   - the child key + its agent_budgets row are written in ONE transaction:
//     a refused delegation leaves no key row behind,
//   - concurrent delegations on the same parent serialize (advisory lock +
//     row lock) to exactly one winner,
//   - revoked siblings stop counting toward the headroom,
//   - child budget updates re-check the bound; the CAS variant runs INSIDE
//     the headroom transaction (a preconditioned widen cannot bypass it),
//   - roots keep the legacy unconstrained paths.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// delBudgetFixture is one isolated slice of the shared stand: an org plus
// every agent key a test created (deleted in cleanup, org last).
type delBudgetFixture struct {
	store *Store
	org   string
	keys  []string // every agent_keys id created; deleted in cleanup
}

var delKeysMu sync.Mutex

func (f *delBudgetFixture) addKey(id string) {
	delKeysMu.Lock()
	f.keys = append(f.keys, id)
	delKeysMu.Unlock()
}

func newDelBudgetFixture(t *testing.T) *delBudgetFixture {
	t.Helper()
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, "del-budget org "+fmt.Sprintf("%x", time.Now().UnixNano()),
		"delb-"+fmt.Sprintf("%x", time.Now().UnixNano()))
	require.NoError(t, err)
	f := &delBudgetFixture{store: store, org: org.ID}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM agent_spend_daily WHERE agent_id::text = ANY($1)`, f.keys)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM agent_budgets WHERE agent_id::text = ANY($1)`, f.keys)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM agent_keys WHERE id::text = ANY($1)`, f.keys)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM organizations WHERE id::text = $1`, f.org)
	})
	return f
}

// rootKey mints a root agent key with the given daily budget (0 = no row).
func (f *delBudgetFixture) rootKey(ctx context.Context, t *testing.T, name string, budgetCents int64) *AgentKey {
	t.Helper()
	token := fmt.Sprintf("%x", time.Now().UnixNano())
	key, err := f.store.CreateAgentKey(ctx, "hash-delb-"+name+"-"+token, "delb "+name, f.org)
	require.NoError(t, err)
	f.addKey(key.ID)
	if budgetCents > 0 {
		_, err = f.store.UpsertAgentBudget(ctx, key.ID, budgetCents)
		require.NoError(t, err)
	}
	return key
}

// childKey mints a real CHILD key of parent (legacy single-insert path —
// the invariant itself is what the tests exercise) with an optional budget
// row (0 = none).
func (f *delBudgetFixture) childKey(ctx context.Context, t *testing.T, parentID, name string, budgetCents int64) *AgentKey {
	t.Helper()
	token := fmt.Sprintf("%x", time.Now().UnixNano())
	expires := time.Now().UTC().Add(time.Hour)
	key, err := f.store.CreateAgentKeyDelegated(ctx, AgentKeyCreateParams{
		KeyHash:   "hash-delbc-" + name + "-" + token,
		Name:      "delb child " + name,
		OrgID:     f.org,
		ParentID:  &parentID,
		ExpiresAt: &expires,
	})
	require.NoError(t, err)
	f.addKey(key.ID)
	if budgetCents > 0 {
		_, err = f.store.UpsertAgentBudget(ctx, key.ID, budgetCents)
		require.NoError(t, err)
	}
	return key
}

// seedSpend writes cost for TODAY (DB clock, matching the enforcer's
// `(now() AT TIME ZONE 'utc')::date` boundary).
func seedDelSpend(ctx context.Context, t *testing.T, f *delBudgetFixture, agentID string, cents int64) {
	t.Helper()
	_, err := f.store.db.Exec(ctx,
		`INSERT INTO agent_spend_daily (agent_id, day, cost_cents, cost_micro_usd)
		 VALUES ($1::uuid, (now() AT TIME ZONE 'utc')::date, $2, $2::bigint * 10000)
		 ON CONFLICT (agent_id, day) DO UPDATE SET cost_cents = $2, cost_micro_usd = $2::bigint * 10000`,
		agentID, cents)
	require.NoError(t, err)
}

// delegParams builds params for a child of parent with the given cap.
func delegParams(orgID, parentID, name string, capCents *int64) AgentKeyCreateParams {
	expires := time.Now().UTC().Add(time.Hour)
	return AgentKeyCreateParams{
		KeyHash:         "hash-child-" + name + "-" + fmt.Sprintf("%x", time.Now().UnixNano()),
		Name:            "delb child " + name,
		OrgID:           orgID,
		ParentID:        &parentID,
		ExpiresAt:       &expires,
		DailyLimitCents: capCents,
	}
}

func TestCreateAgentKeyDelegatedChecked_HeadroomEnforced_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	parent := f.rootKey(ctx, t, "parent", 1000)
	seedDelSpend(ctx, t, f, parent.ID, 400) // headroom = 1000 − 400 = 600

	// Over the headroom: refused, and NO key row may exist (atomicity).
	over := delegParams(f.org, parent.ID, "over", ptrInt64(700))
	_, err := f.store.CreateAgentKeyDelegatedChecked(ctx, over)
	require.ErrorIs(t, err, ErrDelegationHeadroomExceeded)
	var n int
	require.NoError(t, f.store.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM agent_keys WHERE key_hash = $1`, over.KeyHash).Scan(&n))
	require.Equal(t, 0, n, "refused delegation must not leave a key row")
	require.NoError(t, f.store.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM agent_budgets WHERE agent_id::text = ANY($1)`, f.keys).Scan(&n))
	require.Equal(t, 1, n, "only the parent budget row exists")

	// Exactly at the headroom: allowed.
	at := delegParams(f.org, parent.ID, "at-limit", ptrInt64(600))
	child, err := f.store.CreateAgentKeyDelegatedChecked(ctx, at)
	require.NoError(t, err)
	f.addKey(child.ID)
	require.NotNil(t, child.ParentID)
	require.Equal(t, parent.ID, *child.ParentID)
	b, err := f.store.GetAgentBudget(ctx, child.ID)
	require.NoError(t, err)
	require.Equal(t, int64(600), b.DailyLimitCents, "child budget row written in the same tx")
}

func TestCreateAgentKeyDelegatedChecked_SiblingCapsCount_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	parent := f.rootKey(ctx, t, "parent", 1000)
	sibling := f.childKey(ctx, t, parent.ID, "sibling", 300) // active child, cap 300
	seedDelSpend(ctx, t, f, parent.ID, 0)

	// Active sibling cap 300: headroom = 1000 − 0 − 300 = 700.
	p := delegParams(f.org, parent.ID, "too-big", ptrInt64(800))
	_, err := f.store.CreateAgentKeyDelegatedChecked(ctx, p)
	require.ErrorIs(t, err, ErrDelegationHeadroomExceeded)

	// Revoked sibling: its cap stops counting → 800 now fits.
	require.NoError(t, f.store.RevokeAgentKey(ctx, sibling.ID))
	ok := delegParams(f.org, parent.ID, "fits", ptrInt64(800))
	child, err := f.store.CreateAgentKeyDelegatedChecked(ctx, ok)
	require.NoError(t, err)
	f.addKey(child.ID)
}

func TestCreateAgentKeyDelegatedChecked_ParentMustHaveBudget_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	parent := f.rootKey(ctx, t, "no-budget", 0) // root, but no budget row

	p := delegParams(f.org, parent.ID, "child", ptrInt64(100))
	_, err := f.store.CreateAgentKeyDelegatedChecked(ctx, p)
	require.ErrorIs(t, err, ErrParentBudgetMissing, "uncapped parent cannot fund a delegation (fail-closed)")
}

func TestCreateAgentKeyDelegatedChecked_ParentMustBeRoot_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	parent := f.rootKey(ctx, t, "parent", 1000)
	child := delegParams(f.org, parent.ID, "child", ptrInt64(100))
	mid, err := f.store.CreateAgentKeyDelegatedChecked(ctx, child)
	require.NoError(t, err)
	f.addKey(mid.ID)

	// A child of a child: the checked path must refuse (defense in depth —
	// the admin API handler refuses earlier; the store must not depend on it).
	grand := delegParams(f.org, mid.ID, "grandchild", ptrInt64(50))
	_, err = f.store.CreateAgentKeyDelegatedChecked(ctx, grand)
	require.ErrorIs(t, err, ErrParentNotDelegable)
}

func TestCreateAgentKeyDelegatedChecked_ConcurrentExactlyOneWins_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	parent := f.rootKey(ctx, t, "parent", 1000)
	seedDelSpend(ctx, t, f, parent.ID, 400) // headroom 600; each child asks 600

	const racers = 3
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := delegParams(f.org, parent.ID, fmt.Sprintf("racer-%d", i), ptrInt64(600))
			child, err := f.store.CreateAgentKeyDelegatedChecked(ctx, p)
			if err == nil {
				f.addKey(child.ID)
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
			continue
		}
		require.ErrorIs(t, err, ErrDelegationHeadroomExceeded)
	}
	require.Equal(t, 1, wins, "advisory lock + headroom tx must serialize to exactly one winner")
}

func TestUpsertAgentBudgetChecked_ChildBound_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	parent := f.rootKey(ctx, t, "parent", 1000)
	c1 := f.childKey(ctx, t, parent.ID, "c1", 0)
	c2 := f.childKey(ctx, t, parent.ID, "c2", 400)

	// child1 has no budget yet (cap-less child): headroom = 1000 − 0 − 400 = 600.
	_, err := f.store.UpsertAgentBudgetChecked(ctx, c1.ID, 700)
	require.ErrorIs(t, err, ErrDelegationHeadroomExceeded)

	b, err := f.store.UpsertAgentBudgetChecked(ctx, c1.ID, 600)
	require.NoError(t, err)
	require.Equal(t, int64(600), b.DailyLimitCents)

	// Updating child1 again: its OWN current cap (600) is excluded from the
	// sibling sum → headroom still 1000 − 0 − 400 = 600; 600 fits, 601 not.
	_, err = f.store.UpsertAgentBudgetChecked(ctx, c1.ID, 600)
	require.NoError(t, err)
	_, err = f.store.UpsertAgentBudgetChecked(ctx, c1.ID, 601)
	require.ErrorIs(t, err, ErrDelegationHeadroomExceeded)

	// child2 widens past the shared headroom (child1 now holds 600).
	_, err = f.store.UpsertAgentBudgetChecked(ctx, c2.ID, 700)
	require.ErrorIs(t, err, ErrDelegationHeadroomExceeded)

	// Parent spend counts too.
	seedDelSpend(ctx, t, f, parent.ID, 100) // headroom 1000 − 100 − 600 = 300
	_, err = f.store.UpsertAgentBudgetChecked(ctx, c2.ID, 400)
	require.ErrorIs(t, err, ErrDelegationHeadroomExceeded)
	_, err = f.store.UpsertAgentBudgetChecked(ctx, c2.ID, 300)
	require.NoError(t, err)
}

func TestUpsertAgentBudgetChecked_CASInsideHeadroomTx_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	parent := f.rootKey(ctx, t, "parent", 1000)
	child := f.childKey(ctx, t, parent.ID, "child", 0)
	seedDelSpend(ctx, t, f, parent.ID, 400) // headroom 600

	// Absent → first insert within headroom.
	cur, err := f.store.UpsertAgentBudgetPreconditionedChecked(ctx, child.ID, 500,
		&AgentBudgetExpectation{Absent: true})
	require.NoError(t, err)
	require.Equal(t, int64(500), cur.DailyLimitCents)

	// Matching expectation widens within headroom (≤ 600).
	_, err = f.store.UpsertAgentBudgetPreconditionedChecked(ctx, child.ID, 600,
		&AgentBudgetExpectation{DailyLimitCents: 500})
	require.NoError(t, err)

	// Stale expectation → conflict carrying the current row.
	cur, err = f.store.UpsertAgentBudgetPreconditionedChecked(ctx, child.ID, 600,
		&AgentBudgetExpectation{DailyLimitCents: 500})
	require.ErrorIs(t, err, ErrPreconditionFailed)
	require.NotNil(t, cur)
	require.Equal(t, int64(600), cur.DailyLimitCents)

	// A preconditioned WIDEN past the headroom must not pass silently.
	_, err = f.store.UpsertAgentBudgetPreconditionedChecked(ctx, child.ID, 60000,
		&AgentBudgetExpectation{DailyLimitCents: 600})
	require.ErrorIs(t, err, ErrDelegationHeadroomExceeded)
}

func TestUpsertAgentBudgetChecked_RootUnconstrained_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	root := f.rootKey(ctx, t, "root", 100)
	b, err := f.store.UpsertAgentBudgetChecked(ctx, root.ID, 10_000_000)
	require.NoError(t, err)
	require.Equal(t, int64(10_000_000), b.DailyLimitCents,
		"roots keep the legacy unconstrained update path")
}

func TestUpsertAgentBudgetChecked_KeyNotFound_Int(t *testing.T) {
	ctx := context.Background()
	f := newDelBudgetFixture(t)
	_, err := f.store.UpsertAgentBudgetChecked(ctx, "00000000-0000-0000-0000-000000000000", 100)
	require.ErrorIs(t, err, ErrNotFound, "want ErrNotFound")
}

func ptrInt64(v int64) *int64 { return &v }
