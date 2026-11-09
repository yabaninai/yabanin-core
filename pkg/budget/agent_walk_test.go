package budget

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// walkHarness resolves per-agent budgets, spends and the agent_keys parent
// chain for the delegation-walk tests (AUDIT-P1-03): the enforcer must walk
// ancestors, deny on missing ancestor budgets (fail-closed), deny on an
// exhausted ancestor subtree, cap the walk depth and break cycles.
type walkHarness struct {
	parents   map[string]*string // agent_keys.parent_id by id (nil → root; absent id → no row)
	budgets   map[string]int64   // agent_budgets daily_limit_cents by id (absent → no row)
	subtree   map[string]int64   // ancestor subtree spend (SUM over agent_spend_daily) by ancestor id
	spends    map[string]int64   // own agent_spend_daily cost_cents by agent id
	parentErr error              // failure injection for the parent lookup
	subErr    error              // failure injection for the subtree SUM
	budgetQ   []string           // budget lookups performed (for depth-cap assertions)
}

func (h *walkHarness) enforcer(t *testing.T) *AgentEnforcer {
	t.Helper()
	mock := &agentMock{
		budgetFnArgs: func(args ...interface{}) pgx.Row {
			id, _ := args[0].(string)
			h.budgetQ = append(h.budgetQ, id)
			limit, ok := h.budgets[id]
			if !ok {
				return &mockRow{err: pgx.ErrNoRows}
			}
			return &mockRow{data: [][]interface{}{{limit}}}
		},
		spendFnArgs: func(args ...interface{}) pgx.Row {
			id, _ := args[0].(string)
			if spend, ok := h.spends[id]; ok {
				return &mockRow{data: [][]interface{}{{spend}}}
			}
			// getSpendToday maps ErrNoRows → 0.
			return &mockRow{err: pgx.ErrNoRows}
		},
		keysFn: func(query string, args ...interface{}) pgx.Row {
			if strings.Contains(query, "agent_spend_daily") { // subtree SUM
				if h.subErr != nil {
					return &mockRow{err: h.subErr}
				}
				id, _ := args[0].(string)
				return &mockRow{data: [][]interface{}{{h.subtree[id]}}}
			}
			if h.parentErr != nil {
				return &mockRow{err: h.parentErr}
			}
			id, _ := args[0].(string)
			parent, ok := h.parents[id]
			if !ok {
				return &mockRow{err: pgx.ErrNoRows} // no agent_keys row → synthetic id
			}
			if parent == nil {
				return &mockRow{data: [][]interface{}{{nil}}} // root key
			}
			return &mockRow{data: [][]interface{}{{*parent}}}
		},
	}
	e := NewAgentEnforcer(mock, newBudgetTestLogger())
	e.now = fixedNow
	return e
}

func strPtr(s string) *string { return &s }

func TestCheckAgentBudget_RootIgnoresParentChain(t *testing.T) {
	// A root key (parent_id NULL) must behave exactly as before the walk:
	// own budget + own spend only.
	h := &walkHarness{
		parents: map[string]*string{"root": nil},
		budgets: map[string]int64{"root": 500},
		spends:  map[string]int64{"root": 400},
		subtree: map[string]int64{"root": 0},
	}
	assert.NoError(t, h.enforcer(t).CheckAgentBudget(context.Background(), "root"))
}

func TestCheckAgentBudget_SyntheticIDUnaffected(t *testing.T) {
	// Legacy synthetic agent ids (no agent_keys row) keep working: the walk
	// ends immediately and only the own budget applies.
	h := &walkHarness{
		budgets: map[string]int64{"legacy-synthetic": 100},
		spends:  map[string]int64{"legacy-synthetic": 99},
	}
	assert.NoError(t, h.enforcer(t).CheckAgentBudget(context.Background(), "legacy-synthetic"))
}

func TestCheckAgentBudget_ChildUnderParentHeadroom(t *testing.T) {
	h := &walkHarness{
		parents: map[string]*string{"child": strPtr("parent")},
		budgets: map[string]int64{"child": 500, "parent": 1000},
		spends:  map[string]int64{"child": 100},
		subtree: map[string]int64{"parent": 600},
	}
	assert.NoError(t, h.enforcer(t).CheckAgentBudget(context.Background(), "child"))
}

func TestCheckAgentBudget_ParentSubtreeExhausted(t *testing.T) {
	h := &walkHarness{
		parents: map[string]*string{"child": strPtr("parent")},
		budgets: map[string]int64{"child": 500, "parent": 1000},
		spends:  map[string]int64{"child": 100}, // own cap fine
		subtree: map[string]int64{"parent": 1000},
	}
	err := h.enforcer(t).CheckAgentBudget(context.Background(), "child")
	require.ErrorIs(t, err, ErrAgentBudgetExceeded)
	assert.Contains(t, err.Error(), "parent", "denial must name the exhausted ancestor")
}

func TestCheckAgentBudget_ParentBudgetMissingFailClosed(t *testing.T) {
	// A child under a parent without a budget row must be denied even when
	// its own cap has headroom — an uncapped ancestor cannot fund the spend.
	h := &walkHarness{
		parents: map[string]*string{"child": strPtr("parent")},
		budgets: map[string]int64{"child": 500},
		spends:  map[string]int64{"child": 1},
	}
	err := h.enforcer(t).CheckAgentBudget(context.Background(), "child")
	require.ErrorIs(t, err, ErrNoAgentBudget)
	assert.Contains(t, err.Error(), "parent", "denial must name the budgetless ancestor")
}

func TestCheckAgentBudget_ParentLookupUnavailable(t *testing.T) {
	h := &walkHarness{
		parents:   map[string]*string{"child": strPtr("parent")},
		budgets:   map[string]int64{"child": 500},
		parentErr: errors.New("connection refused"),
	}
	err := h.enforcer(t).CheckAgentBudget(context.Background(), "child")
	assert.ErrorIs(t, err, ErrAgentBudgetUnavailable)
}

func TestCheckAgentBudget_SubtreeSpendUnavailable(t *testing.T) {
	h := &walkHarness{
		parents: map[string]*string{"child": strPtr("parent")},
		budgets: map[string]int64{"child": 500, "parent": 1000},
		subErr:  errors.New("statement timeout"),
	}
	err := h.enforcer(t).CheckAgentBudget(context.Background(), "child")
	assert.ErrorIs(t, err, ErrAgentBudgetUnavailable)
}

func TestCheckAgentBudget_DelegationCycleFailClosed(t *testing.T) {
	// Corrupt data (a→b→a) must terminate: the visited set breaks the loop
	// and denies instead of spinning.
	h := &walkHarness{
		parents: map[string]*string{
			"a": strPtr("b"),
			"b": strPtr("a"),
		},
		budgets: map[string]int64{"a": 1000, "b": 1000},
		subtree: map[string]int64{"b": 100},
	}
	err := h.enforcer(t).CheckAgentBudget(context.Background(), "a")
	require.ErrorIs(t, err, ErrAgentBudgetUnavailable)
	assert.Contains(t, err.Error(), "cycle")
}

func TestCheckAgentBudget_WalkDepthCapped(t *testing.T) {
	// The walk enforces at most maxAgentAncestorDepth ancestors (a→b→c→d→e
	// checked; f beyond the cap is never looked up). The admin API only
	// creates depth-1 delegations; this is defense in depth.
	chain := map[string]*string{
		"a": strPtr("b"), "b": strPtr("c"), "c": strPtr("d"),
		"d": strPtr("e"), "e": strPtr("f"), "f": nil,
	}
	budgets := map[string]int64{"a": 1000, "b": 1000, "c": 1000, "d": 1000, "e": 1000, "f": 1000}
	subtree := map[string]int64{"b": 10, "c": 10, "d": 10, "e": 10, "f": 100000}
	h := &walkHarness{parents: chain, budgets: budgets, subtree: subtree}
	require.NoError(t, h.enforcer(t).CheckAgentBudget(context.Background(), "a"))
	assert.NotContains(t, h.budgetQ, "f", "walk must stop at maxAgentAncestorDepth ancestors")
}
