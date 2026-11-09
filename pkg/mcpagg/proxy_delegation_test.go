package mcpagg

// AUTH-02 regression coverage: a delegated agent key must inherit the
// parent's tool restriction on a shared server.
//
// The defect (DEEP-AUDIT AUTH-02): delegation stored an UNRESTRICTED child
// grant (allowed_tools = [] = every tool) whenever the parent's grant on
// that server was tool-restricted, and the invoke path checked only the
// child grant — so a child key could invoke tools its parent was never
// allowed to call. Restriction applied only when an admin hand-narrowed
// the child grant after issuance.
//
// The fix: the store exposes DelegationChainAllowance, which walks the
// agent's whole delegation chain (agent_keys.parent_id) and intersects
// every chain member's enabled grant per server; the proxy applies that
// ceiling at invoke time (redundant with the grant-time copy, so a later
// grant edit cannot re-open the hole), and the catalog hides servers/tools
// the chain does not allow.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isChainQuery reports whether the SQL is the delegation-chain query (the
// recursive agent_keys walk joined to the grants table).
func isChainQuery(sql string) bool {
	return strings.Contains(sql, "WITH RECURSIVE") && strings.Contains(sql, "agent_keys")
}

// chainRowFor answers the delegation-chain aggregate for a single-agent
// (non-delegated) principal: the pre-AUTH-02 mock seams model exactly one
// agent key with its own grant, which as a chain of length 1 rooted at
// itself reproduces the legacy access semantics. A nil grant yields an
// empty allowance (no chain access to any server).
func chainRowFor(grant *Grant) *chainAggregateRow {
	grants := []*Grant{grant}
	if grant == nil {
		grants = nil
	}
	return &chainAggregateRow{chainN: 1, rooted: true, grants: grants}
}

// chainAggregateRow is a pgx.Row over the delegation-chain aggregate query:
// one row (chain_n int, rooted bool, grants jsonb) regardless of grant count.
type chainAggregateRow struct {
	chainN int
	rooted bool
	grants []*Grant
	err    error
}

func (r *chainAggregateRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 3 {
		return fmt.Errorf("chainAggregateRow: expected 3 dests, got %d", len(dest))
	}
	// Same element shape as the store's jsonb_build_object('server', ...,
	// 'tools', ...) aggregate column (chainGrantJSON in store.go).
	encoded := make([]chainGrantJSON, 0, len(r.grants))
	for _, g := range r.grants {
		encoded = append(encoded, chainGrantJSON{Server: g.ServerName, Tools: g.AllowedTools})
	}
	b, err := json.Marshal(encoded)
	if err != nil {
		return err
	}
	*(dest[0].(*int)) = r.chainN
	*(dest[1].(*bool)) = r.rooted
	*(dest[2].(*[]byte)) = b
	return nil
}

// delegationChainDB models the AUTH-02 scenario at the mock-DB layer: the
// child key holds an unrestricted stored grant (the poisoned state), while
// the chain aggregate reports the parent's restricting grant. The QueryRow
// grant answer covers the pre-fix invoke path (GetEnabledGrant), the chain
// answer covers the post-fix path (DelegationChainAllowance) — a RED run on
// the baseline never reaches the chain seam, which is itself evidence.
type delegationChainDB struct {
	childGrant  *Grant   // stored child grant (baseline: unrestricted)
	chainN      int      // chain depth reported by the aggregate
	rooted      bool     // whether the walk reached a root key (parent IS NULL)
	chainGrant  []*Grant // all enabled grants held by chain members
	upstreamURL string   // the registry server points here
}

func (d *delegationChainDB) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if isChainQuery(sql) {
		return &chainAggregateRow{chainN: d.chainN, rooted: d.rooted, grants: d.chainGrant}
	}
	if isGrantQuery(sql) {
		return &grantRow{g: d.childGrant}
	}
	// GetEnabled(server): the ceiling allows both tools so only the grant
	// layer decides.
	return &serverRow{srv: testServer(d.upstreamURL, "search", "delete_file")}
}

func (*delegationChainDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("delegationChainDB: unexpected Query")
}

func (*delegationChainDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

// delegationProxy builds a proxy whose store serves the delegationChainDB.
func delegationProxy(t *testing.T, d *delegationChainDB) *Proxy {
	t.Helper()
	return NewProxy(NewStore(d), testConfig(), loopbackAllow(t), nil, nil)
}

func TestProxy_Invoke_DelegationChain_ParentRestrictionApplies(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	d := &delegationChainDB{
		// The poisoned stored state: the child's own grant is unrestricted.
		childGrant: testGrant("child-1"),
		chainN:     2,
		chainGrant: []*Grant{
			testGrant("child-1"),            // unrestricted child grant
			testGrant("parent-1", "search"), // parent is search-only
		},
		rooted:      true,
		upstreamURL: up.URL,
	}
	p := delegationProxy(t, d)

	// The parent may only search; the child must NOT reach delete_file even
	// though the child's own stored grant allows everything.
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "child-1"},
		InvokeRequest{Server: "knowledge", Tool: "delete_file", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	require.ErrorAs(t, err, &iErr)
	assert.Equal(t, ErrCodeNotFound, iErr.Code,
		"parent-restricted tool must surface as not_found (server-unavailable indistinguishable)")
}

func TestProxy_Invoke_DelegationChain_AllowedToolStillWorks(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	d := &delegationChainDB{
		childGrant: testGrant("child-1"),
		chainN:     2,
		chainGrant: []*Grant{
			testGrant("child-1"),
			testGrant("parent-1", "search"),
		},
		rooted:      true,
		upstreamURL: up.URL,
	}
	p := delegationProxy(t, d)

	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "child-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	require.NoError(t, err)
	assert.Contains(t, string(res), "result:search")
}

func TestProxy_Invoke_DelegationChain_MissingAncestorGrant_Denied(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	d := &delegationChainDB{
		childGrant: testGrant("child-1"),
		chainN:     2,
		// The chain has two members but only the child holds a grant: the
		// ancestor's grant was revoked/disabled → fail closed entirely.
		chainGrant:  []*Grant{testGrant("child-1")},
		rooted:      true,
		upstreamURL: up.URL,
	}
	p := delegationProxy(t, d)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "child-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	require.ErrorAs(t, err, &iErr)
	assert.Equal(t, ErrCodeNotFound, iErr.Code, "missing ancestor grant must deny the whole server")
}

func TestProxy_Invoke_DelegationChain_RestrictedToDisjoint_DeniesAll(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	d := &delegationChainDB{
		childGrant: testGrant("child-1"),
		chainN:     2,
		chainGrant: []*Grant{
			testGrant("child-1", "delete_file"), // child hand-narrowed differently
			testGrant("parent-1", "search"),     // parent search-only
		},
		rooted:      true,
		upstreamURL: up.URL,
	}
	p := delegationProxy(t, d)

	for _, tool := range []string{"search", "delete_file"} {
		_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "child-1"},
			InvokeRequest{Server: "knowledge", Tool: tool, Params: json.RawMessage(`{}`)})
		var iErr *InvokeError
		require.ErrorAs(t, err, &iErr, "tool %s", tool)
		assert.Equal(t, ErrCodeNotFound, iErr.Code,
			"disjoint chain scopes must allow nothing (tool %s)", tool)
	}
}

func TestProxy_Invoke_DelegationChain_BrokenChain_DeniesAll(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	d := &delegationChainDB{
		childGrant: testGrant("child-1"),
		chainN:     2,
		chainGrant: []*Grant{testGrant("child-1"), testGrant("parent-1", "search")},
		// The walk did NOT reach a root key: an ancestor row is missing,
		// foreign-org, or revoked (dead end). The chain is broken → the whole
		// delegation is dead regardless of surviving grants (fail closed).
		rooted:      false,
		upstreamURL: up.URL,
	}
	p := delegationProxy(t, d)

	for _, tool := range []string{"search", "delete_file"} {
		_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "child-1"},
			InvokeRequest{Server: "knowledge", Tool: tool, Params: json.RawMessage(`{}`)})
		var iErr *InvokeError
		require.ErrorAs(t, err, &iErr, "tool %s", tool)
		assert.Equal(t, ErrCodeNotFound, iErr.Code,
			"broken chain must deny the whole server (tool %s)", tool)
	}
}

func TestChainAllowance_Allows_Semantics(t *testing.T) {
	// Absent server → no chain access at all.
	a := ChainAllowance{"knowledge": nil, "docs": []string{"read"}}
	assert.False(t, a.Allows("missing", "search"))
	// nil slice = unrestricted (no member restricts tools).
	assert.True(t, a.Allows("knowledge", "search"))
	assert.True(t, a.Allows("knowledge", "anything"))
	// Non-nil = exactly those tools.
	assert.True(t, a.Allows("docs", "read"))
	assert.False(t, a.Allows("docs", "write"))
	// Restricted-to-empty = nothing allowed.
	empty := ChainAllowance{"docs": []string{}}
	assert.False(t, empty.Allows("docs", "read"))
	// nil allowance map denies everything.
	var none ChainAllowance
	assert.False(t, none.Allows("knowledge", "search"))
}
