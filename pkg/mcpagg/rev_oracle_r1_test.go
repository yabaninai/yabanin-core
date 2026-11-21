package mcpagg

// REV-ORACLE-01 (auth/SSE correction packet, case 8): after revocation,
// invoking the previously successful known tool DIRECTLY (Proxy.Invoke)
// yields the documented refusal — the exact mcp_tool_blocked code, not a
// discovery gap, malformed list or JSON-RPC error that merely happens to
// fail the call. Every refused attempt compares the per-endpoint sink
// counts immediately before/after (zero egress), the policy edit is
// enforced at the edit bound (cached engine, one-minute TTL: only the
// admin-parity invalidation — Store write + Engine.Invalidate — can
// deliver the deadline this fast; expiry cannot), and discovery
// visibility is asserted separately: the catalog still lists the revoked
// tool (tools/list is not policy-filtered), and those list hits are
// isolated from the invoke counter — the shared-sink hazard.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// revOracleUpstream is a counting TLS MCP upstream whose list and call
// endpoints are counted SEPARATELY: discovery and invoke share one server
// (one sink), and the oracle must not mistake a tools/list hit for a
// tools/call egress.
type revOracleUpstream struct {
	srv  *httptest.Server
	URL  string
	list atomic.Int32
	call atomic.Int32
}

func newRevOracleUpstream(t *testing.T) *revOracleUpstream {
	t.Helper()
	u := &revOracleUpstream{}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("rev oracle upstream: read: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("rev oracle upstream: not JSON-RPC: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			u.list.Add(1)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[`+
				`{"name":"search","description":"knowledge search","inputSchema":{"type":"object"}}]}}`)
		case "tools/call":
			u.call.Add(1)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":`+
				`{"content":[{"type":"text","text":"echo"}]}}`)
		default:
			t.Errorf("rev oracle upstream: unexpected method %q", req.Method)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(u.srv.Close)
	u.URL = u.srv.URL
	return u
}

// revOracleFixture wires one org through the full real chain like
// newToolGrantIntFixture, with the per-endpoint upstream and — the oracle
// deadline control — a CACHED engine (TTL one minute). Staleness beyond
// the edit bound can then only be explained by a missing invalidation.
type revOracleFixture struct {
	org      string
	agent    string
	up       *revOracleUpstream
	policies *toolpolicy.Store
	engine   *toolpolicy.Engine
	proxy    *Proxy
}

func newRevOracleFixture(t *testing.T, suffix string) *revOracleFixture {
	t.Helper()
	pool := testdb.Postgres(t)
	appPool := testdb.PostgresApp(t, "test")
	ctx := context.Background()

	var org string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		"r1-revo-"+suffix).Scan(&org))
	t.Cleanup(func() { toolGrantIntCleanup(t, pool, org) })

	var agent string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		org, "r1-revo-"+suffix, "hash-r1-revo-"+suffix).Scan(&agent))

	up := newRevOracleUpstream(t)
	registry := NewStore(appPool)
	_, err := registry.Create(ctx, CreateParams{OrgID: org, Name: "knowledge", URL: up.URL, Enabled: true})
	require.NoError(t, err, "the server row must insert through the app-role RLS posture")
	_, err = registry.CreateGrant(ctx, GrantCreateParams{
		OrgID: org, AgentID: agent, ServerName: "knowledge", Enabled: true})
	require.NoError(t, err, "the agent grant must insert through the app-role RLS posture")

	policies := toolpolicy.NewStore(appPool)
	engine := toolpolicy.NewEngine(policies, time.Minute)
	cfg := testConfig()
	tlsClient := up.srv.Client()
	tlsClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	cfg.HTTP = tlsClient
	proxy := NewProxy(registry, cfg, loopbackAllow(t), nil, nil).WithToolGuard(engine)

	return &revOracleFixture{org: org, agent: agent, up: up,
		policies: policies, engine: engine, proxy: proxy}
}

func revOracleInvoke(fx *revOracleFixture, tool string) error {
	_, err := fx.proxy.Invoke(context.Background(), fx.org, Identity{AgentID: fx.agent},
		InvokeRequest{Server: "knowledge", Tool: tool, Params: json.RawMessage(`{"q":"x"}`)})
	return err
}

func revOracleList(fx *revOracleFixture) ([]ToolDescriptor, error) {
	return fx.proxy.ListServerTools(context.Background(), fx.org,
		Identity{AgentID: fx.agent}, "knowledge")
}

// TestRevOracle_01_RevokedToolRefusal: the previously successful direct
// invocation is refused by the documented code at the edit bound, with
// zero egress, and discovery visibility is its own separately asserted
// fact.
func TestRevOracle_01_RevokedToolRefusal(t *testing.T) {
	fx := newRevOracleFixture(t, "main")
	ctx := context.Background()

	// Pre-revocation: discovery sees the tool; the direct call succeeds.
	descs, err := revOracleList(fx)
	require.NoError(t, err, "discovery must work pre-revocation")
	require.Len(t, descs, 1)
	require.Equal(t, "search", descs[0].Name, "the known tool must be discovered")
	require.NoError(t, revOracleInvoke(fx, "search"), "the known tool must succeed first")
	require.Equal(t, int32(1), fx.up.call.Load(), "exactly one egress so far")
	require.GreaterOrEqual(t, fx.up.list.Load(), int32(1), "discovery hit the shared upstream")

	// Snapshot both sink counters immediately before the edit.
	callBefore, listBefore := fx.up.call.Load(), fx.up.list.Load()

	// The admin revocation bound: the deny row through the real store,
	// then the cache invalidation (tool_policies_handlers.go parity).
	_, err = fx.policies.Create(ctx, toolpolicy.CreateParams{OrgID: fx.org,
		Name: "revoke-search", Subject: "*", Server: "knowledge", Tool: "search",
		Action: toolpolicy.ActionDeny, Priority: 10, Enabled: true})
	require.NoError(t, err, "the deny row must land through the real store")
	fx.engine.Invalidate(fx.org)
	editBound := time.Now()

	// The absolute policy-edit deadline: with a one-minute cached engine,
	// only the invalidation can refuse this zero-sleep re-invocation of
	// the exact previously-successful call.
	err = revOracleInvoke(fx, "search")
	require.Error(t, err, "the revoked direct call must be refused")
	var iErr *InvokeError
	require.ErrorAs(t, err, &iErr, "the refusal must be the typed InvokeError")
	assert.Equal(t, ErrCodeToolBlocked, iErr.Code,
		"the documented refusal is mcp_tool_blocked — a missing discovery, malformed list or JSON-RPC error cannot substitute")
	require.Less(t, time.Since(editBound), time.Minute,
		"enforcement binds to the edit, not to cache expiry")

	// Zero egress across every refused attempt: both endpoints unchanged.
	assert.Equal(t, callBefore, fx.up.call.Load(), "zero tools/call egress after revocation")
	assert.Equal(t, listBefore, fx.up.list.Load(), "zero tools/list side traffic from the refusal")

	// The refusal is stable, not a one-shot.
	err = revOracleInvoke(fx, "search")
	require.ErrorAs(t, err, &iErr)
	assert.Equal(t, ErrCodeToolBlocked, iErr.Code, "the second refusal keeps the documented code")
	assert.Equal(t, callBefore, fx.up.call.Load(), "still zero egress")

	// Discovery visibility, asserted separately: the catalog is not
	// policy-filtered (dimension 4 is skipped for tools/list), so the
	// revoked tool remains listed — its list hit must move ONLY the list
	// counter, never the call counter.
	descs, err = revOracleList(fx)
	require.NoError(t, err, "discovery keeps working after revocation")
	require.Len(t, descs, 1)
	assert.Equal(t, "search", descs[0].Name,
		"catalog visibility is a separate fact: the revoked tool stays listed")
	assert.Equal(t, listBefore+1, fx.up.list.Load(), "exactly the one discovery hit")
	assert.Equal(t, callBefore, fx.up.call.Load(),
		"surface effects sharing the sink are distinguished: no call egress")
}
