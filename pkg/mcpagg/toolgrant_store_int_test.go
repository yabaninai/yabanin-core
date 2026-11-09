package mcpagg

// («запрещённый вызов не достигает upstream инструмента») and the negative
// scenario (подмена tool name, редирект, path/URL injection) proven through
// the REAL boundary, not helper calls: disposable migrated Postgres under
// the application posture (testdb.PostgresApp, yabanin_app NOBYPASSRLS —
// the production pool), the real toolpolicy.Store as the engine loader
// (org_isolation RLS, migration 0002), the real mcpagg registry (server +
// grant rows), and the proxy wired exactly as the gateway builds it
// (gateway.go: NewProxy(...).WithToolGuard(sharedEngine)).
//
// mock registries; this file pins the same decisions when the policy rows
// travel the admin store path (withOrgTx GUC pin → RLS → ListEnabled) into
// the same consumers.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// toolGrantIntUpstream is a counting TLS MCP upstream (the mcp_servers url
// CHECK requires https; the TLS client is injected via Config.HTTP, the
// creds_lifecycle_int_test.go parity).
type toolGrantIntUpstream struct {
	srv   *httptest.Server
	URL   string
	calls atomic.Int32
}

func newToolGrantIntUpstream(t *testing.T, result string) *toolGrantIntUpstream {
	t.Helper()
	if result == "" {
		result = `{"content":[{"type":"text","text":"echo"}]}`
	}
	u := &toolGrantIntUpstream{}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		u.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, result)
	}))
	t.Cleanup(u.srv.Close)
	u.URL = u.srv.URL
	return u
}

// toolGrantIntFixture is one org wired through the full real chain: fresh
// org + agent rows, the registry server pointed at the counting TLS
// upstream, an enabled agent grant, the toolpolicy Store over the app-role
// pool, and the engine-fed proxy.
type toolGrantIntFixture struct {
	org      string
	agent    string
	up       *toolGrantIntUpstream
	policies *toolpolicy.Store
	engine   *toolpolicy.Engine
	proxy    *Proxy
}

func newToolGrantIntFixture(t *testing.T, suffix string) *toolGrantIntFixture {
	t.Helper()
	pool := testdb.Postgres(t)
	appPool := testdb.PostgresApp(t, "test")
	ctx := context.Background()

	var org string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		"r035-tgi-"+suffix).Scan(&org))
	t.Cleanup(func() { toolGrantIntCleanup(t, pool, org) })

	var agent string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		org, "r035-tgi-"+suffix, "hash-r035-tgi-"+suffix).Scan(&agent))

	up := newToolGrantIntUpstream(t, "")
	registry := NewStore(appPool)
	_, err := registry.Create(ctx, CreateParams{
		OrgID: org, Name: "knowledge", URL: up.URL, Enabled: true,
	})
	require.NoError(t, err, "the server row must insert through the app-role RLS posture")
	_, err = registry.CreateGrant(ctx, GrantCreateParams{
		OrgID: org, AgentID: agent, ServerName: "knowledge", Enabled: true,
	})
	require.NoError(t, err, "the agent grant must insert through the app-role RLS posture")

	policies := toolpolicy.NewStore(appPool)
	engine := toolpolicy.NewEngine(policies, 0)
	cfg := testConfig()
	// Production parity for the injected client: trust the TLS httptest
	// upstream AND keep Config.Client()'s no-redirect posture — a 302 must
	// surface as an upstream error, never a followed hop.
	tlsClient := up.srv.Client()
	tlsClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	cfg.HTTP = tlsClient
	proxy := NewProxy(registry, cfg, loopbackAllow(t), nil, nil).WithToolGuard(engine)

	return &toolGrantIntFixture{org: org, agent: agent, up: up,
		policies: policies, engine: engine, proxy: proxy}
}

// toolGrantIntCleanup removes one fixture org's rows (FK order). Best
// effort: a failed cleanup must not mask the test verdict.
func toolGrantIntCleanup(t *testing.T, pool *pgxpool.Pool, org string) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		`DELETE FROM tool_policies WHERE org_id = $1::uuid`,
		`DELETE FROM mcp_server_grants WHERE org_id = $1::uuid`,
		`DELETE FROM mcp_servers WHERE org_id = $1::uuid`,
		`DELETE FROM agent_keys WHERE org_id = $1::uuid`,
		`DELETE FROM organizations WHERE id = $1::uuid`,
	} {
		_, _ = pool.Exec(ctx, stmt, org)
	}
}

// toolGrantIntInvoke is the consumer entrypoint call shape.
func toolGrantIntInvoke(fx *toolGrantIntFixture, tool string, params json.RawMessage) error {
	_, err := fx.proxy.Invoke(context.Background(), fx.org, Identity{AgentID: fx.agent},
		InvokeRequest{Server: "knowledge", Tool: tool, Params: params})
	return err
}

// TestToolGrantInt_StoreDenyRow_BlocksBeforeUpstream is the packet criterion
// through the real boundary: the contract §3 policy pair, written through
// the real admin store, blocks the denied tool at Proxy.Invoke with the
// upstream counter at ZERO, while the wildcard allow keeps the rest of the
// server callable and the deny decision is counted (never as an allow).
func TestToolGrantInt_StoreDenyRow_BlocksBeforeUpstream(t *testing.T) {
	fx := newToolGrantIntFixture(t, "deny")
	ctx := context.Background()

	_, err := fx.policies.Create(ctx, toolpolicy.CreateParams{OrgID: fx.org,
		Name: "deny-gh-delete", Subject: "*", Server: "knowledge", Tool: "delete_issue",
		Action: toolpolicy.ActionDeny, Priority: 50, Enabled: true})
	require.NoError(t, err)
	_, err = fx.policies.Create(ctx, toolpolicy.CreateParams{OrgID: fx.org,
		Name: "allow-github", Subject: "*", Server: "knowledge", Tool: "*",
		Action: toolpolicy.ActionAllow, Priority: 100, Enabled: true})
	require.NoError(t, err)

	err = toolGrantIntInvoke(fx, "delete_issue", json.RawMessage(`{"id":42}`))
	var iErr *InvokeError
	require.ErrorAs(t, err, &iErr)
	assert.Equal(t, ErrCodeToolBlocked, iErr.Code)
	assert.Contains(t, iErr.Message, "deny-gh-delete",
		"the value-free reason names the deny row")
	assert.Zero(t, fx.up.calls.Load(), "the denied call must not reach the upstream tool")

	err = toolGrantIntInvoke(fx, "search", json.RawMessage(`{"q":"x"}`))
	require.NoError(t, err, "the wildcard allow keeps other tools callable")
	assert.Equal(t, int32(1), fx.up.calls.Load())

	assert.InDelta(t, float64(1), metricDelta(t, fx.org, "knowledge", "delete_issue", "deny", func() {
		_ = toolGrantIntInvoke(fx, "delete_issue", json.RawMessage(`{"id":42}`))
	}), 0.001, "the deny decision is counted as deny")
	assert.InDelta(t, float64(0), metricDelta(t, fx.org, "knowledge", "delete_issue", "allow", func() {}),
		0.001, "a blocked call is never counted as an allow")
}

// TestToolGrantInt_Negative_ToolNameSpoofing: renaming the tool cannot
// escape the boundary — a server-class deny row (from the real store)
// blocks the exact name, renamed variants and case/padding spoofing alike,
// and the args payload cannot spoof the policy coordinates (they come from
// the request line + registry, never the payload).
func TestToolGrantInt_Negative_ToolNameSpoofing(t *testing.T) {
	fx := newToolGrantIntFixture(t, "spoof")
	_, err := fx.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fx.org,
		Name: "deny-server", Subject: "*", Server: "knowledge", Tool: "*",
		Action: toolpolicy.ActionDeny, Priority: 10, Enabled: true})
	require.NoError(t, err)

	for _, tool := range []string{"delete_issue", "delete_issue_forever", "DELETE_ISSUE", " search"} {
		err := toolGrantIntInvoke(fx, tool, json.RawMessage(`{}`))
		var iErr *InvokeError
		require.ErrorAs(t, err, &iErr, "tool %q", tool)
		assert.Equal(t, ErrCodeToolBlocked, iErr.Code, "tool %q", tool)
		assert.Contains(t, iErr.Message, "deny-server", "tool %q", tool)
	}
	assert.Zero(t, fx.up.calls.Load(), "no renamed variant may reach the upstream")

	// Payload coordinate spoofing: the "tool"/"server" fields in the args
	// are opaque data — the deny still applies and the request never
	// egresses.
	err = toolGrantIntInvoke(fx, "search",
		json.RawMessage(`{"tool":"delete_issue","server":"elsewhere"}`))
	var iErr *InvokeError
	require.ErrorAs(t, err, &iErr)
	assert.Equal(t, ErrCodeToolBlocked, iErr.Code)
	assert.Zero(t, fx.up.calls.Load())
}

// TestToolGrantInt_Negative_URLInjectionDeniedByStoreRule: an args
// deny_regex rule read from the real store blocks link-local / file-scheme
// URL injection in the params BEFORE any egress; a benign payload passes
// the same rule.
func TestToolGrantInt_Negative_URLInjectionDeniedByStoreRule(t *testing.T) {
	fx := newToolGrantIntFixture(t, "inject")
	_, err := fx.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fx.org,
		Name: "no-internal-urls", Subject: "*", Server: "knowledge", Tool: "*",
		Action: toolpolicy.ActionAllow, Priority: 10, Enabled: true,
		Rules: json.RawMessage(`{"args":{"deny_regex":["169\\.254|file://|\\.internal"]}}`)})
	require.NoError(t, err)

	err = toolGrantIntInvoke(fx, "fetch_url",
		json.RawMessage(`{"url":"http://169.254.169.254/latest/meta-data/"}`))
	var iErr *InvokeError
	require.ErrorAs(t, err, &iErr)
	assert.Equal(t, ErrCodeToolBlocked, iErr.Code)
	assert.Contains(t, iErr.Message, "no-internal-urls")
	assert.Zero(t, fx.up.calls.Load(), "the injected URL must not egress")

	require.NoError(t, toolGrantIntInvoke(fx, "fetch_url",
		json.RawMessage(`{"url":"https://example.test/doc"}`)))
	assert.Equal(t, int32(1), fx.up.calls.Load(), "the benign payload passes the same rule")
}

// TestToolGrantInt_Negative_RedirectNeverFollowed: with the allow posture
// served from the real store, a 302 from the upstream is surfaced as an
// upstream error — the second hop is never contacted.
func TestToolGrantInt_Negative_RedirectNeverFollowed(t *testing.T) {
	fx := newToolGrantIntFixture(t, "redirect")
	_, err := fx.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fx.org,
		Name: "allow-server", Subject: "*", Server: "knowledge", Tool: "*",
		Action: toolpolicy.ActionAllow, Priority: 10, Enabled: true})
	require.NoError(t, err)

	hop2 := newToolGrantIntUpstream(t, "")
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.up.calls.Add(1)
		http.Redirect(w, r, hop2.URL, http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	registry := NewStore(testdb.PostgresApp(t, "test"))
	_, err = registry.Update(context.Background(), fx.org, "knowledge", UpdateParams{URL: &redir.URL})
	require.NoError(t, err, "the real registry update must pass")

	err = toolGrantIntInvoke(fx, "search", json.RawMessage(`{}`))
	require.Error(t, err, "the 302 is not a success")
	assert.Zero(t, hop2.calls.Load(), "the redirect target must never be contacted")
	assert.Equal(t, int32(1), fx.up.calls.Load(), "exactly the first hop happened")
}

// TestToolGrantInt_PolicyEditLandsImmediately: the admin sequence
// (Store.Update + Engine.Invalidate — the tool_policies_handlers.go:288
// parity) lands at the consumer entrypoint at once: disable unblocks,
// re-enable blocks again, all through the real store.
func TestToolGrantInt_PolicyEditLandsImmediately(t *testing.T) {
	fx := newToolGrantIntFixture(t, "edit")
	ctx := context.Background()
	_, err := fx.policies.Create(ctx, toolpolicy.CreateParams{OrgID: fx.org,
		Name: "deny-server", Subject: "*", Server: "knowledge", Tool: "*",
		Action: toolpolicy.ActionDeny, Priority: 10, Enabled: true})
	require.NoError(t, err)

	var blocked *InvokeError
	require.ErrorAs(t, toolGrantIntInvoke(fx, "search", json.RawMessage(`{}`)), &blocked)
	assert.Zero(t, fx.up.calls.Load())

	disabled := false
	_, err = fx.policies.Update(ctx, fx.org, "deny-server", toolpolicy.UpdateParams{Enabled: &disabled})
	require.NoError(t, err)
	fx.engine.Invalidate(fx.org)
	require.NoError(t, toolGrantIntInvoke(fx, "search", json.RawMessage(`{}`)))
	assert.Equal(t, int32(1), fx.up.calls.Load())

	enabled := true
	_, err = fx.policies.Update(ctx, fx.org, "deny-server", toolpolicy.UpdateParams{Enabled: &enabled})
	require.NoError(t, err)
	fx.engine.Invalidate(fx.org)
	require.ErrorAs(t, toolGrantIntInvoke(fx, "search", json.RawMessage(`{}`)), &blocked)
	assert.Equal(t, int32(1), fx.up.calls.Load(), "the re-enabled deny blocks again before egress")
}

// TestToolGrantInt_OrgIsolation_EndToEnd: two orgs, one physical
// tool_policies table, app-role RLS posture — org B's deny-all row blocks
// only org B; org A (no rows) flows through, which is only possible if the
// engine loader never saw the foreign row.
func TestToolGrantInt_OrgIsolation_EndToEnd(t *testing.T) {
	fxA := newToolGrantIntFixture(t, "iso-a")
	fxB := newToolGrantIntFixture(t, "iso-b")
	_, err := fxB.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fxB.org,
		Name: "deny-server", Subject: "*", Server: "knowledge", Tool: "*",
		Action: toolpolicy.ActionDeny, Priority: 10, Enabled: true})
	require.NoError(t, err)

	var blocked *InvokeError
	require.ErrorAs(t, toolGrantIntInvoke(fxB, "search", json.RawMessage(`{}`)), &blocked)
	assert.Zero(t, fxB.up.calls.Load())

	require.NoError(t, toolGrantIntInvoke(fxA, "search", json.RawMessage(`{}`)))
	assert.Equal(t, int32(1), fxA.up.calls.Load(),
		"org A flows through — the foreign deny row is invisible end-to-end")
}
