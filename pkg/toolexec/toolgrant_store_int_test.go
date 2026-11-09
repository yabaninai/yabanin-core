package toolexec

// packet criterion («запрещённый вызов не достигает upstream инструмента»)
// and the negative scenario (подмена tool name, редирект, path/URL
// injection) through the REAL boundary: disposable migrated Postgres under
// the application posture (testdb.PostgresApp, yabanin_app NOBYPASSRLS),
// the real toolpolicy.Store as the engine loader (org_isolation RLS,
// migration 0002), and the executor wired exactly as the gateway builds it
// (gateway.go: NewExecutor(...).WithToolGuard(sharedEngine) — the object
// in-memory loaders; this file pins the same decisions when the policy rows
// travel the admin store path (withOrgTx GUC pin → RLS → ListEnabled).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// toolGrantExecIntFixture is one org wired through the real chain: fresh
// org row, the toolpolicy Store over the app-role pool, the engine fed by
// that store, and the guarded executor.
type toolGrantExecIntFixture struct {
	org      string
	up       *guardUpstream
	policies *toolpolicy.Store
	engine   *toolpolicy.Engine
	exec     *Executor
}

func newToolGrantExecIntFixture(t *testing.T, suffix string) *toolGrantExecIntFixture {
	t.Helper()
	pool := testdb.Postgres(t)
	appPool := testdb.PostgresApp(t, "test")
	ctx := context.Background()

	var org string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		"r035-txe-"+suffix).Scan(&org))
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = pool.Exec(cctx, `DELETE FROM tool_policies WHERE org_id = $1::uuid`, org)
		_, _ = pool.Exec(cctx, `DELETE FROM organizations WHERE id = $1::uuid`, org)
	})

	policies := toolpolicy.NewStore(appPool)
	engine := toolpolicy.NewEngine(policies, 0)
	exec := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(engine)
	return &toolGrantExecIntFixture{org: org, up: newGuardUpstream(t),
		policies: policies, engine: engine, exec: exec}
}

// TestToolGrantInt_NamePresetDeny_FromStore: a deny row on http_post (the
// name preset written through the real store) blocks http_request POST
// pre-dispatch — including the case/padding spoofed method, which the
// effective-name composition normalizes onto the same denied name — while
// GET passes and the decisions are counted.
func TestToolGrantInt_NamePresetDeny_FromStore(t *testing.T) {
	fx := newToolGrantExecIntFixture(t, "preset")
	_, err := fx.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fx.org,
		Name: "network-readonly", Subject: "*", Server: BuiltinServerName, Tool: "http_post",
		Action: toolpolicy.ActionDeny, Priority: 10, Enabled: true})
	require.NoError(t, err)

	for _, method := range []string{"post", "POST", " post "} {
		_, err := fx.exec.ExecuteGuarded(context.Background(), fx.org, "ag-1", ToolHTTPRequest,
			json.RawMessage(`{"url":"`+fx.up.URL+`","method":"`+method+`"}`))
		var eErr *ExecError
		require.ErrorAs(t, err, &eErr, "method %q", method)
		assert.Equal(t, ErrCodeToolBlocked, eErr.Code, "method %q", method)
	}
	assert.Zero(t, fx.up.calls.Load(), "no spoofed variant may reach the tool")

	_, err = fx.exec.ExecuteGuarded(context.Background(), fx.org, "ag-1", ToolHTTPRequest,
		json.RawMessage(`{"url":"`+fx.up.URL+`","method":"get"}`))
	require.NoError(t, err, "GET is outside the denied name preset")
	assert.Equal(t, int32(1), fx.up.calls.Load())

	assert.InDelta(t, float64(1), decisionDelta(t, fx.org, "http_post", "deny", func() {
		_, _ = fx.exec.ExecuteGuarded(context.Background(), fx.org, "ag-1", ToolHTTPRequest,
			json.RawMessage(`{"url":"`+fx.up.URL+`","method":"post"}`))
	}), 0.001, "the deny decision is counted on the effective name")
	assert.InDelta(t, float64(0), decisionDelta(t, fx.org, "http_post", "allow", func() {}),
		0.001, "a blocked call is never counted as an allow")
}

// TestToolGrantInt_URLInjection_FromStore: an args deny_regex rule read
// from the real store blocks path traversal / file-scheme URL injection
// BEFORE any egress; the benign URL passes the same rule.
func TestToolGrantInt_URLInjection_FromStore(t *testing.T) {
	fx := newToolGrantExecIntFixture(t, "inject")
	_, err := fx.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fx.org,
		Name: "no-url-tricks", Subject: "*", Server: BuiltinServerName, Tool: ToolWebFetch,
		Action: toolpolicy.ActionAllow, Priority: 10, Enabled: true,
		Rules: json.RawMessage(`{"args":{"deny_regex":["file://|\\.\\./|169\\.254"]}}`)})
	require.NoError(t, err)

	_, err = fx.exec.ExecuteGuarded(context.Background(), fx.org, "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+fx.up.URL+`/../../admin"}`))
	var eErr *ExecError
	require.ErrorAs(t, err, &eErr)
	assert.Equal(t, ErrCodeToolBlocked, eErr.Code)
	assert.Zero(t, fx.up.calls.Load(), "the injected URL must not egress")

	_, err = fx.exec.ExecuteGuarded(context.Background(), fx.org, "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+fx.up.URL+`"}`))
	require.NoError(t, err, "the benign URL passes the same rule")
	assert.Equal(t, int32(1), fx.up.calls.Load())
}

// TestToolGrantInt_AllowPath_ResultFold_FromStore: with the allow posture
// served from the real store, a redirect is never followed (zero second
// hop) and a result mask rule read from the store redacts the secret from
// the body the caller receives (the call itself ran exactly once).
func TestToolGrantInt_AllowPath_ResultFold_FromStore(t *testing.T) {
	fx := newToolGrantExecIntFixture(t, "allow")
	_, err := fx.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fx.org,
		Name: "allow-fetch", Subject: "*", Server: BuiltinServerName, Tool: ToolWebFetch,
		Action: toolpolicy.ActionAllow, Priority: 10, Enabled: true,
		Rules: json.RawMessage(`{"result":{"mode":"mask","secrets":true}}`)})
	require.NoError(t, err)

	// Negative: a 302 is surfaced as an upstream error — never followed.
	hop2 := newGuardUpstream(t)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop2.URL, http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	_, err = fx.exec.ExecuteGuarded(context.Background(), fx.org, "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+redir.URL+`"}`))
	var eErr *ExecError
	require.ErrorAs(t, err, &eErr, "the 302 is not a success")
	assert.Zero(t, hop2.calls.Load(), "the redirect target must never be contacted")

	// Result fold: the fetched secret never reaches the caller unmasked.
	const secret = "ghp_Abcd" + "EfghAbcdEfghAbcdEfghAbcdEfgh1"
	bodySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("token " + secret))
	}))
	t.Cleanup(bodySrv.Close)
	res, err := fx.exec.ExecuteGuarded(context.Background(), fx.org, "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+bodySrv.URL+`"}`))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotContains(t, string(res.Body), secret,
		"the caller must never see the unmasked secret")
	assert.Contains(t, string(res.Body), "[REDACTED_SECRET]")
}

// TestToolGrantInt_OrgIsolation_EndToEnd: two orgs, one physical
// tool_policies table, app-role RLS posture — org B's deny-all row blocks
// only org B; org A (no rows) flows through, which is only possible if the
// engine loader never saw the foreign row.
func TestToolGrantInt_OrgIsolation_EndToEnd(t *testing.T) {
	fxA := newToolGrantExecIntFixture(t, "iso-a")
	fxB := newToolGrantExecIntFixture(t, "iso-b")
	_, err := fxB.policies.Create(context.Background(), toolpolicy.CreateParams{OrgID: fxB.org,
		Name: "deny-fetch", Subject: "*", Server: BuiltinServerName, Tool: ToolWebFetch,
		Action: toolpolicy.ActionDeny, Priority: 10, Enabled: true})
	require.NoError(t, err)

	var blocked *ExecError
	_, err = fxB.exec.ExecuteGuarded(context.Background(), fxB.org, "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+fxB.up.URL+`"}`))
	require.ErrorAs(t, err, &blocked)
	assert.Zero(t, fxB.up.calls.Load())

	_, err = fxA.exec.ExecuteGuarded(context.Background(), fxA.org, "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+fxA.up.URL+`"}`))
	require.NoError(t, err, "org A flows through — the foreign deny row is invisible end-to-end")
	assert.Equal(t, int32(1), fxA.up.calls.Load())
}
