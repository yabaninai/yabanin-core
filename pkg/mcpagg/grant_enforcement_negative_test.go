package mcpagg

// E01-P04-W02-C02: enforcement NEGATIVE tests at the seam level —
// cross-org reject and privilege-escalation attempts against the REAL
// decision seams named by the W01 inventory: grantAllowsAction
// (grantcheck.go) and Proxy.authorizeGrant (grantcheck.go), the check both
// Invoke (proxy.go) and ListServerTools (catalog.go) route through.
//
// FAKE-VS-REAL DOCTRINE (boundary-fixture precedent, E01-P02 W05 —
// fixtures-negative/README.md): every test below is labeled.
//
//   - MODELED: the org-aware fake store (orgAwareFake) MIRRORS the real SQL
//     predicates (store.go GetEnabled `WHERE org_id = $1 AND name = $2 AND
//     enabled`; GetEnabledGrant `WHERE org_id = $1 AND agent_id = $2 AND
//     server_name = $3 AND enabled`). The pre-existing mcpMockDB harness is
//     org-BLIND (it returns rows regardless of the org argument — that gap
//     is what forced this file); a mirror is a model, not proof. The REAL
//     cross-org fact — the org predicate lives in SQL — is proven only by
//     the integration tests (REAL, disposable migrated Postgres under the
//     application posture via testdb.Postgres/PostgresApp; skipped in
//     -short, hard-failing outside it when Docker is down).
//
// Mandatory variants (W01-C02 matrix, design doc §7): allowed baseline,
// empty/unavailable upstream state, rights-denial + cross-org,
// replay-after-revoke; rollback is N/A at this seam (no durable state is
// created by a read-only authorization path; migration 0020's own down is
// structural and untouched here) — recorded per test.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	pgx "github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// ---------------------------------------------------------------------------
// §A MODELED — org-aware fake store + seam-level calls (always runs)
// ---------------------------------------------------------------------------

// orgAwareFake is a Store whose QueryRow applies the SAME org/server/agent
// predicates as the real SQL, so a refusal it produces models what the real
// WHERE clauses do. It exists because the pre-existing mcpMockDB harness is
// org-blind (regression_r035_test.go documents the gap from the other
// side); a mirror is a model, not proof — REAL proof is §B.
type orgAwareFake struct {
	servers []*Server
	grants  []*Grant
	failErr error // when set, every lookup returns this infrastructure error
}

func (f *orgAwareFake) store() *Store {
	return NewStore(&mcpMockDB{queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
		if f.failErr != nil {
			return &serverRow{err: f.failErr}
		}
		if isChainQuery(sql) {
			return chainRowFor(nil) // never reached: authorizeGrant does not run the chain query
		}
		if isGrantQuery(sql) {
			// Mirror GetEnabledGrant: org_id = $1 AND agent_id = $2 AND server_name = $3 AND enabled
			if len(args) != 3 {
				return &grantRow{err: fmt.Errorf("orgAwareFake: grant query args = %d, want 3", len(args))}
			}
			for _, g := range f.grants {
				if g.OrgID == args[0] && g.AgentID == args[1] && g.ServerName == args[2] && g.Enabled {
					return &grantRow{g: g}
				}
			}
			return &grantRow{} // pgx.ErrNoRows
		}
		// Mirror GetEnabled: org_id = $1 AND name = $2 AND enabled
		if len(args) != 2 {
			return &serverRow{err: fmt.Errorf("orgAwareFake: server query args = %d, want 2", len(args))}
		}
		for _, s := range f.servers {
			if s.OrgID == args[0] && s.Name == args[1] && s.Enabled {
				return &serverRow{srv: s}
			}
		}
		return &serverRow{} // pgx.ErrNoRows
	}})
}

func fakeServerFor(org, name string, tools ...string) *Server {
	srv := testServer("https://upstream.example", tools...)
	srv.OrgID, srv.Name = org, name
	return srv
}

func fakeGrantFor(org, agent, server string, actions []string, tools ...string) *Grant {
	g := testGrant(agent, tools...)
	g.OrgID, g.ServerName, g.AllowedActions = org, server, actions
	return g
}

// seamProxy builds a Proxy over the org-aware fake (MODELED). The zero
// SSRF allow-list is never consulted: authorizeGrant runs before any URL
// validation.
func seamProxy(f *orgAwareFake) *Proxy {
	return NewProxy(f.store(), testConfig(), ssrf.AllowList{}, nil, nil)
}

// TestGrantEnforcement_SeamAllowedBaseline is mandatory variant 1: the
// grant exists, is enabled, carries the action and the tool — the seam
// returns the server + grant with NO refusal and NO error. This green
// baseline proves the negatives below fail for the right reason (red/green
// control, fixtures-negative precedent).
func TestGrantEnforcement_SeamAllowedBaseline(t *testing.T) {
	f := &orgAwareFake{
		servers: []*Server{fakeServerFor("org-a", "knowledge", "search")},
		grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions(), "search")},
	}
	srv, grant, refusal, err := seamProxy(f).authorizeGrant(context.Background(), "org-a",
		Identity{AgentID: "ag-1"}, "knowledge", "search", GrantActionInvoke)
	require.NoError(t, err)
	assert.Nil(t, refusal)
	require.NotNil(t, srv)
	require.NotNil(t, grant)
	assert.Equal(t, "knowledge", srv.Name)
	assert.Equal(t, "ag-1", grant.AgentID)
}

// TestGrantEnforcement_SeamCrossOrgReject: a grant (or server) that exists
// only under another org must not authorize this org's call. MODELED: the
// fake mirrors the org predicates; the REAL SQL fact is §B
// (TestGrantEnforcement_Int_CrossOrgSQLPredicate). Refusals keep the
// not_found indistinguishability posture (grantcheck.go).
func TestGrantEnforcement_SeamCrossOrgReject(t *testing.T) {
	t.Run("server exists only in org-b", func(t *testing.T) {
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-b", "knowledge", "search")},
			grants:  []*Grant{fakeGrantFor("org-b", "ag-1", "knowledge", defaultActions(), "search")},
		}
		_, _, refusal, err := seamProxy(f).authorizeGrant(context.Background(), "org-a",
			Identity{AgentID: "ag-1"}, "knowledge", "search", GrantActionInvoke)
		require.NoError(t, err)
		require.NotNil(t, refusal)
		assert.Equal(t, ErrCodeNotFound, refusal.err.Code)
		assert.Equal(t, OutcomeNotFound, refusal.outcome)
	})

	t.Run("grant exists only in org-b", func(t *testing.T) {
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-a", "knowledge", "search")},
			grants:  []*Grant{fakeGrantFor("org-b", "ag-1", "knowledge", defaultActions(), "search")},
		}
		_, _, refusal, err := seamProxy(f).authorizeGrant(context.Background(), "org-a",
			Identity{AgentID: "ag-1"}, "knowledge", "search", GrantActionInvoke)
		require.NoError(t, err)
		require.NotNil(t, refusal)
		assert.Equal(t, ErrCodeNotFound, refusal.err.Code, "cross-org grant miss keeps the not_found posture")
		assert.Equal(t, OutcomeNotFound, refusal.outcome)
	})
}

// TestGrantEnforcement_SeamPrivilegeEscalation: attempts to act beyond the
// grant's action, tool or server surface are refused, never silently
// narrowed to an allow. MODELED (fake mirrors predicates); action/tool
// dimensions are pure seam logic and need no database.
func TestGrantEnforcement_SeamPrivilegeEscalation(t *testing.T) {
	seam := func(f *orgAwareFake, action, tool string) *grantRefusal {
		t.Helper()
		_, _, refusal, err := seamProxy(f).authorizeGrant(context.Background(), "org-a",
			Identity{AgentID: "ag-1"}, "knowledge", tool, action)
		require.NoError(t, err)
		require.NotNil(t, refusal, "escalation attempt must refuse, not allow")
		return refusal
	}

	t.Run("action escalation invoke on list-only grant", func(t *testing.T) {
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-a", "knowledge")},
			grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "knowledge", []string{GrantActionList})},
		}
		r := seam(f, GrantActionInvoke, "search")
		assert.Equal(t, ErrCodeNotFound, r.err.Code)
		assert.Equal(t, OutcomeNotFound, r.outcome)
	})

	t.Run("action escalation list on invoke-only grant", func(t *testing.T) {
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-a", "knowledge")},
			grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "knowledge", []string{GrantActionInvoke})},
		}
		r := seam(f, GrantActionList, "")
		assert.Equal(t, ErrCodeNotFound, r.err.Code)
	})

	t.Run("empty action vocabulary denies a living subject", func(t *testing.T) {
		// Mandatory variant 2 (empty state): the grant row exists and is
		// enabled, but allowed_actions = [] authorizes nothing.
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-a", "knowledge")},
			grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "knowledge", []string{})},
		}
		assert.Equal(t, ErrCodeNotFound, seam(f, GrantActionInvoke, "search").err.Code)
		assert.Equal(t, ErrCodeNotFound, seam(f, GrantActionList, "").err.Code)
	})

	t.Run("tool escalation beyond grant allow-list", func(t *testing.T) {
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-a", "knowledge", "search", "delete_issue")},
			grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions(), "search")},
		}
		r := seam(f, GrantActionInvoke, "delete_issue")
		assert.Equal(t, ErrCodeNotFound, r.err.Code)
		assert.Contains(t, r.err.Message, "delete_issue")
	})

	t.Run("tool escalation beyond server ceiling", func(t *testing.T) {
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-a", "knowledge", "search")},
			grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions(), "search", "delete_issue")},
		}
		r := seam(f, GrantActionInvoke, "delete_issue")
		assert.Equal(t, ErrCodeNotFound, r.err.Code)
	})

	t.Run("server escalation grant names another server", func(t *testing.T) {
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-a", "knowledge"), fakeServerFor("org-a", "billing")},
			grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "billing", defaultActions())},
		}
		r := seam(f, GrantActionInvoke, "charge")
		assert.Equal(t, ErrCodeNotFound, r.err.Code)
	})

	t.Run("non-agent principal is rejected before any lookup", func(t *testing.T) {
		f := &orgAwareFake{
			servers: []*Server{fakeServerFor("org-a", "knowledge")},
			grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions())},
		}
		_, _, refusal, err := seamProxy(f).authorizeGrant(context.Background(), "org-a",
			Identity{AgentID: ""}, "knowledge", "search", GrantActionInvoke)
		require.NoError(t, err)
		require.NotNil(t, refusal)
		assert.Equal(t, ErrCodeAgentOnly, refusal.err.Code)
		assert.Equal(t, OutcomeDenied, refusal.outcome)
	})
}

// TestGrantEnforcement_SeamGrantAllowsAction_FailClosed pins the action
// seam directly: unknown action strings (including an "admin" class that
// the vocabulary deliberately cannot express) are refused, empty
// vocabularies deny, disabled or missing grants deny.
func TestGrantEnforcement_SeamGrantAllowsAction_FailClosed(t *testing.T) {
	cases := []struct {
		name   string
		grant  *Grant
		action string
		want   bool
	}{
		{"action present", fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions()), GrantActionInvoke, true},
		{"action absent from narrowed vocabulary", fakeGrantFor("org-a", "ag-1", "knowledge", []string{GrantActionList}), GrantActionInvoke, false},
		{"empty vocabulary denies everything", fakeGrantFor("org-a", "ag-1", "knowledge", []string{}), GrantActionInvoke, false},
		{"unknown action string is refused", fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions()), "admin", false},
		{"empty action string is refused", fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions()), "", false},
		{"case-mismatched action is refused", fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions()), "INVOKE", false},
		{"disabled grant denies", &Grant{OrgID: "org-a", AgentID: "ag-1", ServerName: "knowledge", AllowedActions: defaultActions(), Enabled: false}, GrantActionInvoke, false},
		{"nil grant denies", nil, GrantActionInvoke, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, grantAllowsAction(tc.grant, tc.action))
		})
	}
}

// TestGrantEnforcement_SeamInfraErrorSurfaced is mandatory variant 2
// (unavailable upstream state): a store/infrastructure failure surfaces as
// a plain wrapped error — never as a silent allow and never disguised as an
// authorization refusal.
func TestGrantEnforcement_SeamInfraErrorSurfaced(t *testing.T) {
	boom := errors.New("db: connection refused")
	f := &orgAwareFake{
		failErr: boom,
		servers: []*Server{fakeServerFor("org-a", "knowledge")},
		grants:  []*Grant{fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions())},
	}
	_, _, refusal, err := seamProxy(f).authorizeGrant(context.Background(), "org-a",
		Identity{AgentID: "ag-1"}, "knowledge", "search", GrantActionInvoke)
	require.Error(t, err, "infrastructure failure must not pass as success")
	assert.Nil(t, refusal, "infra failure is not an authorization refusal")
	assert.ErrorIs(t, err, boom)
}

// TestGrantEnforcement_SeamReplayAfterRevokeRefused is mandatory variant 4
// (replay): the seam is stateless — an identical request that was allowed
// before the grant was disabled is refused after it; there is no memoized
// verdict. MODELED; the durable (real SQL) replay fact is §B
// (TestGrantEnforcement_Int_RevocationStopsReplay).
func TestGrantEnforcement_SeamReplayAfterRevokeRefused(t *testing.T) {
	grant := fakeGrantFor("org-a", "ag-1", "knowledge", defaultActions(), "search")
	f := &orgAwareFake{
		servers: []*Server{fakeServerFor("org-a", "knowledge", "search")},
		grants:  []*Grant{grant},
	}
	p := seamProxy(f)
	ctx := context.Background()
	id := Identity{AgentID: "ag-1"}

	_, _, refusal, err := p.authorizeGrant(ctx, "org-a", id, "knowledge", "search", GrantActionInvoke)
	require.NoError(t, err)
	assert.Nil(t, refusal, "baseline: the call is authorized before revocation")

	grant.Enabled = false // revocation between the two identical calls

	_, _, refusal, err = p.authorizeGrant(ctx, "org-a", id, "knowledge", "search", GrantActionInvoke)
	require.NoError(t, err)
	require.NotNil(t, refusal, "identical replay after revoke must be refused")
	assert.Equal(t, ErrCodeNotFound, refusal.err.Code)
}

// ---------------------------------------------------------------------------
// §B REAL — disposable migrated Postgres (application posture), the org
// predicate proven in SQL, not in a mirror. Skipped in -short; hard-fails
// when Docker is unavailable outside -short (testdb semantics).
// ---------------------------------------------------------------------------

// grantIntUpstream is a method-dispatching counting TLS upstream: tools/list
// answers a real descriptor array, tools/call answers a content result; the
// per-method counters prove whether a REFUSED call ever egressed.
type grantIntUpstream struct {
	srv    *httptest.Server
	URL    string
	list   atomic.Int32
	invoke atomic.Int32
}

func newGrantIntUpstream(t *testing.T) *grantIntUpstream {
	t.Helper()
	u := &grantIntUpstream{}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			u.list.Add(1)
			_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"s"}]}}`)
		default: // tools/call
			u.invoke.Add(1)
			_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"echo"}]}}`)
		}
	}))
	t.Cleanup(u.srv.Close)
	u.URL = u.srv.URL
	return u
}

// grantIntOrg is one org wired through the real chain: org + agent_keys
// rows, the registry server pointed at the counting upstream, an optional
// grant with the given action vocabulary (nil = column default), and the
// proxy over the app-role store. No tool guard is installed: the guard seam
// is covered by toolgrant_store_int_test.go; this file pins the GRANT seam.
type grantIntOrg struct {
	org   string
	agent string
	up    *grantIntUpstream
	proxy *Proxy
	store *Store
}

func newGrantIntOrg(t *testing.T, suffix, serverName string, actions *[]string) *grantIntOrg {
	t.Helper()
	pool := testdb.Postgres(t)
	appPool := testdb.PostgresApp(t, "test")
	ctx := context.Background()

	var org string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		"w02-gei-"+suffix).Scan(&org))
	t.Cleanup(func() { toolGrantIntCleanup(t, pool, org) })

	var agent string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		org, "w02-gei-"+suffix, "hash-w02-gei-"+suffix).Scan(&agent))

	up := newGrantIntUpstream(t)
	store := NewStore(appPool)
	_, err := store.Create(ctx, CreateParams{OrgID: org, Name: serverName, URL: up.URL, Enabled: true})
	require.NoError(t, err, "server row must insert through the app-role RLS posture")
	if actions != nil {
		_, err = store.CreateGrant(ctx, GrantCreateParams{
			OrgID: org, AgentID: agent, ServerName: serverName,
			AllowedActions: actions, Enabled: true,
		})
	} else {
		_, err = store.CreateGrant(ctx, GrantCreateParams{
			OrgID: org, AgentID: agent, ServerName: serverName, Enabled: true,
		})
	}
	require.NoError(t, err, "grant row must insert through the app-role RLS posture")

	cfg := testConfig()
	tlsClient := up.srv.Client()
	tlsClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTP = tlsClient
	proxy := NewProxy(store, cfg, loopbackAllow(t), nil, nil)
	return &grantIntOrg{org: org, agent: agent, up: up, proxy: proxy, store: store}
}

// grantIntInvoke is the consumer entrypoint shape (one tools/call).
func grantIntInvoke(fx *grantIntOrg, org, agent, server, tool string) error {
	_, err := fx.proxy.Invoke(context.Background(), org, Identity{AgentID: agent},
		InvokeRequest{Server: server, Tool: tool, Params: json.RawMessage(`{"q":"x"}`)})
	return err
}

// notFoundRefusal asserts the error is the authorization-shaped not_found
// refusal (never a silent success, never a bare wrapped error).
func notFoundRefusal(t *testing.T, err error, msgAndArgs ...interface{}) {
	t.Helper()
	var iErr *InvokeError
	require.ErrorAs(t, err, &iErr, msgAndArgs...)
	assert.Equal(t, ErrCodeNotFound, iErr.Code, msgAndArgs...)
}

// TestGrantEnforcement_Int_CrossOrgSQLPredicate is the REAL cross-org
// proof: both orgs run a server NAMED "knowledge" (names repeat across
// orgs; uniqueness is (org_id, name)), but only org-b's agent holds a
// grant. The org predicate lives in the SQL WHERE clauses
// (store.go GetEnabledGrant) — an org-blind mock cannot prove this, which
// is exactly the fake-vs-real gap this file documents. Also carries
// mandatory variant 2a (grant row entirely absent) and variant 1 (allowed
// baseline through the full real chain).
func TestGrantEnforcement_Int_CrossOrgSQLPredicate(t *testing.T) {
	orgA := newGrantIntOrg(t, "xorg-a", "knowledge", nil) // server, grant for its own agent
	orgB := newGrantIntOrg(t, "xorg-b", "knowledge", nil) // same server NAME, its own upstream

	t.Run("foreign-org grant must not authorize this org's call", func(t *testing.T) {
		// org-b's agent calls under org-a's context: org-a's server row
		// resolves (same name), but the grant row is org-b-scoped and the
		// org-a-scoped lookup finds nothing.
		err := grantIntInvoke(orgA, orgA.org, orgB.agent, "knowledge", "search")
		notFoundRefusal(t, err, "the org predicate must reject a foreign-org grant")
		assert.Zero(t, orgA.up.invoke.Load(), "org-a upstream must stay untouched")
		assert.Zero(t, orgB.up.invoke.Load(), "org-b upstream must stay untouched")
	})

	t.Run("agent with no grant at all is refused", func(t *testing.T) {
		// Variant 2a: no grant row exists for a second agent of org-a.
		pool := testdb.Postgres(t)
		ctx := context.Background()
		var stranger string
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, 'w02-gei-stranger', 'hash-w02-gei-stranger') RETURNING id::text`,
			orgA.org).Scan(&stranger))
		err := grantIntInvoke(orgA, orgA.org, stranger, "knowledge", "search")
		notFoundRefusal(t, err, "missing grant row must refuse")
		assert.Zero(t, orgA.up.invoke.Load())
	})

	t.Run("allowed baseline reaches exactly the own-org upstream", func(t *testing.T) {
		// Variant 1 through the REAL chain (auth + chain allowance + egress).
		require.NoError(t, grantIntInvoke(orgB, orgB.org, orgB.agent, "knowledge", "search"))
		assert.Equal(t, int32(1), orgB.up.invoke.Load(), "org-b's own call egresses once")
		assert.Zero(t, orgA.up.invoke.Load(), "org-a's identically-named server is never touched")
	})
}

// TestGrantEnforcement_Int_ActionVocabularyFailClosed is the REAL action
// dimension: allowed_actions values written through the real admin store
// decide invoke/list independently, refusals never egress, and the column
// default (nil at create) keeps both actions (variant 1). Migration 0020's
// CHECK makes any non-vocabulary value unwritable at the schema layer.
func TestGrantEnforcement_Int_ActionVocabularyFailClosed(t *testing.T) {
	listOnly := []string{GrantActionList}
	fx := newGrantIntOrg(t, "act-list", "knowledge", &listOnly)

	t.Run("invoke on a list-only grant is refused before egress", func(t *testing.T) {
		err := grantIntInvoke(fx, fx.org, fx.agent, "knowledge", "search")
		notFoundRefusal(t, err)
		assert.Zero(t, fx.up.invoke.Load())
	})

	t.Run("list on a list-only grant is authorized", func(t *testing.T) {
		_, err := fx.proxy.ListServerTools(context.Background(), fx.org,
			Identity{AgentID: fx.agent}, "knowledge")
		require.NoError(t, err)
		assert.Equal(t, int32(1), fx.up.list.Load(), "the authorized discovery egresses once")
	})

	invokeOnly := []string{GrantActionInvoke}
	fx2 := newGrantIntOrg(t, "act-invoke", "knowledge", &invokeOnly)
	t.Run("list on an invoke-only grant is refused before egress", func(t *testing.T) {
		_, err := fx2.proxy.ListServerTools(context.Background(), fx2.org,
			Identity{AgentID: fx2.agent}, "knowledge")
		notFoundRefusal(t, err, "read escalation beyond the grant's vocabulary must refuse")
		assert.Zero(t, fx2.up.list.Load())
	})

	none := []string{}
	fx3 := newGrantIntOrg(t, "act-none", "knowledge", &none)
	t.Run("empty vocabulary denies a living subject both actions", func(t *testing.T) {
		err := grantIntInvoke(fx3, fx3.org, fx3.agent, "knowledge", "search")
		notFoundRefusal(t, err)
		_, err = fx3.proxy.ListServerTools(context.Background(), fx3.org,
			Identity{AgentID: fx3.agent}, "knowledge")
		notFoundRefusal(t, err)
		assert.Zero(t, fx3.up.invoke.Load())
		assert.Zero(t, fx3.up.list.Load())
	})

	fx4 := newGrantIntOrg(t, "act-default", "knowledge", nil)
	t.Run("column default keeps invoke (variant 1)", func(t *testing.T) {
		require.NoError(t, grantIntInvoke(fx4, fx4.org, fx4.agent, "knowledge", "search"))
		assert.Equal(t, int32(1), fx4.up.invoke.Load())
	})
}

// TestGrantEnforcement_Int_RevocationStopsReplay is mandatory variant 4
// REAL: a byte-identical replay of a previously-allowed call is refused
// immediately after the grant is disabled through the admin store, and the
// upstream counter proves no second egress. Rollback variant: N/A at this
// seam — the test creates no state the seam itself would need to roll back
// (grant rows are fixture state, cleaned up by the fixture).
func TestGrantEnforcement_Int_RevocationStopsReplay(t *testing.T) {
	fx := newGrantIntOrg(t, "revoke", "knowledge", nil)
	ctx := context.Background()

	require.NoError(t, grantIntInvoke(fx, fx.org, fx.agent, "knowledge", "search"))
	require.Equal(t, int32(1), fx.up.invoke.Load())

	disabled := false
	_, err := fx.store.UpdateGrant(ctx, fx.org, fx.agent, "knowledge", GrantUpdateParams{Enabled: &disabled})
	require.NoError(t, err)

	// Byte-identical replay of the exact request that just succeeded.
	err = grantIntInvoke(fx, fx.org, fx.agent, "knowledge", "search")
	notFoundRefusal(t, err, "revocation must stop the identical replay")
	assert.Equal(t, int32(1), fx.up.invoke.Load(), "the replayed call must not egress")
}
