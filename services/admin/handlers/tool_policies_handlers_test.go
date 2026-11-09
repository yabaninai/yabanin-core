package handlers

// Tool policy CRUD handler tests over an in-memory DB mock (the same
// harness style as the A2A registry tests: rootRequest + stub rows).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- stub DB ------------------------------------------------------------

type toolPolicyTestStore struct{ byName map[string]*toolpolicy.Policy }

func newToolPolicyTestStore() *toolPolicyTestStore {
	return &toolPolicyTestStore{byName: map[string]*toolpolicy.Policy{}}
}

func (s *toolPolicyTestStore) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	now := time.Now()
	switch {
	case strings.Contains(sql, "INSERT INTO tool_policies"):
		key := args[0].(string) + "/" + args[1].(string)
		if _, exists := s.byName[key]; exists {
			return &policyRow{err: &pgconn.PgError{Code: "23505", Message: "duplicate key"}}
		}
		// OP-6 insert order: org, name, subject, server, tool, action,
		// rules, priority, enabled.
		p := &toolpolicy.Policy{ID: "tp-1", OrgID: args[0].(string), Name: args[1].(string),
			Subject: args[2].(string), Server: args[3].(string), Tool: args[4].(string),
			Action: args[5].(string), Priority: args[7].(int), Enabled: args[8].(bool),
			CreatedAt: now, UpdatedAt: now}
		if raw, ok := args[6].([]byte); ok && len(raw) > 0 {
			p.Rules = json.RawMessage(raw)
		}
		s.byName[key] = p
		return &policyRow{policy: p}
	case strings.Contains(sql, "UPDATE tool_policies"):
		key := args[0].(string) + "/" + args[1].(string)
		p, ok := s.byName[key]
		if !ok {
			return &policyRow{err: pgx.ErrNoRows}
		}
		// The SQL builder emits only the SET fields that were provided, in
		// a fixed order (subject, server, tool, action, rules, priority,
		// enabled); a type-driven apply is enough for the asserted surface.
		for _, v := range args[2:] {
			switch t := v.(type) {
			case bool:
				p.Enabled = t
			case int:
				p.Priority = t
			case []byte:
				p.Rules = json.RawMessage(t)
			case string:
				switch t {
				case "allow", "deny":
					p.Action = t
				case "*":
					p.Subject = t
				default:
					p.Tool = t
				}
			}
		}
		return &policyRow{policy: p}
	case strings.Contains(sql, "SELECT"):
		key := args[0].(string) + "/" + args[1].(string)
		if p, ok := s.byName[key]; ok {
			return &policyRow{policy: p}
		}
		return &policyRow{err: pgx.ErrNoRows}
	}
	return &policyRow{err: pgx.ErrNoRows}
}

func (s *toolPolicyTestStore) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	return &policyRows{store: s, orgID: args[0].(string)}, nil
}

func (s *toolPolicyTestStore) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "DELETE FROM tool_policies") {
		key := args[0].(string) + "/" + args[1].(string)
		if _, ok := s.byName[key]; !ok {
			return pgconn.CommandTag{}, toolpolicy.ErrNotFound
		}
		delete(s.byName, key)
		return pgconn.NewCommandTag("DELETE 1"), nil
	}
	return pgconn.CommandTag{}, nil
}

// Begin/tx adapter: the store runs every operation inside one transaction
// whose app.current_org GUC is pinned (the org_isolation RLS contract); the
// in-memory mock has no RLS, so the tx delegates to the store and the GUC
// exec is a no-op.
func (s *toolPolicyTestStore) Begin(context.Context) (pgx.Tx, error) {
	return &toolPolicyTestTx{s: s}, nil
}

type toolPolicyTestTx struct{ s *toolPolicyTestStore }

func (t *toolPolicyTestTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return t.s.QueryRow(ctx, sql, args...)
}

func (t *toolPolicyTestTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.s.Query(ctx, sql, args...)
}

func (t *toolPolicyTestTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "set_config") {
		return pgconn.NewCommandTag("SELECT 1"), nil
	}
	return t.s.Exec(ctx, sql, args...)
}

func (t *toolPolicyTestTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("nested transactions are not supported by the mock")
}

func (t *toolPolicyTestTx) Commit(context.Context) error   { return nil }
func (t *toolPolicyTestTx) Rollback(context.Context) error { return nil }
func (t *toolPolicyTestTx) Conn() *pgx.Conn                { return nil }
func (t *toolPolicyTestTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("copy is not supported by the mock")
}

func (t *toolPolicyTestTx) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }

func (t *toolPolicyTestTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("prepare is not supported by the mock")
}

func (t *toolPolicyTestTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nil
}

type policyRow struct {
	policy *toolpolicy.Policy
	err    error
}

func (r *policyRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	p := r.policy
	set := func(i int, v any) {
		switch d := dest[i].(type) {
		case *string:
			*d = v.(string)
		case *int:
			*d = v.(int)
		case *bool:
			*d = v.(bool)
		case *[]byte:
			if b, ok := v.([]byte); ok {
				*d = b
			}
		case *time.Time:
			*d = time.Now()
		}
	}
	var rules []byte
	if len(p.Rules) > 0 {
		rules = []byte(p.Rules)
	}
	vals := []any{p.ID, p.OrgID, p.Name, p.Subject, p.Server, p.Tool, p.Action, rules, p.Priority, p.Enabled}
	for i := range vals {
		set(i, vals[i])
	}
	for i := 10; i < len(dest); i++ {
		if d, ok := dest[i].(*time.Time); ok {
			*d = time.Now()
		}
	}
	return nil
}
func (r *policyRow) Close()                                       {}
func (r *policyRow) Err() error                                   { return r.err }
func (r *policyRow) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *policyRow) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *policyRow) Values() ([]any, error)                       { return nil, r.err }
func (r *policyRow) RawScan(_ []any) error                        { return r.err }

type policyRows struct {
	store *toolPolicyTestStore
	orgID string
	items []*toolpolicy.Policy
	idx   int
}

func (r *policyRows) init() {
	if r.items != nil {
		return
	}
	for _, p := range r.store.byName {
		if p.OrgID == r.orgID {
			cp := *p
			r.items = append(r.items, &cp)
		}
	}
}
func (r *policyRows) Next() bool { r.init(); r.idx++; return r.idx <= len(r.items) }
func (r *policyRows) Scan(dest ...any) error {
	return scanInto(dest, r.items[r.idx-1])
}
func scanInto(dest []any, p *toolpolicy.Policy) error {
	var rules []byte
	if len(p.Rules) > 0 {
		rules = []byte(p.Rules)
	}
	vals := []any{p.ID, p.OrgID, p.Name, p.Subject, p.Server, p.Tool, p.Action, rules, p.Priority, p.Enabled}
	for i := range vals {
		switch d := dest[i].(type) {
		case *string:
			if s, ok := vals[i].(string); ok {
				*d = s
			}
		case *int:
			*d = vals[i].(int)
		case *bool:
			*d = vals[i].(bool)
		case *[]byte:
			if b, ok := vals[i].([]byte); ok {
				*d = b
			}
		}
	}
	for i := 10; i < len(dest); i++ {
		if d, ok := dest[i].(*time.Time); ok {
			*d = time.Now()
		}
	}
	return nil
}
func (r *policyRows) Close()                                       {}
func (r *policyRows) Err() error                                   { return nil }
func (r *policyRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *policyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *policyRows) Values() ([]any, error)                       { return nil, nil }
func (r *policyRows) RawScan(_ []any) error                        { return nil }
func (r *policyRows) NextResultSet() bool                          { return false }
func (r *policyRows) Conn() *pgx.Conn                              { return nil }
func (r *policyRows) RawValues() [][]byte                          { return nil }

// ---- harness ---------------------------------------------------------------

func newToolPolicyTestH(store *toolPolicyTestStore) *AdminHandlers {
	h := New(nil, "", "", []string{})
	h.SetToolPolicyStore(toolpolicy.NewStore(store), nil)
	return h
}

// ---- tests -------------------------------------------------------------------

func TestToolPolicy_NoStore_503(t *testing.T) {
	h := New(nil, "", "", []string{})
	w := httptest.NewRecorder()
	h.CreateToolPolicy()(w, rootRequest("POST", "/api/organizations/org-1/tool-policies", `{}`))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestToolPolicy_CreateValidation(t *testing.T) {
	store := newToolPolicyTestStore()
	h := newToolPolicyTestH(store)
	cases := []string{
		`{"org_id":"org-1","name":"Bad Name","subject":"*","tool":"web_*","action":"deny"}`,       // name
		`{"org_id":"org-1","name":"ok","subject":"a*b","tool":"*","action":"deny"}`,               // subject pattern
		`{"org_id":"org-1","name":"ok","subject":"*","tool":"we*b","action":"deny"}`,              // tool pattern
		`{"org_id":"org-1","name":"ok","subject":"*","tool":"*","action":"maybe"}`,                // action
		`{"org_id":"org-1","name":"ok","subject":"*","tool":"*","action":"deny","priority":5000}`, // priority
	}
	for _, body := range cases {
		w := httptest.NewRecorder()
		h.CreateToolPolicy()(w, rootRequest("POST", "/api/organizations/org-1/tool-policies", body))
		assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s → %s", body, w.Body.String())
	}
}

func TestToolPolicy_CRUD(t *testing.T) {
	store := newToolPolicyTestStore()
	h := newToolPolicyTestH(store)

	w := httptest.NewRecorder()
	h.CreateToolPolicy()(w, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"deny-web","subject":"*","tool":"web_*","action":"deny","priority":50,"enabled":true}`))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var p toolpolicy.Policy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &p))
	assert.Equal(t, "deny-web", p.Name)

	// Duplicate → 409.
	w2 := httptest.NewRecorder()
	h.CreateToolPolicy()(w2, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"deny-web","subject":"*","tool":"web_*","action":"deny"}`))
	assert.Equal(t, http.StatusConflict, w2.Code)

	// List.
	listReq := rootRequest("GET", "/api/organizations/org-1/tool-policies", "")
	listReq.SetPathValue("id", "org-1")
	w3 := httptest.NewRecorder()
	h.ListToolPolicies()(w3, listReq)
	require.Equal(t, http.StatusOK, w3.Code)
	var list []*toolpolicy.Policy
	require.NoError(t, json.Unmarshal(w3.Body.Bytes(), &list))
	require.Len(t, list, 1)

	// Update (disable).
	patch := rootRequest("PATCH", "/api/organizations/org-1/tool-policies/deny-web", `{"enabled":false}`)
	patch.SetPathValue("id", "org-1")
	patch.SetPathValue("name", "deny-web")
	w4 := httptest.NewRecorder()
	h.UpdateToolPolicy()(w4, patch)
	require.Equal(t, http.StatusOK, w4.Code, w4.Body.String())

	// Get → disabled.
	get := rootRequest("GET", "/api/organizations/org-1/tool-policies/deny-web", "")
	get.SetPathValue("id", "org-1")
	get.SetPathValue("name", "deny-web")
	w5 := httptest.NewRecorder()
	h.GetToolPolicy()(w5, get)
	require.Equal(t, http.StatusOK, w5.Code)
	var got toolpolicy.Policy
	_ = json.Unmarshal(w5.Body.Bytes(), &got)
	assert.False(t, got.Enabled)

	// Delete → gone.
	del := rootRequest("DELETE", "/api/organizations/org-1/tool-policies/deny-web", "")
	del.SetPathValue("id", "org-1")
	del.SetPathValue("name", "deny-web")
	w6 := httptest.NewRecorder()
	h.DeleteToolPolicy()(w6, del)
	assert.Equal(t, http.StatusOK, w6.Code)

	w7 := httptest.NewRecorder()
	h.GetToolPolicy()(w7, get)
	assert.Equal(t, http.StatusNotFound, w7.Code)
}

func TestToolPolicy_CRUD_ServerAndRules(t *testing.T) {
	store := newToolPolicyTestStore()
	h := newToolPolicyTestH(store)

	// Create with server + rules (OP-6 guard shape).
	w := httptest.NewRecorder()
	h.CreateToolPolicy()(w, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"guard-github","subject":"*","server":"github","tool":"*","action":"allow",`+
			`"rules":{"args":{"max_bytes":4096}},"priority":10,"enabled":true}`))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var p toolpolicy.Policy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &p))
	assert.Equal(t, "github", p.Server)
	assert.JSONEq(t, `{"args":{"max_bytes":4096}}`, string(p.Rules))

	// Invalid rules → 400 with the compile error.
	w2 := httptest.NewRecorder()
	h.CreateToolPolicy()(w2, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"bad","subject":"*","tool":"*","action":"allow","rules":{"args":{"deny_regex":["(["]}}}`))
	assert.Equal(t, http.StatusBadRequest, w2.Code)

	// Server pattern validation → 400.
	w3 := httptest.NewRecorder()
	h.CreateToolPolicy()(w3, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"bad-server","subject":"*","server":"a*b","tool":"*","action":"allow"}`))
	assert.Equal(t, http.StatusBadRequest, w3.Code)

	// Rules patch → 200 and applied.
	patch := rootRequest("PATCH", "/api/organizations/org-1/tool-policies/guard-github",
		`{"rules":{"args":{"max_bytes":64}}}`)
	patch.SetPathValue("id", "org-1")
	patch.SetPathValue("name", "guard-github")
	w4 := httptest.NewRecorder()
	h.UpdateToolPolicy()(w4, patch)
	require.Equal(t, http.StatusOK, w4.Code, w4.Body.String())
	var got toolpolicy.Policy
	require.NoError(t, json.Unmarshal(w4.Body.Bytes(), &got))
	assert.JSONEq(t, `{"args":{"max_bytes":64}}`, string(got.Rules))

	// Invalid rules patch → 400.
	w5 := httptest.NewRecorder()
	patch2 := rootRequest("PATCH", "/api/organizations/org-1/tool-policies/guard-github",
		`{"rules":{"result":{"mode":"nuke"}}}`)
	patch2.SetPathValue("id", "org-1")
	patch2.SetPathValue("name", "guard-github")
	h.UpdateToolPolicy()(w5, patch2)
	assert.Equal(t, http.StatusBadRequest, w5.Code)
}

func TestToolPolicy_ApplyPreset(t *testing.T) {
	store := newToolPolicyTestStore()
	h := newToolPolicyTestH(store)

	req := rootRequest("POST", "/api/organizations/org-1/tool-policies/presets/network-off", "")
	req.SetPathValue("id", "org-1")
	req.SetPathValue("preset", "network-off")
	w := httptest.NewRecorder()
	h.ApplyToolPolicyPreset()(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var res map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	created := int(res["created"].(float64))
	assert.Positive(t, created)

	// The applied policies must actually deny a web tool for the org.
	listReq := rootRequest("GET", "/api/organizations/org-1/tool-policies", "")
	listReq.SetPathValue("id", "org-1")
	w2 := httptest.NewRecorder()
	h.ListToolPolicies()(w2, listReq)
	var list []*toolpolicy.Policy
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &list))
	engine := toolpolicy.NewEngine(&listLoader{policies: list}, 0)
	d := engine.Decide(context.Background(), "org-1", "any-agent", "web_fetch")
	assert.Equal(t, toolpolicy.ActionDeny, d.Action, "preset must deny web_fetch, got %+v", d)

	// Idempotent: second apply skips existing rows.
	w3 := httptest.NewRecorder()
	h.ApplyToolPolicyPreset()(w3, req)
	require.Equal(t, http.StatusOK, w3.Code)
	var res2 map[string]any
	_ = json.Unmarshal(w3.Body.Bytes(), &res2)
	assert.InDelta(t, float64(created), res2["skipped_existing"], 0.001)

	// Unknown preset → 404.
	req404 := rootRequest("POST", "/api/organizations/org-1/tool-policies/presets/nope", "")
	req404.SetPathValue("id", "org-1")
	req404.SetPathValue("preset", "nope")
	w4 := httptest.NewRecorder()
	h.ApplyToolPolicyPreset()(w4, req404)
	assert.Equal(t, http.StatusNotFound, w4.Code)
}

type listLoader struct{ policies []*toolpolicy.Policy }

func (l *listLoader) ListEnabled(context.Context, string) ([]toolpolicy.Policy, error) {
	out := make([]toolpolicy.Policy, 0, len(l.policies))
	for _, p := range l.policies {
		if p.Enabled {
			out = append(out, *p)
		}
	}
	return out, nil
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *policyRows) TypeMap() *pgtype.Map { return nil }
