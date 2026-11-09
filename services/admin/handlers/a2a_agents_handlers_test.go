package handlers

// A2A agent registry CRUD handler tests over an in-memory DB mock (the same
// harness style as the MCP server handler tests: rootRequest + the shared
// DNS seam for deterministic SSRF checks).

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/reireirei/yabanin/pkg/a2aagg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- mock DB ----------------------------------------------------------------

type a2aTestStore struct{ agents map[string]*a2aagg.Agent } // key: orgID/name

func newA2ATestStore() *a2aTestStore {
	return &a2aTestStore{agents: map[string]*a2aagg.Agent{}}
}

func (s *a2aTestStore) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	now := time.Now()
	switch {
	case strings.Contains(sql, "INSERT INTO a2a_agents"):
		key := args[0].(string) + "/" + args[1].(string)
		if _, exists := s.agents[key]; exists {
			return &a2aRow{err: errA2ADuplicate}
		}
		a := &a2aagg.Agent{ID: "a2a-1", OrgID: args[0].(string), Name: args[1].(string),
			DisplayName: args[2].(*string), URL: args[3].(string), Enabled: args[4].(bool),
			CreatedAt: now, UpdatedAt: now}
		s.agents[key] = a
		return &a2aRow{agent: a}
	case strings.Contains(sql, "AND enabled"):
		key := args[0].(string) + "/" + args[1].(string)
		if a, ok := s.agents[key]; ok && a.Enabled {
			return &a2aRow{agent: a}
		}
		return &a2aRow{err: pgx.ErrNoRows}
	case strings.Contains(sql, "UPDATE a2a_agents"):
		key := args[0].(string) + "/" + args[1].(string)
		a, ok := s.agents[key]
		if !ok {
			return &a2aRow{err: pgx.ErrNoRows}
		}
		// args beyond org/name follow the UpdateParams order in the SQL
		// builder (display_name, url, enabled) — only present when set.
		for _, v := range args[2:] {
			switch t := v.(type) {
			case string:
				a.URL = t
			case bool:
				a.Enabled = t
			}
		}
		return &a2aRow{agent: a}
	case strings.Contains(sql, "SELECT"):
		key := args[0].(string) + "/" + args[1].(string)
		if a, ok := s.agents[key]; ok {
			return &a2aRow{agent: a}
		}
		return &a2aRow{err: pgx.ErrNoRows}
	}
	return &a2aRow{err: pgx.ErrNoRows}
}

func (s *a2aTestStore) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	// List: WHERE org_id = $1 ORDER BY name — return the org's agents sorted.
	if strings.Contains(sql, "ORDER BY name") && len(args) == 1 {
		var out []*a2aagg.Agent
		for _, a := range s.agents {
			if a.OrgID == args[0].(string) {
				out = append(out, a)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return &a2aRows{agents: out}, nil
	}
	return nil, pgx.ErrNoRows
}

// a2aRows is a one-shot pgx.Rows over a fixed slice.
type a2aRows struct {
	agents []*a2aagg.Agent
	idx    int
}

func (r *a2aRows) Next() bool { r.idx++; return r.idx <= len(r.agents) }
func (r *a2aRows) Scan(dest ...any) error {
	a := r.agents[r.idx-1]
	if p, ok := dest[0].(*string); ok {
		*p = a.ID
	}
	if p, ok := dest[1].(*string); ok {
		*p = a.OrgID
	}
	if p, ok := dest[2].(*string); ok {
		*p = a.Name
	}
	if len(dest) > 3 {
		if p, ok := dest[3].(**string); ok {
			*p = a.DisplayName
		}
	}
	if len(dest) > 4 {
		if p, ok := dest[4].(*string); ok {
			*p = a.URL
		}
	}
	if len(dest) > 5 {
		if p, ok := dest[5].(*bool); ok {
			*p = a.Enabled
		}
	}
	if len(dest) > 6 {
		for _, d := range dest[6:] {
			if p, ok := d.(*time.Time); ok {
				*p = time.Now()
			}
		}
	}
	return nil
}
func (r *a2aRows) Values() ([]any, error)                       { return nil, nil }
func (r *a2aRows) Err() error                                   { return nil }
func (r *a2aRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *a2aRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *a2aRows) Close()                                       {}
func (r *a2aRows) NextResultSet() bool                          { return false }
func (r *a2aRows) Conn() *pgx.Conn                              { return nil }
func (r *a2aRows) RawValues() [][]byte                          { return nil }

func (s *a2aTestStore) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "DELETE FROM a2a_agents") {
		key := args[0].(string) + "/" + args[1].(string)
		if _, ok := s.agents[key]; !ok {
			return pgconn.CommandTag{}, a2aagg.ErrNotFound
		}
		delete(s.agents, key)
		return pgconn.NewCommandTag("DELETE 1"), nil
	}
	return pgconn.CommandTag{}, nil
}

// A real pgconn.PgError so the store's isUniqueViolation maps the
// duplicate to the typed "already exists" error the handler renders as 409.
var errA2ADuplicate = &pgconn.PgError{Code: "23505", Message: "duplicate key"}

type a2aRow struct {
	agent *a2aagg.Agent
	err   error
}

func (r *a2aRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	a := r.agent
	if p, ok := dest[0].(*string); ok {
		*p = a.ID
	}
	if p, ok := dest[1].(*string); ok {
		*p = a.OrgID
	}
	if p, ok := dest[2].(*string); ok {
		*p = a.Name
	}
	if len(dest) > 3 {
		if p, ok := dest[3].(**string); ok {
			*p = a.DisplayName
		}
	}
	if len(dest) > 4 {
		if p, ok := dest[4].(*string); ok {
			*p = a.URL
		}
	}
	if len(dest) > 5 {
		if p, ok := dest[5].(*bool); ok {
			*p = a.Enabled
		}
	}
	return nil
}
func (r *a2aRow) Close()                                       {}
func (r *a2aRow) Err() error                                   { return r.err }
func (r *a2aRow) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *a2aRow) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *a2aRow) Values() ([]any, error)                       { return nil, r.err }
func (r *a2aRow) RawScan(_ []any) error                        { return r.err }

// ---- handler wiring ----------------------------------------------------------

func newA2ATestH(store *a2aTestStore, allowedUpstreams []string) *AdminHandlers {
	h := New(nil, "", "", []string{})
	h.SetA2AStore(a2aagg.NewStore(store))
	// The A2A handlers reuse the MCP allow-list seam (shared dial-out
	// surface); wire it via SetMCPStore's list parameter.
	h.SetMCPStore(nil, allowedUpstreams)
	// QG2-D3: deterministic DNS for the registration-time SSRF guard.
	h.mcp.dnsResolver = func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("140.82.121.3")}, nil
	}
	return h
}

// ---- tests --------------------------------------------------------------------

func TestA2AAgents_NoStore_503(t *testing.T) {
	h := New(nil, "", "", []string{})
	req := rootRequest("POST", "/api/organizations/org-1/a2a/agents",
		`{"org_id":"org-1","name":"helper","url":"https://github.com/a2a"}`)
	w := httptest.NewRecorder()
	h.CreateA2AAgent()(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestA2AAgents_CreateValidation(t *testing.T) {
	store := newA2ATestStore()
	h := newA2ATestH(store, []string{"github.com"})

	cases := []struct {
		name string
		body string
		want int
	}{
		{"bad name", `{"org_id":"org-1","name":"Bad Name","url":"https://github.com/a2a"}`, http.StatusBadRequest},
		{"http url", `{"org_id":"org-1","name":"helper","url":"http://github.com/a2a"}`, http.StatusBadRequest},
		{"disallowed domain", `{"org_id":"org-1","name":"helper","url":"https://evil.example.com/a2a"}`, http.StatusBadRequest},
		{"missing org", `{"name":"helper","url":"https://github.com/a2a"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := rootRequest("POST", "/api/organizations/org-1/a2a/agents", tc.body)
			w := httptest.NewRecorder()
			h.CreateA2AAgent()(w, req)
			assert.Equal(t, tc.want, w.Code, "body: %s → %s", tc.body, w.Body.String())
		})
	}
}

func TestA2AAgents_CreateSuccess(t *testing.T) {
	store := newA2ATestStore()
	h := newA2ATestH(store, []string{"github.com"})

	req := rootRequest("POST", "/api/organizations/org-1/a2a/agents",
		`{"org_id":"org-1","name":"helper","url":"https://github.com/a2a","enabled":false}`)
	w := httptest.NewRecorder()
	h.CreateA2AAgent()(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var agent a2aagg.Agent
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &agent))
	assert.Equal(t, "helper", agent.Name)
	assert.Equal(t, "org-1", agent.OrgID)
	assert.False(t, agent.Enabled, "a registered agent must stay inert until enabled")
}

func TestA2AAgents_CreateDuplicate_409(t *testing.T) {
	store := newA2ATestStore()
	h := newA2ATestH(store, []string{"github.com"})
	body := `{"org_id":"org-1","name":"helper","url":"https://github.com/a2a"}`

	w1 := httptest.NewRecorder()
	h.CreateA2AAgent()(w1, rootRequest("POST", "/api/organizations/org-1/a2a/agents", body))
	require.Equal(t, http.StatusCreated, w1.Code)

	w2 := httptest.NewRecorder()
	h.CreateA2AAgent()(w2, rootRequest("POST", "/api/organizations/org-1/a2a/agents", body))
	assert.Equal(t, http.StatusConflict, w2.Code)
}

func TestA2AAgents_OrgScopeMismatch_403(t *testing.T) {
	store := newA2ATestStore()
	h := newA2ATestH(store, []string{"github.com"})

	// Non-root request whose org scope does not match the target org.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/organizations/org-2/a2a/agents",
		strings.NewReader(`{"org_id":"org-2","name":"helper","url":"https://github.com/a2a"}`))
	req.Header.Set("X-Yabanin-Org-Id", "org-1")
	w := httptest.NewRecorder()
	h.CreateA2AAgent()(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestA2AAgents_GetUpdateDelete(t *testing.T) {
	store := newA2ATestStore()
	h := newA2ATestH(store, []string{"github.com"})

	// Seed via create.
	w := httptest.NewRecorder()
	h.CreateA2AAgent()(w, rootRequest("POST", "/api/organizations/org-1/a2a/agents",
		`{"org_id":"org-1","name":"helper","url":"https://github.com/a2a"}`))
	require.Equal(t, http.StatusCreated, w.Code)

	getReq := rootRequest("GET", "/api/organizations/org-1/a2a/agents/helper", "")
	getReq.SetPathValue("id", "org-1")
	getReq.SetPathValue("name", "helper")
	wGet := httptest.NewRecorder()
	h.GetA2AAgent()(wGet, getReq)
	require.Equal(t, http.StatusOK, wGet.Code, wGet.Body.String())

	// Enable via PATCH.
	patchReq := rootRequest("PATCH", "/api/organizations/org-1/a2a/agents/helper", `{"enabled":true}`)
	patchReq.SetPathValue("id", "org-1")
	patchReq.SetPathValue("name", "helper")
	wPatch := httptest.NewRecorder()
	h.UpdateA2AAgent()(wPatch, patchReq)
	require.Equal(t, http.StatusOK, wPatch.Code, wPatch.Body.String())
	assert.Contains(t, wPatch.Body.String(), `"enabled":true`)

	// Delete.
	delReq := rootRequest("DELETE", "/api/organizations/org-1/a2a/agents/helper", "")
	delReq.SetPathValue("id", "org-1")
	delReq.SetPathValue("name", "helper")
	wDel := httptest.NewRecorder()
	h.DeleteA2AAgent()(wDel, delReq)
	assert.Equal(t, http.StatusOK, wDel.Code)

	// Gone afterwards.
	wGet2 := httptest.NewRecorder()
	h.GetA2AAgent()(wGet2, getReq)
	assert.Equal(t, http.StatusNotFound, wGet2.Code)
}

func TestA2AAgents_List(t *testing.T) {
	store := newA2ATestStore()
	h := newA2ATestH(store, []string{"github.com"})

	for _, name := range []string{"alpha", "beta"} {
		w := httptest.NewRecorder()
		h.CreateA2AAgent()(w, rootRequest("POST", "/api/organizations/org-1/a2a/agents",
			`{"org_id":"org-1","name":"`+name+`","url":"https://github.com/a2a"}`))
		require.Equal(t, http.StatusCreated, w.Code)
	}

	listReq := rootRequest("GET", "/api/organizations/org-1/a2a/agents", "")
	listReq.SetPathValue("id", "org-1")
	wList := httptest.NewRecorder()
	h.ListA2AAgents()(wList, listReq)
	require.Equal(t, http.StatusOK, wList.Code, wList.Body.String())

	var agents []*a2aagg.Agent
	require.NoError(t, json.Unmarshal(wList.Body.Bytes(), &agents))
	require.Len(t, agents, 2)
	assert.Equal(t, "alpha", agents[0].Name, "list must be name-ordered")
	assert.Equal(t, "beta", agents[1].Name)
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *a2aRows) TypeMap() *pgtype.Map { return nil }
