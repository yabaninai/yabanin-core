package handlers

// AUX-02: server-side sorting contract for the admin list endpoints
// (DB-backed, real handler stack on the disposable testcontainers stand).
//
// Contract: sort=<allowlisted column>&dir=<asc|desc>; unknown column or
// direction → 400 {"error":"invalid_sort"}; a user-provided string never
// reaches SQL (the store maps the allowlisted name to a fixed expression);
// ties break on id so pagination is stable; no params → the pre-AUX-02
// default order; org scoping survives every sorted query.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSortH(t *testing.T) (*AdminHandlers, *pgxpool.Pool) {
	t.Helper()
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.Default(), nil)
	return New(store, "", "", []string{}), pool
}

type sortPage struct {
	Data       json.RawMessage `json:"data"`
	Pagination struct {
		Page     int   `json:"page"`
		PageSize int   `json:"page_size"`
		Total    int64 `json:"total"`
	} `json:"pagination"`
}

func doSortGet(t *testing.T, hf http.HandlerFunc, query string) (int, sortPage) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/list"+query, nil)
	rw := httptest.NewRecorder()
	hf(rw, req)
	var p sortPage
	if rw.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &p), "query %s", query)
	}
	return rw.Code, p
}

func sortSeedOrg(t *testing.T, h *AdminHandlers, label string) *adminstore.Organization {
	t.Helper()
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	org, err := h.store.CreateOrganization(context.Background(),
		"aux02 org "+label+" "+run, "aux02-"+label+"-"+run)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = h.store.DeleteOrganization(context.Background(), org.ID)
	})
	return org
}

// setCreatedAt pins created_at on a table row so order assertions do not
// depend on statement timing.
func setCreatedAt(t *testing.T, pool *pgxpool.Pool, table, id string, ts time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		"UPDATE "+table+" SET created_at = $1 WHERE id = $2", ts, id)
	require.NoError(t, err)
}

func sortSeedKeys(t *testing.T, h *AdminHandlers, pool *pgxpool.Pool, orgID string, names []string) map[string]string {
	t.Helper()
	ctx := context.Background()
	team, err := h.store.GetDefaultTeam(ctx, orgID)
	require.NoError(t, err)
	ids := map[string]string{}
	for i, n := range names {
		key, err := h.store.CreateAPIKey(ctx, "aux02-hash-"+orgID+"-"+n+"-"+strconv.Itoa(i), n, &orgID, &team.ID)
		require.NoError(t, err)
		ids[n] = key.ID
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), "DELETE FROM api_keys WHERE id = $1", key.ID)
		})
	}
	return ids
}

// namesByID orders names by their entity id (the tie-breaker order).
func namesByID(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return m[names[i]] < m[names[j]] })
	return names
}

func reverse(in []string) []string {
	out := append([]string(nil), in...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func assertOrder(t *testing.T, got, want []string, msg string, args ...interface{}) {
	t.Helper()
	text := fmt.Sprintf(msg, args...)
	require.Len(t, got, len(want), text)
	assert.Equal(t, want, got, text)
}

// --- API keys ---

func TestSort_APIKeys_AllowedColumnsBothDirections(t *testing.T) {
	h, pool := newSortH(t)
	ctx := context.Background()
	org := sortSeedOrg(t, h, "keys")

	ids := sortSeedKeys(t, h, pool, org.ID, []string{"aux02-alpha", "aux02-beta", "aux02-gamma"})
	// Distinct, deliberately different from name/priority order:
	// beta(1h) < gamma(2h) < alpha(3h).
	setCreatedAt(t, pool, "api_keys", ids["aux02-alpha"], time.Now().Add(-3*time.Hour))
	setCreatedAt(t, pool, "api_keys", ids["aux02-beta"], time.Now().Add(-1*time.Hour))
	setCreatedAt(t, pool, "api_keys", ids["aux02-gamma"], time.Now().Add(-2*time.Hour))
	// active: alpha=false, beta/gamma=true.
	_, err := pool.Exec(ctx, "UPDATE api_keys SET active = false WHERE id = $1", ids["aux02-alpha"])
	require.NoError(t, err)

	idOrder := namesByID(ids)
	cases := []struct {
		col, dir string
		want     []string
	}{
		{"name", "asc", []string{"aux02-alpha", "aux02-beta", "aux02-gamma"}},
		{"name", "desc", []string{"aux02-gamma", "aux02-beta", "aux02-alpha"}},
		{"created_at", "asc", []string{"aux02-alpha", "aux02-gamma", "aux02-beta"}},
		{"created_at", "desc", []string{"aux02-beta", "aux02-gamma", "aux02-alpha"}},
		// All-tie columns: the id tie-breaker must make both directions
		// deterministic (id ASC within equal values).
		{"org_id", "asc", idOrder},
		{"org_id", "desc", idOrder},
		{"team_id", "asc", idOrder},
		{"team_id", "desc", idOrder},
		{"id", "asc", idOrder},
		{"id", "desc", reverse(idOrder)},
		{"active", "asc", append([]string{"aux02-alpha"}, namesByID(map[string]string{
			"aux02-beta": ids["aux02-beta"], "aux02-gamma": ids["aux02-gamma"],
		})...)},
		{"active", "desc", append(namesByID(map[string]string{
			"aux02-beta": ids["aux02-beta"], "aux02-gamma": ids["aux02-gamma"],
		}), "aux02-alpha")},
	}
	for _, tc := range cases {
		code, p := doSortGet(t, h.ListAPIKeys(),
			"?org_id="+org.ID+"&sort="+tc.col+"&dir="+tc.dir)
		require.Equal(t, http.StatusOK, code, "col %s dir %s: %s", tc.col, tc.dir, p.Data)
		var keys []adminstore.APIKey
		require.NoError(t, json.Unmarshal(p.Data, &keys))
		got := make([]string, 0, len(keys))
		for _, k := range keys {
			got = append(got, k.Name)
		}
		assertOrder(t, got, tc.want, "keys sort=%s dir=%s", tc.col, tc.dir)
	}
}

func TestSort_APIKeys_DefaultOrderPreserved(t *testing.T) {
	h, pool := newSortH(t)
	org := sortSeedOrg(t, h, "keysdef")
	ids := sortSeedKeys(t, h, pool, org.ID, []string{"aux02-k1", "aux02-k2", "aux02-k3"})
	// k1 newest, k3 oldest; legacy default is created_at DESC.
	setCreatedAt(t, pool, "api_keys", ids["aux02-k1"], time.Now().Add(-1*time.Hour))
	setCreatedAt(t, pool, "api_keys", ids["aux02-k2"], time.Now().Add(-2*time.Hour))
	setCreatedAt(t, pool, "api_keys", ids["aux02-k3"], time.Now().Add(-3*time.Hour))

	code, p := doSortGet(t, h.ListAPIKeys(), "?org_id="+org.ID)
	require.Equal(t, http.StatusOK, code)
	var keys []adminstore.APIKey
	require.NoError(t, json.Unmarshal(p.Data, &keys))
	got := make([]string, 0, len(keys))
	for _, k := range keys {
		got = append(got, k.Name)
	}
	assertOrder(t, got, []string{"aux02-k1", "aux02-k2", "aux02-k3"}, "default order must stay created_at DESC")
}

func TestSort_APIKeys_PaginationStableOnTies(t *testing.T) {
	h, pool := newSortH(t)
	org := sortSeedOrg(t, h, "ties")
	names := make([]string, 6)
	for i := range names {
		names[i] = "aux02-tie"
	}
	ids := sortSeedKeys(t, h, pool, org.ID, names)
	same := time.Now().Add(-4 * time.Hour)
	for _, id := range ids {
		setCreatedAt(t, pool, "api_keys", id, same)
	}

	// All sort values equal → the id tie-breaker must fully determine order.
	seen := map[string]bool{}
	var firstPageIDs []string
	for page := 1; page <= 3; page++ {
		code, p := doSortGet(t, h.ListAPIKeys(),
			fmt.Sprintf("?org_id=%s&sort=name&dir=asc&page_size=2&page=%d", org.ID, page))
		require.Equal(t, http.StatusOK, code)
		var keys []adminstore.APIKey
		require.NoError(t, json.Unmarshal(p.Data, &keys))
		require.Len(t, keys, 2, "page %d", page)
		var pageIDs []string
		for _, k := range keys {
			require.False(t, seen[k.ID], "duplicate id across pages: %s", k.ID)
			seen[k.ID] = true
			pageIDs = append(pageIDs, k.ID)
		}
		if page == 1 {
			firstPageIDs = pageIDs
		}
	}
	require.Len(t, seen, 6, "all six keys must be visited exactly once")

	// Repeating a page returns the same rows in the same order.
	code, p := doSortGet(t, h.ListAPIKeys(), "?org_id="+org.ID+"&sort=name&dir=asc&page_size=2&page=1")
	require.Equal(t, http.StatusOK, code)
	var keys []adminstore.APIKey
	require.NoError(t, json.Unmarshal(p.Data, &keys))
	got := make([]string, 0, len(keys))
	for _, k := range keys {
		got = append(got, k.ID)
	}
	assert.Equal(t, firstPageIDs, got, "page 1 must be deterministic for equal sort values")
}

func TestSort_APIKeys_TwoPagesIntegration(t *testing.T) {
	h, pool := newSortH(t)
	org := sortSeedOrg(t, h, "pages")
	sortSeedKeys(t, h, pool, org.ID, []string{
		"aux02-p1", "aux02-p2", "aux02-p3", "aux02-p4", "aux02-p5",
	})

	list := func(dir string, page int) []string {
		code, p := doSortGet(t, h.ListAPIKeys(),
			fmt.Sprintf("?org_id=%s&sort=name&dir=%s&page_size=2&page=%d", org.ID, dir, page))
		require.Equal(t, http.StatusOK, code)
		var keys []adminstore.APIKey
		require.NoError(t, json.Unmarshal(p.Data, &keys))
		got := make([]string, 0, len(keys))
		for _, k := range keys {
			got = append(got, k.Name)
		}
		return got
	}

	assertOrder(t, list("asc", 1), []string{"aux02-p1", "aux02-p2"}, "keys page 1 asc")
	assertOrder(t, list("asc", 2), []string{"aux02-p3", "aux02-p4"}, "keys page 2 asc")
	assertOrder(t, list("asc", 3), []string{"aux02-p5"}, "keys page 3 asc")
	assertOrder(t, list("desc", 1), []string{"aux02-p5", "aux02-p4"}, "keys page 1 desc")
	assertOrder(t, list("desc", 3), []string{"aux02-p1"}, "keys page 3 desc")
}

// --- Routing rules ---

func sortSeedRules(t *testing.T, h *AdminHandlers, orgID string) map[string]string {
	t.Helper()
	ctx := context.Background()
	ids := map[string]string{}
	specs := []struct {
		expr, target string
		prio         int
	}{
		{"model~aux02-alpha", "zz-model", 10},
		{"model~aux02-beta", "aa-model", 20},
		{"model~aux02-gamma", "mm-model", 30},
	}
	for _, s := range specs {
		rule, err := h.store.CreateRoutingRule(ctx, orgID, s.expr, s.target, s.prio)
		require.NoError(t, err)
		ids[s.expr] = rule.ID
		t.Cleanup(func() { _ = h.store.DeleteRoutingRule(context.Background(), rule.ID) })
	}
	return ids
}

func TestSort_RoutingRules_AllowedColumnsBothDirections(t *testing.T) {
	h, pool := newSortH(t)
	org := sortSeedOrg(t, h, "rules")
	ids := sortSeedRules(t, h, org.ID)
	// created_at: alpha newest, beta oldest, gamma middle.
	setCreatedAt(t, pool, "routing_rules", ids["model~aux02-alpha"], time.Now().Add(-1*time.Hour))
	setCreatedAt(t, pool, "routing_rules", ids["model~aux02-beta"], time.Now().Add(-3*time.Hour))
	setCreatedAt(t, pool, "routing_rules", ids["model~aux02-gamma"], time.Now().Add(-2*time.Hour))
	// enabled: alpha=false, beta/gamma=true.
	_, err := pool.Exec(context.Background(),
		"UPDATE routing_rules SET enabled = false WHERE id = $1", ids["model~aux02-alpha"])
	require.NoError(t, err)

	byExpr := func(want []string) []string { return want }
	cases := []struct {
		col, dir string
		want     []string
	}{
		{"match_expr", "asc", byExpr([]string{"model~aux02-alpha", "model~aux02-beta", "model~aux02-gamma"})},
		{"match_expr", "desc", byExpr([]string{"model~aux02-gamma", "model~aux02-beta", "model~aux02-alpha"})},
		{"target_model", "asc", byExpr([]string{"model~aux02-beta", "model~aux02-gamma", "model~aux02-alpha"})},
		{"target_model", "desc", byExpr([]string{"model~aux02-alpha", "model~aux02-gamma", "model~aux02-beta"})},
		{"priority", "asc", byExpr([]string{"model~aux02-alpha", "model~aux02-beta", "model~aux02-gamma"})},
		{"priority", "desc", byExpr([]string{"model~aux02-gamma", "model~aux02-beta", "model~aux02-alpha"})},
		{"created_at", "asc", byExpr([]string{"model~aux02-beta", "model~aux02-gamma", "model~aux02-alpha"})},
		{"created_at", "desc", byExpr([]string{"model~aux02-alpha", "model~aux02-gamma", "model~aux02-beta"})},
		{"id", "asc", namesByID(ids)},
		{"id", "desc", reverse(namesByID(ids))},
		// enabled ties (beta/gamma both true) break by id.
		{"enabled", "asc", append([]string{"model~aux02-alpha"},
			namesByID(subMap(ids, []string{"model~aux02-beta", "model~aux02-gamma"}))...)},
		{"enabled", "desc", append(
			namesByID(subMap(ids, []string{"model~aux02-beta", "model~aux02-gamma"})),
			"model~aux02-alpha")},
	}
	for _, tc := range cases {
		code, p := doSortGet(t, h.ListRoutingRules(),
			"?org_id="+org.ID+"&sort="+tc.col+"&dir="+tc.dir)
		require.Equal(t, http.StatusOK, code, "col %s dir %s: %s", tc.col, tc.dir, p.Data)
		var rules []adminstore.RoutingRule
		require.NoError(t, json.Unmarshal(p.Data, &rules))
		got := make([]string, 0, len(rules))
		for _, r := range rules {
			got = append(got, r.MatchExpr)
		}
		assertOrder(t, got, tc.want, "rules sort=%s dir=%s", tc.col, tc.dir)
	}
}

func TestSort_RoutingRules_TwoPagesIntegration(t *testing.T) {
	h, _ := newSortH(t)
	org := sortSeedOrg(t, h, "rulepages")
	ctx := context.Background()
	for _, prio := range []int{50, 40, 30, 20, 10} {
		_, err := h.store.CreateRoutingRule(ctx, org.ID,
			fmt.Sprintf("model~prio%d", prio), "target", prio)
		require.NoError(t, err)
	}

	list := func(dir string, page int) []int {
		code, p := doSortGet(t, h.ListRoutingRules(),
			fmt.Sprintf("?org_id=%s&sort=priority&dir=%s&page_size=2&page=%d", org.ID, dir, page))
		require.Equal(t, http.StatusOK, code)
		var rules []adminstore.RoutingRule
		require.NoError(t, json.Unmarshal(p.Data, &rules))
		got := make([]int, 0, len(rules))
		for _, r := range rules {
			got = append(got, r.Priority)
		}
		return got
	}

	assert.Equal(t, []int{10, 20}, list("asc", 1), "rules page 1 asc")
	assert.Equal(t, []int{30, 40}, list("asc", 2), "rules page 2 asc")
	assert.Equal(t, []int{50}, list("asc", 3), "rules page 3 asc")
	assert.Equal(t, []int{50, 40}, list("desc", 1), "rules page 1 desc")
	assert.Equal(t, []int{30, 20}, list("desc", 2), "rules page 2 desc")
	assert.Equal(t, []int{10}, list("desc", 3), "rules page 3 desc")
}

// --- Organizations ---

func TestSort_Organizations_AllowedColumnsBothDirections(t *testing.T) {
	h, pool := newSortH(t)
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	names := []string{"aux02-org-a-" + run, "aux02-org-b-" + run, "aux02-org-c-" + run}
	orgs := make(map[string]*adminstore.Organization) // by short label
	byName := map[string]string{}                     // full name → label
	for i, n := range names {
		org, err := h.store.CreateOrganization(ctx, n, "aux02-o-"+run+"-"+strconv.Itoa(i))
		require.NoError(t, err)
		label := string(n[len("aux02-org-")])
		orgs[label] = org
		byName[n] = label
		t.Cleanup(func() { _ = h.store.DeleteOrganization(context.Background(), org.ID) })
	}
	// Distinct values that disagree with name order:
	// currency EUR(a) < JPY(c) < USD(b); timezone America(a) < Asia(c) < Europe(b);
	// created_at b(1h) < c(2h) < a(3h).
	fix := []struct {
		label, currency, timezone string
		age                       time.Duration
	}{
		{"a", "EUR", "America/Moscow", 3 * time.Hour},
		{"b", "USD", "Europe/Berlin", 1 * time.Hour},
		{"c", "JPY", "Asia/Tokyo", 2 * time.Hour},
	}
	for _, f := range fix {
		o := orgs[f.label]
		require.NoError(t, h.store.UpdateOrganization(ctx, o.ID, o.Name, o.Slug, f.currency, f.timezone, nil))
		setCreatedAt(t, pool, "organizations", o.ID, time.Now().Add(-f.age))
	}

	idLabels := []string{"a", "b", "c"}
	sort.Slice(idLabels, func(i, j int) bool { return orgs[idLabels[i]].ID < orgs[idLabels[j]].ID })
	cases := []struct {
		col, dir string
		want     []string
	}{
		{"name", "asc", []string{"a", "b", "c"}},
		{"name", "desc", []string{"c", "b", "a"}},
		{"slug", "asc", []string{"a", "b", "c"}},
		{"slug", "desc", []string{"c", "b", "a"}},
		{"currency", "asc", []string{"a", "c", "b"}},
		{"currency", "desc", []string{"b", "c", "a"}},
		{"timezone", "asc", []string{"a", "c", "b"}},
		{"timezone", "desc", []string{"b", "c", "a"}},
		{"created_at", "asc", []string{"a", "c", "b"}},
		{"created_at", "desc", []string{"b", "c", "a"}},
		{"id", "asc", idLabels},
		{"id", "desc", reverse(idLabels)},
	}
	for _, tc := range cases {
		code, p := doSortGet(t, h.ListOrganizations(), "?sort="+tc.col+"&dir="+tc.dir)
		require.Equal(t, http.StatusOK, code, "col %s dir %s: %s", tc.col, tc.dir, p.Data)
		var list []*adminstore.Organization
		require.NoError(t, json.Unmarshal(p.Data, &list))
		got := make([]string, 0, len(list))
		for _, o := range list {
			if lbl, ok := byName[o.Name]; ok {
				got = append(got, lbl)
			}
		}
		assertOrder(t, got, tc.want, "orgs sort=%s dir=%s", tc.col, tc.dir)
	}
}

// --- Models ---

func TestSort_Models_AllowedColumnsBothDirections(t *testing.T) {
	h, pool := newSortH(t)
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	specs := []struct {
		name, display, tier, provider string
		enabled                       bool
	}{
		{"aux02-m1-" + run, "zzz display", "smart", "anthropic", true},
		{"aux02-m2-" + run, "aaa display", "fast", "openai", false},
		{"aux02-m3-" + run, "mmm display", "premium", "custom", true},
	}
	var seeded []*adminstore.ModelRegistry
	for _, s := range specs {
		m, err := h.store.CreateModel(ctx, s.name, s.display, s.tier, nil, nil)
		require.NoError(t, err)
		seeded = append(seeded, m)
		t.Cleanup(func() { _ = h.store.DeleteModel(context.Background(), s.name) })
		require.NoError(t, h.store.UpdateModelWithParams(ctx, adminstore.UpdateModelParams{
			ModelName: s.name, Provider: stringPtr(s.provider), Enabled: &s.enabled,
		}))
	}
	// created_at: m2 newest, m3 oldest, m1 middle (differs from name order).
	age := map[string]time.Duration{"m1": 2 * time.Hour, "m2": 1 * time.Hour, "m3": 3 * time.Hour}
	for _, m := range seeded {
		label := m.ModelName[6:8]
		setCreatedAt(t, pool, "models_registry", m.ID, time.Now().Add(-age[label]))
	}

	numericIDOrder := func(desc bool) []string {
		ids := append([]string(nil), seeded[0].ID, seeded[1].ID, seeded[2].ID)
		sort.Slice(ids, func(i, j int) bool {
			a, _ := strconv.Atoi(ids[i])
			b, _ := strconv.Atoi(ids[j])
			if desc {
				return a > b
			}
			return a < b
		})
		return ids
	}
	label := func(id string) string {
		for _, m := range seeded {
			if m.ID == id {
				return m.ModelName[6:8]
			}
		}
		return ""
	}

	cases := []struct {
		col, dir string
		want     []string
	}{
		{"model_name", "asc", []string{"m1", "m2", "m3"}},
		{"model_name", "desc", []string{"m3", "m2", "m1"}},
		{"display_name", "asc", []string{"m2", "m3", "m1"}},
		{"display_name", "desc", []string{"m1", "m3", "m2"}},
		{"tier", "asc", []string{"m2", "m3", "m1"}},
		{"tier", "desc", []string{"m1", "m3", "m2"}},
		{"provider", "asc", []string{"m1", "m3", "m2"}},
		{"provider", "desc", []string{"m2", "m3", "m1"}},
		{"created_at", "asc", []string{"m3", "m1", "m2"}},
		{"created_at", "desc", []string{"m2", "m1", "m3"}},
		{"enabled", "asc", []string{"m2", "m1", "m3"}},
		{"enabled", "desc", []string{"m1", "m3", "m2"}},
		{"id", "asc", mapEach(numericIDOrder(false), label)},
		{"id", "desc", mapEach(numericIDOrder(true), label)},
	}
	for _, tc := range cases {
		code, p := doSortGet(t, h.ListModels(), "?sort="+tc.col+"&dir="+tc.dir)
		require.Equal(t, http.StatusOK, code, "col %s dir %s: %s", tc.col, tc.dir, p.Data)
		var models []*adminstore.ModelRegistry
		require.NoError(t, json.Unmarshal(p.Data, &models))
		got := make([]string, 0, len(models))
		for _, m := range models {
			if len(m.ModelName) > len(run) && m.ModelName[len(m.ModelName)-len(run):] == run {
				got = append(got, m.ModelName[6:8])
			}
		}
		assertOrder(t, got, tc.want, "models sort=%s dir=%s", tc.col, tc.dir)
	}
}

func mapEach(in []string, f func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, f(s))
	}
	return out
}

// --- Admin users ---

func TestSort_AdminUsers_AllowedColumnsBothDirections(t *testing.T) {
	h, pool := newSortH(t)
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	ids := map[string]string{}
	// email asc: a < b < c; display_name: c < a < b; is_root: a=false, b/c=true;
	// active: b=false, a/c=true; created_at: b(1h) < c(2h) < a(3h).
	specs := []struct {
		label, email, display string
		isRoot, active        bool
	}{
		{"a", "aux02-a-" + run + "@test.local", "mid display", false, true},
		{"b", "aux02-b-" + run + "@test.local", "zzz display", true, false},
		{"c", "aux02-c-" + run + "@test.local", "aaa display", true, true},
	}
	for _, s := range specs {
		u, err := h.store.CreateAdminUser(ctx, s.email, s.display, "aux02-not-a-real-hash", s.isRoot)
		require.NoError(t, err)
		ids[s.label] = u.ID
		t.Cleanup(func() { _ = h.store.DeleteAdminUser(context.Background(), u.ID) })
		_, err = pool.Exec(ctx, "UPDATE admin_users SET active = $1 WHERE id = $2", s.active, u.ID)
		require.NoError(t, err)
	}
	setCreatedAt(t, pool, "admin_users", ids["a"], time.Now().Add(-3*time.Hour))
	setCreatedAt(t, pool, "admin_users", ids["b"], time.Now().Add(-1*time.Hour))
	setCreatedAt(t, pool, "admin_users", ids["c"], time.Now().Add(-2*time.Hour))

	idOrder := namesByID(ids) // a, b, c by id
	groupByID := func(labels ...string) []string {
		return namesByID(subMap(ids, labels))
	}
	cases := []struct {
		col, dir string
		want     []string
	}{
		{"email", "asc", []string{"a", "b", "c"}},
		{"email", "desc", []string{"c", "b", "a"}},
		{"display_name", "asc", []string{"c", "a", "b"}},
		{"display_name", "desc", []string{"b", "a", "c"}},
		{"created_at", "asc", []string{"a", "c", "b"}},
		{"created_at", "desc", []string{"b", "c", "a"}},
		{"id", "asc", idOrder},
		{"id", "desc", reverse(idOrder)},
		{"is_root", "asc", append([]string{"a"}, groupByID("b", "c")...)},
		{"is_root", "desc", append(groupByID("b", "c"), "a")},
		{"active", "asc", append([]string{"b"}, groupByID("a", "c")...)},
		{"active", "desc", append(groupByID("a", "c"), "b")},
	}
	for _, tc := range cases {
		code, p := doSortGet(t, h.ListAdminUsers(), "?sort="+tc.col+"&dir="+tc.dir)
		require.Equal(t, http.StatusOK, code, "col %s dir %s: %s", tc.col, tc.dir, p.Data)
		var users []*adminstore.AdminUser
		require.NoError(t, json.Unmarshal(p.Data, &users))
		got := make([]string, 0, len(users))
		for _, u := range users {
			if strings.HasPrefix(u.Email, "aux02-") && strings.Contains(u.Email, run) {
				got = append(got, string(u.Email[6]))
			}
		}
		assertOrder(t, got, tc.want, "admin users sort=%s dir=%s", tc.col, tc.dir)
	}
}

func subMap(m map[string]string, keys []string) map[string]string {
	out := map[string]string{}
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

// TestSort_DefaultOrderPreserved_RulesModelsOrgsAdminUsers pins the legacy
// default order (no sort params) on the remaining list endpoints: rules —
// priority DESC, models — created_at ASC, orgs and admin users —
// created_at DESC. Keys has TestSort_APIKeys_DefaultOrderPreserved.
func TestSort_DefaultOrderPreserved_RulesModelsOrgsAdminUsers(t *testing.T) {
	h, pool := newSortH(t)
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	// Rules: legacy default is priority DESC.
	org := sortSeedOrg(t, h, "defaults")
	sortSeedRules(t, h, org.ID)
	code, p := doSortGet(t, h.ListRoutingRules(), "?org_id="+org.ID)
	require.Equal(t, http.StatusOK, code)
	var rules []adminstore.RoutingRule
	require.NoError(t, json.Unmarshal(p.Data, &rules))
	gotRules := make([]string, 0, len(rules))
	for _, r := range rules {
		gotRules = append(gotRules, r.MatchExpr)
	}
	assertOrder(t, gotRules,
		[]string{"model~aux02-gamma", "model~aux02-beta", "model~aux02-alpha"},
		"rules default must stay priority DESC")

	// Models: legacy default is created_at ASC.
	modelAge := map[string]time.Duration{"d1": 3 * time.Hour, "d2": 2 * time.Hour, "d3": 1 * time.Hour}
	for _, lbl := range []string{"d1", "d2", "d3"} {
		name := "aux02-" + lbl + "-" + run
		m, err := h.store.CreateModel(ctx, name, lbl+" display", "tier-"+lbl, nil, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = h.store.DeleteModel(context.Background(), name) })
		setCreatedAt(t, pool, "models_registry", m.ID, time.Now().Add(-modelAge[lbl]))
	}
	code, p = doSortGet(t, h.ListModels(), "")
	require.Equal(t, http.StatusOK, code)
	var models []*adminstore.ModelRegistry
	require.NoError(t, json.Unmarshal(p.Data, &models))
	gotModels := make([]string, 0, len(models))
	for _, m := range models {
		if strings.HasSuffix(m.ModelName, "-"+run) {
			gotModels = append(gotModels, m.ModelName[len("aux02-"):len("aux02-")+2])
		}
	}
	assertOrder(t, gotModels, []string{"d1", "d2", "d3"}, "models default must stay created_at ASC")

	// Orgs and admin users: legacy default is created_at DESC.
	orgAge := map[string]time.Duration{"o1": 3 * time.Hour, "o2": 2 * time.Hour, "o3": 1 * time.Hour}
	for _, lbl := range []string{"o1", "o2", "o3"} {
		o, err := h.store.CreateOrganization(ctx,
			"aux02-def-"+lbl+"-"+run, "aux02-def-"+lbl+"-"+run)
		require.NoError(t, err)
		t.Cleanup(func() { _ = h.store.DeleteOrganization(context.Background(), o.ID) })
		setCreatedAt(t, pool, "organizations", o.ID, time.Now().Add(-orgAge[lbl]))
	}
	code, p = doSortGet(t, h.ListOrganizations(), "")
	require.Equal(t, http.StatusOK, code)
	var orgs []*adminstore.Organization
	require.NoError(t, json.Unmarshal(p.Data, &orgs))
	gotOrgs := make([]string, 0, len(orgs))
	for _, o := range orgs {
		if strings.HasSuffix(o.Name, "-"+run) {
			gotOrgs = append(gotOrgs, o.Name[len("aux02-def-"):len("aux02-def-")+2])
		}
	}
	assertOrder(t, gotOrgs, []string{"o3", "o2", "o1"}, "orgs default must stay created_at DESC")

	userAge := map[string]time.Duration{"u1": 3 * time.Hour, "u2": 2 * time.Hour, "u3": 1 * time.Hour}
	for _, lbl := range []string{"u1", "u2", "u3"} {
		u, err := h.store.CreateAdminUser(ctx,
			"aux02-"+lbl+"-"+run+"@test.local", "user "+lbl, "aux02-not-a-real-hash", false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = h.store.DeleteAdminUser(context.Background(), u.ID) })
		setCreatedAt(t, pool, "admin_users", u.ID, time.Now().Add(-userAge[lbl]))
	}
	code, p = doSortGet(t, h.ListAdminUsers(), "")
	require.Equal(t, http.StatusOK, code)
	var users []*adminstore.AdminUser
	require.NoError(t, json.Unmarshal(p.Data, &users))
	gotUsers := make([]string, 0, len(users))
	for _, u := range users {
		if strings.HasSuffix(u.Email, "-"+run+"@test.local") {
			gotUsers = append(gotUsers, u.Email[6:8])
		}
	}
	assertOrder(t, gotUsers, []string{"u3", "u2", "u1"}, "admin users default must stay created_at DESC")
}

// --- HTTP error contract on every endpoint ---

func TestSort_UnknownColumnAndBadDirRejectedOnEveryEndpoint(t *testing.T) {
	h, _ := newSortH(t)

	type ep struct {
		name string
		hf   http.HandlerFunc
	}
	endpoints := []ep{
		{"keys", h.ListAPIKeys()},
		{"orgs", h.ListOrganizations()},
		{"models", h.ListModels()},
		// rules requires org_id before it validates sort; any value works
		// because invalid sorts are rejected before the store is touched.
		{"rules", h.ListRoutingRules()},
		{"admin_users", h.ListAdminUsers()},
	}
	for _, e := range endpoints {
		for _, query := range []string{
			"?sort=__bogus__&dir=asc",
			"?sort=name;DROP%20TABLE%20x&dir=asc",
			"?sort=1%3D1&dir=asc",
			"?sort=name%27--&dir=asc",
			"?sort=name&dir=sideways",
			"?sort=name&dir=asc%3BDELETE",
			"?sort=" + url.QueryEscape("name UNION SELECT 1"),
		} {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/list"+query, nil)
			rw := httptest.NewRecorder()
			if e.name == "rules" {
				req.URL.RawQuery += "&org_id=00000000-0000-0000-0000-000000000000"
			}
			e.hf(rw, req)
			assert.Equal(t, http.StatusBadRequest, rw.Code,
				"%s: query %s must be 400, got body %s", e.name, query, rw.Body.String())
			if rw.Code == http.StatusBadRequest {
				assert.JSONEq(t, `{"error":"invalid_sort"}`, rw.Body.String(),
					"%s: query %s", e.name, query)
			}
		}
	}
}

func TestSort_InvalidSortBodyIsMachineReadable(t *testing.T) {
	h, _ := newSortH(t)
	code, _ := doSortGet(t, h.ListModels(), "?sort=nope")
	require.Equal(t, http.StatusBadRequest, code)
	// The error code itself is the contract: {"error":"invalid_sort"}.
	// (Body checked exactly here so clients can branch on it.)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/list?sort=nope", nil)
	rw := httptest.NewRecorder()
	h.ListModels()(rw, req)
	assert.JSONEq(t, `{"error":"invalid_sort"}`, rw.Body.String())
}

// --- Org scope survives sorting ---

func TestSort_OrgScopePreserved(t *testing.T) {
	h, pool := newSortH(t)
	orgA := sortSeedOrg(t, h, "scope-a")
	orgB := sortSeedOrg(t, h, "scope-b")

	sortSeedKeys(t, h, pool, orgA.ID, []string{"aux02-scope-a1", "aux02-scope-a2"})
	sortSeedKeys(t, h, pool, orgB.ID, []string{"aux02-scope-b1"})

	code, p := doSortGet(t, h.ListAPIKeys(), "?org_id="+orgA.ID+"&sort=name&dir=asc")
	require.Equal(t, http.StatusOK, code)
	var keys []adminstore.APIKey
	require.NoError(t, json.Unmarshal(p.Data, &keys))
	require.Len(t, keys, 2)
	for _, k := range keys {
		require.NotNil(t, k.OrgID)
		assert.Equal(t, orgA.ID, *k.OrgID, "sorted key list must stay org-scoped")
	}

	sortSeedRules(t, h, orgA.ID)
	ruleB, err := h.store.CreateRoutingRule(context.Background(), orgB.ID, "model~b", "t", 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.store.DeleteRoutingRule(context.Background(), ruleB.ID) })

	code, p = doSortGet(t, h.ListRoutingRules(), "?org_id="+orgA.ID+"&sort=priority&dir=desc")
	require.Equal(t, http.StatusOK, code)
	var rules []adminstore.RoutingRule
	require.NoError(t, json.Unmarshal(p.Data, &rules))
	require.Len(t, rules, 3)
	for _, r := range rules {
		assert.Equal(t, orgA.ID, r.OrgID, "sorted rule list must stay org-scoped")
	}
}
