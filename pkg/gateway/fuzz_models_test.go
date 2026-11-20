package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// fuzzWL is a modelAccess fake with a static allow table.
type fuzzWL struct {
	allowed map[string]bool
	err     error
}

func (w fuzzWL) Check(_ context.Context, _, _, model string) (bool, error) {
	if w.err != nil {
		return false, w.err
	}
	return w.allowed[model], nil
}

// fuzzLister is a modelLister fake.
type fuzzLister struct {
	entries []modelEntry
	err     error
	calls   *int
}

func (l fuzzLister) ListEnabledModels(context.Context) ([]modelEntry, error) {
	if l.calls != nil {
		*l.calls++
	}
	return l.entries, l.err
}

func fuzzModelEntries() []modelEntry {
	return []modelEntry{
		{ID: "alpha", DisplayName: "Alpha", Provider: "zai", CreatedAt: time.Unix(1700000000, 0)},
		{ID: "beta", DisplayName: "Beta", Provider: "", CreatedAt: time.Unix(1700000001, 0)},
		{ID: "gamma", DisplayName: "Gamma", Provider: "openai",
			CreatedAt: time.Unix(1700000002, 0), AliasOf: "alpha"},
	}
}

func fuzzModelsGateway(lister modelLister, wl modelAccess) *gateway {
	return &gateway{log: discardLogger(), models: lister, wl: wl}
}

func fuzzModelsGetRequest(id string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models/"+id, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func FuzzModelsCatalog(f *testing.F) {
	for id := 1; id <= 26; id++ {
		f.Add([]byte{byte(id)}) // frozen regression corpus
	}
	// Generated-catalog seeds: disabled model plus dangling alias, and an
	// all-enabled two-model layout.
	f.Add([]byte{0x00, 0x01, 0x80, 0x00, 0x00})
	f.Add([]byte{0x40, 0x02, 0x02, 0x02})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 1 && data[0] >= 1 && data[0] <= 26 {
			fuzzMCCases[int(data[0])](t)
			return
		}
		mcGenerated(t, data)
	})
}

// mcGenCatalog derives a catalog layout from fuzzed bytes: 1-3 models with
// generated names, per-model enabled bits and 0-2 aliases targeting either
// a generated model or a dangling name.
type mcGenCatalog struct {
	names    []string
	disabled map[string]bool
	aliases  map[string]string // alias -> target
}

func mcGenCatalogFor(p []byte) mcGenCatalog {
	c := mcGenCatalog{disabled: map[string]bool{}, aliases: map[string]string{}}
	n := 1 + int(p[0])%3
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("fzgen-%02x-%02x", p[1], byte(i))
		c.names = append(c.names, name)
		if p[1+i]&1 == 1 {
			c.disabled[name] = true
		}
	}
	for j := 0; j < int(p[1])%3; j++ {
		alias := fmt.Sprintf("fzgen-al-%02x-%02x", p[0], byte(j))
		if p[2+j]&0x80 == 0 {
			c.aliases[alias] = c.names[int(p[2+j])%len(c.names)]
		} else {
			c.aliases[alias] = "fzgen-dangling"
		}
	}
	return c
}

// mcGenOracle holds the independent catalog invariants for generated rows:
// a disabled model never appears in the listed ids, every listed id is one
// the test inserted (enabled model or alias — no phantoms), the body is a
// JSON list envelope, and a never-inserted id 404s.
func mcGenOracle(t *testing.T, body []byte, c mcGenCatalog, gw *gateway) {
	t.Helper()
	var doc struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("mc gen: list body not JSON: %v (%q)", err, body)
	}
	known := map[string]bool{}
	for _, n := range c.names {
		if !c.disabled[n] {
			known[n] = true
		}
	}
	for a := range c.aliases {
		known[a] = true
	}
	if doc.Object != "list" {
		t.Fatalf("expected a list envelope, got %q", doc.Object)
	}
	got := map[string]bool{}
	for _, e := range doc.Data {
		if got[e.ID] {
			t.Fatalf("duplicate model ID %q", e.ID)
		}
		got[e.ID] = true
	}
	if !maps.Equal(got, known) {
		t.Fatalf("model catalog IDs: got %v, want %v", got, known)
	}
	w := httptest.NewRecorder()
	gw.getModel(w, fuzzModelsGetRequest("fzgen-never"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("mc gen: never-inserted id must 404: %d %s", w.Code, w.Body.String())
	}
}

// mcGenerated seeds a generated catalog layout on the real stand (idempotent
// upserts, rows removed in cleanup) and applies the list/get invariants
// through the live endpoints.
func mcGenerated(t *testing.T, data []byte) {
	t.Helper()
	var p [5]byte
	copy(p[:], data)
	pool := catalogFixture(t)
	c := mcGenCatalogFor(p[:])
	mcSeedCatalog(t, pool, c)
	gw := fuzzModelsGateway(newPGModelLister(pool), nil)
	w := httptest.NewRecorder()
	gw.listModels(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/models", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("mc gen: list %d %s", w.Code, w.Body.String())
	}
	mcGenOracle(t, w.Body.Bytes(), c, gw)
}

// catalogFixture copies the migrated table definitions into a schema owned by
// this test. Concurrent fuzz workers can then use the same model IDs safely.
func catalogFixture(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := testdb.PostgresOwnedSchema(t, "catalog")
	for _, stmt := range []string{
		"CREATE TABLE models_registry (LIKE public.models_registry INCLUDING ALL)",
		"CREATE TABLE model_aliases (LIKE public.model_aliases INCLUDING ALL)",
	} {
		if _, err := pool.Exec(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

// mcSeedCatalog inserts the generated rows into the empty fixture.
func mcSeedCatalog(t *testing.T, pool *pgxpool.Pool, c mcGenCatalog) {
	t.Helper()
	ctx := t.Context()
	for _, n := range c.names {
		if _, err := pool.Exec(ctx,
			`INSERT INTO models_registry (model_name, display_name, enabled)
			 VALUES ($1, 'Fuzz Gen', $2)`,
			n, !c.disabled[n]); err != nil {
			t.Fatalf("mc gen: model upsert: %v", err)
		}
	}
	for a, target := range c.aliases {
		if _, err := pool.Exec(ctx,
			`INSERT INTO model_aliases (alias, target_model) VALUES ($1, $2)`,
			a, target); err != nil {
			t.Fatalf("mc gen: alias upsert: %v", err)
		}
	}
}

var fuzzMCCases = map[int]func(*testing.T){
	1:  fuzzMC01,
	2:  fuzzMC02,
	3:  fuzzMC03,
	4:  fuzzMC04,
	5:  fuzzMC05,
	6:  fuzzMC06,
	7:  fuzzMC07,
	8:  fuzzMC08,
	9:  fuzzMC09,
	10: fuzzMC10,
	11: fuzzMC11,
	12: fuzzMC12,
	13: fuzzMC13,
	14: fuzzMC14,
	15: fuzzMC15,
	16: fuzzMC16,
	17: fuzzMC17,
	18: fuzzMC18,
	19: fuzzMC19,
	20: fuzzMC20,
	21: fuzzMC21,
	22: fuzzMC22,
	23: fuzzMC23,
	24: fuzzMC24,
	25: fuzzMC25,
	26: fuzzMC26,
}

func fuzzMC01(t *testing.T) {
	t.Helper()

	gw := fuzzModelsGateway(nil, nil)
	for _, r := range []*http.Request{
		httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil),
		fuzzModelsGetRequest("alpha"),
	} {
		w := httptest.NewRecorder()
		gw.listModels(w, r)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "models_unavailable") {
			t.Fatalf("MC-01 list: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	gw.getModel(w, fuzzModelsGetRequest("alpha"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("MC-01 get: %d", w.Code)
	}
}

func fuzzMC02(t *testing.T) {
	t.Helper()

	gw := fuzzModelsGateway(fuzzLister{err: errFuzz()}, nil)
	w := httptest.NewRecorder()
	gw.listModels(w, httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "models_unavailable") {
		t.Fatalf("MC-02: %d %s", w.Code, w.Body.String())
	}
}

func fuzzMC03(t *testing.T) {
	t.Helper()

	gw := fuzzModelsGateway(fuzzLister{entries: fuzzModelEntries()}, fuzzWL{err: errFuzz()})
	w := httptest.NewRecorder()
	gw.listModels(w, httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "whitelist_check_unavailable") {
		t.Fatalf("MC-03: %d %s", w.Code, w.Body.String())
	}
}

func fuzzMC04(t *testing.T) {
	t.Helper()

	wl := fuzzWL{allowed: map[string]bool{"alpha": true}}
	gw := fuzzModelsGateway(fuzzLister{entries: fuzzModelEntries()}, wl)
	w := httptest.NewRecorder()
	gw.listModels(w, httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil))
	body := w.Body.String()
	if !strings.Contains(body, `"alpha"`) || strings.Contains(body, `"beta"`) || !strings.Contains(body, `"gamma"`) {
		t.Fatalf("MC-04: alias must resolve to target: %s", body)
	}
}

func fuzzMC05(t *testing.T) {
	t.Helper()

	gw := fuzzModelsGateway(fuzzLister{entries: fuzzModelEntries()}, nil)
	w := httptest.NewRecorder()
	gw.listModels(w, httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil))
	for _, want := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("MC-05: missing %s: %s", want, w.Body.String())
		}
	}
}

func fuzzMC06(t *testing.T) {
	t.Helper()

	empty, err := staticModelLister{}.ListEnabledModels(context.Background())
	if err != nil || len(empty) != 0 {
		t.Fatalf("MC-06: empty static: %v %v", empty, err)
	}
	one, err := staticModelLister{entry: modelEntry{ID: "m1"}}.ListEnabledModels(context.Background())
	if err != nil || len(one) != 1 || one[0].ID != "m1" {
		t.Fatalf("MC-06: single static: %v %v", one, err)
	}
}

func fuzzMC07(t *testing.T) {
	t.Helper()

	p := newPGModelLister(nil)
	if p == nil || p.query == nil || p.now == nil {
		t.Fatal("MC-07: constructor must wire closures")
	}
}

func fuzzMC08(t *testing.T) {
	t.Helper()

	calls := 0
	base := time.Unix(1700000000, 0)
	p := &pgModelLister{
		query: func(context.Context) ([]modelEntry, error) {
			calls++
			return fuzzModelEntries()[:1], nil
		},
		now: func() time.Time { return base },
	}
	first, err := p.ListEnabledModels(context.Background())
	if err != nil || len(first) != 1 || calls != 1 {
		t.Fatalf("MC-08: fill: %v %v %d", first, err, calls)
	}
	first[0].ID = "mutated" // copy-out: must not corrupt the cache
	second, err := p.ListEnabledModels(context.Background())
	if err != nil || calls != 1 || second[0].ID != "alpha" {
		t.Fatalf("MC-08: cache hit must not requery: %v %d", second, calls)
	}
}

func fuzzMC09(t *testing.T) {
	t.Helper()

	calls := 0
	base := time.Unix(1700000000, 0)
	cur := base
	p := &pgModelLister{
		query: func(context.Context) ([]modelEntry, error) {
			calls++
			return nil, nil // nil list → normalized to []
		},
		now: func() time.Time { return cur },
	}
	got, err := p.ListEnabledModels(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("MC-09: nil list must normalize to empty: %v %v", got, err)
	}
	cur = base.Add(modelListCacheTTL + time.Second)
	if _, err := p.ListEnabledModels(context.Background()); err != nil || calls != 2 {
		t.Fatalf("MC-09: expiry must refetch: %d %v", calls, err)
	}
	failing := &pgModelLister{
		query: func(context.Context) ([]modelEntry, error) { return nil, errFuzz() },
		now:   func() time.Time { return base },
	}
	if _, err := failing.ListEnabledModels(context.Background()); err == nil {
		t.Fatal("MC-09: query error must surface")
	}
}

func fuzzMC10(t *testing.T) {
	t.Helper()

	gw := &gateway{cfg: config.Gateway{FallbackModel: "fallback-model"}}
	gw.bindModelLister(nil)
	entries, err := gw.models.ListEnabledModels(context.Background())
	if err != nil || len(entries) != 1 || entries[0].ID != "fallback-model" || entries[0].Provider != "yabanin" {
		t.Fatalf("MC-10: %v %v", entries, err)
	}
}

func fuzzMC11(t *testing.T) {
	t.Helper()

	pool, err := pgxpool.New(context.Background(), "postgres://test:test@127.0.0.1:1/test")
	if err != nil {
		t.Fatalf("MC-11: lazy pool: %v", err)
	}
	t.Cleanup(pool.Close)
	gw := &gateway{}
	gw.bindModelLister(pool)
	if _, ok := gw.models.(*pgModelLister); !ok {
		t.Fatalf("MC-11: want pg lister, got %T", gw.models)
	}
}

func fuzzMC12(t *testing.T) {
	t.Helper()

	gw := fuzzModelsGateway(fuzzLister{entries: fuzzModelEntries()}, nil)
	w := httptest.NewRecorder()
	gw.listModels(w, httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models?limit=2", nil))
	body := w.Body.String()
	if !strings.Contains(body, `"alpha"`) || !strings.Contains(body, `"beta"`) || strings.Contains(body, `"gamma"`) {
		t.Fatalf("MC-12: limit=2 must truncate: %s", body)
	}
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models?limit=2", nil)
	r2.Header.Set("anthropic-version", "v1")
	gw.listModels(w2, r2)
	if !strings.Contains(w2.Body.String(), `"has_more":true`) {
		t.Fatalf("MC-12: has_more must be true: %s", w2.Body.String())
	}
}

func fuzzMC13(t *testing.T) {
	t.Helper()

	gw := fuzzModelsGateway(fuzzLister{entries: fuzzModelEntries()}, nil)
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil)
	r.Header.Set("anthropic-version", "2023-06-01")
	w := httptest.NewRecorder()
	gw.listModels(w, r)
	body := w.Body.String()
	if !strings.Contains(body, `"first_id":"alpha"`) || !strings.Contains(body, `"last_id":"gamma"`) {
		t.Fatalf("MC-13: ids wrong: %s", body)
	}
	empty := fuzzModelsGateway(fuzzLister{entries: []modelEntry{}}, nil)
	r2 := httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil)
	r2.Header.Set("anthropic-version", "2023-06-01")
	w2 := httptest.NewRecorder()
	empty.listModels(w2, r2)
	if strings.Contains(w2.Body.String(), "first_id\":\"") && !strings.Contains(w2.Body.String(), `"first_id":""`) {
		t.Fatalf("MC-13: empty list must have empty ids: %s", w2.Body.String())
	}
}

func fuzzMC14(t *testing.T) {
	t.Helper()

	gw := fuzzModelsGateway(fuzzLister{entries: fuzzModelEntries()[:1]}, nil)
	w := httptest.NewRecorder()
	gw.listModels(w, httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil))
	if !strings.Contains(w.Body.String(), `"object":"list"`) || !strings.Contains(w.Body.String(), `"object":"model"`) {
		t.Fatalf("MC-14: %s", w.Body.String())
	}
}

func fuzzMC15(t *testing.T) {
	t.Helper()

	gw := fuzzModelsGateway(fuzzLister{entries: fuzzModelEntries()}, nil)
	w := httptest.NewRecorder()
	gw.getModel(w, fuzzModelsGetRequest("beta"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"beta"`) {
		t.Fatalf("MC-15 openai: %d %s", w.Code, w.Body.String())
	}
	r := fuzzModelsGetRequest("beta")
	r.Header.Set("anthropic-version", "v1")
	w = httptest.NewRecorder()
	gw.getModel(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"display_name":"Beta"`) {
		t.Fatalf("MC-15 anthropic: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	gw.getModel(w, fuzzModelsGetRequest("nope"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("MC-15: missing id %d", w.Code)
	}
}

func fuzzMC16(t *testing.T) {
	t.Helper()

	mk := func(q string) *http.Request {
		return httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models?"+q, nil)
	}
	if modelsLimit(mk("limit=")) != 1000 || modelsLimit(mk("limit=abc")) != 1000 ||
		modelsLimit(mk("limit=0")) != 1000 || modelsLimit(mk("limit=1001")) != 1000 ||
		modelsLimit(mk("limit=5")) != 5 {
		t.Fatal("MC-16: limit parsing wrong")
	}
}

func fuzzMC17(t *testing.T) {
	t.Helper()

	r := httptest.NewRequestWithContext(context.Background(), "GET", "/v1/models", nil)
	if anthropicModels(r) {
		t.Fatal("MC-17: no header must be openai shape")
	}
	r.Header.Set("anthropic-version", "v1")
	if !anthropicModels(r) {
		t.Fatal("MC-17: header must select anthropic shape")
	}
}

func fuzzMC18(t *testing.T) {
	t.Helper()

	if ownedBy("") != "yabanin" || ownedBy("x") != "x" {
		t.Fatal("MC-18: ownedBy wrong")
	}
}

func fuzzMC19(t *testing.T) {
	t.Helper()

	ts := time.Unix(1700000000, 0)
	m := openAIModel(modelEntry{ID: "m1", Provider: "", CreatedAt: ts})
	if m.ID != "m1" || m.Object != "model" || m.Created != ts.Unix() || m.OwnedBy != "yabanin" {
		t.Fatalf("MC-19: %+v", m)
	}
}

func fuzzMC20(t *testing.T) {
	t.Helper()

	w := httptest.NewRecorder()
	writeOpenAIModelList(w, nil)
	if !strings.Contains(w.Body.String(), `"data":[]`) {
		t.Fatalf("MC-20: empty: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	writeOpenAIModelList(w, fuzzModelEntries()[:1])
	if !strings.Contains(w.Body.String(), `"alpha"`) {
		t.Fatalf("MC-20: non-empty: %s", w.Body.String())
	}
}

func fuzzMC21(t *testing.T) {
	t.Helper()

	m := anthropicModel(modelEntry{ID: "m1", DisplayName: "M", CreatedAt: time.Unix(1700000000, 0)})
	if m.Type != "model" || m.CreatedAt != "2023-11-14T22:13:20Z" {
		t.Fatalf("MC-21: %+v", m)
	}
}

func fuzzMC22(t *testing.T) {
	t.Helper()

	w := httptest.NewRecorder()
	writeAnthropicModelList(w, nil, false)
	if strings.Contains(w.Body.String(), `"first_id":"a"`) || !strings.Contains(w.Body.String(), `"has_more":false`) {
		t.Fatalf("MC-22: empty: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	writeAnthropicModelList(w, fuzzModelEntries(), true)
	body := w.Body.String()
	if !strings.Contains(body, `"first_id":"alpha"`) || !strings.Contains(body, `"last_id":"gamma"`) ||
		!strings.Contains(body, `"has_more":true`) {
		t.Fatalf("MC-22: non-empty: %s", body)
	}
}

func fuzzMC23(t *testing.T) {
	t.Helper()

	w := httptest.NewRecorder()
	writeJSON(w, http.StatusTeapot, map[string]string{"k": "v"})
	if w.Code != http.StatusTeapot || w.Header().Get("Content-Type") != "application/json; charset=utf-8" ||
		!strings.Contains(w.Body.String(), `"k":"v"`) {
		t.Fatalf("MC-23: %d %s %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}

func fuzzMC24(t *testing.T) {
	t.Helper()

	pool, err := pgxpool.New(context.Background(), "postgres://test:test@127.0.0.1:1/test")
	if err != nil {
		t.Fatalf("MC-24: lazy pool: %v", err)
	}
	t.Cleanup(pool.Close)
	p := newPGModelLister(pool)
	if _, err := p.ListEnabledModels(context.Background()); err == nil {
		t.Fatal("MC-24: dead pool query must error")
	}
}

func errFuzz() error { return errors.New("fuzz failure") }

// mc25SeedStand inserts one enabled model, one disabled model and one
// alias→enabled row on the live stand (removed by testdb teardown).
func mc25SeedStand(t *testing.T, pool *pgxpool.Pool, on, off, alias string) {
	t.Helper()
	ctx := t.Context()
	_, err := pool.Exec(ctx, `INSERT INTO models_registry (model_name, display_name, enabled)
		VALUES ($1, 'Fuzz On', true), ($2, 'Fuzz Off', false)`, on, off)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO model_aliases (alias, target_model) VALUES ($1, $2)`, alias, on); err != nil {
		t.Fatal(err)
	}
}

// mc25AssertList runs the endpoint twice (second pass = lister TTL cache
// hit) and requires enabled model and alias visible, disabled hidden.
func mc25AssertList(t *testing.T, gw *gateway, on, off, alias string) {
	t.Helper()
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		gw.listModels(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/models", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("MC-25 pass %d: %d %s", i+1, w.Code, w.Body.String())
		}
		body := w.Body.String()
		for _, want := range []string{on, alias} {
			if !strings.Contains(body, want) {
				t.Fatalf("MC-25 pass %d: %s missing: %s", i+1, want, body)
			}
		}
		if strings.Contains(body, off) {
			t.Fatalf("MC-25 pass %d: disabled model must be hidden: %s", i+1, body)
		}
	}
}

func fuzzMC25(t *testing.T) {
	t.Helper()
	pool := catalogFixture(t)
	const on, off, alias = "fz-on", "fz-off", "fz-alias"
	mc25SeedStand(t, pool, on, off, alias)
	gw := fuzzModelsGateway(newPGModelLister(pool), nil)
	mc25AssertList(t, gw, on, off, alias)
	// The alias resolves through getModel: advertised under its own id,
	// carrying the target model's provider (openai-compat).
	w := httptest.NewRecorder()
	gw.getModel(w, fuzzModelsGetRequest(alias))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"`+alias+`"`) ||
		!strings.Contains(w.Body.String(), `"openai-compat"`) {
		t.Fatalf("MC-25 alias get: %d %s", w.Code, w.Body.String())
	}
}

// mc26RelaxCreatedNull allows NULL created_at on both fixture tables for the scan-error cases.
func mc26RelaxCreatedNull(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, stmt := range []string{
		"ALTER TABLE models_registry ALTER COLUMN created_at DROP NOT NULL",
		"ALTER TABLE model_aliases ALTER COLUMN created_at DROP NOT NULL",
	} {
		if _, err := pool.Exec(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
	}
}

// mc26AliasFault injects a NULL-created_at alias row against a healthy
// registry: the registry scan succeeds and the failure surfaces from the
// alias scan — directly in queryModelAliases and through
// queryEnabledModels' aliases arm.
func mc26AliasFault(t *testing.T, pool *pgxpool.Pool, alias, healthy string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO model_aliases (alias, target_model, created_at) VALUES ($1, $2, NULL)`,
		alias, healthy); err != nil {
		t.Fatalf("MC-26: null alias insert: %v", err)
	}
	if _, err := queryModelAliases(ctx, pool, nil); err == nil {
		t.Fatal("MC-26: NULL alias created_at must fail the alias Scan")
	}
	gw := fuzzModelsGateway(newPGModelLister(pool), nil)
	w := httptest.NewRecorder()
	gw.listModels(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/models", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "models_unavailable") {
		t.Fatalf("MC-26: %d %s", w.Code, w.Body.String())
	}
}

// mc26RegistryFault injects the NULL row into the registry itself: the
// failure now comes from queryEnabledModels' own Scan.
func mc26RegistryFault(t *testing.T, pool *pgxpool.Pool, on string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO models_registry (model_name, display_name, tier, provider, created_at, enabled)
		 VALUES ($1, 'Fuzz Null', 'smart', 'openai-compat', NULL, true)`, on); err != nil {
		t.Fatalf("MC-26: null registry insert: %v", err)
	}
	if _, err := queryEnabledModels(ctx, pool); err == nil {
		t.Fatal("MC-26: NULL registry created_at must fail the registry Scan")
	}
}

func fuzzMC26(t *testing.T) {
	t.Helper()
	pool := catalogFixture(t)
	const on, alias, healthy = "fz-null", "fz-null-alias", "fz-healthy"

	// (a) canceled context: the real pool errors before dialing/executing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := queryModelAliases(ctx, pool, nil); err == nil {
		t.Fatal("MC-26: canceled context must fail the alias query")
	}

	// (b) NULL-timestamp rows behind relaxed NOT NULL: pgx cannot scan NULL
	// into the non-pointer time.Time dest — the genuine Scan error path.
	mc26RelaxCreatedNull(t, pool)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO models_registry (model_name, display_name, tier, provider, enabled)
		 VALUES ($1, 'Fuzz Healthy', 'smart', 'openai-compat', true)`, healthy); err != nil {
		t.Fatalf("MC-26: healthy insert: %v", err)
	}
	mc26AliasFault(t, pool, alias, healthy)
	mc26RegistryFault(t, pool, on)
}
