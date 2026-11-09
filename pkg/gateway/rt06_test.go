package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/reireirei/yabanin/pkg/rulestore"
)

// RT-06 handler-level regressions: request context and error classification
// across the model/alias/affinity/rule lookup boundaries, exercised through
// the real production handlers with a mock provider.

// rt06ModelDB implements resolver's pgxpool for RT-06 handler tests: per-name
// registry rows (same 10-column order as the models_registry SELECT), a
// global failure switch plus per-name hard failures, and an optional gate
// that parks every query until released (the controllable slow loader).
// parkedCh, when set, is signalled (non-blocking) the moment a query reaches
// the gate, so tests synchronize on the park instead of polling or guessing.
type rt06ModelDB struct {
	mu       sync.Mutex
	rows     map[string][]any
	errNames map[string]error
	err      error
	gate     chan struct{}
	parkedCh chan struct{}
}

func (d *rt06ModelDB) QueryRow(ctx context.Context, _ string, args ...interface{}) pgx.Row {
	if ch := d.currentGate(); ch != nil {
		select {
		case d.parkedCh <- struct{}{}:
		default:
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return rt06ErrRow{err: ctx.Err()}
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	name, _ := args[0].(string)
	if err, ok := d.errNames[name]; ok {
		return rt06ErrRow{err: err}
	}
	if d.err != nil {
		return rt06ErrRow{err: d.err}
	}
	row, ok := d.rows[name]
	if !ok {
		return rt06ErrRow{err: pgx.ErrNoRows}
	}
	return rt06ValRow{vals: row}
}

func (d *rt06ModelDB) currentGate() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gate
}

func (d *rt06ModelDB) setErr(err error) {
	d.mu.Lock()
	d.err = err
	d.mu.Unlock()
}

func (d *rt06ModelDB) setGate(ch chan struct{}) {
	d.mu.Lock()
	d.gate = ch
	d.mu.Unlock()
}

func (d *rt06ModelDB) Close() {}

func rt06RegistryRow(name, provider, region, url string) []any {
	return []any{name, name + " display", "standard", url, "", provider, nil, true, int64(0), region}
}

type rt06ErrRow struct{ err error }

func (r rt06ErrRow) Scan(...interface{}) error { return r.err }

type rt06ValRow struct{ vals []any }

func (r rt06ValRow) Scan(dest ...interface{}) error {
	for i, d := range dest {
		if i >= len(r.vals) {
			return fmt.Errorf("not enough values at %d", i)
		}
		if r.vals[i] == nil {
			continue
		}
		switch dp := d.(type) {
		case *string:
			v, ok := r.vals[i].(string)
			if !ok {
				return fmt.Errorf("want string at %d", i)
			}
			*dp = v
		case *[]string:
			v, ok := r.vals[i].([]string)
			if !ok {
				return fmt.Errorf("want []string at %d", i)
			}
			*dp = v
		case *bool:
			v, ok := r.vals[i].(bool)
			if !ok {
				return fmt.Errorf("want bool at %d", i)
			}
			*dp = v
		case *int64:
			v, ok := r.vals[i].(int64)
			if !ok {
				return fmt.Errorf("want int64 at %d", i)
			}
			*dp = v
		default:
			return fmt.Errorf("unsupported dest %T", d)
		}
	}
	return nil
}

func rt06Upstream(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Pointer[string]) {
	t.Helper()
	var calls atomic.Int32
	var lastModel atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			Model string `json:"model"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		lastModel.Store(&body.Model)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &lastModel
}

// rt06Chat posts a chat completion to the handler with org headers.
func rt06Chat(t *testing.T, gw *gateway, model string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	r.Header.Set("X-Session-Id", "sess-1")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

func TestRT06_Chat_RegistryOutage_Terminal503_NoUpstreamCall(t *testing.T) {
	srv, calls, _ := rt06Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{rows: map[string][]any{
		"m1": rt06RegistryRow("m1", "openai", "GLOBAL", srv.URL),
	}}
	db.setErr(errors.New("db connection refused"))
	gw.res = resolver.NewResolver(db, "fb", time.Minute, slog.New(slog.DiscardHandler))

	rec := rt06Chat(t, gw, "m1")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "outage is explicit unavailable, not a fallback")
	assert.Contains(t, rec.Body.String(), "model_registry_unavailable")
	assert.Zero(t, calls.Load(), "a registry outage must never reach the provider")
}

func TestRT06_Chat_OutageNotCachedAsFallback_RecoveryServes(t *testing.T) {
	srv, calls, lastModel := rt06Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{rows: map[string][]any{
		"m1": rt06RegistryRow("m1", "openai", "GLOBAL", srv.URL),
	}}
	db.setErr(errors.New("db down"))
	gw.res = resolver.NewResolver(db, "fb", 5*time.Minute, slog.New(slog.DiscardHandler))

	rec := rt06Chat(t, gw, "m1")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	// Registry recovers: the SAME request must now be served — the outage
	// was not cached as "found fallback model" for the TTL.
	db.setErr(nil)
	rec = rt06Chat(t, gw, "m1")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.EqualValues(t, 1, calls.Load())
	assert.Equal(t, "m1", *lastModel.Load(), "the real model is called, not a fallback substitute")
}

func TestRT06_Chat_CancelDuringModelResolution_NoUpstreamCall(t *testing.T) {
	srv, calls, _ := rt06Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{
		rows: map[string][]any{
			"m1": rt06RegistryRow("m1", "openai", "GLOBAL", srv.URL),
		},
		parkedCh: make(chan struct{}, 1),
	}
	gate := make(chan struct{})
	db.setGate(gate)
	gw.res = resolver.NewResolver(db, "fb", time.Minute, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	body := `{"model":"m1","messages":[{"role":"user","content":"hi"}]}`
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		gw.chatCompletions(rec, r)
		done <- rec
	}()

	// The loader signals when the query is parked inside the controlled slow
	// loader; only then is it safe to cancel: the loader must observe the
	// cancellation.
	select {
	case <-db.parkedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("the model resolution never reached the parked registry load")
	}
	cancel()
	close(gate)

	select {
	case rec = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return after request cancellation")
	}
	assert.NotEqual(t, http.StatusOK, rec.Code, "a cancelled request must not be served")
	assert.Zero(t, calls.Load(), "after cancel there must be no provider call, retry or fallback")
}

func TestRT06_Chat_SlowRulesLoader_SeesCancel_NoProviderCall(t *testing.T) {
	srv, calls, _ := rt06Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{rows: map[string][]any{
		"m1": rt06RegistryRow("m1", "openai", "GLOBAL", srv.URL),
	}}
	gw.res = resolver.NewResolver(db, "fb", time.Minute, slog.New(slog.DiscardHandler))

	// Controlled slow rules loader: parks until released or ctx done. The
	// loader signals the park, so the test synchronizes on the event.
	ruleGate := make(chan struct{})
	ruleDB := &rt06StallRuleDB{gate: ruleGate, parked: make(chan struct{}, 1)}
	gw.ruleStore = rulestore.New(ruleDB, nil, 0, nil, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	body := `{"model":"m1","messages":[{"role":"user","content":"hi"}]}`
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		gw.chatCompletions(rec, r)
		done <- rec
	}()

	select {
	case <-ruleDB.parked:
	case <-time.After(2 * time.Second):
		t.Fatal("the rules loader must be parked inside the DB call")
	}
	cancel()
	close(ruleGate)

	select {
	case rec = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return after request cancellation")
	}
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.Zero(t, calls.Load(), "no provider call, retry or fallback after cancel")
}

// rt06StallRuleDB implements rulestore.dbConn with a park-until-released load.
// parked is signalled (non-blocking) when a query reaches the park.
type rt06StallRuleDB struct {
	gate   chan struct{}
	parked chan struct{}
}

func (d *rt06StallRuleDB) Query(ctx context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
	select {
	case d.parked <- struct{}{}:
	default:
	}
	select {
	case <-d.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &rt06EmptyRows{}, nil
}

// rt06EmptyRows implements pgx.Rows over zero rows.
type rt06EmptyRows struct{}

func (rt06EmptyRows) Next() bool                                   { return false }
func (rt06EmptyRows) Scan(...interface{}) error                    { return nil }
func (rt06EmptyRows) Err() error                                   { return nil }
func (rt06EmptyRows) Close()                                       {}
func (rt06EmptyRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (rt06EmptyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rt06EmptyRows) Conn() *pgx.Conn                              { return nil }
func (rt06EmptyRows) RawValues() [][]byte                          { return nil }
func (rt06EmptyRows) Values() ([]any, error)                       { return nil, nil }

// rt06StaticRuleDB serves a fixed rule set (no cache layer).
type rt06StaticRuleDB struct{ rules []evaluator.Rule }

func (d *rt06StaticRuleDB) Query(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
	rows := &rt06StaticRows{}
	for _, r := range d.rules {
		rows.data = append(rows.data, []interface{}{r.ID, r.OrgID, r.MatchExpr, r.TargetModel, r.Priority, r.Enabled})
	}
	return rows, nil
}

type rt06StaticRows struct {
	data [][]interface{}
	idx  int
}

func (r *rt06StaticRows) Next() bool { r.idx++; return r.idx <= len(r.data) }
func (r *rt06StaticRows) Scan(dest ...interface{}) error {
	if r.idx == 0 || r.idx > len(r.data) {
		return pgx.ErrNoRows
	}
	row := r.data[r.idx-1]
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			*p = row[i].(string)
		case *int:
			*p = row[i].(int)
		case *bool:
			*p = row[i].(bool)
		}
	}
	return nil
}
func (r *rt06StaticRows) Err() error                                   { return nil }
func (r *rt06StaticRows) Close()                                       {}
func (r *rt06StaticRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *rt06StaticRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *rt06StaticRows) Conn() *pgx.Conn                              { return nil }
func (r *rt06StaticRows) RawValues() [][]byte                          { return nil }
func (r *rt06StaticRows) Values() ([]any, error)                       { return nil, nil }

func TestRT06_Chat_AutoCandidate_ZAIGateSeesRegistryProvider(t *testing.T) {
	srv, calls, _ := rt06Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	gw.cfg.ZAICodingEnabled = false
	// The default ("auto") candidate is registered as a ZAI-coding model:
	// the shared gate must see its provider even though the client said only
	// "auto" (RT-06: consistent provider/region data for the gate).
	db := &rt06ModelDB{rows: map[string][]any{
		"zai-model": rt06RegistryRow("zai-model", "zai-coding", "GLOBAL", ""),
	}}
	gw.res = resolver.NewResolver(db, "zai-model", time.Minute, slog.New(slog.DiscardHandler))

	rec := rt06Chat(t, gw, "auto")
	assert.Equal(t, http.StatusForbidden, rec.Code, "the default candidate must pass the same policy gate")
	assert.Contains(t, rec.Body.String(), "provider_not_authorized")
	assert.Zero(t, calls.Load())
}

func TestRT06_Chat_RuleOverride_OutageOnTarget_Terminal503(t *testing.T) {
	srv, calls, _ := rt06Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	// m1 resolves; the rule-overridden target m2 hits a registry outage.
	db := &rt06ModelDB{
		rows: map[string][]any{
			"m1": rt06RegistryRow("m1", "openai", "GLOBAL", srv.URL),
		},
		errNames: map[string]error{"m2": errors.New("db down")},
	}
	gw.res = resolver.NewResolver(db, "fb", time.Minute, slog.New(slog.DiscardHandler))

	gw.ruleStore = rulestore.New(&rt06StaticRuleDB{rules: []evaluator.Rule{{
		ID: "r1", OrgID: "org-1", MatchExpr: "model_requested == 'm1'",
		TargetModel: "m2", Priority: 10, Enabled: true,
	}}}, nil, 0, nil, slog.New(slog.DiscardHandler))

	rec := rt06Chat(t, gw, "m1")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "an override-target resolution outage is terminal unavailable — the request must not silently continue on the old model")
	assert.Zero(t, calls.Load())
}

func TestRT06_Admission_RegistryOutage_Terminal503(t *testing.T) {
	gw := streamTestGateway("http://127.0.0.1:1")
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{rows: map[string][]any{}}
	db.setErr(errors.New("db down"))
	gw.res = resolver.NewResolver(db, "fb", time.Minute, slog.New(slog.DiscardHandler))

	body := `{"model":"m1","input":"hi"}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/embeddings", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	_, ok := gw.admit(rec, r, admitInput{Endpoint: "embeddings", Model: "m1", Body: []byte(body), NoRemap: true})
	assert.False(t, ok)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "model_registry_unavailable")
}

// rt06RemapEnforcer remaps every candidate to RemapTo.
type rt06RemapEnforcer struct{ RemapTo string }

func (e rt06RemapEnforcer) Enforce(context.Context, string, string, policy.Region, string) policy.Decision {
	return policy.Decision{Allowed: true, Region: policy.Region("GLOBAL"), RemappedModel: e.RemapTo}
}

func TestRT06_GateAttemptCandidate_RemappedResolutionOutage_TerminalUnavailable(t *testing.T) {
	gw := streamTestGateway("http://127.0.0.1:1")
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{
		rows: map[string][]any{
			"m1": rt06RegistryRow("m1", "openai", "GLOBAL", "http://x"),
		},
		errNames: map[string]error{"m2": errors.New("db down")},
	}
	gw.res = resolver.NewResolver(db, "fb", time.Minute, slog.New(slog.DiscardHandler))
	gw.residencyEnforcer = rt06RemapEnforcer{RemapTo: "m2"}

	mi, err := gw.res.ResolveChecked(context.Background(), "m1")
	require.NoError(t, err)

	_, pol := gw.gateAttemptCandidate(context.Background(), candidateIdentity{OrgID: "org-1"}, "m1", mi)
	require.NotNil(t, pol, "an outage resolving the remapped candidate is a policy-unavailable outcome")
	assert.Equal(t, http.StatusServiceUnavailable, pol.Status)
	assert.Equal(t, "model_registry_unavailable", pol.ErrType)
}

// rt06AffinityRedis is a Redis double whose calls fail like a dead context.
type rt06AffinityRedis struct{}

func (rt06AffinityRedis) Get(_ context.Context, _ string) *redis.StringCmd {
	return redis.NewStringResult("", context.Canceled)
}
func (rt06AffinityRedis) Set(context.Context, string, interface{}, time.Duration) *redis.StatusCmd {
	return redis.NewStatusResult("OK", errors.New("canceled"))
}
func (rt06AffinityRedis) PExpire(context.Context, string, time.Duration) *redis.BoolCmd {
	return redis.NewBoolResult(false, errors.New("canceled"))
}

func TestRT06_Affinity_CancelledContextDegradesToMiss(t *testing.T) {
	a := router.NewRedisSessionAffinity(rt06AffinityRedis{}, time.Minute, 1, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Empty(t, a.Preferred(ctx, "org-1", "sess-1"), "a cancelled affinity read degrades to a miss, never a block or a foreign model")
	a.Record(ctx, "org-1", "sess-1", "m1", 100) // must not panic / must not block
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *rt06StaticRows) TypeMap() *pgtype.Map { return nil }

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (rt06EmptyRows) TypeMap() *pgtype.Map { return nil }
