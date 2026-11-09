package cli

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
)

// AF-03 handler-level regressions: a cold alias book and an alias-table
// outage must surface as the terminal model_registry_unavailable outcome —
// or serve the alias target once the shared load lands — through the real
// gateway handlers (JSON and SSE). They must never degrade into the RM-09
// fallback substitution, i.e. a successful call on the default model.

// af03Upstream is a mock provider that records every called model and
// answers JSON chat completions, or an SSE stream when the request asked
// for one.
func af03Upstream(t *testing.T) (*httptest.Server, *atomic.Int32, func() []string) {
	t.Helper()
	var (
		mu     sync.Mutex
		models []string
		calls  atomic.Int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		models = append(models, body.Model)
		mu.Unlock()
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
				"data: [DONE]\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), models...)
	}
}

// af03AliasDB implements resolver.aliasQuerier (via QueryAliases) with a
// park-until-released gate, a failure switch, and a parked counter. Every park
// also signals parkSignal (non-blocking; the parked counter stays the source
// of truth), so tests synchronize on the event instead of polling.
type af03AliasDB struct {
	mu         sync.Mutex
	gate       chan struct{}
	err        error
	pairs      [][2]string
	parked     atomic.Int64
	parkSignal chan struct{}
}

func (d *af03AliasDB) Query(ctx context.Context, _ string, _ ...any) (pgx.Rows, error) {
	d.mu.Lock()
	gate, err := d.gate, d.err
	d.mu.Unlock()
	if gate != nil {
		d.parked.Add(1)
		select {
		case d.parkSignal <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return &af03AliasRows{pairs: d.pairs}, nil
}

func (d *af03AliasDB) setGate(ch chan struct{}) {
	d.mu.Lock()
	d.gate = ch
	d.mu.Unlock()
}

func (d *af03AliasDB) setErr(err error) {
	d.mu.Lock()
	d.err = err
	d.mu.Unlock()
}

type af03AliasRows struct {
	pairs [][2]string
	i     int
}

func (r *af03AliasRows) Next() bool { return r.i < len(r.pairs) }
func (r *af03AliasRows) Err() error { return nil }
func (r *af03AliasRows) Close()     {}
func (r *af03AliasRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("")
}
func (r *af03AliasRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *af03AliasRows) Conn() *pgx.Conn                              { return nil }
func (r *af03AliasRows) RawValues() [][]byte                          { return nil }
func (r *af03AliasRows) Values() ([]any, error)                       { return nil, nil }
func (r *af03AliasRows) Scan(dest ...any) error {
	if r.i >= len(r.pairs) {
		return pgx.ErrNoRows
	}
	pair := r.pairs[r.i]
	r.i++
	*(dest[0].(*string)) = pair[0]
	*(dest[1].(*string)) = pair[1]
	return nil
}

// af03WireColdAlias wires a real resolver whose alias book is cold: the
// shared first load is parked on gate until the test releases it.
func af03WireColdAlias(t *testing.T, gw *gateway, db *rt06ModelDB, aliasDB *af03AliasDB, gate chan struct{}, ttl time.Duration) {
	t.Helper()
	res := resolver.NewResolver(db, "default-model", time.Minute, slog.New(slog.DiscardHandler))
	aliasDB.setGate(gate)
	aliasDB.pairs = [][2]string{{"client-alias", "alias-target"}}
	res.UseAliases(resolver.NewAliasBook(ttl, func(ctx context.Context) (map[string]string, error) {
		return resolver.QueryAliases(ctx, aliasDB)
	}, slog.New(slog.DiscardHandler)))
	gw.res = res
}

// af03StreamChat posts a streaming chat completion to the handler.
func af03StreamChat(t *testing.T, gw *gateway, model string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"` + model + `","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	r.Header.Set("X-Session-Id", "sess-1")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

func TestAF03_Chat_ConcurrentColdAlias_NeverSuccessfulDefault(t *testing.T) {
	srv, calls, calledModels := af03Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{rows: map[string][]any{
		"alias-target":  rt06RegistryRow("alias-target", "openai", "EU", srv.URL),
		"default-model": rt06RegistryRow("default-model", "openai", "EU", srv.URL),
	}}

	gate := make(chan struct{})
	aliasDB := &af03AliasDB{parkSignal: make(chan struct{}, 1)}
	af03WireColdAlias(t, gw, db, aliasDB, gate, time.Minute)

	const requests = 8
	results := make(chan *httptest.ResponseRecorder, requests)
	for i := 0; i < requests; i++ {
		go func() {
			results <- rt06Chat(t, gw, "client-alias")
		}()
	}

	// Determinism: the shared alias load signals when it is parked inside the
	// DB call, so every request below is cold while it lands.
	select {
	case <-aliasDB.parkSignal:
	case <-time.After(2 * time.Second):
		t.Fatal("the shared alias load must be parked in flight")
	}
	close(gate)

	for i := 0; i < requests; i++ {
		rec := <-results
		switch rec.Code {
		case http.StatusOK, http.StatusServiceUnavailable:
			// alias target served, or explicit unavailable — both allowed.
		default:
			t.Fatalf("cold concurrent alias request got status %d: %s", rec.Code, rec.Body.String())
		}
		if rec.Code == http.StatusServiceUnavailable {
			assert.Contains(t, rec.Body.String(), "model_registry_unavailable")
		}
	}
	// The defect this card closes: a cold alias book that silently routes to
	// the default model. Every upstream call on a 200 must be the alias
	// target; a successful default-model call is a failure even if some
	// requests were (legitimately) denied as unavailable.
	require.Positive(t, calls.Load(), "the alias target must have been called")
	for _, m := range calledModels() {
		assert.Equal(t, "alias-target", m, "a cold alias book must never produce a default-model call")
	}
}

// af03ProbeUntilOK deadline-polls the probe until it serves 200: the alias
// book reloads after its real 30ms backoff window — an internal timer the
// test can only observe by probing. The 5ms step is the poll interval, not a
// fixed wait.
func af03ProbeUntilOK(t *testing.T, probe func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec := probe()
		if rec.Code == http.StatusOK {
			return rec
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("alias book did not recover within the deadline: status %d: %s", rec.Code, rec.Body.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAF03_Chat_AliasOutage_UnavailableNotFallback_Recovery(t *testing.T) {
	srv, calls, calledModels := af03Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{rows: map[string][]any{
		"alias-target":  rt06RegistryRow("alias-target", "openai", "EU", srv.URL),
		"default-model": rt06RegistryRow("default-model", "openai", "EU", srv.URL),
	}}

	aliasDB := &af03AliasDB{pairs: [][2]string{{"client-alias", "alias-target"}}}
	aliasDB.setErr(errors.New("alias database unavailable"))
	res := resolver.NewResolver(db, "default-model", time.Minute, slog.New(slog.DiscardHandler))
	res.UseAliases(resolver.NewAliasBook(30*time.Millisecond, func(ctx context.Context) (map[string]string, error) {
		return resolver.QueryAliases(ctx, aliasDB)
	}, slog.New(slog.DiscardHandler)))
	gw.res = res

	rec := rt06Chat(t, gw, "client-alias")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "an alias outage is explicit unavailable, not a fallback")
	assert.Contains(t, rec.Body.String(), "model_registry_unavailable")
	assert.Zero(t, calls.Load(), "an alias outage must never reach the provider")

	// Recovery: after the backoff window the book loads and serves the alias.
	aliasDB.setErr(nil)
	rec = af03ProbeUntilOK(t, func() *httptest.ResponseRecorder { return rt06Chat(t, gw, "client-alias") })
	assert.Equal(t, http.StatusOK, rec.Code, "recovery must serve the alias after the backoff window: %s", rec.Body.String())
	for _, m := range calledModels() {
		assert.Equal(t, "alias-target", m, "even during recovery probes, only the alias target may be called")
	}
}

func TestAF03_ChatStream_ConcurrentColdAlias_ServesTargetStream(t *testing.T) {
	srv, calls, calledModels := af03Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{rows: map[string][]any{
		"alias-target":  rt06RegistryRow("alias-target", "openai", "EU", srv.URL),
		"default-model": rt06RegistryRow("default-model", "openai", "EU", srv.URL),
	}}

	gate := make(chan struct{})
	aliasDB := &af03AliasDB{parkSignal: make(chan struct{}, 1)}
	af03WireColdAlias(t, gw, db, aliasDB, gate, time.Minute)

	const requests = 4
	results := make(chan *httptest.ResponseRecorder, requests)
	for i := 0; i < requests; i++ {
		go func() {
			results <- af03StreamChat(t, gw, "client-alias")
		}()
	}
	select {
	case <-aliasDB.parkSignal:
	case <-time.After(2 * time.Second):
		t.Fatal("the shared alias load must be parked in flight")
	}
	close(gate)

	streams := 0
	for i := 0; i < requests; i++ {
		rec := <-results
		switch rec.Code {
		case http.StatusOK:
			body := rec.Body.String()
			assert.Contains(t, body, "data: {\"id\":\"1\"", "the alias target stream must be forwarded")
			assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"), "stream must terminate: %q", body)
			streams++
		case http.StatusServiceUnavailable:
			assert.Contains(t, rec.Body.String(), "model_registry_unavailable")
		default:
			t.Fatalf("cold concurrent stream request got status %d: %s", rec.Code, rec.Body.String())
		}
	}
	require.Positive(t, streams, "cold streaming requests must be served once the shared load lands")
	require.Positive(t, calls.Load())
	for _, m := range calledModels() {
		assert.Equal(t, "alias-target", m, "a cold alias book must never produce a default-model stream call")
	}
}

func TestAF03_ChatStream_AliasOutage_TerminalUnavailable_Recovery(t *testing.T) {
	srv, calls, calledModels := af03Upstream(t)
	gw := streamTestGateway(srv.URL)
	gw.log = slog.New(slog.DiscardHandler)
	db := &rt06ModelDB{rows: map[string][]any{
		"alias-target":  rt06RegistryRow("alias-target", "openai", "EU", srv.URL),
		"default-model": rt06RegistryRow("default-model", "openai", "EU", srv.URL),
	}}

	aliasDB := &af03AliasDB{pairs: [][2]string{{"client-alias", "alias-target"}}}
	aliasDB.setErr(errors.New("alias database unavailable"))
	res := resolver.NewResolver(db, "default-model", time.Minute, slog.New(slog.DiscardHandler))
	res.UseAliases(resolver.NewAliasBook(30*time.Millisecond, func(ctx context.Context) (map[string]string, error) {
		return resolver.QueryAliases(ctx, aliasDB)
	}, slog.New(slog.DiscardHandler)))
	gw.res = res

	rec := af03StreamChat(t, gw, "client-alias")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "an alias outage is terminal for streaming requests too")
	assert.Contains(t, rec.Body.String(), "model_registry_unavailable")
	assert.Zero(t, calls.Load(), "no provider call during the alias outage")

	aliasDB.setErr(nil)
	rec = af03ProbeUntilOK(t, func() *httptest.ResponseRecorder { return af03StreamChat(t, gw, "client-alias") })
	assert.Equal(t, http.StatusOK, rec.Code, "recovery must serve the stream after the backoff window: %s", rec.Body.String())
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
	for _, m := range calledModels() {
		assert.Equal(t, "alias-target", m)
	}
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *af03AliasRows) TypeMap() *pgtype.Map { return nil }
