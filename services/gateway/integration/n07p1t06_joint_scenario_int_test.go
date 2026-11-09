//go:build integration

package integration

// N07-P01-T06 — joint user scenario, REAL leg (build tag `integration`).
//
// Card acceptance: «Совместный пользовательский сценарий пакета выполнен на
// согласованной среде; реальные и mock проверки явно различены» — this file
// is the explicitly-REAL half: the FULL production server factory
// (cli.RunGatewayServer — the same binary path production boots) on a real
// Postgres and Redis stand (testcontainers, disposable), with real header
// auth against the seeded key, real budget escrow (fail-closed wallet +
// team budget rows), real routing and the real async event ledger read back
// from the Redis stream. The boundary drawn against the MOCK legs: the
// upstream LLM is a hermetic recorder (httptest) and model resolution falls
// through to the config's default provider — everything between the client
// socket and the upstream socket is production code.
//
// The scenario walks one client session through the packet's facets on the
// OpenAI-compatible passthrough surface (the dominant production path):
//   - the auth boundary: no key and a wrong key are refused before any
//     upstream dial (real Redis/DB key check);
//   - facet 3 (T04) + facet 2 (T03) + effort (T05): extensions,
//     reasoning_effort and the structured/tool fields reach the upstream
//     verbatim; provider extensions, the refusal field and tool calls come
//     back byte-for-byte;
//   - facet 1 (T02) + the RM-03 usage asymmetry: with
//     stream_options.include_usage the usage-only chunk (with its response
//     extension) passes byte-faithfully; without it the chunk is suppressed
//     while the ledger still records the usage;
//   - the real ledger: exactly one request.completed per successful turn
//     with the usage from every turn (including the suppressed-chunk one),
//     and nothing for the refused auth attempts.
//
// The translated-route refusals (reasoning_effort / response_format
// render-class, exact-reason 400) are the MOCK legs' specialty — their
// resolver seam is stubbed there by design; the real resolver defaults to
// the passthrough provider, so those surfaces are not re-proven here.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/config"
	cli "github.com/reireirei/yabanin/pkg/gateway"
)

const n07t06EventStream = "n07p1t06-events"

// n07t06Upstream is the hermetic upstream recorder: it captures every
// request body verbatim and answers non-stream turns with the canonical
// completion (refusal + tool call + provider extensions) and stream turns
// with the canonical OpenAI SSE fixture (usage chunk + response extension +
// one [DONE]).
func n07t06Upstream(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()

		var probe struct {
			Stream bool `json:"stream"`
		}
		_ = json.Unmarshal(b, &probe)
		if probe.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-t06\",\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Привет\"}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-t06\",\"model\":\"gpt-4\",\"choices\":[],\"usage\":{\"prompt_tokens\":6,\"completion_tokens\":2,\"total_tokens\":8},\"x_provider_ext\":{\"latency_ms\":42}}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-t06","object":"chat.completion","model":"gpt-4","provider_ext":{"trace":"t06"},"choices":[{"index":0,"message":{"role":"assistant","content":"","refusal":"Я не могу помочь с этим.","tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Москва\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10},"x_provider_usage":{"cached":true}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(bodies))
		copy(out, bodies)
		return out
	}
}

// n07t06RealServer boots the production gateway factory against the real
// datastore stand with the hermetic upstream as the configured provider and
// an isolated event stream. Modeled on gatewayTestServer, which keeps its
// dummy upstream and shared stream name.
func n07t06RealServer(t *testing.T, ctx context.Context, rdb *redis.Client, pool *pgxpool.Pool, upstreamURL string) (string, func()) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))

	port := findFreePort(t)
	cfg := config.Gateway{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		AuthMode:    "header",
		PGURI:       gatewayPGURI(),
		Provider:    upstreamURL,
		FallbackKey: "test-api-key",
		EventStream: n07t06EventStream,
	}

	serverCtx, serverCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cli.RunGatewayServer(cfg, rdb, pool, integrationTestKMS{}, logger, serverCtx)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForGatewayReady(t, baseURL)

	return baseURL, func() {
		serverCancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}
}

// n07t06CompletedEvents waits for the ledger to settle (event publishing is
// async) and returns the request.completed entries.
func n07t06CompletedEvents(t *testing.T, rdb *redis.Client) []map[string]string {
	t.Helper()
	_, ok := waitForStreamEntry(t, rdb, n07t06EventStream, func(e map[string]string) bool {
		return e["event_type"] == "request.completed"
	})
	if !ok {
		t.Fatalf("no request.completed event landed in stream %s", n07t06EventStream)
	}
	entries := getRedisStreamEntries(t, rdb, n07t06EventStream)
	var completed []map[string]string
	for _, e := range entries {
		if e["event_type"] == "request.completed" {
			completed = append(completed, e)
		}
	}
	return completed
}

// TestN07P1T06RealDB_JointScenario walks one client session through the
// production gateway on the real stand (see the file comment for the
// REAL/MOCK boundary).
func TestN07P1T06RealDB_JointScenario(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	SeedGatewayOrg(ctx, t, pool)
	seedAPIKey(rdb, pool, "test-api-key", testGatewayOrgID)

	upstream, sentBodies := n07t06Upstream(t)
	baseURL, cleanup := n07t06RealServer(t, ctx, rdb, pool, upstream.URL)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}
	auth := map[string]string{"Authorization": "Bearer test-api-key"}

	// Auth boundary — no key and a wrong key are refused before any upstream
	// dial (real Redis/DB key check), and stay ledger-silent.
	fidelityBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Погода в Москве?","x_client_part":{"locale":"ru"}}],"reasoning_effort":"high","tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],"tool_choice":"auto","response_format":{"type":"text"},"x_client_ext":{"trace":"t06"}}`
	status, _, _ := roundTrip(t, client, baseURL, "/v1/chat/completions", nil, json.RawMessage(fidelityBody))
	require.Equal(t, http.StatusUnauthorized, status, "no key must be refused")
	status, _, _ = roundTrip(t, client, baseURL, "/v1/chat/completions", map[string]string{"Authorization": "Bearer wrong-key"}, json.RawMessage(fidelityBody))
	require.Equal(t, http.StatusUnauthorized, status, "a wrong key must be refused")
	require.Empty(t, sentBodies(), "refused auth must never reach the upstream")

	// Turn 1 (non-stream): extensions + effort + structured fields forward
	// verbatim; provider extensions + refusal + tool calls come back
	// byte-for-byte on the real server path.
	status, _, body := roundTrip(t, client, baseURL, "/v1/chat/completions", auth, json.RawMessage(fidelityBody))
	require.Equal(t, http.StatusOK, status, string(body))
	require.Len(t, sentBodies(), 1, "exactly one upstream dial")
	sent := sentBodies()[0]
	for _, key := range []string{"reasoning_effort", "tools", "tool_choice", "response_format", "x_client_ext"} {
		if !strings.Contains(sent, key) {
			t.Errorf("upstream body missing %q: %s", key, sent)
		}
	}
	for _, want := range []string{`"refusal":"Я не могу помочь с этим."`, `"tool_calls"`, `"get_weather"`, `"provider_ext":{"trace":"t06"}`, `"x_provider_usage":{"cached":true}`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("client body missing %q: %s", want, string(body))
		}
	}

	// Turn 2 (stream, no include_usage): the usage-only chunk is suppressed
	// from the client bytes (RM-03), the stream still terminates with one
	// [DONE].
	noUsage := `{"model":"gpt-4","messages":[{"role":"user","content":"Привет"}],"stream":true}`
	status, headers, body := roundTrip(t, client, baseURL, "/v1/chat/completions", auth, json.RawMessage(noUsage))
	require.Equal(t, http.StatusOK, status, string(body))
	if !strings.Contains(headers["Content-Type"], "text/event-stream") {
		t.Errorf("content type = %q, want text/event-stream", headers["Content-Type"])
	}
	sse := string(body)
	if !strings.Contains(strings.TrimSpace(sse), "data: [DONE]") {
		t.Errorf("stream must terminate with [DONE]: %q", sse)
	}
	if strings.Contains(sse, `"prompt_tokens":6`) {
		t.Errorf("RM-03: usage-only chunk must be withheld without include_usage: %q", sse)
	}

	// Turn 3 (stream, include_usage): the usage chunk passes byte-faithfully
	// with the response extension riding it.
	wantsUsage := `{"model":"gpt-4","messages":[{"role":"user","content":"Привет"}],"stream":true,"stream_options":{"include_usage":true}}`
	status, _, body = roundTrip(t, client, baseURL, "/v1/chat/completions", auth, json.RawMessage(wantsUsage))
	require.Equal(t, http.StatusOK, status, string(body))
	sse = string(body)
	for _, want := range []string{`"usage":{"prompt_tokens":6,"completion_tokens":2,"total_tokens":8}`, `"x_provider_ext":{"latency_ms":42}`, "data: [DONE]"} {
		if !strings.Contains(sse, want) {
			t.Errorf("client stream missing %q: %s", want, sse)
		}
	}

	// Ledger (real Redis stream): exactly one request.completed per
	// successful turn, nothing for the refused auth attempts, and usage from
	// every turn — including the suppressed-chunk one (7+6+6 in, 3+2+2 out).
	completed := n07t06CompletedEvents(t, rdb)
	if len(completed) != 3 {
		t.Fatalf("request.completed events = %d, want exactly 3", len(completed))
	}
	var tokensIn, tokensOut int64
	for _, e := range completed {
		if e["status_code"] != "200" {
			t.Errorf("completed event status = %q, want 200", e["status_code"])
		}
		if e["endpoint"] != "chat.completions" {
			t.Errorf("completed event endpoint = %q, want chat.completions", e["endpoint"])
		}
		if e["model_requested"] != "gpt-4" {
			t.Errorf("completed event model_requested = %q, want gpt-4", e["model_requested"])
		}
		var tin, tout int64
		if _, err := fmt.Sscanf(e["tokens_in"], "%d", &tin); err != nil {
			t.Fatalf("tokens_in %q: %v", e["tokens_in"], err)
		}
		if _, err := fmt.Sscanf(e["tokens_out"], "%d", &tout); err != nil {
			t.Fatalf("tokens_out %q: %v", e["tokens_out"], err)
		}
		tokensIn += tin
		tokensOut += tout
	}
	if tokensIn != 19 {
		t.Errorf("ledger tokens_in = %d, want 19 (usage from all three turns, incl. the suppressed chunk)", tokensIn)
	}
	if tokensOut != 7 {
		t.Errorf("ledger tokens_out = %d, want 7", tokensOut)
	}
}
