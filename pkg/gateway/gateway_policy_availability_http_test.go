package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/migrate"
	"github.com/reireirei/yabanin/pkg/upstream"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestPolicyAvailabilityColdFailureThroughHTTPRoutes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dsn := startPolicyAvailabilityPostgres(t, ctx)
	directPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated seed/auth pool: %v", err)
	}
	t.Cleanup(directPool.Close)
	seedStore := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)
	var upstreamCalls atomic.Int64
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		_, _ = io.WriteString(w, `{"id":"r00905","object":"chat.completion","model":"r00905-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	t.Cleanup(upstreamServer.Close)

	pgConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse isolated Postgres DSN: %v", err)
	}
	proxy := newPolicyAvailabilityProxy(t, net.JoinHostPort(pgConfig.ConnConfig.Host, strconv.Itoa(int(pgConfig.ConnConfig.Port))))
	policyPool := newPolicyAvailabilityPool(t, ctx, dsn, proxy.Addr())
	policyStore := adminstore.New(policyPool, slog.New(slog.DiscardHandler), nil)
	runtime, err := NewPolicyRuntime(policyStore, nil, PolicyModeEnforce, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("construct real policy runtime: %v", err)
	}

	cfg := config.Gateway{}
	cfg.AuthMode = "header"
	cfg.Provider = upstreamServer.URL
	cfg.FallbackModel = "r00905-model"
	cfg.UnknownModelPolicy = "reject"
	gw := &gateway{
		gatewayCore:   gatewayCore{cfg: cfg, log: slog.New(slog.DiscardHandler)},
		gatewayEgress: gatewayEgress{pool: upstream.NewPool(upstream.Options{BaseURL: upstreamServer.URL})},
		gatewayRouting: gatewayRouting{res: stubModelResolver{
			"r00905-model": {ModelName: "r00905-model", Provider: "openai", Enabled: true},
		}},
		gatewayCompliance: gatewayCompliance{policyRuntime: runtime},
	}
	gw.auth = NewAuthMiddleware(cfg, auth.NewResolver(directPool, nil, 300, nil))
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 15 * time.Second

	cases := []struct {
		name, path, body string
	}{
		{"chat", "/v1/chat/completions", `{"model":"r00905-model","messages":[{"role":"user","content":"hello"}]}`},
		{"legacy-completion", "/v1/completions", `{"model":"r00905-model","prompt":"hello"}`},
		{"messages", "/v1/messages", `{"model":"r00905-model","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`},
		{"responses", "/v1/responses", `{"model":"r00905-model","input":"hello"}`},
		{"chat-stream", "/v1/chat/completions", `{"model":"r00905-model","stream":true,"messages":[{"role":"user","content":"hello"}]}`},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			suffix := fmt.Sprintf("%d-%d", i, time.Now().UnixNano())
			org, err := seedStore.CreateOrganization(ctx, "R00905 synthetic", "r00905-"+suffix)
			if err != nil {
				t.Fatalf("create synthetic organization: %v", err)
			}
			team, err := seedStore.CreateTeam(ctx, org.ID, "R00905 team", "r00905-team-"+suffix, nil)
			if err != nil {
				t.Fatalf("create synthetic team: %v", err)
			}
			plainKey, err := auth.GeneratePersonalKey()
			if err != nil {
				t.Fatalf("generate synthetic API key: %v", err)
			}
			if _, err := seedStore.CreateAPIKey(ctx, auth.HashKey(plainKey), "R00905 synthetic", &org.ID, &team.ID); err != nil {
				t.Fatalf("create synthetic API key: %v", err)
			}
			seedPolicyAvailabilityPolicy(t, ctx, seedStore, org.ID)
			before := upstreamCalls.Load()
			proxy.SetUnavailable(true)
			resp := policyAvailabilityRequest(t, ctx, client, server.URL, tc.path, tc.body, plainKey)
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("cold policy-store failure status = %d, want 503; body=%s", resp.StatusCode, resp.Body)
			}
			var envelope struct {
				Error struct {
					Type    string `json:"type"`
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(resp.Body), &envelope); err != nil {
				t.Fatalf("decode cold failure envelope: %v; body=%s", err, resp.Body)
			}
			if tc.path == "/v1/messages" {
				if envelope.Error.Type != "overloaded_error" || !strings.HasPrefix(envelope.Error.Message, "[policy_temporarily_unavailable]") {
					t.Fatalf("Anthropic cold failure envelope = type %q message %q; want overloaded_error with stable policy code prefix", envelope.Error.Type, envelope.Error.Message)
				}
			} else if envelope.Error.Code != "policy_temporarily_unavailable" {
				t.Fatalf("cold failure envelope code = %q, want policy_temporarily_unavailable; body=%s", envelope.Error.Code, resp.Body)
			}
			if strings.Contains(resp.Body, "connection refused") || strings.Contains(resp.Body, "r00905") {
				t.Fatalf("policy-store detail leaked in response: %s", resp.Body)
			}
			if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") || strings.Contains(resp.Body, "data:") {
				t.Fatalf("cold streaming failure emitted SSE: content-type=%q body=%q", resp.Header.Get("Content-Type"), resp.Body)
			}
			if got := upstreamCalls.Load(); got != before {
				t.Fatalf("upstream calls after cold rejection = %d, want unchanged %d", got, before)
			}

			proxy.SetUnavailable(false)
			blockedBody := strings.Replace(tc.body, "hello", "r00905-blocked", 1)
			resp = policyAvailabilityRequest(t, ctx, client, server.URL, tc.path, blockedBody, plainKey)
			denialEnvelope := struct {
				Error struct {
					Type    string `json:"type"`
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}{}
			decodeDenialErr := json.Unmarshal([]byte(resp.Body), &denialEnvelope)
			denialMatches := false
			if decodeDenialErr == nil && tc.path == "/v1/messages" {
				denialMatches = denialEnvelope.Error.Type == "invalid_request_error" && strings.HasPrefix(denialEnvelope.Error.Message, "["+policyDenyErrorCode+"]")
			} else if decodeDenialErr == nil {
				denialMatches = denialEnvelope.Error.Code == policyDenyErrorCode
			}
			if resp.StatusCode != http.StatusBadRequest || !denialMatches {
				t.Fatalf("recovered attached policy status=%d body=%s; want its deny before upstream", resp.StatusCode, resp.Body)
			}
			if got := upstreamCalls.Load(); got != before {
				t.Fatalf("upstream calls after recovered policy denial = %d, want unchanged %d", got, before)
			}
			resp = policyAvailabilityRequest(t, ctx, client, server.URL, tc.path, tc.body, plainKey)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("ordinary request after policy recovery status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
			}
			if got := upstreamCalls.Load(); got != before+1 {
				t.Fatalf("upstream calls after recovery = %d, want %d", got, before+1)
			}
		})
	}

	// A separate organization and runtime exercise the configured fail-open
	// profile at the same HTTP boundary. Its first policy read is cold and
	// unavailable; the healthy auth pool and upstream remain reachable.
	_, failOpenKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "fail-open")
	failOpenRuntime, err := NewPolicyRuntime(policyStore, nil, PolicyModeEnforce, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("construct fail-open real policy runtime: %v", err)
	}
	failOpenRuntime.coldFailureMode = PolicyColdFailureFailOpen
	failOpenGW := &gateway{
		gatewayCore:   gatewayCore{cfg: cfg, log: slog.New(slog.DiscardHandler)},
		gatewayEgress: gatewayEgress{pool: upstream.NewPool(upstream.Options{BaseURL: upstreamServer.URL})},
		gatewayRouting: gatewayRouting{res: stubModelResolver{
			"r00905-model": {ModelName: "r00905-model", Provider: "openai", Enabled: true},
		}},
		gatewayCompliance: gatewayCompliance{policyRuntime: failOpenRuntime},
	}
	failOpenGW.auth = NewAuthMiddleware(cfg, auth.NewResolver(directPool, nil, 300, nil))
	failOpenRouter := chi.NewRouter()
	failOpenGW.routes(failOpenRouter)
	failOpenServer := httptest.NewServer(failOpenRouter)
	t.Cleanup(failOpenServer.Close)
	failOpenClient := failOpenServer.Client()
	failOpenClient.Timeout = 15 * time.Second
	proxy.SetUnavailable(true)
	before := upstreamCalls.Load()
	resp := policyAvailabilityRequest(t, ctx, failOpenClient, failOpenServer.URL, "/v1/chat/completions", `{"model":"r00905-model","messages":[{"role":"user","content":"hello"}]}`, failOpenKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cold fail-open request status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != before+1 {
		t.Fatalf("cold fail-open upstream calls = %d, want %d", got, before+1)
	}
	proxy.SetUnavailable(false)

	// A reachable, empty policy snapshot remains a healthy success and does
	// not depend on the fail-open fallback.
	_, emptyKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "healthy-empty")
	emptyBefore := upstreamCalls.Load()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", `{"model":"r00905-model","messages":[{"role":"user","content":"hello"}]}`, emptyKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reachable empty policy snapshot status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != emptyBefore+1 {
		t.Fatalf("reachable empty snapshot upstream calls = %d, want %d", got, emptyBefore+1)
	}
}

func createPolicyAvailabilityIdentity(t *testing.T, ctx context.Context, store *adminstore.Store, suffix string) (string, string) {
	t.Helper()
	identity := fmt.Sprintf("%s-%d", suffix, time.Now().UnixNano())
	org, err := store.CreateOrganization(ctx, "R00905 synthetic "+suffix, "r00905-"+identity)
	if err != nil {
		t.Fatalf("create synthetic %s organization: %v", suffix, err)
	}
	team, err := store.CreateTeam(ctx, org.ID, "R00905 "+suffix+" team", "r00905-team-"+identity, nil)
	if err != nil {
		t.Fatalf("create synthetic %s team: %v", suffix, err)
	}
	plainKey, err := auth.GeneratePersonalKey()
	if err != nil {
		t.Fatalf("generate synthetic %s API key: %v", suffix, err)
	}
	if _, err := store.CreateAPIKey(ctx, auth.HashKey(plainKey), "R00905 "+suffix, &org.ID, &team.ID); err != nil {
		t.Fatalf("create synthetic %s API key row: %v", suffix, err)
	}
	return org.ID, plainKey
}

func seedPolicyAvailabilityPolicy(t *testing.T, ctx context.Context, store *adminstore.Store, orgID string) {
	t.Helper()
	name := "r00905-deny-marker"
	p, _, err := store.CreatePolicy(ctx, orgID, name, denyWordYAML(name, "r00905-blocked"), "r00905-test", "r00905-test")
	if err != nil {
		t.Fatalf("create synthetic policy: %v", err)
	}
	if _, err := store.SetActivePolicyVersion(ctx, orgID, p.ID, 1); err != nil {
		t.Fatalf("activate synthetic policy version: %v", err)
	}
	if _, err := store.UpdatePolicy(ctx, orgID, p.ID, true); err != nil {
		t.Fatalf("enable synthetic policy: %v", err)
	}
	attachments := []adminstore.PolicyAttachment{
		{ModelPattern: "*", Endpoint: "chat", Priority: 1},
		{ModelPattern: "*", Endpoint: "completions", Priority: 1},
		{ModelPattern: "*", Endpoint: "messages", Priority: 1},
		{ModelPattern: "*", Endpoint: "responses", Priority: 1},
	}
	if _, err := store.SetPolicyAttachments(ctx, orgID, p.ID, attachments); err != nil {
		t.Fatalf("attach synthetic policy: %v", err)
	}
}

func startPolicyAvailabilityPostgres(t *testing.T, ctx context.Context) string {
	t.Helper()
	pg, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	if err != nil {
		t.Fatalf("start R00905-owned Postgres: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cleanupCancel()
		_ = pg.Terminate(cleanupCtx)
	})
	host, err := pg.Host(ctx)
	if err != nil {
		t.Fatalf("get Postgres host: %v", err)
	}
	port, err := pg.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("get Postgres port: %v", err)
	}
	dsn := "postgres://postgres:postgres@" + net.JoinHostPort(host, strings.Split(port.Port(), "/")[0]) + "/yabanin?sslmode=disable"
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err = migrate.Run(ctx, dsn, "sg"); err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("apply production migrations to isolated Postgres: %v", err)
	}
	return dsn
}

func newPolicyAvailabilityPool(t *testing.T, ctx context.Context, dsn, proxyAddr string) *pgxpool.Pool {
	t.Helper()
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse isolated Postgres DSN: %v", err)
	}
	host, portText, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("parse private proxy address: %v", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatalf("parse private proxy port: %v", err)
	}
	pc.ConnConfig.Host = host
	pc.ConnConfig.Port = uint16(port)
	pc.MaxConns = 4
	pc.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatalf("create policy-only PostgreSQL pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type policyAvailabilityResponse struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func policyAvailabilityRequest(t *testing.T, parent context.Context, client *http.Client, baseURL, path, payload, key string) policyAvailabilityResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("construct synthetic API request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send synthetic API request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read synthetic API response: %v", err)
	}
	return policyAvailabilityResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: string(body)}
}

type policyAvailabilityProxy struct {
	ctx      context.Context
	listener net.Listener
	backend  string
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closed   bool
	unavail  atomic.Bool
}

func newPolicyAvailabilityProxy(t *testing.T, backend string) *policyAvailabilityProxy {
	t.Helper()
	ctx := t.Context()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for private policy fault proxy: %v", err)
	}
	p := &policyAvailabilityProxy{ctx: ctx, listener: listener, backend: backend, conns: make(map[net.Conn]struct{})}
	go p.serve()
	t.Cleanup(p.Close)
	return p
}

func (p *policyAvailabilityProxy) Addr() string { return p.listener.Addr().String() }

func (p *policyAvailabilityProxy) SetUnavailable(unavailable bool) {
	p.unavail.Store(unavailable)
	if !unavailable {
		return
	}
	p.mu.Lock()
	for conn := range p.conns {
		_ = conn.Close()
	}
	p.mu.Unlock()
}

func (p *policyAvailabilityProxy) serve() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		if p.unavail.Load() {
			_ = client.Close()
			continue
		}
		backend, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(p.ctx, "tcp", p.backend)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.mu.Lock()
		if p.unavail.Load() || p.closed {
			p.mu.Unlock()
			_ = client.Close()
			_ = backend.Close()
			continue
		}
		p.conns[client] = struct{}{}
		p.conns[backend] = struct{}{}
		p.mu.Unlock()
		go p.forward(client, backend)
		go p.forward(backend, client)
	}
}

func (p *policyAvailabilityProxy) forward(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
	p.mu.Lock()
	delete(p.conns, dst)
	delete(p.conns, src)
	p.mu.Unlock()
}

func (p *policyAvailabilityProxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	_ = p.listener.Close()
	for conn := range p.conns {
		_ = conn.Close()
	}
	p.mu.Unlock()
}

// --- PostgreSQL store, an owned isolated container, and a private fault proxy.

// policyAvailabilityClock is a controllable time source for the policy
// runtime so the TTL boundary is crossed deterministically without sleeping.
// It is only advanced between completed HTTP requests, never concurrently
// with one.
type policyAvailabilityClock struct {
	mu  sync.Mutex
	now time.Time
}

func newPolicyAvailabilityClock() *policyAvailabilityClock {
	return &policyAvailabilityClock{now: time.Now()}
}

func (c *policyAvailabilityClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *policyAvailabilityClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// policyAvailabilityLoadedAt reads the org's installed snapshot load
// timestamp (zero when no successful entry exists).
func policyAvailabilityLoadedAt(t *testing.T, rt *PolicyRuntime, orgID string) time.Time {
	t.Helper()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	e := rt.orgs[orgID]
	if e == nil {
		return time.Time{}
	}
	return e.loadedAt
}

// newPolicyAvailabilityUpstream counts every forwarded request so tests can
// prove that cold rejections never reach the provider.
func newPolicyAvailabilityUpstream(t *testing.T, upstreamCalls *atomic.Int64) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		_, _ = io.WriteString(w, `{"id":"r00905","object":"chat.completion","model":"r00905-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	t.Cleanup(server.Close)
	return server
}

// startPolicyAvailabilityHTTPGateway mounts the production gw.routes with the
// given policy runtime over an httptest server whose auth path uses the
// direct (healthy) pool — only the policy store rides the fault proxy.
func startPolicyAvailabilityHTTPGateway(t *testing.T, cfg config.Gateway, upstreamURL string, directPool *pgxpool.Pool, rt *PolicyRuntime) (*httptest.Server, *http.Client) {
	t.Helper()
	gw := &gateway{
		gatewayCore:   gatewayCore{cfg: cfg, log: slog.New(slog.DiscardHandler)},
		gatewayEgress: gatewayEgress{pool: upstream.NewPool(upstream.Options{BaseURL: upstreamURL})},
		gatewayRouting: gatewayRouting{res: stubModelResolver{
			"r00905-model": {ModelName: "r00905-model", Provider: "openai", Enabled: true},
		}},
		gatewayCompliance: gatewayCompliance{policyRuntime: rt},
	}
	gw.auth = NewAuthMiddleware(cfg, auth.NewResolver(directPool, nil, 300, nil))
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 15 * time.Second
	return server, client
}

// TestPolicyAvailabilityHTTPColdDegradationAudited drives the real chat route
// against a real PostgreSQL policy store behind a private fault proxy.
// Fail-closed cold failure answers 503 with the stable code before any
// upstream byte; both cold profiles record exactly one enforce/cold
// degradation per request (counter plus fixed-class structured log); and an
// explicitly fail-open runtime still enforces a warm healthy snapshot while
// the store is down.
func TestPolicyAvailabilityHTTPColdDegradationAudited(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dsn := startPolicyAvailabilityPostgres(t, ctx)
	directPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated seed/auth pool: %v", err)
	}
	t.Cleanup(directPool.Close)
	seedStore := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)
	var upstreamCalls atomic.Int64
	upstreamServer := newPolicyAvailabilityUpstream(t, &upstreamCalls)
	pgConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse isolated Postgres DSN: %v", err)
	}
	proxy := newPolicyAvailabilityProxy(t, net.JoinHostPort(pgConfig.ConnConfig.Host, strconv.Itoa(int(pgConfig.ConnConfig.Port))))
	policyPool := newPolicyAvailabilityPool(t, ctx, dsn, proxy.Addr())
	policyStore := adminstore.New(policyPool, slog.New(slog.DiscardHandler), nil)

	failClosedLog := &capturedPolicyLog{}
	runtime, err := NewPolicyRuntime(policyStore, nil, PolicyModeEnforce, nil, slog.New(failClosedLog))
	if err != nil {
		t.Fatalf("construct fail-closed runtime: %v", err)
	}
	failOpenLog := &capturedPolicyLog{}
	failOpenRuntime, err := NewPolicyRuntime(policyStore, nil, PolicyModeEnforce, nil, slog.New(failOpenLog))
	if err != nil {
		t.Fatalf("construct fail-open runtime: %v", err)
	}
	failOpenRuntime.coldFailureMode = PolicyColdFailureFailOpen

	cfg := config.Gateway{}
	cfg.AuthMode = "header"
	cfg.Provider = upstreamServer.URL
	cfg.FallbackModel = "r00905-model"
	cfg.UnknownModelPolicy = "reject"
	server, client := startPolicyAvailabilityHTTPGateway(t, cfg, upstreamServer.URL, directPool, runtime)
	failOpenServer, failOpenClient := startPolicyAvailabilityHTTPGateway(t, cfg, upstreamServer.URL, directPool, failOpenRuntime)

	chatBody := `{"model":"r00905-model","messages":[{"role":"user","content":"hello"}]}`
	denyBody := strings.Replace(chatBody, "hello", "r00905-blocked", 1)

	// A healthy deny snapshot warms on the fail-open runtime while the store
	// is reachable; the override must never weaken loaded enforcement later.
	healthyOrg, healthyKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "degrade-healthy")
	seedPolicyAvailabilityPolicy(t, ctx, seedStore, healthyOrg)
	resp := policyAvailabilityRequest(t, ctx, failOpenClient, failOpenServer.URL, "/v1/chat/completions", chatBody, healthyKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fail-open warm request status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}

	_, coldKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "degrade-cold")
	_, failOpenColdKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "degrade-fail-open")
	beforeCold := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))
	beforeUpstream := upstreamCalls.Load()
	proxy.SetUnavailable(true)

	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, coldKey)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("cold fail-closed status = %d, want 503; body=%s", resp.StatusCode, resp.Body)
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &envelope); err != nil {
		t.Fatalf("decode cold failure envelope: %v; body=%s", err, resp.Body)
	}
	if envelope.Error.Code != "policy_temporarily_unavailable" {
		t.Fatalf("cold failure code = %q, want policy_temporarily_unavailable; body=%s", envelope.Error.Code, resp.Body)
	}
	if got := upstreamCalls.Load(); got != beforeUpstream {
		t.Fatalf("upstream calls after cold 503 = %d, want unchanged %d", got, beforeUpstream)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != beforeCold+1 {
		t.Fatalf("cold degradation counter = %v, want exactly %v (one outcome per hook boundary)", after, beforeCold+1)
	}
	if failClosedLog.find("policy load failed", map[string]string{"mode": "enforce", "cache_state": "cold", "failure_class": "store_read"}) < 0 {
		t.Fatalf("cold 503 was not audited with the fixed store_read failure class: %+v", failClosedLog.records)
	}

	// The same cold boundary under explicit fail-open documents progress and
	// records the degradation exactly once per request: the post-upstream
	// hook reuses the pre-hook outcome instead of re-reading the store.
	beforeFailOpen := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))
	resp = policyAvailabilityRequest(t, ctx, failOpenClient, failOpenServer.URL, "/v1/chat/completions", chatBody, failOpenColdKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cold fail-open status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != beforeUpstream+1 {
		t.Fatalf("cold fail-open upstream calls = %d, want %d", got, beforeUpstream+1)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != beforeFailOpen+1 {
		t.Fatalf("fail-open cold counter = %v, want exactly %v (no per-hook double count)", after, beforeFailOpen+1)
	}
	if failOpenLog.find("policy load failed", map[string]string{"mode": "enforce", "cache_state": "cold", "failure_class": "store_read"}) < 0 {
		t.Fatalf("fail-open cold progress was not audited: %+v", failOpenLog.records)
	}

	// Healthy enforcement survives the fail-open setting while the store is
	// still down: the warm snapshot denies, and no degradation signal fires.
	denyBefore := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))
	denyBeforeUpstream := upstreamCalls.Load()
	resp = policyAvailabilityRequest(t, ctx, failOpenClient, failOpenServer.URL, "/v1/chat/completions", denyBody, healthyKey)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("fail-open warm deny status = %d, want 400; body=%s", resp.StatusCode, resp.Body)
	}
	var denyEnvelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &denyEnvelope); err != nil || denyEnvelope.Error.Code != policyDenyErrorCode {
		t.Fatalf("fail-open warm deny code = %q (err %v), want %s; body=%s", denyEnvelope.Error.Code, err, policyDenyErrorCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != denyBeforeUpstream {
		t.Fatalf("denied request reached upstream: %d calls, want unchanged %d", got, denyBeforeUpstream)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != denyBefore {
		t.Fatalf("healthy deny emitted a cold degradation signal: %v, want %v", after, denyBefore)
	}

	// The cold org retries on a later request once the store recovers.
	proxy.SetUnavailable(false)
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, coldKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recovered cold org status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != beforeUpstream+2 {
		t.Fatalf("upstream calls after recovery = %d, want %d", got, beforeUpstream+2)
	}
}

// TestPolicyAvailabilityHTTPColdIsolationBetweenOrgs proves per-org cache and
// availability isolation over the real routes: under a blocked store, a cold
// org is rejected while an independently warmed org keeps proceeding from its
// own successful empty snapshot, and the cold org recovers on a later request.
func TestPolicyAvailabilityHTTPColdIsolationBetweenOrgs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dsn := startPolicyAvailabilityPostgres(t, ctx)
	directPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated seed/auth pool: %v", err)
	}
	t.Cleanup(directPool.Close)
	seedStore := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)
	var upstreamCalls atomic.Int64
	upstreamServer := newPolicyAvailabilityUpstream(t, &upstreamCalls)
	pgConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse isolated Postgres DSN: %v", err)
	}
	proxy := newPolicyAvailabilityProxy(t, net.JoinHostPort(pgConfig.ConnConfig.Host, strconv.Itoa(int(pgConfig.ConnConfig.Port))))
	policyPool := newPolicyAvailabilityPool(t, ctx, dsn, proxy.Addr())
	policyStore := adminstore.New(policyPool, slog.New(slog.DiscardHandler), nil)
	runtime, err := NewPolicyRuntime(policyStore, nil, PolicyModeEnforce, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("construct real policy runtime: %v", err)
	}
	cfg := config.Gateway{}
	cfg.AuthMode = "header"
	cfg.Provider = upstreamServer.URL
	cfg.FallbackModel = "r00905-model"
	cfg.UnknownModelPolicy = "reject"
	server, client := startPolicyAvailabilityHTTPGateway(t, cfg, upstreamServer.URL, directPool, runtime)

	chatBody := `{"model":"r00905-model","messages":[{"role":"user","content":"hello"}]}`

	// Org B warms a successful empty snapshot while the store is reachable.
	_, warmKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "isolation-warm")
	resp := policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, warmKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("warm org status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	warmBeforeUpstream := upstreamCalls.Load()

	_, coldKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "isolation-cold")
	beforeCold := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))
	proxy.SetUnavailable(true)

	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, coldKey)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("cold org status = %d, want 503; body=%s", resp.StatusCode, resp.Body)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != beforeCold+1 {
		t.Fatalf("cold org counter = %v, want %v", after, beforeCold+1)
	}

	// The warm org proceeds from its own snapshot; the cold neighbor's
	// failure neither invalidates it nor adds a stale signal.
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, warmKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("warm org during cold outage status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != warmBeforeUpstream+1 {
		t.Fatalf("warm org upstream calls = %d, want %d", got, warmBeforeUpstream+1)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != beforeCold+1 {
		t.Fatalf("warm org request changed the cold counter: %v, want %v", after, beforeCold+1)
	}

	// The cold org recovers independently on a later request.
	proxy.SetUnavailable(false)
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, coldKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cold org after recovery status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != warmBeforeUpstream+2 {
		t.Fatalf("upstream calls after cold org recovery = %d, want %d", got, warmBeforeUpstream+2)
	}
}

// TestPolicyAvailabilityHTTPLastGoodRefreshFailureRecovers drives the
// last-good contract over the real chat route with a controlled clock: a
// failed refresh at the TTL boundary keeps enforcing the immutable snapshot
// with its original load timestamp and a stale degradation signal; restoring
// the store lets the next request install a fresh snapshot and emit the
// recovery log.
func TestPolicyAvailabilityHTTPLastGoodRefreshFailureRecovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dsn := startPolicyAvailabilityPostgres(t, ctx)
	directPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated seed/auth pool: %v", err)
	}
	t.Cleanup(directPool.Close)
	seedStore := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)
	var upstreamCalls atomic.Int64
	upstreamServer := newPolicyAvailabilityUpstream(t, &upstreamCalls)
	pgConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse isolated Postgres DSN: %v", err)
	}
	proxy := newPolicyAvailabilityProxy(t, net.JoinHostPort(pgConfig.ConnConfig.Host, strconv.Itoa(int(pgConfig.ConnConfig.Port))))
	policyPool := newPolicyAvailabilityPool(t, ctx, dsn, proxy.Addr())
	policyStore := adminstore.New(policyPool, slog.New(slog.DiscardHandler), nil)

	runtimeLog := &capturedPolicyLog{}
	runtime, err := NewPolicyRuntime(policyStore, nil, PolicyModeEnforce, nil, slog.New(runtimeLog))
	if err != nil {
		t.Fatalf("construct real policy runtime: %v", err)
	}
	clock := newPolicyAvailabilityClock()
	runtime.now = clock.Now

	cfg := config.Gateway{}
	cfg.AuthMode = "header"
	cfg.Provider = upstreamServer.URL
	cfg.FallbackModel = "r00905-model"
	cfg.UnknownModelPolicy = "reject"
	server, client := startPolicyAvailabilityHTTPGateway(t, cfg, upstreamServer.URL, directPool, runtime)

	chatBody := `{"model":"r00905-model","messages":[{"role":"user","content":"hello"}]}`
	denyBody := strings.Replace(chatBody, "hello", "r00905-blocked", 1)

	org, key := createPolicyAvailabilityIdentity(t, ctx, seedStore, "last-good")
	seedPolicyAvailabilityPolicy(t, ctx, seedStore, org)

	// Warm the deny snapshot while the store is reachable.
	resp := policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", denyBody, key)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("warm deny status = %d, want 400; body=%s", resp.StatusCode, resp.Body)
	}
	loadedAt := policyAvailabilityLoadedAt(t, runtime, org)
	if loadedAt.IsZero() {
		t.Fatal("warm request did not install a policy snapshot")
	}

	// Cross the TTL boundary and fail the refresh: the immutable last-good
	// snapshot still enforces, its loadedAt survives, and the degradation is
	// a stale (not cold) signal.
	clock.Advance(2 * policyCacheTTL)
	proxy.SetUnavailable(true)
	beforeStale := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale"))

	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", denyBody, key)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("last-good deny during refresh failure status = %d, want 400; body=%s", resp.StatusCode, resp.Body)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale")); after != beforeStale+1 {
		t.Fatalf("stale degradation counter = %v, want %v", after, beforeStale+1)
	}
	if got := policyAvailabilityLoadedAt(t, runtime, org); !got.Equal(loadedAt) {
		t.Fatalf("failed refresh mutated the last-good timestamp: %v, want %v", got, loadedAt)
	}
	if runtimeLog.find("policy load failed", map[string]string{"mode": "enforce", "cache_state": "stale", "failure_class": "store_read"}) < 0 {
		t.Fatalf("stale refresh failure was not audited: %+v", runtimeLog.records)
	}

	// Ordinary traffic keeps flowing through the same last-good snapshot;
	// each request under the outage retries the load once (stale signal).
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("last-good ordinary request status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	ordinaryUpstream := upstreamCalls.Load()
	if ordinaryUpstream != 1 {
		t.Fatalf("upstream calls through last-good = %d, want 1", ordinaryUpstream)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale")); after != beforeStale+2 {
		t.Fatalf("stale counter after second outage request = %v, want %v", after, beforeStale+2)
	}

	// Restore the store: the next request retries the load, installs the
	// fresh snapshot, and emits the recovery log.
	proxy.SetUnavailable(false)
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-recovery status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != ordinaryUpstream+1 {
		t.Fatalf("upstream calls after recovery = %d, want %d", got, ordinaryUpstream+1)
	}
	recoveredAt := policyAvailabilityLoadedAt(t, runtime, org)
	if !recoveredAt.After(loadedAt) {
		t.Fatalf("recovered snapshot loadedAt = %v, want newer than %v", recoveredAt, loadedAt)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale")); after != beforeStale+2 {
		t.Fatalf("recovery added a stale signal: %v, want %v", after, beforeStale+2)
	}
	if runtimeLog.find("policy store load succeeded", map[string]string{}) < 0 {
		t.Fatalf("recovery success log missing: %+v", runtimeLog.records)
	}

	// The fresh snapshot still enforces its deny.
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", denyBody, key)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-recovery deny status = %d, want 400; body=%s", resp.StatusCode, resp.Body)
	}
}
