package cli

// Fuzz seeds for gateway FAMILY-02 boot lifecycle: RunGatewayServerWithJWT
// (gateway.go:106) and newGatewayHTTPRouter (gateway.go:147) — task
// gateway-corpus-fam02, head 0e32ff48b1f67e9dfc548c5f3b77e30f7a7eb86d. The
// auth/session cases (F02-01..18) live in fuzz_family02_test.go; this file
// drives the REAL production server lifecycle: a real loopback listener per
// boot, real cancellation/shutdown, and response oracles against the booted
// process — never a hand-mounted router.
//
// Frozen case table (same convention as the A2A/toolgate seeds):
//
//	F02-19 BOOT-LIFECYCLE strict static-key boot on a free loopback port;
//	                        /healthz 200 {"status":"ok","redis":"skipped"} +
//	                        X-Yabanin-Build; HEAD /api/hello 200 unauth;
//	                        chat without/with wrong key -> 401; cancel ->
//	                        nil error; listener closed after shutdown
//	F02-20 BOOT-AUTHORIZED authorized chat through the booted server:
//	                        200 parseable JSON; upstream hit EXACTLY once
//	                        (zero unintended upstream effects incl. a later
//	                        denied request); exact X-Request-ID receipt
//	                        upstream; spoofed X-Org-Id stripped upstream;
//	                        gateway key never forwarded upstream; degraded
//	                        health visible (503 redis down) while serving
//	F02-21 BOOT-NEGATIVE  Validate wrap ("invalid gateway config" +
//	                        auth_mode / event_stream texts); buildGateway
//	                        passthrough (invalid encryption_key, NOT the
//	                        Validate wrap); occupied listen port ->
//	                        "gateway listen failed"; every negative errors
//	                        (no silent skip)
//	F02-22 BOOT-ADMIN     admin listener + metrics + CORS + shadow + tracing
//	                        + pprof boot: /debug/vars 200 (localhost Bearer
//	                        cfg.APIKey, config echo), /metrics 200, CORS
//	                        preflight echoes AllowedOrigins, denied request
//	                        through the traced router, upstream hits 0
//	                        (no completion -> no shadow mirror, no publish)
//	F02-23 BOOT-JWT       JWTWiring boot against a loopback JWKS: valid
//	                        RS256 -> 200, upstream sees the token org id
//	                        exactly once; static gateway key still accepted
//	                        (dual mode); expired/garbage tokens -> 401
//
// Controls: the corpus runs the same frozen seeds under the original,
// fixed, and isolated populations with the installed 300s shared budget;
// per-execution cost is one boot (<100ms ready) plus <=4 requests.
//
// Fixture rules (verified against head):
//   - Validate() REQUIRES non-empty EventStream and PGURI, so every
//     successful boot has a live publisher (NewRedisPublisher is
//     unconditionally non-nil, gateway.go:349).
//   - A nil *redis.Client cannot serve XAdd: Client embeds cmdable BY
//     VALUE (go-redis v9.23), so any completed request would panic the
//     async publish goroutine (events.go:105 has no recover). Boots that
//     complete requests therefore pass a real client pointed at dead
//     loopback 127.0.0.1:1 — XAdd fails fast, errors are swallowed by the
//     bounded retry loop, health reports degraded. F02-19 (no completed
//     inference) is the one nil-redis boot and asserts the skipped shape.
//   - pool stays nil: buildGateway never dials PG, and resolveModelInfo
//     returns a static ModelInfo (upstream.go:357) so the authorized chain
//     completes against the httptest upstream at cfg.Provider.
//   - readiness = ANY /healthz response (200 ok and 503 degraded both mean
//     the listener is serving); failures to start are hard errors, never
//     skips (per the family contract).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/config"
)

// --- shared boot fixtures -----------------------------------------------------------

// f02BootEnv pins the drain knob to zero so shutdown after cancel is
// immediate (invalid values would fail startup — fail-closed knob).
func f02BootEnv(t *testing.T) {
	t.Helper()
	t.Setenv("YABANIN_READINESS_DRAIN_DELAY", "0")
}

// f02DeadRedis returns a real client for a dead loopback port: dial errors
// are immediate, surfaced as ordinary command errors, and never panic.
func f02DeadRedis() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1",
		DialTimeout:  100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		MaxRetries:   -1,
		PoolSize:     2,
	})
}

// f02FreeAddr picks a free loopback address. The tiny close/rebind window is
// acceptable: a lost race surfaces as a listen failure, which this family
// treats as a hard error.
func f02FreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("F02 boot: free-address probe failed: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("F02 boot: free-address probe close failed: %v", err)
	}
	return addr
}

// f02Upstream is a recording OpenAI-compatible upstream: it counts requests,
// keeps the last received header set, and answers a fixed chat completion.
type f02Upstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits int
	hdr  http.Header
	body string
}

const f02UpstreamChatBody = `{"id":"chatcmpl-f02-boot","object":"chat.completion","created":1,` +
	`"model":"smart","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},` +
	`"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

func f02UpstreamRecorder(t *testing.T) *f02Upstream {
	t.Helper()
	u := &f02Upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.hits++
		u.hdr = r.Header.Clone()
		u.body = string(body)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f02UpstreamChatBody))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *f02Upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits
}

func (u *f02Upstream) lastHeader() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hdr
}

func (u *f02Upstream) lastBody() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.body
}

// f02BootConfig builds the minimal VALID production config: strict static
// key, required EventStream/PGURI strings (the pool itself stays nil —
// buildGateway never dials PG), dead-loopback PG target, no RedisAddr (so
// no cache_hmac_secret requirement).
func f02BootConfig(listen, provider, apiKey string) config.Gateway {
	return config.Gateway{
		GatewayServer: config.GatewayServer{
			ListenAddr:  listen,
			AuthMode:    "strict",
			APIKey:      apiKey,
			EventStream: "yabanin-f02-boot",
			PGURI:       "postgres://f02:f02@127.0.0.1:1/f02?sslmode=disable",
		},
		GatewayEgress: config.GatewayEgress{
			Provider: provider,
		},
		GatewayRouting: config.GatewayRouting{
			FallbackModel: "smart",
		},
	}
}

// f02BootServer is a live RunGatewayServerWithJWT boot.
type f02BootServer struct {
	baseURL  string
	cancel   context.CancelFunc
	done     <-chan error
	stopOnce sync.Once
	stopErr  error
	stopped  chan struct{}
}

// errF02BootStopTimeout marks a boot that ignored cancellation; stop is
// idempotent so the explicit shutdown assert and the t.Cleanup join can
// both observe the single join result.
var errF02BootStopTimeout = errors.New("F02 boot: server did not stop within 10s of cancel")

func (bs *f02BootServer) stop() error {
	bs.cancel()
	bs.stopOnce.Do(func() {
		select {
		case bs.stopErr = <-bs.done:
		case <-time.After(10 * time.Second):
			bs.stopErr = errF02BootStopTimeout
		}
		close(bs.stopped)
	})
	<-bs.stopped
	return bs.stopErr
}

// f02BootGateway boots the real server and blocks until /healthz answers
// (any status). A server exit before readiness is a hard failure — the
// family contract has no skip path.
func f02BootGateway(t *testing.T, cfg config.Gateway, rdb *redis.Client, jwtw JWTWiring) *f02BootServer {
	t.Helper()
	f02BootEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		done <- RunGatewayServerWithJWT(cfg, rdb, nil, nil, l, ctx, jwtw, CircuitScopeWiring{})
	}()
	bs := &f02BootServer{
		baseURL: "http://" + cfg.ListenAddr,
		cancel:  cancel,
		done:    done,
		stopped: make(chan struct{}),
	}
	if rdb != nil {
		r := rdb
		t.Cleanup(func() { _ = r.Close() })
	}

	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("F02 boot: server exited before readiness: %v", err)
			}
			t.Fatal("F02 boot: server returned nil before readiness")
		default:
		}
		resp, err := client.Get(bs.baseURL + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			t.Cleanup(func() {
				if err := bs.stop(); err != nil {
					t.Errorf("F02 boot: shutdown error: %v", err)
				}
			})
			return bs
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("F02 boot: %s never became ready: %v", bs.baseURL, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// f02HealthJSON fetches and decodes /healthz.
func f02HealthJSON(t *testing.T, baseURL string) (int, map[string]string, http.Header) {
	t.Helper()
	resp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("F02 boot: healthz: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("F02 boot: healthz body %q: %v", string(body), err)
	}
	return resp.StatusCode, m, resp.Header
}

// f02Chat fires one chat completion through the booted server.
func f02Chat(t *testing.T, baseURL, auth, requestID, orgSpoof string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions",
		strings.NewReader(`{"model":"smart","messages":[{"role":"user","content":"f02 boot"}]}`))
	if err != nil {
		t.Fatalf("F02 boot: chat request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	if orgSpoof != "" {
		req.Header.Set("X-Org-Id", orgSpoof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("F02 boot: chat do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// --- generated-input behavior --------------------------------------------------------

func f02BootGenFixture(t testing.TB) (string, JWTWiring) {
	t.Helper()
	k := mustRSAJWK(t, "boot-gen-kid")
	srv := newJWKSServer(t, k)
	w := JWTWiring{
		JWKSURL:       srv.srv.URL,
		Issuer:        "https://idp.example",
		Audience:      "yabanin-gateway",
		OrgClaim:      "org_id",
		KeyLabelClaim: "key_labels",
	}
	claims := f02OrgClaims(w.Issuer, w.Audience, "org-42")
	return signToken(t, k, claims), w
}

// f02BootGenerated derives the expected outcome independently and drives one
// full boot per execution: mode 0 static key, 1 valid JWT, 2 unauthenticated.
func f02BootGenerated(t *testing.T, data []byte, token string, wiring JWTWiring) {
	t.Helper()
	p := data
	if len(p) < 6 {
		p = append(append([]byte{}, p...), 0, 1, 2, 3, 4, 5)
	}
	mode, adminOn := int(p[0])%3, int(p[1])%2 == 1
	spoof, rid, traceOn := int(p[2])%2 == 1, int(p[3])%2 == 1, int(p[4])%2 == 1

	up := f02UpstreamRecorder(t)
	cfg := f02BootConfig(f02FreeAddr(t), up.srv.URL, "f02-gen-key")
	if adminOn {
		cfg.AdminListen = f02FreeAddr(t)
		cfg.MetricsEnabled = int(p[5])%2 == 1
	}
	if traceOn {
		cfg.OTELTracingEndpoint = "http://127.0.0.1:4317"
	}
	jwtw := JWTWiring{}
	auth := ""
	switch mode {
	case 0:
		auth = "Bearer f02-gen-key"
	case 1:
		jwtw, auth = wiring, "Bearer "+token
	}
	bs := f02BootGateway(t, cfg, f02DeadRedis(), jwtw)

	ridVal := ""
	if rid {
		ridVal = "f02-gen-rid"
	}
	spoofVal := ""
	if spoof {
		spoofVal = "org-spoof"
	}
	resp, _ := f02Chat(t, bs.baseURL, auth, ridVal, spoofVal)
	wantStatus := http.StatusOK
	if mode == 2 {
		wantStatus = http.StatusUnauthorized
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("F02 gen boot: mode=%d admin=%v spoof=%v: want %d got %d",
			mode, adminOn, spoof, wantStatus, resp.StatusCode)
	}
	wantHits := 0
	if wantStatus == http.StatusOK {
		wantHits = 1
	}
	if got := up.count(); got != wantHits {
		t.Fatalf("F02 gen boot: mode=%d: upstream hits %d, want exactly %d", mode, got, wantHits)
	}
	if wantHits == 1 && rid && up.lastHeader().Get("X-Request-ID") != "f02-gen-rid" {
		t.Fatalf("F02 gen boot: upstream X-Request-ID %q, want exact f02-gen-rid",
			up.lastHeader().Get("X-Request-ID"))
	}
	if wantHits == 1 && spoof {
		if mode == 1 && up.lastHeader().Get("X-Org-Id") != "org-42" {
			t.Fatalf("F02 gen boot: jwt upstream org %q, want org-42", up.lastHeader().Get("X-Org-Id"))
		}
		if mode == 0 && up.lastHeader().Get("X-Org-Id") == "org-spoof" {
			t.Fatal("F02 gen boot: spoofed X-Org-Id reached the upstream")
		}
	}
}

// --- frozen cases --------------------------------------------------------------------

// F02-19 lifecycle: boot, health, unauthenticated denial, clean shutdown,
// closed listener. The one nil-redis boot (no completed inference -> no
// publish, so the nil client is never dereferenced).
func fuzzF0219(t *testing.T) {
	t.Helper()
	up := f02UpstreamRecorder(t)
	cfg := f02BootConfig(f02FreeAddr(t), up.srv.URL, "f02-boot-key")
	bs := f02BootGateway(t, cfg, nil, JWTWiring{})

	code, m, hdr := f02HealthJSON(t, bs.baseURL)
	if code != http.StatusOK || m["status"] != "ok" || m["redis"] != "skipped" {
		t.Fatalf("F02-19: healthz %d %v, want 200 ok/skipped", code, m)
	}
	if hdr.Get("X-Yabanin-Build") == "" {
		t.Fatal("F02-19: missing X-Yabanin-Build header")
	}

	// Unauthenticated surface: the health route and the public hello.
	hello, err := http.Head(bs.baseURL + "/api/hello")
	if err != nil {
		t.Fatalf("F02-19: /api/hello: %v", err)
	}
	_, _ = io.Copy(io.Discard, hello.Body)
	_ = hello.Body.Close()
	if hello.StatusCode != http.StatusOK {
		t.Fatalf("F02-19: HEAD /api/hello = %d, want 200", hello.StatusCode)
	}

	for _, auth := range []string{"", "Bearer wrong-key"} {
		resp, _ := f02Chat(t, bs.baseURL, auth, "", "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("F02-19: chat auth %q = %d, want 401", auth, resp.StatusCode)
		}
	}
	if got := up.count(); got != 0 {
		t.Fatalf("F02-19: denied requests reached upstream %d times", got)
	}

	if err := bs.stop(); err != nil {
		t.Fatalf("F02-19: shutdown error: %v", err)
	}
	if _, err := http.Get(bs.baseURL + "/healthz"); err == nil {
		t.Fatal("F02-19: listener still serving after shutdown")
	}
}

// F02-20 authorized chain through the booted server, with exact request-ID
// receipt, identity hygiene, and the zero-side-effect upstream oracle.
func fuzzF0220(t *testing.T) {
	t.Helper()
	up := f02UpstreamRecorder(t)
	cfg := f02BootConfig(f02FreeAddr(t), up.srv.URL, "f02-boot-key")
	bs := f02BootGateway(t, cfg, f02DeadRedis(), JWTWiring{})

	// Dead redis is visible in health but must not block serving.
	code, m, _ := f02HealthJSON(t, bs.baseURL)
	if code != http.StatusServiceUnavailable || m["status"] != "degraded" || m["redis"] != "down" {
		t.Fatalf("F02-20: healthz %d %v, want 503 degraded/down", code, m)
	}

	resp, body := f02Chat(t, bs.baseURL, "Bearer f02-boot-key", "f02-boot-req-42", "org-hacker")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("F02-20: authorized chat = %d body %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("F02-20: response Content-Type %q", ct)
	}
	// Request-ID contract (gateway.go mount comment): the client's
	// X-Request-ID is echoed verbatim on the response.
	if got := resp.Header.Get("X-Request-ID"); got != "f02-boot-req-42" {
		t.Fatalf("F02-20: response X-Request-ID %q, want verbatim f02-boot-req-42", got)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("F02-20: response not JSON: %v body %s", err, body)
	}

	// A later denied request must not add upstream effects.
	denied, _ := f02Chat(t, bs.baseURL, "", "", "")
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F02-20: denied chat = %d, want 401", denied.StatusCode)
	}
	if got := up.count(); got != 1 {
		t.Fatalf("F02-20: upstream hits = %d, want exactly 1 (zero unintended upstream effects)", got)
	}
	h := up.lastHeader()
	if got := h.Get("X-Request-ID"); got != "f02-boot-req-42" {
		t.Fatalf("F02-20: upstream X-Request-ID %q, want exact f02-boot-req-42", got)
	}
	if got := h.Get("X-Org-Id"); got == "org-hacker" {
		t.Fatal("F02-20: spoofed X-Org-Id reached the upstream")
	}
	if auth := h.Get("Authorization"); strings.Contains(auth, "f02-boot-key") {
		t.Fatalf("F02-20: gateway key leaked upstream: %q", auth)
	}
	if b := up.lastBody(); !strings.Contains(b, "f02 boot") {
		t.Fatalf("F02-20: upstream body %q missing request content", b)
	}
}

// F02-21 startup negatives: every configuration class fails loudly, with
// the documented error shapes and no skip path.
func fuzzF0221(t *testing.T) {
	t.Helper()
	f02BootEnv(t)
	up := f02UpstreamRecorder(t)
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	run := func(cfg config.Gateway) error {
		return RunGatewayServerWithJWT(cfg, nil, nil, nil, l, ctx, JWTWiring{}, CircuitScopeWiring{})
	}

	// Validate() wrap.
	badMode := f02BootConfig(f02FreeAddr(t), up.srv.URL, "k")
	badMode.AuthMode = "bogus"
	if err := run(badMode); err == nil || !strings.Contains(err.Error(), "invalid gateway config") ||
		!strings.Contains(err.Error(), "auth_mode must be") {
		t.Fatalf("F02-21: auth_mode negative: %v", err)
	}

	noStream := f02BootConfig(f02FreeAddr(t), up.srv.URL, "k")
	noStream.EventStream = ""
	if err := run(noStream); err == nil || !strings.Contains(err.Error(), "event_stream is required") {
		t.Fatalf("F02-21: event_stream negative: %v", err)
	}

	// buildGateway passthrough (NOT the Validate wrap).
	badKey := f02BootConfig(f02FreeAddr(t), up.srv.URL, "k")
	badKey.EncryptionKey = "f02-not-a-valid-key"
	if err := run(badKey); err == nil || !strings.Contains(err.Error(), "invalid encryption_key") {
		t.Fatalf("F02-21: encryption_key negative: %v", err)
	} else if strings.Contains(err.Error(), "invalid gateway config") {
		t.Fatalf("F02-21: encryption_key negative wrapped by Validate: %v", err)
	}

	// Occupied listen port: hold the address, expect the listen failure.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("F02-21: hold listener: %v", err)
	}
	defer held.Close()
	occupied := f02BootConfig(held.Addr().String(), up.srv.URL, "k")
	errCh := make(chan error, 1)
	go func() { errCh <- run(occupied) }()
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "gateway listen failed") {
			t.Fatalf("F02-21: occupied port: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("F02-21: occupied-port boot never returned")
	}
	if got := up.count(); got != 0 {
		t.Fatalf("F02-21: negatives reached upstream %d times", got)
	}
}

// F02-22 admin surface: metrics, debug vars, CORS, shadow registration, and
// tracing mounts — all observable without completing an inference (so the
// upstream stays untouched and the shadow mirror never samples).
func fuzzF0222(t *testing.T) {
	t.Helper()
	up := f02UpstreamRecorder(t)
	cfg := f02BootConfig(f02FreeAddr(t), up.srv.URL, "f02-admin-key")
	cfg.AdminListen = f02FreeAddr(t)
	cfg.MetricsEnabled = true
	cfg.AllowedOrigins = []string{"https://boot.example"}
	cfg.Shadow.Enabled = true
	cfg.Shadow.SampleRate = 0
	cfg.DebugPprof = true
	cfg.OTELTracingEndpoint = "http://127.0.0.1:4317"
	bs := f02BootGateway(t, cfg, f02DeadRedis(), JWTWiring{})
	admin := "http://" + cfg.AdminListen

	// /debug/vars: localhost + Bearer cfg.APIKey, config echo.
	req, _ := http.NewRequest(http.MethodGet, admin+"/debug/vars", nil)
	req.Header.Set("Authorization", "Bearer f02-admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("F02-22: /debug/vars: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("F02-22: /debug/vars = %d body %s", resp.StatusCode, string(body))
	}
	var dbg map[string]map[string]string
	if err := json.Unmarshal(body, &dbg); err != nil {
		t.Fatalf("F02-22: /debug/vars body: %v", err)
	}
	if dbg["config"]["listen_addr"] != cfg.ListenAddr || dbg["config"]["provider"] != up.srv.URL {
		t.Fatalf("F02-22: /debug/vars echo %+v", dbg["config"])
	}
	// Without the bearer the debug surface refuses.
	noAuth, err := http.Get(admin + "/debug/vars")
	if err != nil {
		t.Fatalf("F02-22: /debug/vars without bearer: %v", err)
	}
	_, _ = io.Copy(io.Discard, noAuth.Body)
	_ = noAuth.Body.Close()
	if noAuth.StatusCode != http.StatusForbidden {
		t.Fatalf("F02-22: /debug/vars without bearer = %d, want 403", noAuth.StatusCode)
	}

	metricsResp, err := http.Get(admin + "/metrics")
	if err != nil {
		t.Fatalf("F02-22: /metrics: %v", err)
	}
	metricsBody, _ := io.ReadAll(metricsResp.Body)
	_ = metricsResp.Body.Close()
	if metricsResp.StatusCode != http.StatusOK || len(metricsBody) == 0 {
		t.Fatalf("F02-22: /metrics = %d len %d", metricsResp.StatusCode, len(metricsBody))
	}

	// CORS preflight echoes the configured origin.
	pre, _ := http.NewRequest(http.MethodOptions, bs.baseURL+"/v1/chat/completions", nil)
	pre.Header.Set("Origin", "https://boot.example")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	preflight, err := http.DefaultClient.Do(pre)
	if err != nil {
		t.Fatalf("F02-22: preflight: %v", err)
	}
	_, _ = io.Copy(io.Discard, preflight.Body)
	_ = preflight.Body.Close()
	if preflight.StatusCode != http.StatusOK && preflight.StatusCode != http.StatusNoContent {
		t.Fatalf("F02-22: preflight = %d", preflight.StatusCode)
	}
	if got := preflight.Header.Get("Access-Control-Allow-Origin"); got != "https://boot.example" {
		t.Fatalf("F02-22: ACAO %q, want https://boot.example", got)
	}

	// The traced main router still denies unauthenticated traffic.
	denied, _ := f02Chat(t, bs.baseURL, "", "", "")
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F02-22: denied chat = %d, want 401", denied.StatusCode)
	}
	if got := up.count(); got != 0 {
		t.Fatalf("F02-22: upstream hits = %d, want 0 (no completion, no shadow mirror)", got)
	}
}

// F02-23 JWT boot: service-account tokens through the real server, dual mode
// with the static key, org identity to the upstream, rejections at the gate.
func fuzzF0223(t *testing.T) {
	t.Helper()
	up := f02UpstreamRecorder(t)
	k := mustRSAJWK(t, "f02-boot-kid")
	jwks := newJWKSServer(t, k)
	jwtw := JWTWiring{
		JWKSURL:       jwks.srv.URL,
		Issuer:        "https://idp.example",
		Audience:      "yabanin-gateway",
		OrgClaim:      "org_id",
		KeyLabelClaim: "key_labels",
	}
	cfg := f02BootConfig(f02FreeAddr(t), up.srv.URL, "f02-boot-key")
	bs := f02BootGateway(t, cfg, f02DeadRedis(), jwtw)

	valid := signToken(t, k, f02OrgClaims(jwtw.Issuer, jwtw.Audience, "org-42"))
	resp, body := f02Chat(t, bs.baseURL, "Bearer "+valid, "f02-jwt-rid", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("F02-23: jwt chat = %d body %s", resp.StatusCode, body)
	}
	if got := up.count(); got != 1 {
		t.Fatalf("F02-23: upstream hits = %d, want exactly 1", got)
	}
	h := up.lastHeader()
	if got := h.Get("X-Org-Id"); got != "org-42" {
		t.Fatalf("F02-23: upstream X-Org-Id %q, want org-42", got)
	}
	if got := h.Get("X-Request-ID"); got != "f02-jwt-rid" {
		t.Fatalf("F02-23: upstream X-Request-ID %q, want f02-jwt-rid", got)
	}

	// Dual mode: the static gateway key still authenticates.
	respKey, _ := f02Chat(t, bs.baseURL, "Bearer f02-boot-key", "", "")
	if respKey.StatusCode != http.StatusOK {
		t.Fatalf("F02-23: static key chat = %d, want 200 (dual mode)", respKey.StatusCode)
	}

	// Expired and garbage tokens never reach the upstream.
	expiredClaims := f02OrgClaims(jwtw.Issuer, jwtw.Audience, "org-42")
	expiredClaims["exp"] = time.Now().Add(-2 * time.Minute).Unix()
	expired := signToken(t, k, expiredClaims)
	respExp, _ := f02Chat(t, bs.baseURL, "Bearer "+expired, "", "")
	if respExp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F02-23: expired token = %d, want 401", respExp.StatusCode)
	}
	respJunk, _ := f02Chat(t, bs.baseURL, "Bearer f02.junk.token", "", "")
	if respJunk.StatusCode != http.StatusUnauthorized {
		t.Fatalf("F02-23: garbage token = %d, want 401", respJunk.StatusCode)
	}
	if got := up.count(); got != 2 {
		t.Fatalf("F02-23: upstream hits = %d, want exactly 2 (jwt + static)", got)
	}
}

// --- corpus wiring -------------------------------------------------------------------

func FuzzFamily02BootLifecycle(f *testing.F) {
	for id := 19; id <= 23; id++ {
		f.Add([]byte{byte(id)}) // frozen regression corpus
	}
	// Generated-boot seeds: static valid, jwt valid, unauthenticated;
	// admin/metrics, spoof, request-id, and tracing flag mixes.
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01})
	f.Add([]byte{0x02, 0x00, 0x01, 0x00, 0x01, 0x00})
	token, wiring := f02BootGenFixture(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 1 && data[0] >= 19 && data[0] <= 23 {
			fuzzF02BootCases[int(data[0])](t)
			return
		}
		f02BootGenerated(t, data, token, wiring)
	})
}

var fuzzF02BootCases = map[int]func(*testing.T){
	19: fuzzF0219,
	20: fuzzF0220,
	21: fuzzF0221,
	22: fuzzF0222,
	23: fuzzF0223,
}

func TestFamily02BootRefusesPaidCallsWithoutAccounting(t *testing.T) {
	t.Run("redis-unreachable", func(t *testing.T) { checkBootAdmissionWithoutStore(t, f02DeadRedis()) })
	t.Run("redis-disabled", func(t *testing.T) { checkBootAdmissionWithoutStore(t, nil) })
}

func checkBootAdmissionWithoutStore(t *testing.T, rdb *redis.Client) {
	t.Helper()
	token, wiring := f02BootGenFixture(t)
	up := f02UpstreamRecorder(t)
	cfg := f02BootConfig(f02FreeAddr(t), up.srv.URL, "test-static")
	server := f02BootGateway(t, cfg, rdb, wiring)
	for _, tc := range []struct {
		name, credential string
		wantStatus       int
	}{
		{"anonymous", "", http.StatusUnauthorized},
		{"static", "Bearer test-static", http.StatusServiceUnavailable},
		{"jwt", "Bearer " + token, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := f02Chat(t, server.baseURL, tc.credential, "boot-check-"+tc.name, "")
			if count := up.count(); count != 0 {
				t.Fatalf("unexpected provider dispatches: %d", count)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("HTTP %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusServiceUnavailable {
				var result struct{ Error struct{ Code string } }
				if err := json.Unmarshal([]byte(body), &result); err != nil || result.Error.Code != "history_unavailable" {
					t.Fatalf("unexpected accounting error envelope: %s", body)
				}
			}
		})
	}
}
