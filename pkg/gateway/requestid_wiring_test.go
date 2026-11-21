package cli

// REQID — production request-ID wiring (unit tier: no Docker, no Redis, no
// DB). The mock-browser symptom this pins: after the budget precondition
// expires the gateway answers HTTP 200, but the response X-Request-ID is
// null for a client-supplied ID. Root cause: the production chain mounted
// chi's middleware.RequestID, which never writes the response header, and
// pkg/requestid.Inject — the package that owns the contract (echo the
// client's X-Request-ID verbatim, carry it in the context for upstream
// propagation and event persistence, generate req_<hex> only when absent) —
// was never mounted outside tests. Test harnesses that re-declare their own
// chi router cannot see that; these tests mount the REAL production chain
// (newGatewayHTTPRouter, the single place RunGatewayServerWithJWT mounts
// it) and drive it with a real HTTP client.

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// reqidRecordingUpstream is the mock model provider: it records the
// X-Request-ID of every upstream call and answers a minimal OpenAI
// completion with usage.
type reqidRecordingUpstream struct {
	srv *httptest.Server
	mu  sync.Mutex
	ids []string
}

func startReqidUpstream(t *testing.T) *reqidRecordingUpstream {
	t.Helper()
	u := &reqidRecordingUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		u.mu.Lock()
		u.ids = append(u.ids, id)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(w, `{"id":"reqid-up","object":"chat.completion","model":"stub-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`); err != nil {
			t.Errorf("write upstream completion: %v", err)
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *reqidRecordingUpstream) requestIDs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.ids...)
}

// reqidUnitServer builds the unit-tier stand: a minimal gateway (strict
// static-key auth, no DB/Redis — org attribution is empty and no event is
// published) mounted on the REAL production middleware chain plus the real
// routes, served over real TCP.
func reqidUnitServer(t *testing.T, u *reqidRecordingUpstream) *httptest.Server {
	t.Helper()
	cfg := config.Gateway{
		AuthMode:      "strict",
		APIKey:        "test-key",
		Provider:      u.srv.URL,
		FallbackModel: "stub-model",
	}
	gw := &gateway{
		cfg:  cfg,
		log:  slog.New(slog.DiscardHandler),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"stub-model": {ModelName: "stub-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}},
		pool: upstream.NewPool(upstream.Options{BaseURL: u.srv.URL}),
	}
	router, _, _ := newGatewayHTTPRouter(gw.cfg, gw.log)
	gw.routes(router)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

// reqidUnitPost drives a real HTTP client POST /v1/chat/completions with the
// given request ID ("" = header absent). Returns the status and echoed request ID.
func reqidUnitPost(t *testing.T, srv *httptest.Server, requestID string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"stub-model","messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Logf("POST /v1/chat/completions request-id=%q -> %d %s", requestID, resp.StatusCode, body)
	return resp.StatusCode, resp.Header.Get("X-Request-ID")
}

// REQID-U1: a client-supplied X-Request-ID is echoed on the response
// verbatim and reaches the upstream with the same value — exact identity,
// not a generated or reformatted stand-in.
func TestRequestIDWiring_ClientIDEchoedAndPropagated(t *testing.T) {
	u := startReqidUpstream(t)
	srv := reqidUnitServer(t, u)
	const clientID = "reqid-unit-client-7f3a2b"

	status, echoed := reqidUnitPost(t, srv, clientID)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, clientID, echoed,
		"the production chain must echo the client's X-Request-ID verbatim")

	ids := u.requestIDs()
	require.NotEmpty(t, ids, "the request must have reached the upstream")
	assert.Equal(t, clientID, ids[len(ids)-1],
		"the upstream hop must carry the same request ID")
}

// REQID-U2: when the header is absent the production chain generates an ID
// (requestid's req_<hex> format), echoes it, and propagates it upstream;
// distinct requests get distinct IDs.
func TestRequestIDWiring_GeneratedWhenAbsent(t *testing.T) {
	u := startReqidUpstream(t)
	srv := reqidUnitServer(t, u)

	status, id1 := reqidUnitPost(t, srv, "")
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, id1, "an ID must be generated when the client sends none")
	assert.True(t, strings.HasPrefix(id1, "req_"),
		"generated IDs use the requestid package format, got %q", id1)
	ids := u.requestIDs()
	require.NotEmpty(t, ids)
	assert.Equal(t, id1, ids[len(ids)-1], "the upstream hop must carry the generated ID")

	status, id2 := reqidUnitPost(t, srv, "")
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2, "distinct requests must not share a generated ID")
}

// REQID-U3: the response header is set BEFORE routing, so it survives paths
// that never reach a handler: a 404 and an auth denial (401) still carry the
// client's ID — the mock browser can correlate every answer, not just 200s.
func TestRequestIDWiring_HeaderPresentOnErrorPaths(t *testing.T) {
	u := startReqidUpstream(t)
	srv := reqidUnitServer(t, u)

	// Unknown path → chi's 404; the chain already ran.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/v1/nope", nil)
	require.NoError(t, err)
	req.Header.Set("X-Request-ID", "reqid-unit-404")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "reqid-unit-404", resp.Header.Get("X-Request-ID"),
		"a 404 response must still carry the request ID")

	// Invalid key → 401 from the auth middleware inside /v1; chain already ran.
	req2, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"stub-model","messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer wrong-key")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Request-ID", "reqid-unit-401")
	resp2, err := srv.Client().Do(req2)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode, "tenant denial must not be weakened")
	assert.Equal(t, "reqid-unit-401", resp2.Header.Get("X-Request-ID"),
		"a 401 response must still carry the request ID")
	assert.Empty(t, u.requestIDs(), "a denied request must not reach the upstream")
}
