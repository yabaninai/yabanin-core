package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// Exercise the production constructors and router with both optional stores absent.
func TestPaidAdmissionWithoutStoresThroughGateway(t *testing.T) {
	var dispatches atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dispatches.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(provider.Close)

	key := mustRSAJWK(t, "admission-test")
	jwks := newJWKSServer(t, key)
	wiring := JWTWiring{JWKSURL: jwks.srv.URL, Issuer: "https://idp.example", Audience: "yabanin-gateway", OrgClaim: "org_id"}
	cfg := newGatewayConfig("strict", "local-test-key", "")
	cfg.Provider = provider.URL
	log := fuzzDiscardLogger()
	gw, err := buildGateway(cfg, nil, nil, log, t.Context(), wiring, CircuitScopeWiring{})
	require.NoError(t, err)
	router, _, _ := newGatewayHTTPRouter(cfg, log)
	gw.routes(router)

	for _, tc := range []struct {
		name, token string
		status      int
	}{
		{"anonymous", "", http.StatusUnauthorized},
		{"static", "local-test-key", http.StatusServiceUnavailable},
		{"jwt", signToken(t, key, baseClaims()), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"smart","messages":[{"role":"user","content":"hello"}]}`))
			req.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, req)
			require.Zero(t, dispatches.Load())
			require.Equal(t, tc.status, resp.Code, resp.Body.String())
			if tc.status == http.StatusServiceUnavailable {
				var result struct{ Error struct{ Code string } }
				require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
				require.Equal(t, "history_unavailable", result.Error.Code)
			}
		})
	}
}

func TestRealtimeRequiresFlushingBeforeAdmission(t *testing.T) {
	wire := realtimeBoundaryWire(t, "trailing")
	var arrivals atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrivals.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, wire)
	}))
	t.Cleanup(provider.Close)
	gw := r105TestGateway(t, realtimeTestModel(provider.URL))
	store := &fakeInvocationStore{}
	gw.invocations = store
	buffered := r105GatewayServer(t, gw, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(struct{ http.ResponseWriter }{w}, r)
		})
	})
	const request = `{"model":"m","input":"boundary"}`
	refused := r105RealPost(t, buffered, "/v1/realtime", request)
	defer refused.Body.Close()
	require.Equal(t, http.StatusNotImplemented, refused.StatusCode)
	require.Zero(t, arrivals.Load())
	store.mu.Lock()
	admitted, attemptedFacts := len(store.admitted), store.factsCalls
	store.mu.Unlock()
	require.Zero(t, admitted)
	require.Zero(t, attemptedFacts)

	streaming := r105GatewayServer(t, gw)
	served := r105RealPost(t, streaming, "/v1/realtime", request)
	defer served.Body.Close()
	require.Equal(t, http.StatusOK, served.StatusCode)
	got, err := io.ReadAll(served.Body)
	require.NoError(t, err)
	require.Equal(t, wire, string(got))
	require.EqualValues(t, 1, arrivals.Load())
	store.mu.Lock()
	defer store.mu.Unlock()
	require.Len(t, store.admitted, 1)
	require.Len(t, store.facts, 1)
}
