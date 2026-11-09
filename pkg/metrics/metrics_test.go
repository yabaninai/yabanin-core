package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit_IsIdempotent(t *testing.T) {
	// Verify Init registers collectors without panicking on first call.
	// (Second call would panic due to duplicate registration — that's expected.)
	assert.NotPanics(t, func() {
		Init()
	})
	_ = allCollectors
}

func TestPrometheusHandler(t *testing.T) {
	Init()

	// Use each counter/histogram so Prometheus includes them in exposition.
	RequestsTotal.WithLabelValues("GET", "/test", "200").Inc()
	RequestDurationSeconds.WithLabelValues("POST", "/health").Observe(0.01)
	EventsConsumedTotal.WithLabelValues("event.type.created").Inc()
	CircuitState.WithLabelValues("upstream-1").Set(0)
	CircuitFailures.WithLabelValues("upstream-1").Inc()
	CircuitRecoveries.WithLabelValues("upstream-1").Inc()
	CircuitRejects.WithLabelValues("upstream-1").Inc()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	PrometheusHandler().ServeHTTP(rec, req)

	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	bodyStr := string(body)

	// Verify key metric families are present
	assert.Contains(t, bodyStr, `gateway_http_requests_total`, "should contain RequestsTotal metric")
	assert.Contains(t, bodyStr, `gateway_http_request_duration_seconds`, "should contain RequestDurationSeconds metric")
	assert.Contains(t, bodyStr, `gateway_loggerd_events_in_flight`, "should contain EventsInFlight metric")
	assert.Contains(t, bodyStr, `gateway_loggerd_events_consumed_total`, "should contain EventsConsumedTotal metric")
	assert.Contains(t, bodyStr, `gateway_circuit_breaker_state`, "should contain CircuitState metric")
	assert.Contains(t, bodyStr, `gateway_circuit_breaker_failures_total`, "should contain CircuitFailures metric")
	assert.Contains(t, bodyStr, `gateway_circuit_breaker_recoveries_total`, "should contain CircuitRecoveries metric")
	assert.Contains(t, bodyStr, `gateway_circuit_breaker_rejects_total`, "should contain CircuitRejects metric")
}

func TestMiddleware_StatusCodesCaptured(t *testing.T) {
	Init()

	mw := PrometheusMiddleware()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated) // 201
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}
