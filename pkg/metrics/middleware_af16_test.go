package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registryHasLabeledSeries reports whether the default registry currently
// gathers a series with the exact metric name and label set.
func registryHasLabeledSeries(t *testing.T, name string, labels map[string]string) bool {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			if len(got) == len(labels) {
				match := true
				for k, v := range labels {
					if got[k] != v {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
	}
	return false
}

// AF-16: the request path label must stay a bounded route pattern. The
// middleware used to fall back to the raw URL path for requests that matched
// no route, so any 404 scanner noise minted a permanent new
// gateway_http_requests_total series. Now every non-routed request collapses
// into the fixed "unmatched" label, while routed requests keep their chi
// route template.
func TestMiddleware_UnmatchedPathIsBoundedLabel(t *testing.T) {
	r := chi.NewRouter()
	r.Use(PrometheusMiddleware())
	r.Get("/orgs/{orgID}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Routed request: the concrete URL (path + query) must never reach the
	// label — only the chi template. Counters are process-global, so with
	// in-process test repeats (-count=N) prior runs' increments persist:
	// assert DELTAS around each request, never absolute values.
	routedBefore := testutil.ToFloat64(RequestsTotal.WithLabelValues(http.MethodGet, "/orgs/{orgID}", "200"))
	res := httptest.NewRecorder()
	r.ServeHTTP(res, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/orgs/org-abc?leak=1", nil))
	require.Equal(t, http.StatusOK, res.Code)
	assert.InDelta(t, routedBefore+1,
		testutil.ToFloat64(RequestsTotal.WithLabelValues(http.MethodGet, "/orgs/{orgID}", "200")),
		0.001, "routed requests are labelled by the chi route pattern")

	// Scanner-style unmatched noise: distinct raw paths share one label.
	unmatchedBefore := testutil.ToFloat64(RequestsTotal.WithLabelValues(http.MethodGet, "unmatched", "404"))
	noisyPaths := []string{"/.env", "/admin/secret", "/wp-login.php", "/a/b/c/d/e"}
	for _, p := range noisyPaths {
		res := httptest.NewRecorder()
		r.ServeHTTP(res, httptest.NewRequestWithContext(context.Background(), http.MethodGet, p, nil))
		require.Equal(t, http.StatusNotFound, res.Code)
	}
	assert.InDelta(t, unmatchedBefore+float64(len(noisyPaths)),
		testutil.ToFloat64(RequestsTotal.WithLabelValues(http.MethodGet, "unmatched", "404")),
		0.001, "all unmatched requests collapse into the fixed 'unmatched' label value")

	// Negative (the audited defect): the middleware minted no series keyed
	// by any raw unmatched path — neither for the counter nor for the
	// duration histogram.
	for _, p := range noisyPaths {
		assert.False(t, registryHasLabeledSeries(t, "gateway_http_requests_total",
			map[string]string{"method": http.MethodGet, "path": p, "status": "404"}),
			"raw unmatched path must never become a counter label value: %q", p)
		assert.False(t, registryHasLabeledSeries(t, "gateway_http_request_duration_seconds",
			map[string]string{"method": http.MethodGet, "path": p}),
			"raw unmatched path must never become a histogram label value: %q", p)
	}

	// The histogram carries exactly the same bounded fallback label.
	assert.True(t, registryHasLabeledSeries(t, "gateway_http_request_duration_seconds",
		map[string]string{"method": http.MethodGet, "path": "unmatched"}),
		"unmatched requests are observed under the fixed 'unmatched' path label")
}
