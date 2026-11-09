package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusHandler returns an http.Handler that serves /metrics in the
// Prometheus exposition format. It is safe to call even before Init().
func PrometheusHandler() http.Handler {
	return promhttp.Handler()
}

// PrometheusMiddleware returns a chi middleware that records HTTP request count
// and duration histograms via Prometheus.
func PrometheusMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code.
			pw := &prometheusWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(pw, r)

			duration := time.Since(start).Seconds()

			// AF-16: the label must stay a bounded route pattern. The raw
			// URL path would let any unmatched request (e.g. scanner noise
			// against unknown paths) mint a permanent new label value and
			// grow the series cardinality without bound.
			path := chi.RouteContext(r.Context()).RoutePattern()
			if path == "" {
				path = "unmatched" // request never matched a registered route pattern
			}

			method := r.Method
			status := strconv.Itoa(pw.statusCode)

			RequestsTotal.WithLabelValues(method, path, status).Inc()
			RequestDurationSeconds.WithLabelValues(method, path).Observe(duration)
		})
	}
}

// prometheusWriter wraps http.ResponseWriter to capture the status code.
type prometheusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (pw *prometheusWriter) WriteHeader(code int) {
	pw.statusCode = code
	pw.ResponseWriter.WriteHeader(code)
}
