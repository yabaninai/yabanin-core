package mcpserver

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// counterVec reads one labeled counter value from a *prometheus.CounterVec.
func counterVec(t *testing.T, vec *prometheus.CounterVec, labelValues ...string) float64 {
	t.Helper()
	return testutil.ToFloat64(vec.WithLabelValues(labelValues...))
}
