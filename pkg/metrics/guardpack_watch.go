package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// GuardPackRuntimeAdoptionsTotal counts durable guard-pack version adoptions
// applied by a running gateway replica's runtime watcher (card FIX-03 /
// audit CA-02). Every increment corresponds to one atomic hook swap, so the
// counter is the applied-version timeline operators can diff against the
// durable guard_pack_state row.
var GuardPackRuntimeAdoptionsTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "guard_pack_runtime_adoptions_total",
		Help:      "Durable guard-pack versions adopted by a running replica's runtime watcher.",
	},
)

// GuardPackWatchFailuresTotal counts failed runtime-adoption probes: an
// unreadable durable record or a pack version that is not loadable from the
// replica's pack root. The replica keeps enforcing its last known-good hook
// through every failure; a growing counter with a flat adoptions counter is
// the "replica stuck on an old version" alarm.
var GuardPackWatchFailuresTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "guard_pack_watch_failures_total",
		Help:      "Failed guard-pack runtime-adoption probes (store read or pack load); last known-good keeps enforcing.",
	},
)

var guardPackWatchCollectors = []prometheus.Collector{
	GuardPackRuntimeAdoptionsTotal,
	GuardPackWatchFailuresTotal,
}

func init() {
	allCollectors = append(allCollectors, guardPackWatchCollectors...)
}
