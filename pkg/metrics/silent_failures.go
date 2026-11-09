package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// a swallowed error visible (fallback branches, cache invalidation errors,
// best-effort writes), instead of ad-hoc counters per incident.

// LeaderFnFailedTotal counts leader-election workload invocations that
// returned a non-nil error (loggerd Leader.Lead). Previously the error was
// discarded (`_ = fn(leaderCtx)`), making repeated workload crashes invisible.
var LeaderFnFailedTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "leader_fn_failed_total",
		Help: "Leader election workload functions that exited with an error.",
	},
)

// RegionCacheInvalidateFailedTotal counts failed region-cache mutations
// (regionrouter): op="set" covers Resolve write-back (positive and negative
// cache), op="del" covers Invalidate. A failed mutation silently forces DB
// lookups or leaves a stale region mapping cached until TTL.
var RegionCacheInvalidateFailedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "region_cache_invalidate_failed_total",
		Help: "Failed region-cache mutations (op=set/del); stale entries persist until TTL.",
	},
	[]string{"op"},
)

// SilentFailuresTotal counts errors swallowed at best-effort / fallback
//   - place:  the code site class, a bounded enum from silentFailurePlaces;
//   - reason: what was swallowed, a bounded enum per place — never request
//     identifiers, org ids, model names or other high-cardinality values.
//
// The label set is closed: increments go through SilentFailure, which
// rejects unregistered (place, reason) pairs, so the series count is fixed
// by the registry below and cannot explode at runtime.
var SilentFailuresTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gateway_silent_failures_total",
		Help: "Errors swallowed at best-effort/fallback sites, by place and reason (IMP-98 silent-failure map).",
	},
	[]string{"place", "reason"},
)

// Silent-failure places of the unified counter. Each entry lists the bounded
// reason set; a new call site must register its pair here first.
var silentFailurePlaces = map[string][]string{
	// Responses→chat request translation: an optional field with malformed
	// JSON keeps its zero value and the request proceeds without it
	// (pkg/apiformat responses_to_chat.go).
	"apiformat_request_parse": {
		"prompt_cache_key", "stream", "message_item", "image_url",
		"function_call", "tool_output", "system_text", "tool_format",
		"reasoning", "user",
	},
	// Responses SSE translation: a data frame that fails to decode is
	// skipped instead of failing the stream (pkg/apiformat
	// responses_stream.go).
	"apiformat_stream_parse": {"chunk_decode"},
	// Loggerd consumer ingest: a payload that fails to decode is stored
	// without its derived linkage/labels and falls back to the reconcile
	// path (services/loggerd/consumer). "policy" is the OP-9 decision-log
	// payload: a malformed/invalid `policy` field skips the decision row
	// (the request log still lands) — counted, never wedged.
	"audit_ingest_decode": {"reservations", "labels", "settlement_link", "tool_frame", "policy"},
	// CORE-TRACE-05 decision envelope: a producer stamps an envelope_version
	// this consumer does not know. The decision row still lands (stripped
	// version marker), but nothing inside the unknown version is interpreted
	// — the counter keeps that interpretation gap observable
	// (services/loggerd/consumer/policy_decisions.go).
	"audit_ingest_policy_envelope": {"unknown_version"},
	// CORE-TRACE-05 trace-completeness stamp (G4, producer pkg/gateway →
	// request_logs.labels): a stamped label this consumer cannot interpret
	// is stripped before storage and counted here. "unknown_version" — the
	// producer envelope version is newer (or corrupt); "invalid_value" —
	// vocabulary or reason-grammar violation. The request row still lands;
	// only the marker is dropped (services/loggerd/consumer).
	"audit_ingest_trace_completeness": {"unknown_version", "invalid_value"},
	// MCP/A2A aggregator audit trails: a failing audit write is swallowed —
	// availability over audit (pkg/mcpagg, pkg/a2aagg).
	"mcp_audit_write": {"log_failed"},
	"a2a_audit_write": {"log_failed"},
	// Gateway analytics/audit event funnel (pkg/gateway events.go): every
	// event that never leaves the producer is the start of a history gap.
	// "backlog_full" — the in-process publish semaphore was saturated, so
	// the event was skipped synchronously; "publish_failed" — the bounded
	// retries against the stream (Redis) were exhausted (queue outage).
	"event_publish": {"backlog_full", "publish_failed"},
}

// silentFailureCounter is the lookup key → Counter child, built at init so
// SilentFailure stays allocation-free on the hot path and every registered
// pair is exposed on /metrics with value 0 from process start.
var silentFailureCounter = func() map[string]prometheus.Counter {
	m := make(map[string]prometheus.Counter, 16)
	for place, reasons := range silentFailurePlaces {
		for _, reason := range reasons {
			m[place+"\x00"+reason] = SilentFailuresTotal.WithLabelValues(place, reason)
		}
	}
	return m
}()

// SilentFailure increments the silent-failure counter for a registered
// (place, reason) pair. Unregistered pairs panic: the map is closed by
// design, and a typo must fail in tests, not silently grow cardinality in
// production.
func SilentFailure(place, reason string) {
	c, ok := silentFailureCounter[place+"\x00"+reason]
	if !ok {
		panic(fmt.Sprintf("metrics: unregistered silent-failure pair place=%q reason=%q — add it to silentFailurePlaces", place, reason))
	}
	c.Inc()
}

// SilentFailureEntry documents one counter of the silent-failure map.
// keep their own metric names — they are reused, not re-counted under
// gateway_silent_failures_total (no double counting).
type SilentFailureEntry struct {
	// Name is the Prometheus metric name as exposed on /metrics.
	Name string
	// Labels is the label set (empty for unlabelled counters).
	Labels []string
	// Owner is the package that increments it.
	Owner string
	// Note is what a non-zero value means operationally.
	Note string
}

// SilentFailureMap is the registry of every silent-failure counter: the
// unified gateway_silent_failures_total series plus the legacy counters that
// cover the same failure class. A panel can chart the map as
// `sum by (place, reason) (gateway_silent_failures_total)` plus the four
// legacy names.
var SilentFailureMap = func() []SilentFailureEntry {
	entries := []SilentFailureEntry{
		{
			Name:   "gateway_silent_failures_total",
			Labels: []string{"place", "reason"},
			Owner:  "pkg/metrics SilentFailure",
			Note:   "Unified map; series are exactly the silentFailurePlaces pairs above.",
		},
		{
			Name:  "leader_fn_failed_total",
			Owner: "services/loggerd/consumer (IMP-92)",
			Note:  "Leader workload exited with an error.",
		},
		{
			Name:   "region_cache_invalidate_failed_total",
			Labels: []string{"op"},
			Owner:  "pkg/regionrouter (IMP-92)",
			Note:   "Region-cache mutation failed; stale entry lives until TTL (op=set also covers the Resolve write-back).",
		},
		{
			Name:  "credit_audit_dropped_total",
			Owner: "services/admin/handlers (IMP-12)",
			Note:  "Credit audit entry dropped because the bounded audit queue was full.",
		},
		{
			Name:  "cache_write_queue_drops_total",
			Owner: "pkg/cache",
			Note:  "Best-effort cache write job dropped because the write queue was full.",
		},
	}
	return entries
}()

// silentCollectors is appended to allCollectors in init() so Init()
// registers the unified counter alongside the HTTP/circuit ones.
var silentCollectors = []prometheus.Collector{
	SilentFailuresTotal,
}

func init() {
	allCollectors = append(allCollectors, silentCollectors...)
}
