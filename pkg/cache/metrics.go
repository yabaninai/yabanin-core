// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CacheHitsTotal counts cache hits by type (exact, semantic, miss).
	//
	// AF-16: the per-org label was removed — org_id values are raw tenant
	// identifiers and made the series cardinality grow without bound with
	// org churn. Per-org hit-rate analytics remain available through the
	// in-memory Analytics snapshot (GET /api/cache/analytics).
	CacheHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total number of cache hits by lookup type.",
		},
		[]string{"type"}, // type: exact | semantic | miss
	)

	// CacheWritesTotal counts cache writes, including drops from queue overflow.
	CacheWritesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_writes_total",
			Help: "Total number of cache write attempts.",
		},
		[]string{"status"}, // status: queued | written | failed | skipped | dropped
	)

	// CachePurgedTotal counts expired entries removed from each backend.
	CachePurgedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_purged_total",
			Help: "Total number of cache entries purged by TTL.",
		},
		[]string{"backend"}, // backend: redis | pgvector
	)

	// CacheSizeGauge reports the current number of entries in each backend.
	CacheSizeGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cache_size",
			Help: "Current number of entries in the cache by backend.",
		},
		[]string{"backend"}, // backend: redis | pgvector
	)

	// CacheLatencySeconds measures lookup latency in seconds.
	CacheLatencySeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cache_lookup_duration_seconds",
			Help:    "Cache lookup duration in seconds by type.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
		},
		[]string{"type"}, // type: exact | semantic
	)

	// CacheWriteQueueSize gauges the current size of the write job queue.
	CacheWriteQueueSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "cache_write_queue_size",
			Help: "Current number of pending cache write jobs.",
		},
	)

	// CacheWriteQueueDropsTotal counts dropped write jobs due to full queue.
	CacheWriteQueueDropsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_write_queue_drops_total",
			Help: "Total number of cache write jobs dropped due to full queue.",
		},
	)

	// CacheEmbeddingErrorsTotal counts embedding service failures.
	CacheEmbeddingErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_embedding_errors_total",
			Help: "Total number of embedding service errors during cache write.",
		},
	)

	// CacheSimilarityScore is a histogram of cosine similarity values on semantic hits.
	CacheSimilarityScore = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cache_similarity_score",
			Help:    "Cosine similarity score for semantic cache hits (0..1).",
			Buckets: prometheus.LinearBuckets(0.9, 0.02, 6), // 0.9, 0.92, ..., 1.0
		},
	)

	// CacheJanitorRunsTotal counts janitor cleanup runs.
	CacheJanitorRunsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_janitor_runs_total",
			Help: "Total number of TTL janitor cleanup runs.",
		},
	)

	// CacheJanitorDeletedTotal counts entries deleted by the janitor.
	CacheJanitorDeletedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_janitor_deleted_total",
			Help: "Total number of cache entries deleted by the TTL janitor.",
		},
	)

	// CacheJanitorErrorsTotal counts janitor errors.
	CacheJanitorErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_janitor_errors_total",
			Help: "Total number of errors encountered by the TTL janitor.",
		},
	)

	// CacheEmbedFlightBusyTotal counts embedding lookups degraded to a
	// cache miss because the N03-P05 stampede flight limit was reached.
	// These lookups made NO upstream embedding call. Sustained growth means
	// the limit (or the embedder's capacity) is undersized for the traffic.
	CacheEmbedFlightBusyTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_embed_flight_busy_total",
			Help: "Embedding lookups degraded to a cache miss by the stampede flight limit (no upstream call).",
		},
	)

	// CacheRedisPartitionTotal counts exact-layer lookups that ran in Redis
	// partition mode (N03-P05-T04): the backend errored as unavailable or
	// the cooldown presumes it down. These lookups are coalesced instead of
	// multiplying into independent upstream calls. Sustained growth means
	// Redis (or the network to it) is unhealthy.
	CacheRedisPartitionTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_redis_partition_total",
			Help: "Exact-cache lookups served in Redis-partition mode (backend unavailable or presumed down).",
		},
	)

	// CachePartitionCoalescedTotal counts waiters served a published payload
	// by a partition flight — upstream calls avoided by the guard.
	CachePartitionCoalescedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_partition_coalesced_total",
			Help: "Lookups coalesced onto a published partition-flight payload (upstream calls avoided).",
		},
	)

	// CachePartitionLeasesTotal counts leadership mandates granted to
	// partition-flight waiters: each may produce exactly one upstream call,
	// bounding the upstream attempt rate per hot key at one per lease window.
	CachePartitionLeasesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_partition_leases_total",
			Help: "Leadership mandates granted to partition-flight waiters (bounded upstream attempts).",
		},
	)

	// CachePartitionOverflowTotal counts lookups that found the partition
	// flight table full and failed open as independent misses (bounded by
	// maxPartitionFlights). Growth with healthy Redis is normal; growth
	// during incidents means key diversity exceeds the coalescing capacity.
	CachePartitionOverflowTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_partition_overflow_total",
			Help: "Lookups that exceeded the partition flight table cap and failed open un-coalesced.",
		},
	)

	// CacheEnforcementOffSkippedTotal counts cache operations (lookups and
	// writes) silenced at the policy-regime gate because tenant policy
	// enforcement was off or unverifiable for the org (N03-P02-T04: the
	// armed regime resolver answered ""). These operations produce no
	// hit/miss/write signals of their own, so without this counter a gated
	// lookup is indistinguishable from an organic miss in the metrics.
	// Sustained nonzero growth means an org (or the stand) runs with
	// enforcement off or unverifiable while clients keep sending cacheable
	// traffic; a spike right after a control-plane change points at regime
	// resolution failing (N03-P02-T05).
	CacheEnforcementOffSkippedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_enforcement_off_skipped_total",
			Help: "Cache operations (lookups and writes) skipped because tenant policy enforcement was off or unverifiable for the org (no cache layer or queue touched).",
		},
	)

	// CacheABArmTotal counts A/B experiment arm assignments for cache behavior.
	CacheABArmTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_ab_arm_total",
			Help: "A/B experiment arm assignments (control=treatments) for cache decisions.",
		},
		[]string{"variant", "experiment_id"}, // variant: control | treatment
	)
)

// RecordHit records a cache hit by type (exact|semantic). The org dimension
// intentionally does not exist here (AF-16: bounded cardinality, no raw
// tenant identifiers in metric labels).
func RecordHit(hitType string) {
	CacheHitsTotal.WithLabelValues(hitType).Inc()
}

// RecordMiss records a cache miss for the miss type of CacheHitsTotal.
func RecordMiss() {
	CacheHitsTotal.WithLabelValues("miss").Inc()
}

// RecordWrite records a cache write status.
func RecordWrite(status string) {
	CacheWritesTotal.WithLabelValues(status).Inc()
}

// RecordPurge records entries purged from a backend.
func RecordPurge(backend string, count int) {
	for i := 0; i < count; i++ {
		CachePurgedTotal.WithLabelValues(backend).Inc()
	}
}

// RecordLatency measures lookup latency.
func RecordLatency(hitType string, duration float64) {
	CacheLatencySeconds.WithLabelValues(hitType).Observe(duration)
}

// RecordWriteQueueSize updates the write queue size gauge.
func RecordWriteQueueSize(size int64) {
	CacheWriteQueueSize.Set(float64(size))
}

// RecordWriteDrops increments the total dropped writes counter.
func RecordWriteDrops(count int64) {
	for i := int64(0); i < count; i++ {
		CacheWriteQueueDropsTotal.Inc()
	}
}

// RecordEmbeddingErrors increments the embedding error counter.
func RecordEmbeddingErrors(count int64) {
	for i := int64(0); i < count; i++ {
		CacheEmbeddingErrorsTotal.Inc()
	}
}

// RecordSimilarity records a semantic cache hit similarity score.
func RecordSimilarity(score float32) {
	CacheSimilarityScore.Observe(float64(score))
}

// RecordJanitorRun increments the janitor run counter.
func RecordJanitorRun() {
	CacheJanitorRunsTotal.Inc()
}

// RecordJanitorDeleted counts entries deleted by the janitor.
func RecordJanitorDeleted(count int) {
	for i := 0; i < count; i++ {
		CacheJanitorDeletedTotal.Inc()
	}
}

// RecordJanitorError increments the janitor error counter.
func RecordJanitorError() {
	CacheJanitorErrorsTotal.Inc()
}

// RecordEmbedFlightBusy counts an embedding lookup that hit the stampede
// flight limit and degraded to a cache miss without an upstream call.
func RecordEmbedFlightBusy() {
	CacheEmbedFlightBusyTotal.Inc()
}

// RecordRedisPartition counts an exact-layer lookup that entered Redis
// partition mode (classified outage or cooldown skip).
func RecordRedisPartition() {
	CacheRedisPartitionTotal.Inc()
}

// RecordPartitionCoalesced counts a waiter served from a published partition
// flight payload (an upstream call avoided).
func RecordPartitionCoalesced() {
	CachePartitionCoalescedTotal.Inc()
}

// RecordPartitionLease counts a leadership mandate granted to a waiter (one
// bounded upstream attempt).
func RecordPartitionLease() {
	CachePartitionLeasesTotal.Inc()
}

// RecordPartitionOverflow counts a lookup that failed open because the
// partition flight table was at its cap.
func RecordPartitionOverflow() {
	CachePartitionOverflowTotal.Inc()
}

// RecordEnforcementOffSkip counts one cache operation silenced at the
// policy-regime gate (armed resolver answered "" — enforcement off or
// unverifiable for the org). The operation performed no lookup, no write and
// touched no cache layer or queue; it would otherwise surface as a plain
// miss (and, on the write path, as nothing at all).
func RecordEnforcementOffSkip() {
	CacheEnforcementOffSkippedTotal.Inc()
}

// RecordABArm records an A/B experiment arm assignment for cache decisions.
func RecordABArm(variant, experimentID string) {
	CacheABArmTotal.WithLabelValues(variant, experimentID).Inc()
}
