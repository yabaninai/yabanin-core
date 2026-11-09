package tracing

// of request logs over OTLP/HTTP (parity: Portkey complete-logs export /
// Bifrost OTel). One gateway request event becomes one OTLP LogRecord carrying
// the GenAI attributes below plus Yabanin attribution.
//
// CONTENT CONTRACT (no content by default): message text and provider error
// bodies are NEVER exported unless the operator opts in with IncludeContent
// (env YABANIN_OTEL_LOGS_* wiring lives in services/run/loggerd.go). With
// IncludeContent=false (the default) the record body stays empty and only the
// content-free attributes below are attached — the exporter is safe to point
// at a third-party collector.
//
// Exported attributes:
//
//	GenAI semconv:
//	  genai.system              provider bucket derived from the upstream
//	                            host (e.g. "openai", "anthropic");
//	                            allowlist-enforced: known hosts map to
//	                            their semconv name, unknown hosts bucket
//	                            to the fixed "other" value — a raw host
//	                            is never exported and the value set stays
//	                            bounded even when upstream base URLs are
//	                            per-tenant; omitted when no upstream URL
//	  genai.operation.name      "chat"
//	  genai.request.model       model_requested
//	  genai.response.model      model_used
//	  genai.usage.input_tokens  tokens_in
//	  genai.usage.output_tokens tokens_out
//	  genai.request.temperature NOT exported — the gateway event carries no
//	Yabanin:
//	  org.id, request.id, yabanin.session_id
//	  yabanin.cost_usd          estimated_cost_usd (float USD)
//	  yabanin.cache_hit         true when the cache layer served the request
//	  yabanin.policy_verdict    policy-pipeline verdict (e.g. "allow", "deny");
//	                            omitted for legacy events without `policy`
//	  yabanin.event_type        completed | failed | budget_exceeded |
//	                            shadow_completed
//	  yabanin.status_code, yabanin.duration_ms
//	  yabanin.error             true when the event carried an error field
//	                            (presence only — the error TEXT is content)
//
// Backpressure: Enqueue never blocks the consumer loop. Records enter a
// bounded channel; on overflow the record is dropped and counted in the
// yabanin_otel_logs_dropped_total Prometheus counter. A single pump goroutine
// feeds the SDK batch processor, which performs the actual OTLP/HTTP export
// with its own bounded queue, so an unreachable collector can only cost
// drops, never consumer latency.
//
// Attribute bounds (N13-P02-T03): every string field is clamped at the
// Enqueue boundary BEFORE the record enters the queue, so the queued record,
// the exported OTLP attributes and both queue layers are bounded by the same
// envelope regardless of what a producer event carried. genai.system stays
// allowlist-bounded (SystemFromUpstreamURL + boundedGenaiSystem); identifier
// attributes (request.id, org.id, yabanin.session_id) remain high-cardinality
// BY DESIGN — they are log-record identifiers, never metric labels.
//
// Queue memory (N13-P02-T03): memory is bounded by construction, not by
// hope — QueueSize is capped by maxLogQueueSize and additionally clamped so
// that the worst case of BOTH layers (the enqueue channel and the SDK batch
// queue, each up to QueueSize records of per-record worst-case size) stays
// within maxQueueMemoryBytes. WorstCaseQueueMemoryBytes reports the exact
// bound; the same limit is documented for operators in
// docs/observability/otel-export.md ("Attribute bounds and queue memory").
//
// Failure visibility: a failed export attempt (collector unreachable,
// rejecting or misconfigured) never aborts the gateway — the error is
// returned to the SDK batch processor, which drops that batch and moves on.
// Every failed attempt is counted in yabanin_otel_export_errors_total and
// WARN-logged at most once per exportErrorLogInterval, so an outage is
// observable on /metrics and in the log without a log storm.
//
// KNOWN LIMIT (documented, not hidden): drops that happen inside the OTel
// SDK — records shed by its internal queue between our queue and the
// network, and records lost with a failed export attempt — are NOT visible
// per-record in any Yabanin counter. yabanin_otel_export_errors_total counts
// the failed ATTEMPT (the outage signal), not the individual records lost
// with it. Memory stays bounded on both layers either way; the same limit is
// documented for operators in docs/observability/otel-export.md
// ("Backpressure and drops").
//
// Sampling is DETERMINISTIC: fnv64a(request_id) maps each request to a
// reproducible decision, so the same request is sampled-or-not consistently
// across retries, replicas and reprocessing (no coin flip).

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

// OTelLogsDroppedTotal counts request-log records dropped because the export
// queue was full (backpressure) or the exporter was shutting down. The name
var OTelLogsDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "yabanin_otel_logs_dropped_total",
	Help: "OTLP request-log records dropped (export queue full or shutdown race); the consumer loop is never blocked.",
})

// otelExportErrorsMetricName is the Prometheus name of OTelExportErrorsTotal.
const otelExportErrorsMetricName = "yabanin_otel_export_errors_total"

// OTelExportErrorsTotal counts FAILED OTLP/HTTP export attempts (collector
// unreachable, rejecting or a client-side request failure). One failed batch
// attempt counts once — this is the outage signal that makes an exporter
// failure visible on /metrics, not a per-record loss ledger. Export is a
// side-sink: the failed attempt is returned to the SDK batch processor,
// which drops that batch and keeps going, so the gateway never stops
// serving because of it.
var OTelExportErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: otelExportErrorsMetricName,
	Help: "Failed OTLP request-log export attempts (collector down/rejecting); export stays non-fatal, failed batches are dropped.",
})

// RequestLog is the content-free projection of one gateway request event used
// to build exactly one OTLP LogRecord. The consumer maps the raw stream
// fields onto this struct; the exporter never sees Redis shapes.
type RequestLog struct {
	// EventType is one of completed, failed, budget_exceeded,
	// shadow_completed (yabanin.event_type).
	EventType string
	// Timestamp is the request's business time (producer ts), not delivery.
	Timestamp time.Time
	RequestID string
	OrgID     string
	SessionID string
	// ModelRequested/ModelUsed map to genai.request.model /
	// genai.response.model.
	ModelRequested string
	ModelUsed      string
	// UpstreamURL is used ONLY to derive genai.system; the URL itself is
	// never exported.
	UpstreamURL string
	StatusCode  int64
	DurationMs  int64
	TokensIn    int64
	TokensOut   int64
	CostUSD     float64
	CacheHit    bool
	// PolicyVerdict is the policy-pipeline verdict, empty for legacy events.
	PolicyVerdict string
	// HasError reports error presence; the error text is never exported.
	HasError bool
	// Content optionally carries the prompt payload sample. It is dropped
	// inside Enqueue unless the exporter was built with IncludeContent=true;
	// with the default (false) the value never leaves the process.
	Content string
}

// LogExporterConfig configures the OTLP/HTTP logs exporter. Zero-value
// duration/size fields take the defaults documented per field.
type LogExporterConfig struct {
	// ServiceName lands in resource service.name (default "loggerd").
	ServiceName string
	// Endpoint is the OTLP/HTTP collector. Either host:port (HTTPS, like
	// the trace exporter) or a full http(s):// URL for plain-HTTP
	// collectors. Empty endpoint means "disabled" — NewLogExporter returns
	// nil and the process behaves bit-for-bit as before. A malformed
	// http(s) URL fails construction: the SDK option would otherwise
	// silently fall back to the default collector (egress to an
	// unconfigured endpoint).
	Endpoint string
	// Headers are attached to every export request (e.g. auth for SaaS
	// collectors).
	Headers map[string]string
	// SampleRate is the deterministic fraction of requests exported
	// (fnv64a of request_id). Clamped to [0,1] (NaN fails closed to 0);
	// default 1.0.
	SampleRate float64
	// IncludeContent opts into exporting the prompt payload sample as the
	// record body. Default false — no message text ever leaves the process.
	IncludeContent bool
	// QueueSize is the bounded enqueue queue (default 4096). Full queue =
	// drop + yabanin_otel_logs_dropped_total. The effective value is
	// clamped at construction: hard cap maxLogQueueSize, then a
	// maxQueueMemoryBytes budget clamp covering BOTH queue layers (see
	// WorstCaseQueueMemoryBytes) — a huge configured value cannot translate
	// into unbounded resident memory.
	QueueSize int
	// ExportInterval is the SDK batch flush interval (default 5s).
	ExportInterval time.Duration
	// ExportBatchSize is the SDK max records per OTLP request (default 512).
	ExportBatchSize int
	// ExportTimeout bounds one OTLP request (default 10s).
	ExportTimeout time.Duration

	// exporterOverride replaces the OTLP/HTTP exporter normally built from
	// Endpoint. Unexported test seam for failing-exporter injection: the
	// production wiring never sets it, and a non-nil value skips exporter
	// construction (no socket, no endpoint parsing) while keeping the same
	// batch-processing pipeline and instrumentation.
	exporterOverride sdklog.Exporter
}

// Defaults mirroring pkg/tracing.Init's trace pipeline.
const (
	defaultLogQueueSize        = 4096
	defaultLogExportInterval   = 5 * time.Second
	defaultLogExportBatchSize  = 512
	defaultLogExportTimeout    = 10 * time.Second
	maxContentExportChars      = 4096
	otelLogInstrumentationName = "yabanin.requestlogs"
)

// Attribute and queue-memory bounds (N13-P02-T03). Every string field is
// clamped at the Enqueue boundary; the queue is clamped at construction so
// the worst case of BOTH bounded layers (the enqueue channel and the SDK
// batch queue) fits a fixed memory budget. The clamps are the enforcement
// of the cardinality contract documented in docs/observability/otel-export.md.
const (
	// maxAttributeBytes bounds identifier/model/verdict attribute values.
	// Real UUIDs are ≤36 bytes and real model names <100; the headroom is
	// deliberate so legitimate long values survive while a hostile or
	// buggy producer cannot inflate per-record memory or mint arbitrarily
	// large attribute values downstream.
	maxAttributeBytes = 256
	// maxEventTypeBytes bounds yabanin.event_type; the live value set has
	// four members ("completed", "failed", "budget_exceeded",
	// "shadow_completed") — the clamp is the defensive boundary.
	maxEventTypeBytes = 64
	// maxUpstreamURLBytes bounds the upstream URL, which is NEVER exported
	// and only feeds genai.system derivation: every allowlist host and
	// suffix pattern resolves from a prefix far shorter than this, so the
	// clamp cannot change any derived value while it keeps the queued
	// record bounded.
	maxUpstreamURLBytes = 512
	// maxLogQueueSize is the hard cap on the configurable queue size,
	// applied to both bounded layers (the enqueue channel and the SDK
	// batch processor's max queue size).
	maxLogQueueSize = 8192
	// maxQueueMemoryBytes is the total worst-case resident-memory budget
	// across both queue layers: 2 × effective QueueSize × per-record
	// worst case must fit. With content opted in this clamps QueueSize
	// below the hard cap; without content the hard cap is the binding
	// limit (64 MiB / (2×2624) ≈ 12786 > 8192).
	maxQueueMemoryBytes = 64 << 20
	// requestLogFixedOverheadBytes is the conservative fixed estimate for
	// one queued RequestLog beyond its clamped strings: struct scalars,
	// time.Time, string headers, and channel-slot overhead rounded up.
	requestLogFixedOverheadBytes = 512
)

// perRecordMaxBytes is the worst-case resident size of ONE queued record
// after all Enqueue-boundary clamps: the fixed overhead plus the per-field
// string caps (six maxAttributeBytes fields + event type + upstream URL),
// plus the content cap only when content export is opted in.
func perRecordMaxBytes(includeContent bool) int {
	n := requestLogFixedOverheadBytes +
		6*maxAttributeBytes +
		maxEventTypeBytes +
		maxUpstreamURLBytes
	if includeContent {
		n += maxContentExportChars
	}
	return n
}

// worstCaseQueueMemoryBytes is the worst-case resident memory of the export
// pipeline's two bounded queue layers: the enqueue channel and the SDK batch
// processor queue each hold at most queueSize records.
func worstCaseQueueMemoryBytes(queueSize int, includeContent bool) int {
	return 2 * queueSize * perRecordMaxBytes(includeContent)
}

// LogExporter exports request logs as OTLP LogRecords with GenAI semconv
// attributes. Enqueue is non-blocking; Shutdown flushes.
type LogExporter struct {
	cfg      LogExporterConfig
	queue    chan RequestLog
	logger   log.Logger
	provider *sdklog.LoggerProvider

	mu      sync.RWMutex // guards closed vs concurrent Enqueue
	closed  bool
	drained chan struct{} // closed by the pump after the queue is empty
}

// NewLogExporter builds the logs pipeline (exporter → batch processor →
// provider). An empty endpoint disables the exporter: it returns (nil, nil)
// and nothing is initialized — no goroutines, no sockets.
func NewLogExporter(ctx context.Context, cfg LogExporterConfig) (*LogExporter, error) {
	return newLogExporter(ctx, cfg, true)
}

// newLogExporter is the constructor body; startPump=false is a test seam that
// leaves the queue undrained so overflow accounting is deterministic.
//
//nolint:nilnil // (nil, nil) IS the documented "disabled" state, not an invalid value: the nil exporter is safe to use (nil-receiver methods) and callers treat it as feature-off
func newLogExporter(ctx context.Context, cfg LogExporterConfig, startPump bool) (*LogExporter, error) {
	if cfg.Endpoint == "" {
		return nil, nil
	}

	// escapes both range comparisons below (all comparisons are false) and
	// would be echoed verbatim by Config(); it fails closed to 0 — the same
	// direction the env layer takes for an unparseable rate.
	switch {
	case cfg.SampleRate <= 0 || math.IsNaN(cfg.SampleRate):
		cfg.SampleRate = 0
	case cfg.SampleRate > 1:
		cfg.SampleRate = 1
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "unknown"
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultLogQueueSize
	}
	// Queue-memory clamp (N13-P02-T03): the hard cap first, then the
	// bytes budget across BOTH layers (enqueue channel + SDK batch queue,
	// each up to QueueSize records of clamped worst-case size). The
	// division floor keeps the invariant by construction, so no loop and
	// no second-guessing: effQueue ≤ maxLogQueueSize AND
	// 2×effQueue×perRecord ≤ maxQueueMemoryBytes.
	if effQueue := maxQueueMemoryBytes / (2 * perRecordMaxBytes(cfg.IncludeContent)); cfg.QueueSize > effQueue {
		cfg.QueueSize = effQueue
	}
	if cfg.QueueSize > maxLogQueueSize {
		cfg.QueueSize = maxLogQueueSize
	}
	if cfg.ExportInterval <= 0 {
		cfg.ExportInterval = defaultLogExportInterval
	}
	if cfg.ExportBatchSize <= 0 {
		cfg.ExportBatchSize = defaultLogExportBatchSize
	}
	if cfg.ExportTimeout <= 0 {
		cfg.ExportTimeout = defaultLogExportTimeout
	}

	var exporter sdklog.Exporter
	switch {
	case cfg.exporterOverride != nil:
		// Test seam: inject a (typically failing) exporter without
		// building a real OTLP client; everything downstream — the
		// failure counter, the batch processor, the bounded queue —
		// stays identical to production.
		exporter = cfg.exporterOverride
	default:
		opts := []otlploghttp.Option{
			otlploghttp.WithTimeout(cfg.ExportTimeout),
		}
		if strings.HasPrefix(cfg.Endpoint, "http://") || strings.HasPrefix(cfg.Endpoint, "https://") {
			// silently ignores an unparseable URL and falls back to the SDK
			// default collector (localhost:4318) — a typo would egress to an
			// unconfigured endpoint. Fail construction instead; callers do
			// log-and-continue (services/run/loggerd.go), so observability
			// never blocks startup.
			u, err := url.Parse(cfg.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("tracing: invalid OTLP logs endpoint URL %q: %w", cfg.Endpoint, err)
			}
			if u.Host == "" {
				return nil, fmt.Errorf("tracing: invalid OTLP logs endpoint URL %q: missing host", cfg.Endpoint)
			}
			opts = append(opts, otlploghttp.WithEndpointURL(cfg.Endpoint))
		} else {
			opts = append(opts, otlploghttp.WithEndpoint(cfg.Endpoint))
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
		}

		otlpExporter, err := otlploghttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("tracing: failed to create OTLP logs exporter: %w", err)
		}
		exporter = otlpExporter
	}
	// Failure visibility: every failed export attempt is counted and
	// rate-limited WARN-logged; the error itself is passed through
	// unchanged, so exporter failures stay visible without becoming fatal.
	exporter = newObservedExporter(exporter)

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithAttributes(
			attribute.String("service.name", cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: failed to create logs resource: %w", err)
	}

	// The SDK batch processor performs the actual OTLP requests on its own
	// goroutine/ticker; its own queue bounds memory when the collector is
	// slow or down. Export failures are visible through observedExporter
	// (yabanin_otel_export_errors_total counts each failed attempt);
	// per-record drops inside the SDK (its queue full, records lost with a
	// failed batch) remain the documented invisible limit — our counter
	// covers the Enqueue boundary the consumer actually hits.
	processor := sdklog.NewBatchProcessor(exporter,
		sdklog.WithMaxQueueSize(cfg.QueueSize),
		sdklog.WithExportInterval(cfg.ExportInterval),
		sdklog.WithExportMaxBatchSize(cfg.ExportBatchSize),
		sdklog.WithExportTimeout(cfg.ExportTimeout),
	)
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(processor),
	)

	e := &LogExporter{
		cfg:      cfg,
		queue:    make(chan RequestLog, cfg.QueueSize),
		logger:   provider.Logger(otelLogInstrumentationName),
		provider: provider,
		drained:  make(chan struct{}),
	}
	if startPump {
		//nolint:contextcheck // the pump deliberately outlives any caller context: exports are the side-sink's own lifecycle (Shutdown flushes), never bound to a consumer request ctx
		go e.pump()
	}
	return e, nil
}

// exportErrorLogInterval rate-limits the WARN line per failing exporter: an
// outage must be visible, not spam the log at batch frequency (the batch
// interval is 5s by default — an hour-long outage would otherwise be ~720
// identical lines). The Prometheus counter counts EVERY failed attempt.
const exportErrorLogInterval = 30 * time.Second

// observedExporter decorates the OTLP log exporter and makes export failures
// visible without changing their outcome: the error is returned to the SDK
// batch processor untouched, which drops that batch and keeps serving, so a
// down collector keeps costing only drops — never consumer latency, never
// gateway availability. A failed attempt bumps OTelExportErrorsTotal and is
// WARN-logged at most once per exportErrorLogInterval. Shutdown/ForceFlush
// are inherited from the wrapped exporter; LogExporter.Shutdown already
// surfaces their results to the caller.
type observedExporter struct {
	sdklog.Exporter

	logMu       sync.Mutex // guards lastLogWarn
	lastLogWarn time.Time
}

func newObservedExporter(inner sdklog.Exporter) *observedExporter {
	return &observedExporter{Exporter: inner}
}

// Export delegates one batch and, on failure, counts the failed attempt and
// emits the rate-limited WARN. The error is never swallowed, wrapped or
// retried here — retry policy belongs to the OTLP client.
func (o *observedExporter) Export(ctx context.Context, records []sdklog.Record) error {
	err := o.Exporter.Export(ctx, records)
	if err != nil {
		OTelExportErrorsTotal.Inc()
		o.warnExportFailure(err)
	}
	return err
}

func (o *observedExporter) warnExportFailure(err error) {
	o.logMu.Lock()
	defer o.logMu.Unlock()
	now := time.Now()
	if !o.lastLogWarn.IsZero() && now.Sub(o.lastLogWarn) < exportErrorLogInterval {
		return
	}
	o.lastLogWarn = now
	slog.Warn("tracing: OTLP request-log export failed (non-fatal; the gateway keeps serving)",
		"error", err,
		"metric", otelExportErrorsMetricName)
}

// Config exposes the effective configuration (defaults applied) for
// startup logging.
func (e *LogExporter) Config() LogExporterConfig { return e.cfg }

// ExportRequestLog satisfies the loggerd consumer's OTelLogSink contract;
// it is Enqueue under its consumer-facing name.
func (e *LogExporter) ExportRequestLog(rec RequestLog) { e.Enqueue(rec) }

// IncludeContent reports whether prompt payload samples are exported
// (the consumer uses it to avoid copying content at all when false).
func (e *LogExporter) IncludeContent() bool { return e != nil && e.cfg.IncludeContent }

// Enqueue offers one record for export. It NEVER blocks: sampling is
// deterministic on RequestID, an overflowing bounded queue drops the record
// and bumps yabanin_otel_logs_dropped_total. Content is dropped here unless
// IncludeContent was enabled at construction. Safe for concurrent use and
// after Shutdown.
//
// Attribute bounds are applied here, BEFORE the queue: the queued record is
// already clamped, so both queue layers and the exported attributes obey the
// same envelope. Sampling runs on the RAW RequestID first (clamping before
// sampling would map long ids sharing a maxAttributeBytes prefix onto one
// sample decision). Truncated strings are freshly materialized (string(cut)),
// so a clamped record no longer pins the producer's original allocation —
// otherwise a megabyte model string truncated to 256 bytes would still hold
// the megabyte alive inside the queue.
func (e *LogExporter) Enqueue(rec RequestLog) {
	if e == nil {
		return
	}
	if !e.cfg.IncludeContent {
		rec.Content = "" // never leaves the process by default
	} else if len(rec.Content) > maxContentExportChars {
		rec.Content = rec.Content[:maxContentExportChars]
	}
	if !e.shouldSample(rec.RequestID) {
		return
	}

	// N13-P02-T03 attribute bounds: identifier/model/verdict values are
	// clamped at the export boundary — value LENGTH is bounded; the
	// genai.system VALUE SET is separately bounded by the allowlist (see
	// boundedGenaiSystem). request.id / org.id / yabanin.session_id stay
	// high-cardinality identifiers by design: they are log-record
	// attributes, never Prometheus labels.
	rec.EventType = boundString(rec.EventType, maxEventTypeBytes)
	rec.RequestID = boundString(rec.RequestID, maxAttributeBytes)
	rec.OrgID = boundString(rec.OrgID, maxAttributeBytes)
	rec.SessionID = boundString(rec.SessionID, maxAttributeBytes)
	rec.ModelRequested = boundString(rec.ModelRequested, maxAttributeBytes)
	rec.ModelUsed = boundString(rec.ModelUsed, maxAttributeBytes)
	rec.PolicyVerdict = boundString(rec.PolicyVerdict, maxAttributeBytes)
	rec.UpstreamURL = boundString(rec.UpstreamURL, maxUpstreamURLBytes)

	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		OTelLogsDroppedTotal.Inc()
		return
	}
	select {
	case e.queue <- rec:
	default:
		OTelLogsDroppedTotal.Inc()
	}
}

// boundString clamps s to at most max bytes WITHOUT splitting a UTF-8 rune
// and materializes a fresh string on the truncation path, so the clamped
// value cannot keep the oversized original allocation alive. s shorter than
// max passes through unchanged; max ≤ 0 yields "".
//
// UTF-8 is self-synchronizing: a lead byte at the cut position means a rune
// starts exactly there, so everything before it is complete runes. Only when
// the byte AT the cut position is a continuation byte (10xxxxxx) was a rune
// split — the truncation then backs up over the split rune's continuation
// bytes AND its lead byte (a dangling lead byte with its continuations cut
// off is not valid UTF-8 either). (The last byte INSIDE cut is never the
// right signal: a complete multi-byte rune always ends with a continuation
// byte.)
func boundString(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	if s[max]&0xC0 == 0x80 { // cut split a rune: remove the partial rune
		for len(cut) > 0 && cut[len(cut)-1]&0xC0 == 0x80 {
			cut = cut[:len(cut)-1]
		}
		// cut now ends at the split rune's lead byte (or is empty).
		if len(cut) > 0 {
			cut = cut[:len(cut)-1]
		}
	}
	return string(cut)
}

// WorstCaseQueueMemoryBytes reports the worst-case resident memory of the
// two bounded queue layers (enqueue channel + SDK batch queue) under the
// EFFECTIVE configuration: 2 × QueueSize × per-record worst case, where
// every string field is at its Enqueue-boundary clamp. The constructor
// clamps QueueSize so this stays within maxQueueMemoryBytes; the value is
// reported for startup logs and operator verification.
func (e *LogExporter) WorstCaseQueueMemoryBytes() int {
	if e == nil {
		return 0
	}
	return worstCaseQueueMemoryBytes(e.cfg.QueueSize, e.cfg.IncludeContent)
}

// shouldSample is the deterministic per-request sampler: fnv64a(request_id)
// finalized with splitmix64, normalized to [0,1) compared against the
// configured rate. The same request_id always maps to the same decision
// (replay/retry stability). The finalizer matters: FNV-1a alone clusters
// inputs that differ only in a trailing byte (consecutive counters share
// high bits), which would band whole id ranges in or out of the sample.
func (e *LogExporter) shouldSample(requestID string) bool {
	if e.cfg.SampleRate >= 1 {
		return true
	}
	if e.cfg.SampleRate <= 0 {
		return false
	}
	return sampleHash(requestID)/float64(math.MaxUint64) < e.cfg.SampleRate
}

// sampleHash is fnv64a followed by the splitmix64 finalizer — a cheap,
// stateless, well-distributed mix with no allocation beyond the digest state.
func sampleHash(s string) float64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	z := h.Sum64() + 0x9e3779b97f4a7c15
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return float64(z ^ (z >> 31))
}

// pump drains the bounded queue into the SDK batch processor. Emit is
// non-blocking (the processor has its own queue), so one pump keeps up with
// the enqueue rate; on Shutdown it exits after the queue is fully drained.
func (e *LogExporter) pump() {
	defer close(e.drained)
	for rec := range e.queue {
		e.emit(rec)
	}
}

// emit renders the record with the GenAI semconv attribute contract and hands
// it to the SDK batch processor.
func (e *LogExporter) emit(rec RequestLog) {
	var r log.Record
	r.SetTimestamp(rec.Timestamp)
	r.SetSeverityText(severityText(rec.EventType))
	r.SetSeverity(severityNumber(rec.EventType))
	r.SetEventName("yabanin.request." + rec.EventType)
	if e.cfg.IncludeContent && rec.Content != "" {
		r.SetBody(attribute.StringValue(rec.Content))
	}

	attrs := make([]attribute.KeyValue, 0, 16)
	attrs = append(attrs,
		attribute.String("yabanin.event_type", rec.EventType),
		attribute.String("genai.operation.name", "chat"),
	)
	if rec.RequestID != "" {
		attrs = append(attrs, attribute.String("request.id", rec.RequestID))
	}
	if rec.OrgID != "" {
		attrs = append(attrs, attribute.String("org.id", rec.OrgID))
	}
	if rec.SessionID != "" {
		attrs = append(attrs, attribute.String("yabanin.session_id", rec.SessionID))
	}
	// genai.system passes the allowlist policy gate before export: the
	// derived value is already bounded, and the clamp keeps that contract
	// true at the boundary no matter how a future path derives it.
	if system := boundedGenaiSystem(SystemFromUpstreamURL(rec.UpstreamURL)); system != "" {
		attrs = append(attrs, attribute.String("genai.system", system))
	}
	if rec.ModelRequested != "" {
		attrs = append(attrs, attribute.String("genai.request.model", rec.ModelRequested))
	}
	if rec.ModelUsed != "" {
		attrs = append(attrs, attribute.String("genai.response.model", rec.ModelUsed))
	}
	if rec.TokensIn > 0 {
		attrs = append(attrs, attribute.Int64("genai.usage.input_tokens", rec.TokensIn))
	}
	if rec.TokensOut > 0 {
		attrs = append(attrs, attribute.Int64("genai.usage.output_tokens", rec.TokensOut))
	}
	if rec.StatusCode != 0 {
		attrs = append(attrs, attribute.Int64("yabanin.status_code", rec.StatusCode))
	}
	if rec.DurationMs > 0 {
		attrs = append(attrs, attribute.Int64("yabanin.duration_ms", rec.DurationMs))
	}
	if rec.CostUSD != 0 {
		attrs = append(attrs, attribute.Float64("yabanin.cost_usd", rec.CostUSD))
	}
	if rec.CacheHit {
		attrs = append(attrs, attribute.Bool("yabanin.cache_hit", true))
	}
	if rec.PolicyVerdict != "" {
		attrs = append(attrs, attribute.String("yabanin.policy_verdict", rec.PolicyVerdict))
	}
	if rec.HasError {
		attrs = append(attrs, attribute.Bool("yabanin.error", true))
	}
	r.AddAttributes(attrs...)

	// The batch processor's Emit enqueues internally and never blocks.
	e.logger.Emit(context.Background(), r)
}

// severityText/number follow the OTLP severity table: completed and shadow
// records are INFO, budget blocks are WARN, failures are ERROR.
func severityText(eventType string) string {
	switch eventType {
	case "failed":
		return "ERROR"
	case "budget_exceeded":
		return "WARN"
	default:
		return "INFO"
	}
}

func severityNumber(eventType string) log.Severity {
	switch eventType {
	case "failed":
		return log.SeverityError
	case "budget_exceeded":
		return log.SeverityWarn
	default:
		return log.SeverityInfo
	}
}

// Shutdown drains the bounded queue into the SDK pipeline and flushes pending
// batches to the collector, bounded by ctx. Safe to call more than once.
func (e *LogExporter) Shutdown(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		close(e.queue)
	}
	e.mu.Unlock()

	select {
	case <-e.drained:
	case <-ctx.Done():
		return ctx.Err()
	}
	return e.provider.Shutdown(ctx)
}

// genaiSystemOther is the fixed bucket for upstream hosts outside the
// label values: unbounded genai.system cardinality would blow up the
// metrics backend and the OTel backend alike.
const genaiSystemOther = "other"

// genaiSystemByHost maps known upstream hosts to GenAI semconv system values.
// Unknown hosts bucket to "other" (genaiSystemOther) — the raw host is never
// exported, so the attribute's value set stays bounded by the allowlist
// regardless of how many tenants configure their own upstream base URLs.
var genaiSystemByHost = map[string]string{
	"api.openai.com":                    "openai",
	"api.anthropic.com":                 "anthropic",
	"generativelanguage.googleapis.com": "gemini",
	"aiplatform.googleapis.com":         "vertex_ai",
	"api.deepseek.com":                  "deepseek",
	"api.mistral.ai":                    "mistral_ai",
	"api.x.ai":                          "x_ai",
	"api.cohere.com":                    "cohere",
	"api.cohere.ai":                     "cohere",
	"openrouter.ai":                     "openrouter",
	"api.groq.com":                      "groq",
	"api.together.xyz":                  "together",
	"api.fireworks.ai":                  "fireworks",
	"api.perplexity.ai":                 "perplexity",
}

// SystemFromUpstreamURL derives the genai.system value from the upstream
// provider URL: a known host (exact or suffix pattern) maps to its semconv
// system name, any unknown host maps to the fixed bucket "other", an unusable
// URL maps to "" (attribute omitted). The value set is bounded: {allowlist
// systems, "other"} — never the raw host.
func SystemFromUpstreamURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	if s, ok := genaiSystemByHost[host]; ok {
		return s
	}
	switch {
	case strings.HasSuffix(host, ".amazonaws.com") && strings.Contains(host, "bedrock"):
		return genaiSystemAWSBedrock
	case strings.HasSuffix(host, ".openai.azure.com"):
		return genaiSystemAzureOpenAI
	case strings.HasSuffix(host, ".api.sambanova.ai"):
		return genaiSystemSambaNova
	}
	return genaiSystemOther
}

// Suffix-rule system values: produced only by the suffix patterns above.
const (
	genaiSystemAWSBedrock  = "aws.bedrock"
	genaiSystemAzureOpenAI = "azure.ai.openai"
	genaiSystemSambaNova   = "sambanova"
)

// genaiSystemValues is the CLOSED value domain of the genai.system
// attribute: every allowlist system, every suffix-rule system and the fixed
// "other" bucket — nothing else. The raw host of an upstream URL is not a
// member and can never become one.
var genaiSystemValues = func() map[string]struct{} {
	values := make(map[string]struct{}, len(genaiSystemByHost)+4)
	for _, s := range genaiSystemByHost {
		values[s] = struct{}{}
	}
	for _, s := range []string{
		genaiSystemAWSBedrock, genaiSystemAzureOpenAI, genaiSystemSambaNova, genaiSystemOther,
	} {
		values[s] = struct{}{}
	}
	return values
}()

// boundedGenaiSystem enforces the genai.system allowlist at the export
// boundary: a value inside the closed domain passes unchanged, any other
// non-empty value is DROPPED BY POLICY into the fixed "other" bucket (never
// forwarded), and "" stays "" (attribute omitted). SystemFromUpstreamURL
// already derives only bounded values; this clamp is the defensive gate that
// keeps the cardinality contract true even if a future code path derives the
// attribute differently.
func boundedGenaiSystem(system string) string {
	if system == "" {
		return ""
	}
	if _, ok := genaiSystemValues[system]; ok {
		return system
	}
	return genaiSystemOther
}
