package consumer

// boundaries — consumer delivery entry (processMessage, the same boundary as
// (not a recording fake) → a real OTLP/HTTP collector stub over the network.
//
// Card criteria proven here:
//   - a delivered request event arrives at the collector as an OTLP
//     ExportLogsServiceRequest carrying the BOUNDED genai.system bucket
//     (ratified D1: a tenant-controlled upstream host must surface as the
//     fixed "other" bucket, never the raw host; allowlisted hosts keep their
//     provider name);
//   - on sink failure the consumer delivery stays healthy (commit path
//     unaffected) and the record is dropped AT OUR BOUNDARY, counted in
//     yabanin_otel_logs_dropped_total (the honest D-3 boundary: losses inside
//     the SDK batch processor are out of sight by design).
//
// in-process consumer + real exporter over real HTTP to a loopback stub;
// the fresh-OS-process service boundary is covered separately by the
// int-class TestEgressStartupFreshProcess_* tests (services/run).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/tracing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"
)

// pipelineCollector is the collector stub for the pipeline tests: it decodes
// OTLP/HTTP ExportLogsServiceRequest bodies and keeps every LogRecord with
// its attributes for boundary assertions.
type pipelineCollector struct {
	mu      sync.Mutex
	records []*logspb.LogRecord
	batches int
	notify  chan struct{}
}

func newPipelineCollector(t *testing.T) (*pipelineCollector, *httptest.Server) {
	t.Helper()
	c := &pipelineCollector{notify: make(chan struct{}, 64)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = r.Body.Close() }()
		var req collectorlogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		for _, rl := range req.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				c.records = append(c.records, sl.GetLogRecords()...)
			}
		}
		c.batches++
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		select {
		case c.notify <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *pipelineCollector) snapshot() ([]*logspb.LogRecord, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*logspb.LogRecord(nil), c.records...), c.batches
}

func (c *pipelineCollector) waitFor(t *testing.T, cond func(recs []*logspb.LogRecord) bool) []*logspb.LogRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		recs, _ := c.snapshot()
		if cond(recs) {
			return recs
		}
		select {
		case <-c.notify:
		case <-time.After(20 * time.Millisecond):
		}
	}
	recs, _ := c.snapshot()
	return recs
}

// pipelineAttrs flattens one received LogRecord into key→string-value pairs.
func pipelineAttrs(rec *logspb.LogRecord) map[string]string {
	out := make(map[string]string, len(rec.GetAttributes()))
	for _, kv := range rec.GetAttributes() {
		out[kv.GetKey()] = kv.GetValue().GetStringValue()
	}
	return out
}

// pipelineSinkCfg builds a REAL exporter config against the stub collector:
// fast batch interval so records surface without Shutdown, small bounded
// queue (backpressure stays bounded by construction).
func pipelineSinkCfg(endpoint string) tracing.LogExporterConfig {
	return tracing.LogExporterConfig{
		ServiceName:     "loggerd-pipeline-test",
		Endpoint:        endpoint,
		SampleRate:      1.0,
		QueueSize:       8,
		ExportInterval:  25 * time.Millisecond,
		ExportBatchSize: 4,
		ExportTimeout:   2 * time.Second,
	}
}

// pipeline (consumer delivery → real LogExporter → OTLP/HTTP collector stub)
// and arrives exactly once, with genai.system bucketed per ratified D1 — a
// tenant-controlled upstream host lands in the fixed "other" bucket (the raw
// host must appear NOWHERE in the record), an allowlisted host keeps its
// provider name. No content leaves the process (default opt-out).
func TestOTelExportPipeline_RealSinkDeliversBucketedGenAISystem(t *testing.T) {
	collector, srv := newPipelineCollector(t)
	sink, err := tracing.NewLogExporter(context.Background(), pipelineSinkCfg(srv.URL))
	require.NoError(t, err)
	require.NotNil(t, sink)
	t.Cleanup(func() { _ = sink.Shutdown(context.Background()) })

	c := New(&mockRedis{}, &mockDB{}, "otel-pipeline-stream", silentLogger())
	c.SetOTelSink(sink)

	tenantFields := requestFields("req-pipeline-tenant-1")
	tenantFields["upstream_url"] = "https://tenant-07.proxy.example.com:9443/v1"
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "1-0", Values: tenantFields}))

	allowFields := requestFields("req-pipeline-openai-2")
	allowFields["upstream_url"] = "https://api.openai.com/v1/chat/completions"
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "2-0", Values: allowFields}))

	recs := collector.waitFor(t, func(recs []*logspb.LogRecord) bool { return len(recs) >= 2 })
	require.Len(t, recs, 2, "both delivered events must reach the collector exactly once")

	byRequestID := map[string]*logspb.LogRecord{}
	for _, rec := range recs {
		byRequestID[pipelineAttrs(rec)["request.id"]] = rec
	}

	tenant := byRequestID["req-pipeline-tenant-1"]
	require.NotNil(t, tenant, "tenant event must arrive")
	tenantAttrs := pipelineAttrs(tenant)
	assert.Equal(t, "other", tenantAttrs["genai.system"],
		"ratified D1: tenant-controlled host must bucket to the fixed value, never leak")
	assert.Equal(t, "completed", tenantAttrs["yabanin.event_type"])
	for key, value := range tenantAttrs {
		assert.NotContains(t, value, "tenant-07.proxy.example.com",
			"raw host must not appear in any attribute (leak in %q)", key)
	}
	assert.Empty(t, tenant.GetBody().GetStringValue(), "no content may leave the process by default")

	openai := byRequestID["req-pipeline-openai-2"]
	require.NotNil(t, openai, "allowlisted event must arrive")
	assert.Equal(t, "openai", pipelineAttrs(openai)["genai.system"],
		"allowlisted host keeps its provider bucket")
}

// the deterministic form of an unavailable sink), consumer deliveries stay
// healthy (the commit path is untouched, error-free), the record is dropped
// at OUR export boundary and counted in yabanin_otel_logs_dropped_total, and
// the collector receives nothing further. Memory stays bounded: the drop is
// immediate, nothing accumulates.
func TestOTelExportPipeline_SinkFailureDropsCountedDeliveryUnaffected(t *testing.T) {
	before := testutil.ToFloat64(tracing.OTelLogsDroppedTotal)

	collector, srv := newPipelineCollector(t)
	sink, err := tracing.NewLogExporter(context.Background(), pipelineSinkCfg(srv.URL))
	require.NoError(t, err)
	require.NotNil(t, sink)

	c := New(&mockRedis{}, &mockDB{}, "otel-pipeline-stream", silentLogger())
	c.SetOTelSink(sink)

	// Baseline through the healthy pipeline: the event arrives.
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{
		ID: "1-0", Values: requestFields("req-pipeline-sinkfail-1"),
	}))
	recs := collector.waitFor(t, func(recs []*logspb.LogRecord) bool { return len(recs) >= 1 })
	require.Len(t, recs, 1)
	assert.InDelta(t, before, testutil.ToFloat64(tracing.OTelLogsDroppedTotal), 0,
		"a healthy pipeline must not drop anything")

	// Sink fails (shut down — the definite unavailable-sink state).
	require.NoError(t, sink.Shutdown(context.Background()))

	// The consumer keeps delivering: the commit path is unaffected, the
	// record is dropped at the export boundary and COUNTED.
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{
		ID: "2-0", Values: requestFields("req-pipeline-sinkfail-2"),
	}), "sink failure must not affect consumer delivery")
	assert.InDelta(t, before+1, testutil.ToFloat64(tracing.OTelLogsDroppedTotal), 0,
		"the dropped record must be counted in yabanin_otel_logs_dropped_total")

	// Nothing further reaches the collector, and the count stays exact.
	time.Sleep(150 * time.Millisecond)
	recs, batches := collector.snapshot()
	assert.Len(t, recs, 1, "the dropped record must never arrive")
	assert.Equal(t, 1, batches, "no further export requests may hit the sink")
}
