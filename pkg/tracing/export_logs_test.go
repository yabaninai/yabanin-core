package tracing

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// otlpCollector is a minimal OTLP/HTTP logs collector for tests: it accepts
// protobuf ExportLogsServiceRequest bodies and accumulates every LogRecord.
type otlpCollector struct {
	t  *testing.T
	mu sync.Mutex

	records []*logspb.LogRecord
	batches int
	// authHeaders records one entry per received export request: the
	// Authorization header it carried ("" when absent).
	authHeaders []string

	// exportNotify is signalled once per received export request.
	exportNotify chan struct{}
}

func newOTLPCollector(t *testing.T) (*otlpCollector, *httptest.Server) {
	t.Helper()
	c := &otlpCollector{t: t, exportNotify: make(chan struct{}, 64)}
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
		c.authHeaders = append(c.authHeaders, r.Header.Get("Authorization"))
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		// OTLP responses are a (usually empty) protobuf message; the
		// exporter tolerates an empty body.
		select {
		case c.exportNotify <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *otlpCollector) snapshot() ([]*logspb.LogRecord, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.records, c.batches
}

// requestAuth returns the per-request Authorization header capture.
func (c *otlpCollector) requestAuth() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.authHeaders...)
}

// waitFor waits until cond observes the accumulated records, bounded by 5s.
func (c *otlpCollector) waitFor(t *testing.T, cond func(recs []*logspb.LogRecord) bool) []*logspb.LogRecord {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recs, _ := c.snapshot()
		if cond(recs) {
			return recs
		}
		time.Sleep(10 * time.Millisecond)
	}
	recs, _ := c.snapshot()
	return recs
}

func attrMap(rec *logspb.LogRecord) map[string]*commonpb.AnyValue {
	out := make(map[string]*commonpb.AnyValue, len(rec.GetAttributes()))
	for _, kv := range rec.GetAttributes() {
		out[kv.GetKey()] = kv.GetValue()
	}
	return out
}

func attrString(t *testing.T, m map[string]*commonpb.AnyValue, key string) (string, bool) {
	t.Helper()
	v, ok := m[key]
	if !ok || v.GetStringValue() == "" {
		return "", false
	}
	return v.GetStringValue(), true
}

func attrInt64(t *testing.T, m map[string]*commonpb.AnyValue, key string) (int64, bool) {
	t.Helper()
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch {
	case v.GetIntValue() != 0:
		return v.GetIntValue(), true
	case v.GetDoubleValue() != 0:
		return int64(v.GetDoubleValue()), true
	default:
		return 0, true // present and zero
	}
}

func attrBool(t *testing.T, m map[string]*commonpb.AnyValue, key string) (bool, bool) {
	t.Helper()
	v, ok := m[key]
	if !ok {
		return false, false
	}
	return v.GetBoolValue(), true
}

func attrFloat64(t *testing.T, m map[string]*commonpb.AnyValue, key string) (float64, bool) {
	t.Helper()
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	return v.GetDoubleValue(), true
}

func testCfg(endpoint string) LogExporterConfig {
	return LogExporterConfig{
		ServiceName:     "loggerd-test",
		Endpoint:        endpoint,
		SampleRate:      1.0,
		QueueSize:       64,
		ExportInterval:  50 * time.Millisecond,
		ExportBatchSize: 16,
		ExportTimeout:   2 * time.Second,
	}
}

// fullRecord is a request.completed record with every attribute populated.
func fullRecord() RequestLog {
	return RequestLog{
		EventType:      "completed",
		Timestamp:      time.UnixMilli(1759800000000),
		RequestID:      "req-otel-1",
		OrgID:          "org-42",
		SessionID:      "sess-7",
		ModelRequested: "gpt-5-mini",
		ModelUsed:      "gpt-5",
		UpstreamURL:    "https://api.openai.com/v1/chat/completions",
		StatusCode:     200,
		DurationMs:     1234,
		TokensIn:       100,
		TokensOut:      57,
		CostUSD:        0.0042,
		CacheHit:       true,
		PolicyVerdict:  "allow",
		Content:        "SECRET PROMPT TEXT never-exported-by-default",
	}
}

// and Yabanin attribute contract attached.
func TestLogExporter_ExportsGenAISemconvBatch(t *testing.T) {
	collector, srv := newOTLPCollector(t)
	e, err := NewLogExporter(context.Background(), testCfg(srv.URL))
	require.NoError(t, err)
	require.NotNil(t, e)

	e.Enqueue(fullRecord())
	e.Enqueue(RequestLog{
		EventType:      "failed",
		Timestamp:      time.UnixMilli(1759800000001),
		RequestID:      "req-otel-2",
		OrgID:          "org-42",
		ModelRequested: "claude-sonnet-5",
		ModelUsed:      "claude-sonnet-5",
		UpstreamURL:    "https://api.anthropic.com/v1/messages",
		StatusCode:     502,
		HasError:       true,
	})

	recs := collector.waitFor(t, func(recs []*logspb.LogRecord) bool { return len(recs) >= 2 })
	require.Len(t, recs, 2)

	byID := map[string]*logspb.LogRecord{}
	for _, r := range recs {
		m := attrMap(r)
		id, _ := attrString(t, m, "request.id")
		byID[id] = r
	}

	completed := byID["req-otel-1"]
	require.NotNil(t, completed, "completed record missing")
	m := attrMap(completed)

	for key, want := range map[string]string{
		"genai.system":           "openai",
		"genai.operation.name":   "chat",
		"genai.request.model":    "gpt-5-mini",
		"genai.response.model":   "gpt-5",
		"org.id":                 "org-42",
		"request.id":             "req-otel-1",
		"yabanin.session_id":     "sess-7",
		"yabanin.policy_verdict": "allow",
		"yabanin.event_type":     "completed",
	} {
		got, ok := attrString(t, m, key)
		require.True(t, ok, "attribute %s missing", key)
		assert.Equal(t, want, got, "attribute %s", key)
	}
	for key, want := range map[string]int64{
		"genai.usage.input_tokens":  100,
		"genai.usage.output_tokens": 57,
		"yabanin.status_code":       200,
		"yabanin.duration_ms":       1234,
	} {
		got, ok := attrInt64(t, m, key)
		require.True(t, ok, "attribute %s missing", key)
		assert.Equal(t, want, got, "attribute %s", key)
	}
	cacheHit, ok := attrBool(t, m, "yabanin.cache_hit")
	if assert.True(t, ok, "yabanin.cache_hit missing") {
		assert.True(t, cacheHit)
	}
	cost, ok := attrFloat64(t, m, "yabanin.cost_usd")
	require.True(t, ok, "yabanin.cost_usd missing")
	assert.InDelta(t, 0.0042, cost, 1e-9)

	// Severity + timestamps.
	assert.Equal(t, "INFO", completed.GetSeverityText())
	assert.Equal(t, logspb.SeverityNumber(9), completed.GetSeverityNumber())
	assert.Equal(t, uint64(1759800000000000000), completed.GetTimeUnixNano())

	// NO CONTENT (default): the body must be empty even though the record
	// carried Content. (The SDK transmits an empty AnyValue body rather
	// than omitting the field.)
	assert.Empty(t, completed.GetBody().GetStringValue(), "record body must be empty with include_content=false")

	// The failed record: ERROR severity, error presence flag, no error text.
	failed := byID["req-otel-2"]
	require.NotNil(t, failed, "failed record missing")
	assert.Equal(t, "ERROR", failed.GetSeverityText())
	assert.Equal(t, logspb.SeverityNumber(17), failed.GetSeverityNumber())
	fm := attrMap(failed)
	sys, ok := attrString(t, fm, "genai.system")
	require.True(t, ok)
	assert.Equal(t, "anthropic", sys)
	errFlag, ok := attrBool(t, fm, "yabanin.error")
	if assert.True(t, ok, "yabanin.error missing") {
		assert.True(t, errFlag)
	}
	assert.Empty(t, failed.GetBody().GetStringValue(), "error text must never be exported")

	require.NoError(t, e.Shutdown(context.Background()))
}

// transitively; opting in exports it as the record body.
func TestLogExporter_ContentGating(t *testing.T) {
	collector, srv := newOTLPCollector(t)
	cfg := testCfg(srv.URL)
	cfg.IncludeContent = true
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)

	e.Enqueue(fullRecord())
	recs := collector.waitFor(t, func(recs []*logspb.LogRecord) bool { return len(recs) >= 1 })
	require.Len(t, recs, 1)
	require.NotNil(t, recs[0].GetBody(), "opted-in content must be the record body")
	assert.Equal(t, "SECRET PROMPT TEXT never-exported-by-default", recs[0].GetBody().GetStringValue())
	require.NoError(t, e.Shutdown(context.Background()))

	// Default: IncludeContent=false — the same record exports body-less.
	collector2, srv2 := newOTLPCollector(t)
	e2, err := NewLogExporter(context.Background(), testCfg(srv2.URL))
	require.NoError(t, err)
	assert.False(t, e2.IncludeContent())
	e2.Enqueue(fullRecord())
	recs2 := collector2.waitFor(t, func(recs []*logspb.LogRecord) bool { return len(recs) >= 1 })
	require.Len(t, recs2, 1)
	assert.Empty(t, recs2[0].GetBody().GetStringValue(), "no content by default")
	require.NoError(t, e2.Shutdown(context.Background()))
}

func TestLogExporter_SampleZeroSuppressesEverything(t *testing.T) {
	collector, srv := newOTLPCollector(t)
	cfg := testCfg(srv.URL)
	cfg.SampleRate = 0
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, e)

	for i := 0; i < 20; i++ {
		rec := fullRecord()
		rec.RequestID = "sampled-away-" + strconv.Itoa(i)
		e.Enqueue(rec)
	}
	// Past two batch intervals: nothing may have been exported.
	time.Sleep(200 * time.Millisecond)
	recs, batches := collector.snapshot()
	assert.Empty(t, recs, "sample=0 must export no records")
	assert.Zero(t, batches)
	require.NoError(t, e.Shutdown(context.Background()))
}

// Deterministic sampling: the same request_id always maps to the same
// decision; across many ids both outcomes occur for an interior rate.
func TestLogExporter_DeterministicSampling(t *testing.T) {
	_, srv := newOTLPCollector(t)
	cfg := testCfg(srv.URL)
	cfg.SampleRate = 0.5
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)

	// Same id → same decision, 100 repetitions.
	rec := fullRecord()
	stable := e.shouldSample(rec.RequestID)
	for i := 0; i < 100; i++ {
		assert.Equal(t, stable, e.shouldSample(rec.RequestID), "sampling must be deterministic per request_id")
	}

	sampled, unsampled := 0, 0
	for i := 0; i < 500; i++ {
		if e.shouldSample("request-" + strconv.Itoa(i)) {
			sampled++
		} else {
			unsampled++
		}
	}
	assert.Positive(t, sampled, "interior rate must sample some requests")
	assert.Positive(t, unsampled, "interior rate must skip some requests")
	require.NoError(t, e.Shutdown(context.Background()))
}

// enqueues stay non-blocking and drops are counted once the bounded queue
// (simulated here with an undrained queue) is full.
func TestLogExporter_QueueOverflowDropsAndNeverBlocks(t *testing.T) {
	before := testutil.ToFloat64(OTelLogsDroppedTotal)

	// Point at an unreachable endpoint AND skip the pump so the queue stays
	// full — deterministic overflow without timing races.
	cfg := testCfg("http://127.0.0.1:1") // port 1: nothing listens
	cfg.QueueSize = 2
	e, err := newLogExporter(context.Background(), cfg, false)
	require.NoError(t, err)
	require.NotNil(t, e)

	rec := fullRecord()
	e.Enqueue(rec) // queue 1/2
	e.Enqueue(rec) // queue 2/2

	start := time.Now()
	e.Enqueue(rec) // overflow → drop, counted, no block
	assert.Less(t, time.Since(start), time.Second, "enqueue must never block")
	e.Enqueue(rec) // second overflow

	assert.InDelta(t, before+2, testutil.ToFloat64(OTelLogsDroppedTotal), 0, "two dropped records must be counted")
}

// Records offered after Shutdown are dropped (counted), never panic.
func TestLogExporter_EnqueueAfterShutdownDrops(t *testing.T) {
	before := testutil.ToFloat64(OTelLogsDroppedTotal)

	collector, srv := newOTLPCollector(t)
	e, err := NewLogExporter(context.Background(), testCfg(srv.URL))
	require.NoError(t, err)
	require.NoError(t, e.Shutdown(context.Background()))

	e.Enqueue(fullRecord())
	assert.InDelta(t, before+1, testutil.ToFloat64(OTelLogsDroppedTotal), 0)
	recs, _ := collector.snapshot()
	assert.Empty(t, recs)
}

// Graceful shutdown flushes records accepted after the last batch interval.
func TestLogExporter_ShutdownFlushesPending(t *testing.T) {
	collector, srv := newOTLPCollector(t)
	e, err := NewLogExporter(context.Background(), testCfg(srv.URL))
	require.NoError(t, err)

	e.Enqueue(fullRecord()) // no sleep: only Shutdown can flush in time
	require.NoError(t, e.Shutdown(context.Background()))
	recs := collector.waitFor(t, func(recs []*logspb.LogRecord) bool { return len(recs) >= 1 })
	require.Len(t, recs, 1, "Shutdown must flush the pending record")
}

// Empty endpoint disables the exporter entirely: nil sink, no error.
func TestLogExporter_DisabledWithoutEndpoint(t *testing.T) {
	e, err := NewLogExporter(context.Background(), testCfg(""))
	require.NoError(t, err)
	assert.Nil(t, e, "empty endpoint must disable the exporter")

	// A nil exporter is a safe no-op everywhere.
	e.Enqueue(fullRecord())
	e.ExportRequestLog(fullRecord())
	assert.False(t, e.IncludeContent())
	assert.NoError(t, e.Shutdown(context.Background()))
}

func TestSystemFromUpstreamURL(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://api.openai.com/v1/chat/completions", "openai"},
		{"https://api.anthropic.com/v1/messages", "anthropic"},
		{"https://generativelanguage.googleapis.com/v1beta/models", "gemini"},
		{"https://aiplatform.googleapis.com/v1/projects", "vertex_ai"},
		{"https://api.deepseek.com/chat/completions", "deepseek"},
		{"https://openrouter.ai/api/v1", "openrouter"},
		{"https://bedrock-runtime.us-east-1.amazonaws.com/model/x", "aws.bedrock"},
		{"https://foo.openai.azure.com/openai/deployments", "azure.ai.openai"},
		// the rule had no direct case). Subdomains of .api.sambanova.ai map
		// to "sambanova"; spoofed and apex hosts fail safe below.
		{"https://api-01.team.api.sambanova.ai/v1/chat/completions", "sambanova"},
		// Suffix rules apply to the HOST only — path tricks and lookalike
		// TLDs must never smuggle a provider label through.
		{"https://api.sambanova.ai.evil.com/v1", "other"},
		{"https://openai.azure.com.attacker.io/openai/deployments", "other"},
		// The apex host does not carry the ".api.sambanova.ai" suffix the
		// rule matches on: ratified D1 behavior is the fixed fail-safe
		// bucket, not a per-host exception.
		{"https://api.sambanova.ai/v1", "other"},
		// Userinfo, casing, ports, IPv6: only the hostname decides, and it
		// is lowercased with the port stripped before matching.
		{"https://user:pass@api.openai.com/v1", "openai"},
		{"https://API.OpenAI.COM/v1", "openai"},
		{"https://api.anthropic.com:8443/v1", "anthropic"},
		{"https://[::1]/v1", "other"},
		{"https://some-gateway.example.com/v1", "other"}, // unknown host → fixed bucket
		{"https://10.0.0.7:8443/v1", "other"},            // raw IP host → fixed bucket
		{"https://tenant-42.proxy.corp.internal:9443/v1", "other"},
		// Unusable inputs degrade to "" (attribute omitted), never to a
		// guessed or raw-host label.
		{"", ""},
		{"::::", ""},                       // unusable → no host → omitted
		{"api.openai.com/v1", ""},          // schemeless: no Host field → omitted, never "openai"
		{"https://", ""},                   // scheme without host
		{"https://example.com/%zz", ""},    // invalid percent-escape → parse error
		{"ht\ttp://api.openai.com/v1", ""}, // control byte → parse error
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, SystemFromUpstreamURL(tc.url), "url %q", tc.url)
	}
}

// host must collapse into the fixed "other" bucket, so the exported value set
// can never grow with the number of tenants or upstream base URLs.
func TestSystemFromUpstreamURL_CardinalityBounded(t *testing.T) {
	seen := make(map[string]struct{})
	add := func(url string) {
		seen[SystemFromUpstreamURL(url)] = struct{}{}
	}
	// Known allowlist entries keep their provider names.
	for _, url := range []string{
		"https://api.openai.com/v1",
		"https://bedrock-runtime.eu-west-1.amazonaws.com/model/x",
		"https://bar.openai.azure.com/openai/deployments",
		"https://api-01.team.api.sambanova.ai/v1/chat/completions",
	} {
		add(url)
	}
	// Tenant-controlled upstreams: distinct hosts, ports, IPs, casing,
	// userinfo tricks — every one of them must land in "other".
	for i := 0; i < 100; i++ {
		add("https://tenant-" + strconv.Itoa(i) + ".proxy.example.com/v1")
		add("https://gateway" + strconv.Itoa(i) + ".internal:" + strconv.Itoa(8000+i) + "/v1")
		add("https://10.1." + strconv.Itoa(i) + ".5/v1")
		add("https://UPPER-" + strconv.Itoa(i) + ".Example.COM/v1")
	}
	delete(seen, "") // no-URL records carry no attribute at all
	assert.Equal(t, map[string]struct{}{"openai": {}, "aws.bedrock": {}, "azure.ai.openai": {}, "sambanova": {}, "other": {}}, seen,
		"genai.system value set must stay bounded: allowlist systems + the fixed %q bucket, never raw hosts", genaiSystemOther)
}

// Sample rates are clamped into [0,1] at construction.
func TestLogExporter_SampleRateClamped(t *testing.T) {
	_, srv := newOTLPCollector(t)
	for _, rate := range []float64{-5, 0, 42} {
		cfg := testCfg(srv.URL)
		cfg.SampleRate = rate
		e, err := NewLogExporter(context.Background(), cfg)
		require.NoError(t, err)
		want := rate
		if rate < 0 {
			want = 0
		} else if rate > 1 {
			want = 1
		}
		assert.InDelta(t, want, e.Config().SampleRate, 1e-9)
		require.NoError(t, e.Shutdown(context.Background()))
	}
}

// Standard OTel env vars must never enable the logs exporter: only the
// explicit LogExporterConfig.Endpoint decides egress. With the configured
// endpoint empty the constructor returns the disabled nil sink and the
// env-targeted local collector receives nothing.
func TestLogExporter_EnvCannotEnableExport(t *testing.T) {
	collector, srv := newOTLPCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", srv.URL)

	e, err := NewLogExporter(context.Background(), testCfg(""))
	require.NoError(t, err)
	require.Nil(t, e, "empty configured endpoint must disable the exporter regardless of OTel env")
	e.Enqueue(fullRecord()) // nil-receiver no-op by contract
	recs, batches := collector.snapshot()
	assert.Empty(t, recs, "the env-targeted collector must receive no records")
	assert.Zero(t, batches)
}

// A configured exporter egresses ONLY to its configured endpoint: every
// accepted record reaches it carrying the configured headers, and a second
// local listener receives nothing. Shutdown flushes before the counts are
// read, so the assertions are deterministic.
func TestLogExporter_ConfiguredEndpointIsTheOnlyEgress(t *testing.T) {
	collector, srv := newOTLPCollector(t)
	stranger, _ := newOTLPCollector(t)
	cfg := testCfg(srv.URL)
	cfg.Headers = map[string]string{"Authorization": "Bearer synthetic-local"}
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		rec := fullRecord()
		rec.RequestID = "only-egress-" + strconv.Itoa(i)
		e.Enqueue(rec)
	}
	require.NoError(t, e.Shutdown(context.Background()))

	recs, batches := collector.snapshot()
	assert.Len(t, recs, 3, "all accepted records must reach the configured endpoint")
	assert.Positive(t, batches)
	for _, auth := range collector.requestAuth() {
		assert.Equal(t, "Bearer synthetic-local", auth, "every export request carries the configured header")
	}
	sRecs, sBatches := stranger.snapshot()
	assert.Empty(t, sRecs, "a non-configured local listener must receive nothing")
	assert.Zero(t, sBatches)
}

// flakyCollector accepts or rejects every export request depending on the
// accept flag; rejected (non-retryable 500) batches are dropped inside the
// SDK batch processor and never surface as records.
type flakyCollector struct {
	t *testing.T

	accept   atomic.Bool
	mu       sync.Mutex
	records  []*logspb.LogRecord
	attempts int
	notify   chan struct{}
}

func (c *flakyCollector) handle(w http.ResponseWriter, r *http.Request) {
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
	accept := c.accept.Load()
	c.mu.Lock()
	c.attempts++
	if accept {
		for _, rl := range req.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				c.records = append(c.records, sl.GetLogRecords()...)
			}
		}
	}
	c.mu.Unlock()
	if accept {
		select {
		case c.notify <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	// 500 is NOT retryable for the OTLP client (only 429/502/503/504 are):
	// the batch is dropped immediately, without a retry stall.
	w.WriteHeader(http.StatusInternalServerError)
}

func (c *flakyCollector) attemptCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempts
}

func (c *flakyCollector) snapshotRecords() []*logspb.LogRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*logspb.LogRecord(nil), c.records...)
}

// must fail fast at flush time (no retry stall on Shutdown), surface the
// export error, and never wedge the producer. Records lost inside the SDK
// batch processor are NOT counted by yabanin_otel_logs_dropped_total — that
// honest boundary is the documented D-3 limit; the counter grows at OUR
// queue boundary (post-shutdown enqueues below).
func TestLogExporter_UnreachableSinkFailsFastAndDrops(t *testing.T) {
	before := testutil.ToFloat64(OTelLogsDroppedTotal)

	cfg := testCfg("http://127.0.0.1:1") // port 1: nothing listens
	cfg.QueueSize = 8
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, e)

	e.Enqueue(fullRecord()) // accepted at our boundary, lost in the SDK later
	e.Enqueue(fullRecord())
	assert.InDelta(t, before, testutil.ToFloat64(OTelLogsDroppedTotal), 0,
		"accepted in-flight records never hit the drop counter (D-3)")

	start := time.Now()
	shErr := e.Shutdown(context.Background())
	assert.Less(t, time.Since(start), 5*time.Second,
		"an unreachable sink must fail the flush fast, not stall Shutdown in retries")
	require.Error(t, shErr, "the failed final flush must surface a diagnosable cause")
	require.ErrorContains(t, shErr, "connection refused")

	e.Enqueue(fullRecord()) // after Shutdown: drop, counted
	assert.InDelta(t, before+1, testutil.ToFloat64(OTelLogsDroppedTotal), 0,
		"post-shutdown enqueues land in the drop counter")
}

// A non-retryable 500 drops the in-flight batch inside the SDK; the producer is
// unaffected, and the
// pipeline must NOT be poisoned — once the sink recovers, later batches flow
// again. The rejected record never arrives (at-least-nothing-worse: lost
// export data is preferable to lost or delayed request logs).
func TestLogExporter_SinkRejectionDropsBatchWithoutPoisoning(t *testing.T) {
	fc := &flakyCollector{t: t, notify: make(chan struct{}, 64)}
	srv := httptest.NewServer(http.HandlerFunc(fc.handle))
	t.Cleanup(srv.Close)

	e, err := NewLogExporter(context.Background(), testCfg(srv.URL))
	require.NoError(t, err)

	recA := fullRecord()
	recA.RequestID = "batchfail-a"
	e.Enqueue(recA) // first batch → 500 → dropped inside the SDK

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && fc.attemptCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	require.GreaterOrEqual(t, fc.attemptCount(), 1, "the sink must have rejected the first batch")
	assert.Empty(t, fc.snapshotRecords(), "a 500 batch is dropped, never stored")

	fc.accept.Store(true)
	recB := fullRecord()
	recB.RequestID = "batchfail-b"
	e.Enqueue(recB) // later batches must flow again after the sink recovers

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(fc.snapshotRecords()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	recs := fc.snapshotRecords()
	require.Len(t, recs, 1, "exactly the recovered batch must reach the sink")

	ids := map[string]bool{}
	for _, r := range recs {
		id, _ := attrString(t, attrMap(r), "request.id")
		ids[id] = true
	}
	assert.Equal(t, map[string]bool{"batchfail-b": true}, ids,
		"the rejected record must never arrive; recovery must not replay or duplicate it")
	require.NoError(t, e.Shutdown(context.Background()))
}

// endpoint must FAIL construction. The SDK's WithEndpointURL silently
// ignores a parse error and would fall back to the default collector —
// egress to an unconfigured endpoint violates the configured-endpoint-only
// contract. Callers log-and-continue, so the error only leaves export off.
func TestLogExporter_MalformedHTTPEndpointFailsConstruction(t *testing.T) {
	for _, endpoint := range []string{
		"http://exa mple.com/v1", // space in host → parse error
		"http://[::bad/v1",       // unclosed IPv6 bracket → parse error
		"https://",               // scheme without host
		"http://",                // scheme without host
	} {
		e, err := NewLogExporter(context.Background(), testCfg(endpoint))
		require.Error(t, err, "endpoint %q must fail construction, not silently re-route", endpoint)
		require.ErrorContains(t, err, "invalid OTLP logs endpoint URL")
		require.Nil(t, e, "endpoint %q", endpoint)

		// The failed-construction nil sink is a safe no-op, exactly like the
		// disabled sink.
		e.Enqueue(fullRecord())
		assert.NoError(t, e.Shutdown(context.Background()))
	}
}

// A schemeless endpoint is taken literally as host:port. The SDK composes
// and validates the target URL eagerly, so garbage fails construction too —
// every malformed endpoint form fails closed at the boundary instead of
// leaving a half-open pipeline behind.
func TestLogExporter_SchemelessGarbageEndpointFailsClosed(t *testing.T) {
	e, err := NewLogExporter(context.Background(), testCfg("::::"))
	require.Error(t, err, "garbage host:port must fail construction")
	require.ErrorContains(t, err, "failed to create OTLP logs exporter")
	require.Nil(t, e)

	// The failed-construction nil sink is a safe no-op, exactly like the
	// disabled sink.
	e.Enqueue(fullRecord())
	assert.NoError(t, e.Shutdown(context.Background()))
}

// invalid on the wire (control byte) passes construction — headers are only
// validated at request time — and must then fail the export client-side:
// nothing is delivered anywhere, Shutdown surfaces the cause fast, and the
// process stays safe.
func TestLogExporter_MisconfiguredHeaderFailsSafe(t *testing.T) {
	before := testutil.ToFloat64(OTelLogsDroppedTotal)

	collector, srv := newOTLPCollector(t)
	cfg := testCfg(srv.URL)
	cfg.Headers = map[string]string{"X-Yabanin-Test": "line1\nline2"} // control byte: invalid field value
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err, "header validity is only checked at request time")

	e.Enqueue(fullRecord())
	start := time.Now()
	shErr := e.Shutdown(context.Background())
	assert.Less(t, time.Since(start), 5*time.Second,
		"a client-side request failure must be fast, not retry-stalled")
	require.Error(t, shErr, "the failed export must surface a diagnosable cause")
	require.ErrorContains(t, shErr, "invalid header field value")

	recs, batches := collector.snapshot()
	assert.Empty(t, recs, "a record with an invalid header must never reach the endpoint")
	assert.Zero(t, batches)
	assert.InDelta(t, before, testutil.ToFloat64(OTelLogsDroppedTotal), 0,
		"SDK-internal export loss stays outside the drop counter (D-3)")
}

// must produce a total clamp — NaN fails CLOSED to 0 (suppress all export;
// mirrors the env layer's out-of-range handling, which already rejects NaN),
// ±Inf clamp to the nearest bound. Before the fix NaN escaped both range
// comparisons and was echoed verbatim by Config().
func TestLogExporter_SampleRateNonFiniteFailsClosed(t *testing.T) {
	collector, srv := newOTLPCollector(t)

	cfg := testCfg(srv.URL)
	cfg.SampleRate = math.NaN()
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)
	assert.InDelta(t, 0, e.Config().SampleRate, 0, "NaN must fail closed to 0, never be echoed verbatim")

	e.Enqueue(fullRecord())
	time.Sleep(150 * time.Millisecond) // two batch intervals: nothing may surface
	recs, batches := collector.snapshot()
	assert.Empty(t, recs, "a NaN sample rate must suppress all export")
	assert.Zero(t, batches)
	require.NoError(t, e.Shutdown(context.Background()))

	for _, tc := range []struct{ rate, want float64 }{
		{math.Inf(1), 1},
		{math.Inf(-1), 0},
	} {
		cfg := testCfg(srv.URL)
		cfg.SampleRate = tc.rate
		e, err := NewLogExporter(context.Background(), cfg)
		require.NoError(t, err)
		assert.InDelta(t, tc.want, e.Config().SampleRate, 0, "rate %v must clamp to the nearest bound", tc.rate)
		require.NoError(t, e.Shutdown(context.Background()))
	}
}

// failingExporterStub is an injectable sdklog.Exporter that fails every
// export attempt with a fixed error (failing-exporter injection). It obeys
// the interface contract: the records slice is never retained — only its
// length is observed.
type failingExporterStub struct {
	exportErr error

	calls     atomic.Int64
	lastBatch atomic.Int64
	shutdowns atomic.Int64
}

func (s *failingExporterStub) Export(_ context.Context, records []sdklog.Record) error {
	s.calls.Add(1)
	s.lastBatch.Store(int64(len(records)))
	return s.exportErr
}

func (s *failingExporterStub) Shutdown(context.Context) error { s.shutdowns.Add(1); return nil }

func (s *failingExporterStub) ForceFlush(context.Context) error { return nil }

// captureHandler is a minimal slog.Handler capturing message texts.
type captureHandler struct {
	mu       sync.Mutex
	messages []string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages, r.Message)
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *captureHandler) WithGroup(string) slog.Handler { return h }

func (h *captureHandler) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.messages...)
}

// Table-driven: a successful export is delegated untouched and uncounted; a
// failed export is counted once per attempt and the error is passed through
// unchanged (never swallowed — retry policy belongs to the OTLP client).
func TestObservedExporter_CountsFailedAttemptsAndDelegates(t *testing.T) {
	wantErr := errors.New("synthetic collector outage")
	cases := []struct {
		name      string
		exportErr error
		attempts  int
		batchLen  int
		wantDelta float64
		wantErr   error
	}{
		{
			name:      "success is delegated and not counted",
			exportErr: nil,
			attempts:  1,
			batchLen:  3,
			wantDelta: 0,
			wantErr:   nil,
		},
		{
			name:      "failure is counted per attempt and returned unchanged",
			exportErr: wantErr,
			attempts:  2,
			batchLen:  2,
			wantDelta: 2,
			wantErr:   wantErr,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := testutil.ToFloat64(OTelExportErrorsTotal)
			stub := &failingExporterStub{exportErr: tc.exportErr}
			o := newObservedExporter(stub)

			var lastErr error
			for i := 0; i < tc.attempts; i++ {
				batch := make([]sdklog.Record, tc.batchLen)
				lastErr = o.Export(context.Background(), batch)
			}

			if tc.wantErr == nil {
				require.NoError(t, lastErr)
			} else {
				require.ErrorIs(t, lastErr, tc.wantErr, "the export error must pass through unchanged")
			}
			assert.InDelta(t, before+tc.wantDelta, testutil.ToFloat64(OTelExportErrorsTotal), 0,
				"exactly one counter increment per failed attempt")
			assert.Equal(t, int64(tc.attempts), stub.calls.Load(), "every attempt must reach the wrapped exporter")
			assert.Equal(t, int64(tc.batchLen), stub.lastBatch.Load(), "the batch must be delegated unmodified")
		})
	}
}

// The WARN line makes an outage visible in the log, but at most once per
// exportErrorLogInterval: an hour-long outage at a 5s batch interval must
// not become a ~720-line storm. The counter counts every attempt regardless.
func TestObservedExporter_WarnIsRateLimited(t *testing.T) {
	capture := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(prev) })

	stub := &failingExporterStub{exportErr: errors.New("connection refused")}
	o := newObservedExporter(stub)

	before := testutil.ToFloat64(OTelExportErrorsTotal)
	_ = o.Export(context.Background(), []sdklog.Record{{}})
	_ = o.Export(context.Background(), []sdklog.Record{{}}) // inside the interval: suppressed
	msgs := capture.snapshot()
	require.Len(t, msgs, 1, "the first failure logs, immediate repeats are suppressed")
	assert.Contains(t, msgs[0], "non-fatal")

	// After the window passes, the next failure logs again.
	o.logMu.Lock()
	o.lastLogWarn = time.Now().Add(-exportErrorLogInterval - time.Second)
	o.logMu.Unlock()
	_ = o.Export(context.Background(), []sdklog.Record{{}})
	msgs = capture.snapshot()
	require.Len(t, msgs, 2, "a failure after the rate-limit window logs again")
	assert.Contains(t, msgs[1], "non-fatal")

	assert.Equal(t, int64(3), stub.calls.Load())
	assert.InDelta(t, before+3, testutil.ToFloat64(OTelExportErrorsTotal), 0,
		"the counter counts every attempt, the log line is the rate-limited channel")
}

// Exporter failure must be VISIBLE and NON-FATAL: a fully failing exporter
// (injected) is counted on /metrics, the enqueue path never blocks, the
// pipeline shuts down within bounds, and post-shutdown behavior is
// unchanged. The gateway keeps serving — the exporter is a side-sink.
func TestLogExporter_FailingExporterIsVisibleAndNonFatal(t *testing.T) {
	beforeErrs := testutil.ToFloat64(OTelExportErrorsTotal)
	beforeDrops := testutil.ToFloat64(OTelLogsDroppedTotal)

	stub := &failingExporterStub{exportErr: errors.New("synthetic collector outage")}
	cfg := testCfg("http://127.0.0.1:1") // satisfies the endpoint gate; no socket is built (override)
	cfg.exporterOverride = stub
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, e)

	// The consumer loop keeps enqueueing at full speed during the outage.
	start := time.Now()
	for i := 0; i < 32; i++ {
		rec := fullRecord()
		rec.RequestID = "outage-" + strconv.Itoa(i)
		e.Enqueue(rec)
	}
	assert.Less(t, time.Since(start), time.Second,
		"enqueue must stay non-blocking while the exporter fails")

	// Every failed attempt is visible on /metrics.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && testutil.ToFloat64(OTelExportErrorsTotal) <= beforeErrs {
		time.Sleep(10 * time.Millisecond)
	}
	assert.Greater(t, testutil.ToFloat64(OTelExportErrorsTotal), beforeErrs,
		"a failed export attempt must be counted in yabanin_otel_export_errors_total")
	assert.GreaterOrEqual(t, stub.calls.Load(), int64(1), "the exporter was reached with real batches")
	assert.Positive(t, stub.lastBatch.Load(), "records were actually handed to the failing exporter")

	// Non-fatal: Shutdown completes within bounds (by now the timer-driven
	// batches already consumed the queue, so the final flush may or may not
	// carry records — if it errors, only with the diagnosable export cause).
	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shErr := e.Shutdown(shCtx)
	if shErr != nil {
		require.ErrorIs(t, shErr, stub.exportErr, "a failed flush must surface the export cause, never a wedge")
	}
	assert.GreaterOrEqual(t, stub.shutdowns.Load(), int64(1), "the wrapped exporter was shut down exactly through the pipeline")

	e.Enqueue(fullRecord()) // after shutdown → counted drop, no panic
	assert.InDelta(t, beforeDrops+1, testutil.ToFloat64(OTelLogsDroppedTotal), 0,
		"post-shutdown drops are unaffected by the exporter outage")

	// Deterministic failed-flush surfacing: with the interval timer out of
	// reach (10s), the ONLY export path is the shutdown flush of the one
	// pending record — its failure is returned to the caller, not swallowed.
	stubFlush := &failingExporterStub{exportErr: errors.New("synthetic collector outage")}
	cfgFlush := testCfg("http://127.0.0.1:1")
	cfgFlush.exporterOverride = stubFlush
	cfgFlush.ExportInterval = 10 * time.Second
	eFlush, err := NewLogExporter(context.Background(), cfgFlush)
	require.NoError(t, err)
	eFlush.Enqueue(fullRecord())
	startFlush := time.Now()
	shCtxFlush, cancelFlush := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFlush()
	shErrFlush := eFlush.Shutdown(shCtxFlush)
	assert.Less(t, time.Since(startFlush), 5*time.Second,
		"a failing flush must be fast, not retry-stalled")
	require.ErrorIs(t, shErrFlush, stubFlush.exportErr,
		"the failed flush of the pending record must surface a diagnosable cause")
	assert.Equal(t, int64(1), stubFlush.calls.Load())
	assert.Equal(t, int64(1), stubFlush.lastBatch.Load(), "the pending record reached the failing exporter through the flush")
}

// The genai.system allowlist is enforced at the export boundary: values
// inside the closed domain pass, everything else drops to the fixed "other"
// bucket, and the domain itself covers exactly what the derivation can
// produce.
func TestBoundedGenaiSystem_AllowlistPolicy(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty omits the attribute", "", ""},
		{"allowlist value passes", "openai", "openai"},
		{"second allowlist value passes", "anthropic", "anthropic"},
		{"suffix-rule value passes", genaiSystemAWSBedrock, genaiSystemAWSBedrock},
		{"other bucket passes", genaiSystemOther, genaiSystemOther},
		{"raw host is dropped to other", "api.openai.com", genaiSystemOther},
		{"case-mangled value is dropped", "OpenAI", genaiSystemOther},
		{"whitespace-wrapped value is dropped", " openai", genaiSystemOther},
		{"unknown provider is dropped", "custom-llm-inc", genaiSystemOther},
		{"URL-like value is dropped", "https://api.openai.com/v1", genaiSystemOther},
		{"lookalike suffix is dropped", "openai.x", genaiSystemOther},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, boundedGenaiSystem(tc.in), "case %q", tc.name)
	}

	// Domain completeness: every value the derivation can produce is a
	// member, so a legit pipeline output can never be re-bucketed.
	for host, sys := range genaiSystemByHost {
		assert.Contains(t, genaiSystemValues, sys, "allowlist value for host %s must be in the domain", host)
	}
	for _, sys := range []string{genaiSystemAWSBedrock, genaiSystemAzureOpenAI, genaiSystemSambaNova, genaiSystemOther} {
		assert.Contains(t, genaiSystemValues, sys, "suffix/bucket value %s must be in the domain", sys)
	}

	// Determinism: hostile inputs stay inside the closed domain.
	for i := 0; i < 500; i++ {
		assert.Contains(t, genaiSystemValues, boundedGenaiSystem("hostile-"+strconv.Itoa(i)),
			"boundedGenaiSystem must never mint a value outside the domain")
	}
}

// End-to-end through the in-memory OTLP receiver: records built from
// tenant-controlled upstream URLs export a genai.system inside the closed
// domain, and the raw host never surfaces in any attribute value.
func TestLogExporter_GenaiSystemAllowlistEnforcedEndToEnd(t *testing.T) {
	collector, srv := newOTLPCollector(t)
	e, err := NewLogExporter(context.Background(), testCfg(srv.URL))
	require.NoError(t, err)

	cases := []struct {
		name string
		url  string
		want string
	}{
		{"allowlisted host keeps its system", "https://api.openai.com/v1/chat/completions", "openai"},
		{"tenant azure host keeps its system", "https://contoso.openai.azure.com/openai/deployments", "azure.ai.openai"},
		{"tenant-controlled host buckets", "https://tenant-42.proxy.example.com:8443/v1", genaiSystemOther},
		{"raw IP host buckets", "https://10.9.9.9/v1", genaiSystemOther},
		{"spoofed suffix buckets", "https://api.sambanova.ai.evil.com/v1", genaiSystemOther},
	}
	for i, tc := range cases {
		rec := fullRecord()
		rec.RequestID = "allowlist-e2e-" + strconv.Itoa(i)
		rec.UpstreamURL = tc.url
		e.Enqueue(rec)
	}

	recs := collector.waitFor(t, func(recs []*logspb.LogRecord) bool { return len(recs) >= len(cases) })
	require.Len(t, recs, len(cases), "every record must reach the in-memory receiver")

	hostLeaks := []string{"proxy.example.com", "10.9.9.9", "evil.com", "contoso"}
	for _, r := range recs {
		m := attrMap(r)
		sys, ok := attrString(t, m, "genai.system")
		require.True(t, ok, "every record carries genai.system")
		assert.Contains(t, genaiSystemValues, sys,
			"exported genai.system %q must stay inside the closed allowlist domain", sys)

		id, _ := attrString(t, m, "request.id")
		if strings.HasPrefix(id, "allowlist-e2e-") {
			idx, err := strconv.Atoi(strings.TrimPrefix(id, "allowlist-e2e-"))
			require.NoError(t, err)
			assert.Equal(t, cases[idx].want, sys, "case %q", cases[idx].name)
		}
		for _, kv := range r.GetAttributes() {
			for _, leak := range hostLeaks {
				assert.NotContains(t, kv.GetValue().GetStringValue(), leak,
					"a raw upstream host must never be forwarded in attribute %q", kv.GetKey())
			}
		}
	}
	require.NoError(t, e.Shutdown(context.Background()))
}

// capturingExporterStub is an injectable sdklog.Exporter that captures the
// attributes of the LAST record in every batch (attribute-bound regression
// teeth). Records are never retained beyond their attribute projection.
type capturingExporterStub struct {
	calls atomic.Int64

	mu    sync.Mutex
	attrs map[string]string
}

func (s *capturingExporterStub) Export(_ context.Context, records []sdklog.Record) error {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attrs = make(map[string]string, 16)
	if len(records) == 0 {
		return nil
	}
	last := &records[len(records)-1]
	last.WalkAttributes(func(kv attribute.KeyValue) bool {
		s.attrs[string(kv.Key)] = kv.Value.String()
		return true
	})
	return nil
}

func (s *capturingExporterStub) snapshot() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.attrs))
	for k, v := range s.attrs {
		out[k] = v
	}
	return out
}

func (s *capturingExporterStub) Shutdown(context.Context) error { return nil }

func (s *capturingExporterStub) ForceFlush(context.Context) error { return nil }

// waitForExports polls until the stub observed at least n export calls or
// the deadline passes (batch flushes are timer-driven).
func waitForExports(t *testing.T, stub *capturingExporterStub, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && stub.calls.Load() < n {
		time.Sleep(5 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, stub.calls.Load(), n, "the stub must observe %d export calls", n)
}

// Regression teeth for the N13-P02-T03 attribute bounds: oversized producer
// strings are clamped AT THE ENQUEUE BOUNDARY — the exported attributes (and
// therefore the queued records feeding them) never carry a value beyond its
// documented cap, genai.system derivation still works from a clamped URL,
// and the sampled-ness of the record is decided on the RAW request id.
func TestLogExporter_EnqueueBoundsAttributeLengths(t *testing.T) {
	long := strings.Repeat("x", 10_000)
	stub := &capturingExporterStub{}
	cfg := testCfg("http://127.0.0.1:1") // endpoint gate satisfied; override skips any socket
	cfg.exporterOverride = stub
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, e)

	e.Enqueue(RequestLog{
		EventType:      "completed" + long,
		RequestID:      "req-1" + long,
		OrgID:          "org-1" + long,
		SessionID:      "sess-1" + long,
		ModelRequested: "gpt-9" + long,
		ModelUsed:      "gpt-9b" + long,
		PolicyVerdict:  "allow" + long,
		// host inside the first maxUpstreamURLBytes bytes: derivation must
		// survive the clamp.
		UpstreamURL: "https://api.openai.com/v1/" + long,
	})
	waitForExports(t, stub, 1)

	attrs := stub.snapshot()
	require.Contains(t, attrs, "genai.request.model")
	require.Contains(t, attrs, "request.id")
	for key, capBytes := range map[string]int{
		"genai.request.model":    maxAttributeBytes,
		"genai.response.model":   maxAttributeBytes,
		"request.id":             maxAttributeBytes,
		"org.id":                 maxAttributeBytes,
		"yabanin.session_id":     maxAttributeBytes,
		"yabanin.policy_verdict": maxAttributeBytes,
		"yabanin.event_type":     maxEventTypeBytes,
	} {
		v := attrs[key]
		require.LessOrEqual(t, len(v), capBytes,
			"attribute %s must be clamped to %d bytes, got %d", key, capBytes, len(v))
		require.True(t, utf8.ValidString(v), "attribute %s must stay valid UTF-8 after clamping", key)
	}
	assert.Equal(t, "openai", attrs["genai.system"],
		"genai.system derivation must survive the upstream-URL clamp")
}

// Clamping must not split a multi-byte rune at the cut point: a multibyte
// string truncated at maxAttributeBytes stays valid UTF-8 and never exceeds
// the cap.
func TestLogExporter_AttributeBoundsMultibyte(t *testing.T) {
	multi := strings.Repeat("ж", 5000) // 2 bytes per rune — any byte cut could split a rune
	stub := &capturingExporterStub{}
	cfg := testCfg("http://127.0.0.1:1")
	cfg.exporterOverride = stub
	e, err := NewLogExporter(context.Background(), cfg)
	require.NoError(t, err)

	e.Enqueue(RequestLog{
		EventType:      "completed",
		RequestID:      "req-mb",
		ModelRequested: multi,
	})
	waitForExports(t, stub, 1)

	attrs := stub.snapshot()
	v := attrs["genai.request.model"]
	require.LessOrEqual(t, len(v), maxAttributeBytes)
	require.True(t, utf8.ValidString(v), "a byte-cut inside a multibyte rune must back up to the rune start")
	require.True(t, strings.HasPrefix(multi, v), "the clamped value must be a prefix of the input")
}

// Queue-memory bound (N13-P02-T03): a huge configured QueueSize cannot
// translate into unbounded resident memory. The effective queue is clamped
// by the hard cap AND the two-layer bytes budget; the reported worst case
// respects the budget; sane configured values (the 4096 default) pass
// through untouched.
func TestLogExporter_QueueSizeClampAndMemoryBudget(t *testing.T) {
	cases := []struct {
		name           string
		queueSize      int
		includeContent bool
	}{
		{name: "huge queue without content", queueSize: 10_000_000, includeContent: false},
		{name: "huge queue with content", queueSize: 10_000_000, includeContent: true},
		{name: "default queue with content", queueSize: defaultLogQueueSize, includeContent: true},
		{name: "default queue without content", queueSize: defaultLogQueueSize, includeContent: false},
		{name: "zero queue falls back to default", queueSize: 0, includeContent: false},
		{name: "negative queue falls back to default", queueSize: -5, includeContent: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := newLogExporter(context.Background(), LogExporterConfig{
				ServiceName:    "loggerd-test",
				Endpoint:       "http://127.0.0.1:1",
				QueueSize:      tc.queueSize,
				IncludeContent: tc.includeContent,
			}, false)
			require.NoError(t, err)
			require.NotNil(t, e)

			eff := e.Config().QueueSize
			assert.GreaterOrEqual(t, eff, 1, "the effective queue must never be empty")
			assert.LessOrEqual(t, eff, maxLogQueueSize, "the hard cap must hold")
			assert.LessOrEqual(t, e.WorstCaseQueueMemoryBytes(), maxQueueMemoryBytes,
				"the two-layer worst case must stay within the %d-byte budget", maxQueueMemoryBytes)
			assert.Equal(t, worstCaseQueueMemoryBytes(eff, tc.includeContent), e.WorstCaseQueueMemoryBytes(),
				"the reported bound must be computed from the EFFECTIVE config")
			if tc.queueSize > 0 && tc.queueSize <= maxLogQueueSize &&
				tc.queueSize <= maxQueueMemoryBytes/(2*perRecordMaxBytes(tc.includeContent)) {
				assert.Equal(t, tc.queueSize, eff, "a sane configured value must pass through untouched")
			}
		})
	}
}

// The budget clamp must hold at the extremes too: an exporter built with the
// largest queue the constructor allows reports a worst case within budget.
func TestLogExporter_WorstCaseMemoryWithinBudget(t *testing.T) {
	for _, includeContent := range []bool{false, true} {
		maxEff := maxQueueMemoryBytes / (2 * perRecordMaxBytes(includeContent))
		if maxEff > maxLogQueueSize {
			maxEff = maxLogQueueSize
		}
		assert.LessOrEqual(t, worstCaseQueueMemoryBytes(maxEff, includeContent), maxQueueMemoryBytes,
			"includeContent=%v: budget must hold at the effective maximum", includeContent)
	}
}

// boundString unit pins: exact passthrough under the cap, rune-safe
// truncation over it, empty/degenerate handling.
func TestBoundString(t *testing.T) {
	assert.Empty(t, boundString("", 10))
	assert.Empty(t, boundString("abc", 0))
	assert.Empty(t, boundString("abc", -1))
	assert.Equal(t, "abc", boundString("abc", 3), "exactly-at-cap passes through")
	assert.Equal(t, "abc", boundString("abcd", 3))
	assert.Equal(t, strings.Repeat("a", maxAttributeBytes), boundString(strings.Repeat("a", maxAttributeBytes+1), maxAttributeBytes))

	multi := strings.Repeat("ж", 10) // 2-byte runes, 20 bytes
	got := boundString(multi, 5)
	require.LessOrEqual(t, len(got), 5)
	require.True(t, utf8.ValidString(got))
	require.True(t, strings.HasPrefix(multi, got))
	// A rune-start landing exactly on the cap: cut after the second full rune.
	assert.Equal(t, "жж", boundString("жжж", 4))
	// A dangling lead byte (its continuations cut off) is not valid UTF-8:
	// the partial rune goes entirely.
	assert.Equal(t, "жж", boundString("жжж", 5))
	// 3-byte runes (U+65E5 "日"): split and exact cases.
	assert.Equal(t, "日", boundString("日日", 3))
	assert.Equal(t, "日", boundString("日日", 4))
	// 4-byte runes (U+1F600): a cut inside the rune yields "".
	assert.Empty(t, boundString("\U0001F600x", 2))
	// len(s) == max passes through even when it ends inside multi-byte runes.
	assert.Equal(t, "\U0001F600x", boundString("\U0001F600x", 4+1))
	assert.Equal(t, "\U0001F600x", boundString("\U0001F600x"+strings.Repeat("y", 10), 5))
}
