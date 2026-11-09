package cli

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/reireirei/yabanin/pkg/rulestore"
)

// RT-06 benchmarks: gateway request overhead (handler entry → upstream call →
// response) against a mock provider, JSON and SSE, over identical fixtures for
// baseline and post-change runs. p50/p95/p99 are reported in milliseconds over
// per-request latencies; allocation counts come from -benchmem.

const rt06MaxLatencySamples = 200000

func rt06BenchGateway(b *testing.B, upstreamURL string) *gateway {
	b.Helper()
	gw := streamTestGateway(upstreamURL)
	gw.log = slog.New(slog.DiscardHandler)
	gw.res = stubModelResolver{
		"gpt-4": {ModelName: "gpt-4", Provider: "openai", UpstreamURL: upstreamURL, Enabled: true},
	}
	gw.ruleStore = rulestore.New(&rt01RuleDB{rules: map[string][]evaluator.Rule{}}, nil, 0, nil, slog.New(slog.DiscardHandler))
	gw.unknownModelPolicy = "fallback"
	return gw
}

// rt06BenchProvider is the mock provider: it distinguishes stream/non-stream
// by the forwarded OpenAI request body, so one server serves both benches.
func rt06BenchProvider(b *testing.B, sseBody, jsonBody string) *httptest.Server {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		if strings.Contains(string(buf[:n]), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(sseBody))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonBody))
	}))
	b.Cleanup(srv.Close)
	return srv
}

func rt06ChatBench(b *testing.B, stream bool) {
	b.Helper()
	const jsonBody = `{"id":"cmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	const sseBody = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
		"data: [DONE]\n\n"
	srv := rt06BenchProvider(b, sseBody, jsonBody)
	gw := rt06BenchGateway(b, srv.URL)
	body := `{"model":"gpt-4","stream":` + strconv.FormatBool(stream) +
		`,"messages":[{"role":"user","content":"bench"}]}`

	samples := make([]float64, 0, rt06MaxLatencySamples)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("X-Org-Id", "bench-org")
		req.Header.Set("X-Session-Id", "bench-sess")
		rec := httptest.NewRecorder()
		start := time.Now()
		gw.chatCompletions(rec, req)
		elapsed := time.Since(start)
		if rec.Code != http.StatusOK {
			b.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		if len(samples) < rt06MaxLatencySamples {
			samples = append(samples, float64(elapsed.Nanoseconds())/1e6)
		}
	}
	b.StopTimer()
	sort.Float64s(samples)
	b.ReportMetric(rt06Percentile(samples, 50), "p50_ms")
	b.ReportMetric(rt06Percentile(samples, 95), "p95_ms")
	b.ReportMetric(rt06Percentile(samples, 99), "p99_ms")
}

func rt06Percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func BenchmarkRT06_GatewayOverhead_JSON(b *testing.B) { rt06ChatBench(b, false) }
func BenchmarkRT06_GatewayOverhead_SSE(b *testing.B)  { rt06ChatBench(b, true) }
