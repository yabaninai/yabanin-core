package mcpagg

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/metrics"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// mcpCalls returns the current value of gateway_mcp_calls_total for the given
// labels (a helper around testutil for the labelled series).
func mcpCalls(server, tool, outcome string) float64 {
	return testutil.ToFloat64(metrics.MCPCallsTotal.WithLabelValues(server, tool, outcome))
}

// TestProxy_Invoke_MCPCallsTotal_IncrementsPerOutcome: MCP-05 — every tool
// call increments gateway_mcp_calls_total{server,tool,outcome}, on both the
// success and failure paths. The outcome label matches the audit outcome.
func TestProxy_Invoke_MCPCallsTotal_IncrementsPerOutcome(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)

	// Success path → outcome=ok.
	okBefore := mcpCalls("knowledge", "search", OutcomeOK)
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if got := mcpCalls("knowledge", "search", OutcomeOK); got != okBefore+1 {
		t.Fatalf("ok counter: want %v, got %v", okBefore+1, got)
	}

	// Denied path (guard hook denies) → outcome=denied.
	deniedHook := &denyHook{reason: "pii"}
	pd := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), deniedHook, nil)
	deniedBefore := mcpCalls("knowledge", "search", OutcomeDenied)
	if _, err := pd.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)}); err == nil {
		t.Fatal("want deny, got success")
	}
	if got := mcpCalls("knowledge", "search", OutcomeDenied); got != deniedBefore+1 {
		t.Fatalf("denied counter: want %v, got %v", deniedBefore+1, got)
	}

	// No-grant path → outcome=not_found, server label is the requested name.
	pn := NewProxy(storeForUpstreamWithGrant(up.URL, nil, nil /* no grant */), testConfig(), loopbackAllow(t), nil, nil)
	nfBefore := mcpCalls("knowledge", "search", OutcomeNotFound)
	if _, err := pn.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("want not_found, got success")
	}
	if got := mcpCalls("knowledge", "search", OutcomeNotFound); got != nfBefore+1 {
		t.Fatalf("not_found counter: want %v, got %v", nfBefore+1, got)
	}
}

// TestProxy_Invoke_SpanPerToolCall: MCP-05 — each tool call emits an OTel span
// named "mcp.tools/call" with the mcp.server/tool/agent_id/outcome attributes.
// Uses the OTel SDK with an in-memory exporter (tracetest) so the assertion is
// independent of any global tracing.Init.
func TestProxy_Invoke_SpanPerToolCall(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	// SimpleSpanProcessor exports synchronously on span.End, so the span is
	// visible to GetSpans() immediately after Invoke returns (a Batch processor
	// would still be buffering it).
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)),
		sdktrace.WithResource(sdkresource.Default()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	up := newUpstreamMCP(t, "json", "")
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)
	p.tracer = tp.Tracer("test") // inject the test tracer (no global Init needed)

	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1", TeamID: "tm-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("invoke: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("want exactly 1 span, got %d", len(spans))
	}
	if name := spans[0].Name; name != "mcp.tools/call" {
		t.Errorf("span name = %q, want mcp.tools/call", name)
	}
	want := map[string]string{
		"mcp.server":   "knowledge",
		"mcp.tool":     "search",
		"mcp.agent_id": "ag-1",
		"mcp.outcome":  OutcomeOK,
	}
	attrs := spans[0].Attributes
	for k, v := range want {
		var found bool
		for _, a := range attrs {
			if string(a.Key) == k && a.Value.AsString() == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("span missing attr %s=%q (have %v)", k, v, attrs)
		}
	}
}

// denyHook is a pre-egress guard that always denies (MCP-06 shape) — used to
// exercise the denied outcome in the metric/span tests.
type denyHook struct{ reason string }

func (h *denyHook) Scan(_ context.Context, _ []byte) ([]byte, string, string) {
	return nil, h.reason, "deny"
}
