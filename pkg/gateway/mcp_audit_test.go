package cli

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/mcpagg"
)

// MCP-03: the audit event mapping. Each tool call becomes a request event that
// loggerd persists to request_logs, labeled mcp:<server>:<tool> and tagged with
// the invoking agent + task.

func TestMCPAuditEvent_OK(t *testing.T) {
	ev := mcpAuditEvent(mcpagg.AuditEvent{
		OrgID:          "org-1",
		AgentID:        "ag-1",
		TeamID:         "tm-1",
		ServerName:     "knowledge",
		Tool:           "search",
		ParamsRedacted: []byte(`{"q":"***"}`),
		LatencyMS:      42,
		Outcome:        mcpagg.OutcomeOK,
		UpstreamStatus: 200,
		RequestID:      "req-1",
		TaskID:         "task-a",
		UpstreamURL:    "https://mcp.example.com",
	})
	if ev.EventType != "request.completed" {
		t.Fatalf("ok outcome must be request.completed, got %q", ev.EventType)
	}
	if ev.ModelUsed != "mcp:knowledge:search" {
		t.Fatalf("model label must be mcp:server:tool, got %q", ev.ModelUsed)
	}
	if ev.AgentID != "ag-1" || ev.TaskID != "task-a" || ev.TeamID != "tm-1" {
		t.Fatalf("agent/task/team must be tagged: %+v", ev)
	}
	if ev.RequestID != "req-1" || ev.UpstreamURL != "https://mcp.example.com" {
		t.Fatalf("request id + upstream url must be set: %+v", ev)
	}
	if ev.StatusCode != 200 || ev.DurationMs != 42 {
		t.Fatalf("status/latency: %+v", ev)
	}
	if ev.Payload != `{"q":"***"}` {
		t.Fatalf("redacted params must be in the payload, got %q", ev.Payload)
	}
	if ev.Error != "" {
		t.Fatalf("ok outcome must have no error, got %q", ev.Error)
	}
}

func TestMCPAuditEvent_Failed(t *testing.T) {
	ev := mcpAuditEvent(mcpagg.AuditEvent{
		OrgID:          "org-1",
		AgentID:        "ag-1",
		ServerName:     "knowledge",
		Tool:           "search",
		Outcome:        mcpagg.OutcomeUpstreamError,
		UpstreamStatus: 502,
	})
	if ev.EventType != "request.failed" {
		t.Fatalf("failed outcome must be request.failed, got %q", ev.EventType)
	}
	if ev.Error == "" {
		t.Fatal("failed outcome must carry an error string")
	}
	if ev.StatusCode != 502 {
		t.Fatalf("upstream status must surface, got %d", ev.StatusCode)
	}
}

func TestMCPAuditEvent_AgentOnlyHasNoUpstream(t *testing.T) {
	ev := mcpAuditEvent(mcpagg.AuditEvent{
		OrgID:      "org-1",
		ServerName: "knowledge",
		Tool:       "search",
		Outcome:    mcpagg.OutcomeDenied, // agent_only path
	})
	if ev.EventType != "request.failed" {
		t.Fatalf("agent-only denial must be request.failed, got %q", ev.EventType)
	}
	// No upstream was reached — status stays 0 (not a 2xx, not an upstream code).
	if ev.StatusCode != 0 {
		t.Fatalf("agent-only must have no upstream status, got %d", ev.StatusCode)
	}
}
