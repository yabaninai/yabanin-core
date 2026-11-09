package cli

// a2aAuditEvent mapping tests (mirrors mcp_audit_test.go): ok →
// request.completed, failures → request.failed with the a2a: outcome label,
// redacted params in the payload.

import (
	"encoding/json"
	"testing"

	"github.com/reireirei/yabanin/pkg/a2aagg"
)

func TestA2AAuditEvent_OK(t *testing.T) {
	ev := a2aAuditEvent(a2aagg.AuditEvent{
		OrgID: "org-1", AgentID: "agent-9", TeamID: "team-2",
		RequestID: "req-1", TaskID: "task-3",
		TargetName: "helper", Method: a2aagg.MethodSend,
		ParamsRedacted: json.RawMessage(`{"message":{}}`),
		LatencyMS:      42, Outcome: a2aagg.OutcomeOK, UpstreamStatus: 200,
		UpstreamURL: "https://agent.example.com/a2a",
	})
	if ev.EventType != "request.completed" {
		t.Fatalf("event type: %q", ev.EventType)
	}
	if ev.ModelRequested != "a2a" || ev.ModelUsed != "a2a:helper" {
		t.Fatalf("model labels: %q / %q", ev.ModelRequested, ev.ModelUsed)
	}
	if ev.AgentID != "agent-9" || ev.TaskID != "task-3" || ev.TeamID != "team-2" {
		t.Fatalf("attribution lost: %+v", ev)
	}
	if ev.Error != "" {
		t.Fatalf("ok event must carry no error, got %q", ev.Error)
	}
	if ev.Payload != `{"message":{}}` {
		t.Fatalf("redacted params must ride the payload, got %q", ev.Payload)
	}
}

func TestA2AAuditEvent_Failed(t *testing.T) {
	ev := a2aAuditEvent(a2aagg.AuditEvent{
		OrgID: "org-1", AgentID: "a",
		TargetName: "helper",
		Outcome:    a2aagg.OutcomeUpstreamError, UpstreamStatus: 503,
	})
	if ev.EventType != "request.failed" {
		t.Fatalf("event type: %q", ev.EventType)
	}
	if ev.Error != "a2a:upstream_error (upstream 503)" {
		t.Fatalf("error label: %q", ev.Error)
	}
}

func TestA2AAuditEvent_AgentOnlyHasNoUpstream(t *testing.T) {
	ev := a2aAuditEvent(a2aagg.AuditEvent{
		OrgID: "org-1", Outcome: a2aagg.OutcomeDenied,
	})
	if ev.EventType != "request.failed" || ev.Error != "a2a:denied" {
		t.Fatalf("denied event: %q / %q", ev.EventType, ev.Error)
	}
	if ev.UpstreamURL != "" || ev.ModelUsed != "a2a:" {
		t.Fatalf("pre-egress denial must not reference an upstream: %+v", ev)
	}
}
