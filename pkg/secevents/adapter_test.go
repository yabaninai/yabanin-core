package secevents

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
)

// anchorReceived is the fixed consumer-side reception time: no test may
// read the wall clock (deterministic anchors).
var anchorReceived = time.Date(2026, 11, 2, 12, 0, 5, 0, time.UTC)

// anchorTSms is the fixed producer timestamp (ms) used in core events.
var anchorTSms = anchorOcc.UnixMilli()

// policyRecord is an OP-8/OP-9-shaped decision record: two policies, three
// findings total. Categories/severities/actions only — never content.
const policyRecord = `[
	{"policy_id":"p-1","name":"sovereign-default","version":2,"mode":"enforce","verdict":"deny",
	 "findings":[
	   {"step":"scan.pii","category":"innsnils","severity":"high","action":"deny"},
	   {"step":"scan.secrets","category":"aws_key","severity":"critical","action":"flag"}
	 ]},
	{"policy_id":"p-2","name":"tool-gate","version":1,"mode":"shadow","verdict":"allow",
	 "findings":[
	   {"step":"tool.pre","category":"file_exfil","severity":"medium","action":"mask"}
	 ]}
]`

func coreEvent(policy string) eventpublisher.Event {
	return eventpublisher.Event{
		EventType:        "request.completed",
		Source:           "gateway",
		TS:               anchorTSms,
		RequestID:        "req-9",
		SessionID:        "sess-42",
		OrgID:            "org-1",
		AgentID:          "agent-7",
		TaskID:           "task-α",
		CostStatus:       "priced",
		EstimatedCostUSD: 0.0123,
		PromptHash:       strings.Repeat("ef", 32),
		Policy:           policy,
	}
}

func TestAdapterVersion(t *testing.T) {
	if AdapterVersion != "v1" {
		t.Fatalf("AdapterVersion = %q, pin broken", AdapterVersion)
	}
	if got := (CoreAdapter{}).Version(); got != AdapterVersion {
		t.Fatalf("Version = %q, want %q", got, AdapterVersion)
	}
}

func TestAdapterNoPolicyMeansNoSecuritySignal(t *testing.T) {
	events, err := CoreAdapter{}.AdaptPublisherEvent(coreEvent(""), anchorReceived)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected zero events for a non-security core event, got %d", len(events))
	}
	// Whitespace-only policy is also no signal.
	events, err = CoreAdapter{}.AdaptPublisherEvent(coreEvent("  "), anchorReceived)
	if err != nil || len(events) != 0 {
		t.Fatalf("whitespace policy: events=%d err=%v", len(events), err)
	}
}

func TestAdapterMalformedPolicyFailsClosed(t *testing.T) {
	for _, bad := range []string{`{"not":"an array"}`, `[{"policy_id":`, `not json`} {
		_, err := CoreAdapter{}.AdaptPublisherEvent(coreEvent(bad), anchorReceived)
		if !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("policy %q: err = %v, want ErrInvalidEvent (fail closed)", bad, err)
		}
	}
}

func TestAdapterEmitsOneEventPerFinding(t *testing.T) {
	events, err := CoreAdapter{}.AdaptPublisherEvent(coreEvent(policyRecord), anchorReceived)
	if err != nil {
		t.Fatalf("AdaptPublisherEvent: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3 (one per finding)", len(events))
	}
	wantTypes := []string{"policy.deny", "policy.flag", "policy.mask"}
	for i, w := range wantTypes {
		if events[i].EventType != w {
			t.Fatalf("event[%d].EventType = %q, want %q", i, events[i].EventType, w)
		}
	}
	e := events[0]
	if e.EventID == "" || e.OrgID != "org-1" || e.SchemaVersion != SchemaVersion {
		t.Fatalf("event[0] scalars: %+v", e.wire)
	}
	if !e.OccurredAt.Equal(anchorOcc) {
		t.Fatalf("OccurredAt = %v, want producer TS %v (never rebased to receivedAt)", e.OccurredAt, anchorOcc)
	}
	// Identity block (W01): agent/session/task known, tool absent.
	if e.Identity.Agent.Value != "agent-7" || e.Identity.Agent.State != IDKnown {
		t.Fatalf("agent = %+v", e.Identity.Agent)
	}
	if e.Identity.Session.Value != "sess-42" || e.Identity.Task.Value != "task-α" {
		t.Fatalf("session/task = %+v %+v", e.Identity.Session, e.Identity.Task)
	}
	if e.Identity.Tool.State != IDAbsent {
		t.Fatalf("tool = %+v, want absent (OP-8 findings carry no tool identity)", e.Identity.Tool)
	}
	if !strings.Contains(e.Summary, "sovereign-default") || !strings.Contains(e.Summary, "innsnils") {
		t.Fatalf("summary = %q", e.Summary)
	}
	// Evidence (W03): payload digest + policy record digest, no content.
	if len(e.Evidence) != 2 {
		t.Fatalf("evidence = %+v", e.Evidence)
	}
	if e.Evidence[0].Kind != EvidencePayloadDigest || e.Evidence[0].Digest != strings.Repeat("ef", 32) {
		t.Fatalf("payload ref = %+v", e.Evidence[0])
	}
	if e.Evidence[1].Kind != EvidencePolicyDecision {
		t.Fatalf("policy ref = %+v", e.Evidence[1])
	}
	out := mustEncode(t, e)
	// The derived events must never embed the (hypothetical) request body:
	// only digests ride the security event.
	for _, leak := range []string{"aws_key_value_aws", "BEGIN RSA", "data:"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Fatalf("wire form leaks content marker %q: %s", leak, out)
		}
	}
	// All emitted events validate against the schema.
	for i := range events {
		if err := (&events[i]).Validate(); err != nil {
			t.Fatalf("event[%d] invalid: %v", i, err)
		}
	}
}

// The adapter EventIDs must be deterministic: re-adapting the same core
// event yields identical ids, so ingest deduplicates a redelivery.
func TestAdapterEventIDsDeterministic(t *testing.T) {
	a, err := CoreAdapter{}.AdaptPublisherEvent(coreEvent(policyRecord), anchorReceived)
	if err != nil {
		t.Fatalf("first adapt: %v", err)
	}
	b, err := CoreAdapter{}.AdaptPublisherEvent(coreEvent(policyRecord), anchorReceived)
	if err != nil {
		t.Fatalf("second adapt: %v", err)
	}
	for i := range a {
		if a[i].EventID != b[i].EventID {
			t.Fatalf("event[%d] EventID not deterministic: %q vs %q", i, a[i].EventID, b[i].EventID)
		}
	}
	// A different request must not collide with the original.
	other := coreEvent(policyRecord)
	other.RequestID = "req-10"
	c, err := CoreAdapter{}.AdaptPublisherEvent(other, anchorReceived)
	if err != nil {
		t.Fatalf("other adapt: %v", err)
	}
	if c[0].EventID == a[0].EventID {
		t.Fatalf("different requests derived the same EventID %q", a[0].EventID)
	}
}

// M3 anchor: the core CostStatus contract must map unknown to the unknown
// state — never to zero (acceptance: "unknown cost does not turn into ...
// zero").
func TestAdapterCostMapping(t *testing.T) {
	cases := []struct {
		status    string
		usd       float64
		wantState CostState
		wantMicro int64
	}{
		{"priced", 0.0123, CostKnown, 12300},
		{"priced", 0, CostKnown, 0}, // priced-but-free is known-free
		{"cache_hit", 0, CostKnown, 0},
		{"unknown_price", 0, CostUnknown, 0},
		{"no_usage", 0, CostUnknown, 0},
		{"legacy", 0, CostUnknown, 0},
		{"", 0, CostNone, 0},
		{"something_new", 0, CostNone, 0},
	}
	for _, tc := range cases {
		t.Run("status_"+tc.status, func(t *testing.T) {
			got := mapCost(tc.status, tc.usd)
			if got.State != tc.wantState || got.MicroUSD != tc.wantMicro {
				t.Fatalf("mapCost(%q, %v) = %+v, want %s/%d", tc.status, tc.usd, got, tc.wantState, tc.wantMicro)
			}
		})
	}
	// And the unknown mapping survives validation + encode (never carries a
	// value).
	ev := coreEvent(policyRecord)
	ev.CostStatus = "unknown_price"
	ev.EstimatedCostUSD = 0
	events, err := CoreAdapter{}.AdaptPublisherEvent(ev, anchorReceived)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if events[0].Cost.State != CostUnknown {
		t.Fatalf("cost = %+v, want unknown", events[0].Cost)
	}
}

func TestAdapterProducerTSRequiredOrFallback(t *testing.T) {
	t.Run("ts_zero_falls_back_to_received", func(t *testing.T) {
		ev := coreEvent(policyRecord)
		ev.TS = 0
		events, err := CoreAdapter{}.AdaptPublisherEvent(ev, anchorReceived)
		if err != nil {
			t.Fatalf("adapt: %v", err)
		}
		if !events[0].OccurredAt.Equal(anchorReceived) {
			t.Fatalf("OccurredAt = %v, want receivedAt %v", events[0].OccurredAt, anchorReceived)
		}
	})
	t.Run("zero_received_rejected", func(t *testing.T) {
		if _, err := (CoreAdapter{}).AdaptPublisherEvent(coreEvent(policyRecord), time.Time{}); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("err = %v, want ErrInvalidEvent", err)
		}
	})
}

// An ordinary (non-agent) core request maps its missing principals to
// absent identifiers, not unknown ones.
func TestAdapterOrdinaryRequestIdentityAbsent(t *testing.T) {
	ev := coreEvent(policyRecord)
	ev.AgentID = ""
	ev.TaskID = ""
	events, err := (CoreAdapter{}).AdaptPublisherEvent(ev, anchorReceived)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	id := events[0].Identity
	if id.Agent.State != IDAbsent || id.Task.State != IDAbsent {
		t.Fatalf("agent/task = %+v/%+v, want absent", id.Agent, id.Task)
	}
	if id.Session.State != IDKnown {
		t.Fatalf("session = %+v, want known (still present)", id.Session)
	}
}

func TestAdapterSkipsOutOfContractAction(t *testing.T) {
	rec := `[{"policy_id":"p","name":"n","version":1,"mode":"enforce","verdict":"deny",
	 "findings":[
	   {"step":"s","category":"c","severity":"high","action":"EXPLOIT!!!"},
	   {"step":"s","category":"c2","severity":"high","action":"deny"}
	 ]}]`
	events, err := CoreAdapter{}.AdaptPublisherEvent(coreEvent(rec), anchorReceived)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(events) != 1 || events[0].EventType != "policy.deny" {
		t.Fatalf("events = %+v, want only the in-contract finding", events)
	}
}
