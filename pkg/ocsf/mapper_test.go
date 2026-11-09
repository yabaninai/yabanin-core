package ocsf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/secevents"
)

// fixture builds a Validate-clean secevents event. Variants mutate it
// afterwards; every mutation that breaks the secevents contract is
// deliberate and marked in its test.
func fixture(eventType string) secevents.Event {
	ev := secevents.Event{}
	ev.SchemaVersion = secevents.SchemaVersion
	ev.EventID = "core-" + hex.EncodeToString(make([]byte, 32))
	ev.EventType = eventType
	ev.OrgID = "org-1"
	ev.OccurredAt = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	ev.Identity = secevents.Identity{
		Agent:   secevents.IDRef{Value: "agent-1", State: secevents.IDKnown},
		Session: secevents.IDRef{Value: "sess-1", State: secevents.IDKnown},
		Task:    secevents.IDRef{State: secevents.IDAbsent},
		Tool:    secevents.IDRef{State: secevents.IDAbsent},
	}
	ev.Summary = "policy guard v1 observe: step1 category=schema severity=high action=deny"
	ev.Cost = secevents.Cost{State: secevents.CostKnown, MicroUSD: 1500}
	ev.Evidence = []secevents.EvidenceRef{
		{Kind: "payload_digest", Digest: digestHex(1), Location: "request_logs:payload:req-1"},
		{Kind: "policy_decision", Digest: digestHex(2)},
	}
	return ev
}

func digestHex(b byte) string {
	d := sha256.Sum256([]byte{b})
	return hex.EncodeToString(d[:])
}

// TestOCSFTargetVersionPinned guards the mapping-artifact §1 pin: the
// live-checked current OCSF release at implementation time is 1.9.0. A
// change here is an additive contract change and must update the mapping
// artifact and the golden fixtures.
func TestOCSFTargetVersionPinned(t *testing.T) {
	if OCSFTargetVersion != "1.9.0" {
		t.Fatalf("OCSFTargetVersion = %q, mapping artifact pins 1.9.0", OCSFTargetVersion)
	}
}

// asMap decodes a record's canonical JSON into a generic map for
// key-level assertions.
func asMap(t *testing.T, rec NormalizedRecord) map[string]any {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	return m
}

func TestMapEventKnownTypes(t *testing.T) {
	cases := []struct {
		eventType string
		severity  int
	}{
		{"policy.deny", 4},
		{"policy.mask", 3},
		{"policy.flag", 2},
		{"policy.allow", 1},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			ev := fixture(tc.eventType)
			if err := ev.Validate(); err != nil {
				t.Fatalf("fixture must be a valid secevents event: %v", err)
			}
			rec, err := MapEvent(ev)
			if err != nil {
				t.Fatalf("MapEvent: %v", err)
			}
			if rec.SchemaVersion != recordSchemaVersion {
				t.Errorf("schema_version = %d, want %d", rec.SchemaVersion, recordSchemaVersion)
			}
			if rec.CategoryUID != 2 || rec.ClassUID != 2004 {
				t.Errorf("classification = (%d,%d), want (2,2004) Findings/Detection Finding", rec.CategoryUID, rec.ClassUID)
			}
			if rec.ActivityID != 1 || rec.TypeUID != 200401 {
				t.Errorf("activity/type = (%d,%d), want (1,200401) Create", rec.ActivityID, rec.TypeUID)
			}
			if rec.SeverityID != tc.severity {
				t.Errorf("severity_id = %d, want %d", rec.SeverityID, tc.severity)
			}
			if !rec.Mapped {
				t.Errorf("mapped = false for known type %q", tc.eventType)
			}
			if rec.SourceEventType != tc.eventType {
				t.Errorf("source_event_type = %q, want %q", rec.SourceEventType, tc.eventType)
			}
			if rec.FindingInfo.UID != ev.EventID {
				t.Errorf("finding_info.uid = %q, want event_id %q", rec.FindingInfo.UID, ev.EventID)
			}
			if rec.FindingInfo.Title != ev.Summary {
				t.Errorf("finding_info.title = %q, want summary %q", rec.FindingInfo.Title, ev.Summary)
			}
			if rec.Time != ev.OccurredAt.UnixMilli() {
				t.Errorf("time = %d, want %d (epoch ms)", rec.Time, ev.OccurredAt.UnixMilli())
			}
			if rec.Metadata.Version != OCSFTargetVersion {
				t.Errorf("metadata.version = %q, want %q", rec.Metadata.Version, OCSFTargetVersion)
			}
			if rec.Metadata.Product != (RecordProduct{VendorName: ProductVendorName, Name: ProductName, Version: ProductVersion}) {
				t.Errorf("metadata.product = %+v", rec.Metadata.Product)
			}
			if rec.Metadata.SecEventsSchemaVersion != ev.SchemaVersion {
				t.Errorf("metadata.secevents_schema_version = %d, want %d", rec.Metadata.SecEventsSchemaVersion, ev.SchemaVersion)
			}
			if rec.OrgID != ev.OrgID {
				t.Errorf("org_id = %q, want %q", rec.OrgID, ev.OrgID)
			}
		})
	}
}

func TestMapEventUnknownTypeNeverDropped(t *testing.T) {
	for _, unknown := range []string{"policy.quarantine", "telemetry.thing"} {
		t.Run(unknown, func(t *testing.T) {
			ev := fixture(unknown)
			rec, err := MapEvent(ev)
			if err != nil {
				t.Fatalf("unknown type must map, not error: %v", err)
			}
			if rec.TypeUID != 200400 || rec.ActivityID != 0 || rec.SeverityID != 0 {
				t.Errorf("unmapped classification = (%d,%d,%d), want (200400,0,0)", rec.TypeUID, rec.ActivityID, rec.SeverityID)
			}
			if rec.Mapped {
				t.Errorf("mapped = true for unknown type %q", unknown)
			}
			if rec.SourceEventType != unknown {
				t.Errorf("source_event_type = %q, want the original type preserved", rec.SourceEventType)
			}
			// The record is still a full record: identity/evidence/cost ride along.
			if rec.FindingInfo.UID != ev.EventID || rec.Identity.Agent.Value != "agent-1" || len(rec.Evidence) != 2 {
				t.Errorf("unmapped record lost source data: %+v", rec)
			}
		})
	}
}

func TestMapEventDeterministic(t *testing.T) {
	ev := fixture("policy.deny")
	first, err := MapEvent(ev)
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wantSHA := sha256.Sum256(firstJSON)
	for i := 0; i < 100; i++ {
		rec, err := MapEvent(ev)
		if err != nil {
			t.Fatalf("MapEvent rep %d: %v", i, err)
		}
		if !reflect.DeepEqual(rec, first) {
			t.Fatalf("rep %d: struct drift", i)
		}
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal rep %d: %v", i, err)
		}
		got := sha256.Sum256(data)
		if got != wantSHA {
			t.Fatalf("rep %d: canonical JSON not byte-deterministic", i)
		}
	}
}

func TestMapEventIdentityTriStateVerbatim(t *testing.T) {
	ev := fixture("policy.flag")
	ev.Identity.Session = secevents.IDRef{State: secevents.IDUnknown} // value stripped by redaction
	rec, err := MapEvent(ev)
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	if rec.Identity != (RecordIdentity{
		Agent:   secevents.IDRef{Value: "agent-1", State: secevents.IDKnown},
		Session: secevents.IDRef{State: secevents.IDUnknown},
		Task:    secevents.IDRef{State: secevents.IDAbsent},
		Tool:    secevents.IDRef{State: secevents.IDAbsent},
	}) {
		t.Fatalf("identity not carried verbatim: %+v", rec.Identity)
	}
	m := asMap(t, rec)
	ident := m["identity"].(map[string]any)
	agent := ident["agent"].(map[string]any)
	if agent["value"] != "agent-1" || agent["state"] != "known" {
		t.Errorf("identity.agent = %v, want known agent-1", agent)
	}
	sess := ident["session"].(map[string]any)
	if _, has := sess["value"]; has {
		t.Errorf("identity.session must not carry a value in unknown state: %v", sess)
	}
	if sess["state"] != "unknown" {
		t.Errorf("identity.session.state = %v, want unknown (not collapsed to absent)", sess["state"])
	}
	task := ident["task"].(map[string]any)
	if _, has := task["value"]; has {
		t.Errorf("identity.task must not carry a value in absent state: %v", task)
	}
	if task["state"] != "absent" {
		t.Errorf("identity.task.state = %v, want absent", task["state"])
	}
}

func TestMapEventEvidenceDigestsOnly(t *testing.T) {
	ev := fixture("policy.mask")
	rec, err := MapEvent(ev)
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	if len(rec.Evidence) != 2 {
		t.Fatalf("evidence len = %d, want 2", len(rec.Evidence))
	}
	if rec.Evidence[0] != (secevents.EvidenceRef{Kind: "payload_digest", Digest: digestHex(1), Location: "request_logs:payload:req-1"}) {
		t.Errorf("evidence[0] = %+v", rec.Evidence[0])
	}
	if rec.Evidence[1] != (secevents.EvidenceRef{Kind: "policy_decision", Digest: digestHex(2)}) {
		t.Errorf("evidence[1] = %+v", rec.Evidence[1])
	}
	m := asMap(t, rec)
	for _, raw := range m["evidence"].([]any) {
		ev := raw.(map[string]any)
		if len(ev) > 3 {
			t.Errorf("evidence object carries more than kind/digest/location: %v", ev)
		}
		if _, has := ev["content"]; has {
			t.Errorf("evidence object carries content: %v", ev)
		}
		if _, has := ev["payload"]; has {
			t.Errorf("evidence object carries payload: %v", ev)
		}
	}
}

func TestMapEventCostStates(t *testing.T) {
	t.Run("known", func(t *testing.T) {
		ev := fixture("policy.deny")
		ev.Cost = secevents.Cost{State: secevents.CostKnown, MicroUSD: 1500}
		rec, err := MapEvent(ev)
		if err != nil {
			t.Fatalf("MapEvent: %v", err)
		}
		if rec.Cost == nil || rec.Cost.State != "known" || rec.Cost.MicroUSD == nil || *rec.Cost.MicroUSD != 1500 {
			t.Fatalf("cost = %+v, want known 1500", rec.Cost)
		}
	})
	t.Run("known-free zero stays explicit", func(t *testing.T) {
		ev := fixture("policy.deny")
		ev.Cost = secevents.Cost{State: secevents.CostKnown, MicroUSD: 0}
		rec, err := MapEvent(ev)
		if err != nil {
			t.Fatalf("MapEvent: %v", err)
		}
		if rec.Cost == nil || rec.Cost.MicroUSD == nil || *rec.Cost.MicroUSD != 0 {
			t.Fatalf("cost = %+v, want known with explicit micro_usd=0", rec.Cost)
		}
		m := asMap(t, rec)
		cost := m["cost"].(map[string]any)
		if _, has := cost["micro_usd"]; !has {
			t.Errorf("known-free 0 must serialize an explicit micro_usd: %v", cost)
		}
	})
	t.Run("unknown never collapses to zero", func(t *testing.T) {
		ev := fixture("policy.deny")
		ev.Cost = secevents.Cost{State: secevents.CostUnknown}
		rec, err := MapEvent(ev)
		if err != nil {
			t.Fatalf("MapEvent: %v", err)
		}
		if rec.Cost == nil || rec.Cost.State != "unknown" || rec.Cost.MicroUSD != nil {
			t.Fatalf("cost = %+v, want unknown without a number", rec.Cost)
		}
		m := asMap(t, rec)
		cost := m["cost"].(map[string]any)
		if _, has := cost["micro_usd"]; has {
			t.Errorf("unknown cost must not carry micro_usd: %v", cost)
		}
	})
	t.Run("none omits the field", func(t *testing.T) {
		ev := fixture("policy.deny")
		ev.Cost = secevents.Cost{State: secevents.CostNone}
		rec, err := MapEvent(ev)
		if err != nil {
			t.Fatalf("MapEvent: %v", err)
		}
		if rec.Cost != nil {
			t.Fatalf("cost = %+v, want nil for CostNone", rec.Cost)
		}
		m := asMap(t, rec)
		if _, has := m["cost"]; has {
			t.Errorf("cost field must be absent for CostNone: %v", m["cost"])
		}
	})
}

func TestMapEventInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*secevents.Event)
	}{
		{"no schema version", func(ev *secevents.Event) { ev.SchemaVersion = 0 }},
		{"future schema version", func(ev *secevents.Event) { ev.SchemaVersion = secevents.SchemaVersion + 1 }},
		{"empty event id", func(ev *secevents.Event) { ev.EventID = "" }},
		{"empty event type", func(ev *secevents.Event) { ev.EventType = "" }},
		{"empty org", func(ev *secevents.Event) { ev.OrgID = "" }},
		{"zero occurred at", func(ev *secevents.Event) { ev.OccurredAt = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := fixture("policy.deny")
			tc.mut(&ev)
			_, err := MapEvent(ev)
			if err == nil {
				t.Fatalf("expected ErrInvalidInput")
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput (wrapped)", err)
			}
		})
	}
}

func TestMapEventsBatch(t *testing.T) {
	events := []secevents.Event{
		fixture("policy.deny"),
		fixture("policy.allow"),
		fixture("policy.unknown-thing"),
	}
	records, err := MapEvents(events)
	if err != nil {
		t.Fatalf("MapEvents: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records len = %d, want 3", len(records))
	}
	if !records[0].Mapped || !records[1].Mapped || records[2].Mapped {
		t.Errorf("mapped flags = %v,%v,%v", records[0].Mapped, records[1].Mapped, records[2].Mapped)
	}
	// The error path names the offending index.
	bad := fixture("policy.deny")
	bad.OrgID = ""
	_, err = MapEvents([]secevents.Event{fixture("policy.deny"), bad})
	if err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("batch error = %v, want wrapped ErrInvalidInput", err)
	}
}

// TestNoSignalComposition proves the no-signal contract end to end at the
// mapper boundary: a core publisher event without a policy decision
// record produces zero secevents events (adapter no-signal, adapter.go
// "explicit no-signal outcome") and therefore zero normalized records.
// Composition, not modification: neither the adapter nor the core
// publisher is changed.
func TestNoSignalComposition(t *testing.T) {
	core := eventpublisher.Event{
		EventType: "request.completed",
		Source:    "gateway",
		TS:        time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).UnixMilli(),
		SessionID: "sess-1",
		Payload:   `{"model":"m"}`,
		OrgID:     "org-1",
		Method:    "POST",
	}
	events, err := (secevents.CoreAdapter{}).AdaptPublisherEvent(core, time.Date(2026, 11, 7, 12, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("no-signal core event produced %d events, want 0", len(events))
	}
	records, err := MapEvents(events)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("no-signal core event produced %d records, want 0", len(records))
	}
}

// TestAdaptedSignalComposition proves the full chain on the happy path:
// one OP-9 finding (action deny) → one secevents event (policy.deny) →
// one mapped record (Detection Finding: Create, High). This pins the
// eventTypePrefix + action composition the mapping table is built on.
func TestAdaptedSignalComposition(t *testing.T) {
	core := eventpublisher.Event{
		EventType:  "request.completed",
		Source:     "gateway",
		TS:         time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).UnixMilli(),
		RequestID:  "req-1",
		SessionID:  "sess-1",
		Payload:    `{"model":"m"}`,
		OrgID:      "org-1",
		Method:     "POST",
		Policy:     `[{"policy_id":"p1","name":"guard","version":1,"mode":"observe","verdict":"allow","findings":[{"step":"step1","category":"schema","severity":"high","action":"deny"}]}]`,
		CostStatus: "priced", EstimatedCostUSD: 0.0015,
	}
	events, err := (secevents.CoreAdapter{}).AdaptPublisherEvent(core, time.Date(2026, 11, 7, 12, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if err := events[0].Validate(); err != nil {
		t.Fatalf("adapted event must be valid: %v", err)
	}
	records, err := MapEvents(events)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	rec := records[0]
	if rec.SourceEventType != "policy.deny" || !rec.Mapped || rec.SeverityID != 4 || rec.TypeUID != 200401 {
		t.Fatalf("composed record = %+v, want mapped policy.deny 200401/High", rec)
	}
	if rec.Time != core.TS {
		t.Errorf("time = %d, want producer TS %d", rec.Time, core.TS)
	}
	if rec.Cost == nil || rec.Cost.State != "known" || rec.Cost.MicroUSD == nil || *rec.Cost.MicroUSD != 1500 {
		t.Errorf("cost = %+v, want known 1500 (0.0015 USD)", rec.Cost)
	}
}
