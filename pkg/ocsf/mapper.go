package ocsf

import (
	"errors"
	"fmt"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// ErrInvalidInput marks a secevents event that cannot be mapped because
// it violates the invariants the normalized record relies on. It is a
// cousin of secevents.ErrInvalidEvent: MapEvent does not re-run the full
// secevents validation, it only enforces what the record contract needs
// (identifiers present, timestamp set, schema version decodable).
var ErrInvalidInput = errors.New("ocsf: unmappable secevents event")

// OCSF classification constants (mapping artifact §3): every known
// policy event type is a Detection Finding (class 2004, category
// Findings 2) recorded as a new detection (activity Create 1 ⇒ type_uid
// 200401). An unknown type keeps the class but reports Unknown activity
// (0 ⇒ 200400).
const (
	categoryFindings      = 2
	classDetectionFinding = 2004
	activityCreate        = 1
	activityUnknown       = 0
	typeUIDCreate         = 200401 // 2004*100 + 1
	typeUIDUnknown        = 200400 // 2004*100 + 0
)

// typeMapping is the full known-type table of the mapping artifact §3:
// secevents event type → severity_id. All four actions share the
// Detection Finding: Create classification; they differ only in
// severity_id, mirroring the toolpolicy severity scale
// (pkg/toolpolicy/step.go: deny→high, mask→medium, else low; allow has
// no toolpolicy level and maps to Informational, one step below Low).
var typeMapping = map[string]int{
	"policy.deny":  4, // High
	"policy.mask":  3, // Medium
	"policy.flag":  2, // Low
	"policy.allow": 1, // Informational
}

// MapEvent maps one secevents event to its normalized OCSF-aligned
// record (mapping artifact W01). It is a pure function of the input:
// identical events map to identical records, and the canonical encoding
// (json.Marshal of the struct) is byte-deterministic.
//
// Unknown event types are NOT errors and are never dropped: they map to
// Detection Finding: Unknown (200400, severity_id 0, mapped=false) with
// the original type string preserved in SourceEventType (artifact §4).
//
// Events that violate the mapping invariants (empty identifiers, zero
// timestamp, missing/unknown schema version) return ErrInvalidInput —
// wrapped, with the offending field named.
func MapEvent(ev secevents.Event) (NormalizedRecord, error) {
	if ev.SchemaVersion <= 0 {
		return NormalizedRecord{}, fmt.Errorf("%w: schema_version %d: missing", ErrInvalidInput, ev.SchemaVersion)
	}
	if ev.SchemaVersion > secevents.SchemaVersion {
		return NormalizedRecord{}, fmt.Errorf("%w: schema_version %d > %d: fail closed", ErrInvalidInput, ev.SchemaVersion, secevents.SchemaVersion)
	}
	if ev.EventID == "" {
		return NormalizedRecord{}, fmt.Errorf("%w: event_id is empty", ErrInvalidInput)
	}
	if ev.EventType == "" {
		return NormalizedRecord{}, fmt.Errorf("%w: event_type is empty", ErrInvalidInput)
	}
	if ev.OrgID == "" {
		return NormalizedRecord{}, fmt.Errorf("%w: org_id is empty", ErrInvalidInput)
	}
	if ev.OccurredAt.IsZero() {
		return NormalizedRecord{}, fmt.Errorf("%w: occurred_at is zero", ErrInvalidInput)
	}

	severityID, mapped := typeMapping[ev.EventType]

	rec := NormalizedRecord{
		SchemaVersion: recordSchemaVersion,
		CategoryUID:   categoryFindings,
		ClassUID:      classDetectionFinding,
		ActivityID:    activityCreate,
		TypeUID:       typeUIDCreate,
		SeverityID:    severityID,
		Time:          ev.OccurredAt.UnixMilli(),
		FindingInfo: RecordFindingInfo{
			UID:   ev.EventID,
			Title: ev.Summary,
		},
		Metadata: RecordMetadata{
			Version:                OCSFTargetVersion,
			Product:                RecordProduct{VendorName: ProductVendorName, Name: ProductName, Version: ProductVersion},
			SecEventsSchemaVersion: ev.SchemaVersion,
		},
		OrgID:           ev.OrgID,
		Identity:        RecordIdentity{Agent: ev.Identity.Agent, Session: ev.Identity.Session, Task: ev.Identity.Task, Tool: ev.Identity.Tool},
		SourceEventType: ev.EventType,
		Mapped:          mapped,
	}
	if !mapped {
		rec.ActivityID = activityUnknown
		rec.TypeUID = typeUIDUnknown
		rec.SeverityID = 0
	}

	if len(ev.Evidence) > 0 {
		rec.Evidence = append([]secevents.EvidenceRef(nil), ev.Evidence...)
	}
	rec.Cost = mapCost(ev.Cost)

	return rec, nil
}

// mapCost transfers the secevents cost tri-state to the record extension
// (artifact §7): none → nil (the field is omitted; missing must not be
// read as free), unknown → {state:"unknown"} without a number (unknown
// never collapses into zero), known → explicit micro_usd including a
// known-free 0.
func mapCost(c secevents.Cost) *RecordCost {
	switch c.State {
	case secevents.CostKnown:
		v := c.MicroUSD
		return &RecordCost{State: "known", MicroUSD: &v}
	case secevents.CostUnknown:
		return &RecordCost{State: "unknown"}
	default: // CostNone or empty (constructor-default): no cost dimension
		return nil
	}
}

// MapEvents maps a batch of events, failing on the first unmappable one
// with its index named. The one-by-one loop keeps the mapping pure; no
// cross-event state exists in batch A.
func MapEvents(events []secevents.Event) ([]NormalizedRecord, error) {
	records := make([]NormalizedRecord, 0, len(events))
	for i, ev := range events {
		rec, err := MapEvent(ev)
		if err != nil {
			return nil, fmt.Errorf("%w: event[%d]", err, i)
		}
		records = append(records, rec)
	}
	return records, nil
}
