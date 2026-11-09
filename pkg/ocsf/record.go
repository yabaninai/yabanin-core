// Package ocsf implements the normalized OCSF-aligned export form of
// security events (packet E07-P01).
//
// It is an additive, core-Apache mapping layer on top of pkg/secevents:
// the enterprise-facing security-event contract stays the single source
// of truth, and this package derives from it a stable, deterministic
// record shaped after the Open Cybersecurity Schema Framework
// (Detection Finding class 2004, category Findings 2).
//
// Scope of batch A (cards W01-C01…C03, W02-C01…C03):
//
//   - W01-C01: the secevents → OCSF mapping table artifact
//     (artifacts/enterprise-beta/E07-P01/W01-ocsf-mapping-2026-11-07.md);
//   - W01-C02: this record shape and MapEvent;
//   - W01-C03: golden fixtures pinning the canonical encoding;
//   - W02-C01/W02-C02: the versioned export schema (schema/export-v1.json,
//     ExportSchemaVersion) and its embedded validator;
//   - W02-C03: the schema-versioning artifact.
//
// Non-claims (see the mapping artifact): the record is an OCSF-aligned
// subset plus documented extensions (org_id, identity, evidence, cost,
// source_event_type, mapped); full OCSF conformance is not claimed, and
// no OCSF schema text is copied into the product.
//
// The canonical encoding of a record is json.Marshal of the struct:
// fields are emitted in declaration order and no map types participate,
// so the same record always serializes to byte-identical JSON.
package ocsf

import (
	"github.com/reireirei/yabanin/pkg/secevents"
)

// recordSchemaVersion is the export-schema version stamped on every
// record by MapEvent. It is the record-level twin of ExportSchemaVersion
// (version.go, added by W02-C01); validate_test.go asserts the two stay
// equal. It is unexported because the exported versioning surface is
// ExportSchemaVersion; the stamp must never diverge from it.
const recordSchemaVersion = 1

// OCSFTargetVersion is the pinned OCSF schema release the mapping targets
// (mapping artifact §1; live check 2026-11-07: 1.9.0 is the current
// release, main is 1.10.0-dev and unreleased). It is recorded in
// metadata.version of every record. Changing it is an additive contract
// change governed by the W02 versioning artifact.
const OCSFTargetVersion = "1.9.0"

// Product metadata constants for metadata.product.
const (
	ProductVendorName = "yabanin"
	ProductName       = "secevents-ocsf-export"
	ProductVersion    = "v1"
)

// RecordFindingInfo mirrors the OCSF finding_info object as a subset:
// uid anchors dedup (the secevents event_id), title is the bounded event
// summary.
type RecordFindingInfo struct {
	UID   string `json:"uid"`
	Title string `json:"title,omitempty"`
}

// RecordProduct identifies the producing export adapter.
type RecordProduct struct {
	VendorName string `json:"vendor_name"`
	Name       string `json:"name"`
	Version    string `json:"version"`
}

// RecordMetadata carries the OCSF metadata block of the record:
// the pinned target schema version, the producing product, and the
// source secevents schema version (dual version pinning — see the W02
// versioning artifact).
type RecordMetadata struct {
	Version                string        `json:"version"`
	Product                RecordProduct `json:"product"`
	SecEventsSchemaVersion int           `json:"secevents_schema_version"`
}

// RecordCost is the cost extension. State is "known" or "unknown";
// a cost-less event omits the whole cost field (nil *RecordCost):
// missing must never be read as free. MicroUSD is present if and only if
// State is "known" — a known-free 0 is emitted as an explicit 0, and an
// unknown cost never carries a number (it must not collapse into zero).
type RecordCost struct {
	State    string `json:"state"`
	MicroUSD *int64 `json:"micro_usd,omitempty"`
}

// RecordIdentity carries the secevents tri-state identifier block
// verbatim (known/unknown/absent states are the E01-P03-W01 contract;
// unknown must never be conflated with absent or a known empty value).
// The secevents IDRef wire shape ({value?, state?}) is reused as-is on
// purpose: the extension is defined as a verbatim transfer, not a
// re-derivation.
type RecordIdentity struct {
	Agent   secevents.IDRef `json:"agent"`
	Session secevents.IDRef `json:"session"`
	Task    secevents.IDRef `json:"task"`
	Tool    secevents.IDRef `json:"tool"`
}

// NormalizedRecord is one secevents event in the OCSF-aligned export
// form (mapping artifact W01). Field declaration order is the canonical
// JSON key order; do not reorder fields (golden fixtures pin it).
type NormalizedRecord struct {
	// SchemaVersion is the export-schema version (ExportSchemaVersion).
	SchemaVersion int `json:"schema_version"`
	// OCSF classification block. Known policy event types map to
	// Detection Finding: Create (2, 2004, 1, 200401); an unknown type
	// maps to Detection Finding: Unknown (2, 2004, 0, 200400) with
	// severity_id 0 — never dropped, see Mapped and SourceEventType.
	CategoryUID int `json:"category_uid"`
	ClassUID    int `json:"class_uid"`
	ActivityID  int `json:"activity_id"`
	TypeUID     int `json:"type_uid"`
	// SeverityID is derived from the policy action (deny→4 High,
	// mask→3 Medium, flag→2 Low, allow→1 Informational, unknown→0).
	SeverityID int `json:"severity_id"`
	// Time is the event occurrence time in epoch milliseconds (OCSF
	// timestamp_t; the secevents source granularity is milliseconds).
	Time int64 `json:"time"`
	// FindingInfo anchors dedup (uid = secevents event_id).
	FindingInfo RecordFindingInfo `json:"finding_info"`
	// Metadata pins the target OCSF version, the product and the source
	// secevents schema version.
	Metadata RecordMetadata `json:"metadata"`
	// OrgID is the tenant scope of the event, carried verbatim.
	OrgID string `json:"org_id"`
	// Identity is the tri-state identifier block, carried verbatim.
	Identity RecordIdentity `json:"identity"`
	// Evidence is the redacted evidence-reference list (digests only; the
	// type cannot carry content by construction).
	Evidence []secevents.EvidenceRef `json:"evidence,omitempty"`
	// Cost carries the cost dimension when the event has one. nil means
	// no cost dimension (CostNone) — distinct from unknown.
	Cost *RecordCost `json:"cost,omitempty"`
	// SourceEventType is the original secevents event_type, always
	// preserved — for mapped and unmapped records alike.
	SourceEventType string `json:"source_event_type"`
	// Mapped reports whether the source type was in the known mapping
	// table. false + SourceEventType is the explicit unmapped contract.
	Mapped bool `json:"mapped"`
	// ReplayID is RESERVED (E07-P01-W04 replay semantics): the field name
	// and its schema slot are fixed by W02-C01 so later batches can add
	// replay handling without a schema break. Batch A never sets it.
	ReplayID string `json:"replay_id,omitempty"`
}
