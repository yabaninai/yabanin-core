// Package historyarchive pins the storage-phase contract of the request
// history archive (N10-P02, PRODUCT-CONTRACT §4): which columns constitute a
// history record, the fixed 90-day hot-storage threshold, and the media and
// redaction policies the archive must preserve.
//
// The package is deliberately data-free: it declares the contract as typed
// constants and one ordered column manifest, and the tests in this package
// enforce the manifest against the live migration schema
// (migrations/0001_init.up.sql). Any future schema change to request_logs
// (hot tier) therefore fails this package's contract tests until the
// manifest is updated in the same change — schema evolution is pinned, which
// is the seam the S3/Iceberg object writer and the hot→cold transfer consume.
//
// Scope boundaries (owner decisions I26-I30/I62/I63):
//   - 90 days is a TIER boundary, never an age-based deletion deadline.
//     Reaching it does not delete data; transfer ownership lives in
//     N10-P02-T06 (idempotent hot→cold transfer) and N10-P02-T08 (no hidden
//     deletion in PG-only mode).
//   - The archive carries media METADATA only (I62): the schema has no
//     media-byte columns and none may be added (enforced by contract test).
//     Media bytes/base64 remain an Enterprise opt-in backend (N10-P06).
//   - The chosen redaction policy is originals-org-opt-in (I63): original
//     captures (upstream_request / upstream_response) are persisted only for
//     orgs with an explicit opt-in; the fail-closed default persists
//     processed content only (adminstore.OriginalRetentionPlatformDefault).
package historyarchive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// HotRetentionDays is the fixed 90-day hot-storage threshold for request
// history (contract §4: «Горячее хранение — 90 дней»). It is intentionally a
// constant, not configuration: the card N10-P02-T02 pins the threshold, so
// there is no env override that could silently move the tier boundary.
//
// Semantics: history younger than HotRetentionDays is served from the hot
// PostgreSQL tier; rows older than the boundary become ELIGIBLE for transfer
// to the S3/Iceberg archive. Crossing the boundary must never delete
// anything by itself — deletion happens only after a confirmed catalog
// commit (N10-P02-T06), and the archive itself is retained indefinitely by
// default (I29).
const HotRetentionDays = 90

// MediaPolicyMetadataOnly is the pinned media policy of the archive (I62):
// media enters the archive as metadata and links, never as bytes, base64 or
// data URLs. The schema enforces this structurally — the history schema has
// no media-byte columns — and SchemaContract tests keep it that way.
// Enterprise media-byte storage is a separate opt-in backend (N10-P06) and
// must not reintroduce byte columns into the hot request_logs schema.
const MediaPolicyMetadataOnly = "metadata-only"

// RedactionPolicyOriginalsOrgOptIn is the chosen redaction policy for the
// archive (I63): full-fidelity ORIGINAL captures (upstream_request /
// upstream_response) are part of the archived history only when the org has
// explicitly opted in via org original-text retention; the fail-closed
// default persists processed text only. Reading retained originals requires
// the separate requests.read_originals capability, hot and cold alike.
const RedactionPolicyOriginalsOrgOptIn = "originals-org-opt-in"

// RedactContentDefault mirrors team_retention_policies.redact_content
// (DEFAULT true): archive exports render content payloads as null unless the
// org's effective policy says otherwise. Hashes, metadata and lineage
// digests always survive verbatim.
const RedactContentDefault = true

// ColumnKind classifies a history column for archival treatment: what the
// transfer writer (T05/T06) must do with it, and which policy guards it.
type ColumnKind string

const (
	// KindMetadata is operational/financial/routing metadata. It transfers
	// verbatim; no redaction policy may drop it (search, cost reporting and
	// the lineage chain depend on it hot and cold).
	KindMetadata ColumnKind = "metadata"
	// KindContentProcessed is the processed response snapshot (the visible
	// Requests payload). It is NOT subject to the originals opt-in: the
	// fail-closed original-retention gate already resolved what may persist
	// at capture time. Content profiles (legacy / metadata-only) remain
	// upstream of persistence and therefore of the archive.
	KindContentProcessed ColumnKind = "content-processed"
	// KindContentOriginal is a full-fidelity original capture
	// (upstream_request / upstream_response). In the archive these columns
	// carry SQL NULL unless the org's effective original-text retention is
	// on (RedactionPolicyOriginalsOrgOptIn), mirroring the hot-path
	// fail-closed strip; the strip decision is made at capture time, the
	// archive preserves whatever the hot tier lawfully holds.
	KindContentOriginal ColumnKind = "content-original"
	// KindAuthz is an ownership/authorization column. Authz columns
	// transfer verbatim and are never dropped or redacted: permissions are
	// identical hot and cold, so the archive must keep the columns the
	// payload-authorization predicates filter on.
	KindAuthz ColumnKind = "authz"
)

// HistoryColumn is one column of the history schema. DBType is the exact
// type token from migrations/0001_init.up.sql so the contract tests can
// byte-compare manifest and schema.
type HistoryColumn struct {
	Name   string
	DBType string
	Kind   ColumnKind
}

// HistoryColumns is the ordered history-record manifest — the exact column
// list of CREATE TABLE public.request_logs in migrations/0001_init.up.sql,
// in schema order. This is the schema the hot→cold transfer replicates and
// the digest that pins schema evolution; no migration adds request_logs
// columns today (enforced), so this table is the single column source.
//
// Classification notes (the honest ones):
//   - error is metadata: production capture does not strip provider error
//     text under the originals policy (only upstream_request /
//     upstream_response / tool-call arguments are fail-closed stripped), so
//     the archive treats it the same way. Known limitation, recorded in the
//     lane record; a future card may reclassify it.
//   - labels is metadata: org-supplied key/value labels, no content payload.
var HistoryColumns = []HistoryColumn{
	{Name: "id", DBType: "bigint", Kind: KindMetadata},
	{Name: "session_id", DBType: "uuid", Kind: KindMetadata},
	{Name: "org_id", DBType: "uuid", Kind: KindAuthz},
	{Name: "model_requested", DBType: "text", Kind: KindMetadata},
	{Name: "model_used", DBType: "text", Kind: KindMetadata},
	{Name: "upstream_url", DBType: "text", Kind: KindMetadata},
	{Name: "method", DBType: "text", Kind: KindMetadata},
	{Name: "status_code", DBType: "integer", Kind: KindMetadata},
	{Name: "duration_ms", DBType: "integer", Kind: KindMetadata},
	{Name: "tokens_in", DBType: "integer", Kind: KindMetadata},
	{Name: "tokens_out", DBType: "integer", Kind: KindMetadata},
	{Name: "error", DBType: "text", Kind: KindMetadata},
	{Name: "created_at", DBType: "timestamp with time zone", Kind: KindMetadata},
	{Name: "updated_at", DBType: "timestamp with time zone", Kind: KindMetadata},
	{Name: "request_id", DBType: "text", Kind: KindMetadata},
	{Name: "prompt_hash", DBType: "text", Kind: KindMetadata},
	{Name: "response", DBType: "jsonb", Kind: KindContentProcessed},
	{Name: "cache_hit_type", DBType: "text", Kind: KindMetadata},
	{Name: "cache_similarity", DBType: "real", Kind: KindMetadata},
	{Name: "counterfactual_cost_usd", DBType: "numeric(12,6)", Kind: KindMetadata},
	{Name: "cost_in_usd", DBType: "numeric(12,6)", Kind: KindMetadata},
	{Name: "classifier_class", DBType: "text", Kind: KindMetadata},
	{Name: "classifier_confidence", DBType: "real", Kind: KindMetadata},
	{Name: "classifier_source", DBType: "text", Kind: KindMetadata},
	{Name: "tier_used", DBType: "text", Kind: KindMetadata},
	{Name: "ab_group", DBType: "text", Kind: KindMetadata},
	{Name: "evalgate_sampled", DBType: "boolean", Kind: KindMetadata},
	{Name: "team_id", DBType: "uuid", Kind: KindAuthz},
	{Name: "home_region", DBType: "text", Kind: KindMetadata},
	{Name: "task_id", DBType: "text", Kind: KindMetadata},
	{Name: "agent_id", DBType: "uuid", Kind: KindMetadata},
	{Name: "routing_decision", DBType: "text", Kind: KindMetadata},
	{Name: "upstream_request", DBType: "jsonb", Kind: KindContentOriginal},
	{Name: "upstream_response", DBType: "jsonb", Kind: KindContentOriginal},
	{Name: "first_token_ms", DBType: "integer", Kind: KindMetadata},
	{Name: "attempt_count", DBType: "integer", Kind: KindMetadata},
	{Name: "retry_count", DBType: "integer", Kind: KindMetadata},
	{Name: "endpoint", DBType: "text", Kind: KindMetadata},
	{Name: "usage_source", DBType: "text", Kind: KindMetadata},
	{Name: "cost_status", DBType: "text", Kind: KindMetadata},
	{Name: "cache_read_tokens", DBType: "integer", Kind: KindMetadata},
	{Name: "cache_creation_tokens", DBType: "integer", Kind: KindMetadata},
	{Name: "labels", DBType: "jsonb", Kind: KindMetadata},
	{Name: "user_id", DBType: "uuid", Kind: KindAuthz},
	{Name: "api_key_id", DBType: "uuid", Kind: KindAuthz},
	{Name: "session_key_id", DBType: "uuid", Kind: KindMetadata},
}

// Column returns the manifest entry for name.
func Column(name string) (HistoryColumn, bool) {
	for _, c := range HistoryColumns {
		if c.Name == name {
			return c, true
		}
	}
	return HistoryColumn{}, false
}

// ColumnsOfKind returns the manifest columns of one kind, in schema order.
func ColumnsOfKind(kind ColumnKind) []HistoryColumn {
	var out []HistoryColumn
	for _, c := range HistoryColumns {
		if c.Kind == kind {
			out = append(out, c)
		}
	}
	return out
}

// HotCutoff returns the tier boundary: history rows with created_at strictly
// before this instant are eligible for hot→cold transfer. Pure time math —
// the boundary never implies deletion.
func HotCutoff(now time.Time) time.Time {
	return now.AddDate(0, 0, -HotRetentionDays)
}

// TierEligible reports whether a history row's created_at has crossed the
// 90-day tier boundary. Eligibility is the ONLY thing the threshold decides;
// transfer-and-delete orchestration lives behind the catalog commit
// protocol (N10-P02-T06), never here.
func TierEligible(createdAt, now time.Time) bool {
	return createdAt.Before(HotCutoff(now))
}

// Digest returns a deterministic fingerprint over a column manifest (sha256,
// hex). The transfer writer records it per archive batch so a reader can
// detect which schema generation a cold batch was written with — the hook
// for N10-P02-T05 schema evolution. Pass HistoryColumns for the live digest.
func Digest(cols []HistoryColumn) string {
	h := sha256.New()
	for _, c := range cols {
		// hash.Hash never returns a write error; the ignore matches the
		// repo-wide idiom for writes into in-memory sinks.
		_, _ = fmt.Fprintf(h, "%s\x1f%s\x1f%s\x1e", c.Name, c.DBType, c.Kind)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateManifest checks manifest invariants that must hold for any schema
// generation: non-empty, unique column names, and every content/authz
// column classified. It returns the manifest's digest as well.
func ValidateManifest(cols []HistoryColumn) (string, error) {
	if len(cols) == 0 {
		return "", fmt.Errorf("history archive manifest is empty")
	}
	seen := make(map[string]struct{}, len(cols))
	for _, c := range cols {
		if c.Name == "" {
			return "", fmt.Errorf("history archive manifest has an unnamed column")
		}
		if _, dup := seen[c.Name]; dup {
			return "", fmt.Errorf("history archive manifest has duplicate column %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		if c.DBType == "" {
			return "", fmt.Errorf("history archive column %q has no DB type", c.Name)
		}
		switch c.Kind {
		case KindMetadata, KindContentProcessed, KindContentOriginal, KindAuthz:
		default:
			return "", fmt.Errorf("history archive column %q has unknown kind %q", c.Name, c.Kind)
		}
	}
	// Structural media-policy pin (I62): the history schema carries media as
	// metadata only — no byte-carrier column may ever join the manifest.
	for _, c := range cols {
		if isMediaByteCarrier(c.DBType) {
			return "", fmt.Errorf("history archive column %q has media-byte carrier type %q (media policy %s)", c.Name, c.DBType, MediaPolicyMetadataOnly)
		}
	}
	return Digest(cols), nil
}

// isMediaByteCarrier reports whether a DB type can carry media bytes.
func isMediaByteCarrier(dbType string) bool {
	t := strings.ToLower(strings.TrimSpace(dbType))
	switch {
	case strings.Contains(t, "bytea"), strings.Contains(t, "blob"), strings.Contains(t, "large_object"):
		return true
	}
	return false
}
