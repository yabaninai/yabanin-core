// Package inventory implements the observable asset registry (packet
// E02-P01): the org-scoped inventory of agent, service, MCP-server, tool,
// model and provider identities, each carrying where it is known from
// (source), how trustworthy that knowledge is (confidence) and when it was
// last observed (first_seen/last_seen).
//
// Placement (DISPATCH E02-P01 §1): additive core-Apache SPI per the
// pkg/secevents precedent — org-scoped security-adjacent infrastructure in
// core as an open SPI, with migration 0022 as the production home of the
// table and pkg/inventory.Store as the access layer. Proprietary
// enterprise/ adapters (federation, cross-deployment aggregation) are NOT
// part of this package; enterprise activation is the territory of
// E01-P05/E02-P08 and nothing here imports enterprise/.
//
// Acceptance invariants (E02.md §P01, fixed by W01-C01):
//
//   - Every asset carries source, confidence and last_seen. A row without
//     provenance is not an asset; Validate rejects it.
//
//   - Absence of observations is NOT absence of the asset. An imported
//     asset (e.g. from the MCP registry) stays in the registry with its
//     original source and last_seen even when no events ever mention it;
//     only an explicit upstream signal may tombstone it (see the import
//     adapters). Store.UpsertAsset never deletes on missing observation.
//
// Relation to secevents.Identity (pkg/secevents/schema.go:76–130): the
// registry reuses the IDRef state vocabulary as its observation semantics —
//
//	known   → the identity is present and attributable: an observation
//	          updates last_seen/source on the matching asset.
//	unknown → the identity exists but its value could not be determined
//	          (e.g. redaction stripped it): NO asset is created or touched —
//	          an unknown value cannot be attributed to any asset_key.
//	absent  → no such identity is involved: no observation, no effect.
//
// The join itself (security events updating asset last_seen) is owned by
// the observation cards (W04); this file fixes only the model and the
// vocabulary mapping above.
package inventory

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// AssetKind is the closed vocabulary of registry asset kinds (W01-C01).
// The six kinds cover every identity source of the packet: agents (event
// publisher agent ids, A2A registry, admin principals), services and MCP
// servers (mcpagg registry), tools (MCP tool catalog), models and providers
// (models_registry, model catalog, pricing reference pack).
type AssetKind string

const (
	// KindAgent is an agent identity (eventpublisher agent id, A2A agent,
	// admin principal).
	KindAgent AssetKind = "agent"
	// KindService is a generic service identity. MCP servers land as the
	// more specific KindMCPServer; KindService is the open slot for other
	// service identities.
	KindService AssetKind = "service"
	// KindMCPServer is one org-registered MCP server (mcpagg.Server).
	KindMCPServer AssetKind = "mcp_server"
	// KindTool is one tool advertised by an MCP server
	// (mcpagg.ToolDescriptor).
	KindTool AssetKind = "tool"
	// KindModel is a served model identity (models_registry / catalog).
	KindModel AssetKind = "model"
	// KindProvider is a provider identity (models_registry chk_provider
	// vocabulary, catalog providers).
	KindProvider AssetKind = "provider"
)

// AssetKinds is every kind in a stable order (documentation and tests).
var AssetKinds = []AssetKind{KindAgent, KindService, KindMCPServer, KindTool, KindModel, KindProvider}

// ValidAssetKind reports whether k is a member of the closed vocabulary.
func ValidAssetKind(k AssetKind) bool {
	switch k {
	case KindAgent, KindService, KindMCPServer, KindTool, KindModel, KindProvider:
		return true
	}
	return false
}

// Source names where an asset's knowledge comes from. The empty source is
// invalid (the provenance invariant). Batch A defines the MCP-registry
// import source; observation and model-catalog sources are added by their
// own cards (W04/W03).
type Source string

const (
	// SourceMCPRegistry marks assets imported from the org MCP registry
	// (pkg/mcpagg Store + tool catalog, W02).
	SourceMCPRegistry Source = "mcp_registry"
)

// Confidence grades how trustworthy the source's claim is. Registry rows
// are authoritative imports (high); an observation of a previously unseen
// identity only proves the identity was used (low). Confidence never grows
// without new observations (W04-C03 stale battery pins this).
type Confidence string

const (
	// ConfidenceHigh marks an authoritative source claim.
	ConfidenceHigh Confidence = "high"
	// ConfidenceLow marks a bare existence observation.
	ConfidenceLow Confidence = "low"
)

// ValidConfidence reports whether c is a member of the vocabulary.
func ValidConfidence(c Confidence) bool {
	return c == ConfidenceHigh || c == ConfidenceLow
}

// Asset is one registry row: the (org, asset_key, kind) triple carries the
// identity, Payload is the verbatim source document (jsonb), and the
// provenance fields carry the acceptance invariant. AssetKey derivation
// per kind (URL normalization, alias resolution, principal+agent ids) is
// owned by the dedup card (W05-C01); import adapters must emit stable,
// deterministic keys so dedup can converge later.
type Asset struct {
	OrgID      string          `json:"org_id"`
	AssetKey   string          `json:"asset_key"`
	Kind       AssetKind       `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	Source     Source          `json:"source"`
	Confidence Confidence      `json:"confidence"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
}

// Validate enforces the model contract on a constructed asset: closed kind
// and confidence vocabularies, non-empty provenance, a JSON-object payload
// and a coherent seen window. It is the shared precondition of Store writes
// and import adapters, so an unprovenanced row cannot enter the registry
// through any path.
func (a Asset) Validate() error {
	if err := validKeyPart("org_id", a.OrgID); err != nil {
		return err
	}
	if err := validKeyPart("asset_key", a.AssetKey); err != nil {
		return err
	}
	if !ValidAssetKind(a.Kind) {
		return fmt.Errorf("inventory: unknown asset kind %q", a.Kind)
	}
	if a.Source == "" {
		return fmt.Errorf("inventory: asset %s: source is required (provenance invariant)", a.AssetKey)
	}
	if !ValidConfidence(a.Confidence) {
		return fmt.Errorf("inventory: asset %s: unknown confidence %q", a.AssetKey, a.Confidence)
	}
	if len(a.Payload) == 0 {
		return fmt.Errorf("inventory: asset %s: payload is required", a.AssetKey)
	}
	if !json.Valid(a.Payload) {
		return fmt.Errorf("inventory: asset %s: payload is not valid JSON", a.AssetKey)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(a.Payload)), "{") {
		return fmt.Errorf("inventory: asset %s: payload must be a JSON object", a.AssetKey)
	}
	if a.FirstSeen.IsZero() {
		return fmt.Errorf("inventory: asset %s: first_seen is required", a.AssetKey)
	}
	if a.LastSeen.IsZero() {
		return fmt.Errorf("inventory: asset %s: last_seen is required", a.AssetKey)
	}
	if a.LastSeen.Before(a.FirstSeen) {
		return fmt.Errorf("inventory: asset %s: last_seen %s before first_seen %s",
			a.AssetKey, a.LastSeen.Format(time.RFC3339Nano), a.FirstSeen.Format(time.RFC3339Nano))
	}
	return nil
}

// validKeyPart accepts a non-empty identifier without control characters or
// whitespace, up to 256 bytes (asset keys and org ids end up in the primary
// key and logs; the shape mirrors secevents.validID).
func validKeyPart(what, s string) error {
	if s == "" {
		return fmt.Errorf("inventory: %s is required", what)
	}
	if len(s) > 256 || !utf8.ValidString(s) {
		return fmt.Errorf("inventory: %s length/encoding", what)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("inventory: %s must not contain control characters or whitespace", what)
		}
	}
	return nil
}
