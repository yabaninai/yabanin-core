package historyops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// FamiliesSchemaVersion is the engine's own version stamp for the family
// semantics (column surfaces, cascade rules) as implemented in this package.
// Bump it whenever family counting/planning semantics change in a way that
// changes what a digest commits to, so stale digests refuse cleanly.
const FamiliesSchemaVersion = 1

// SchemaStamp pins a selection (and therefore a digest and a job) to a
// migration-consistent shape of the underlying data (02-PREVIEW-OPERATION-
// DESIGN §4): if a migration lands between preview and replay, the digest
// changes and the replay refuses digest_mismatch instead of acting on
// stale assumptions.
//
// Only migration_head and families_schema_version enter the digest: the
// running code version is deliberately excluded so a re-deploy does not
// invalidate prepared previews (the digest commits to data shape, not to
// binary identity).
type SchemaStamp struct {
	MigrationHead         int64 `json:"migration_head"`
	FamiliesSchemaVersion int   `json:"families_schema_version"`
}

// digestInput is the canonical digest payload (§4). Field order and omitempty
// behavior are fixed by this struct; the families list is pre-normalized
// (sorted, deduplicated) and periods are canonical UTC RFC3339 strings, so
// the encoding is byte-stable for equal selections.
type digestInput struct {
	Op          string           `json:"op"`
	OrgID       string           `json:"org_id"`
	TeamID      string           `json:"team_id,omitempty"`
	PeriodTo    string           `json:"period_to"`
	PeriodFrom  string           `json:"period_from"`
	Families    []string         `json:"families"`
	Filters     SelectionFilters `json:"filters"`
	SchemaStamp SchemaStamp      `json:"schema_stamp"`
}

// SelectionDigest computes the selection digest for an operation: canonical
// JSON over the digest input, hashed with SHA-256, hex-encoded. The same
// (operation, selection, stamp) always yields the same digest; any change to
// scope, families, filters, period, operation or schema stamp yields a
// different digest.
func SelectionDigest(op Operation, sel Selection, stamp SchemaStamp) (string, error) {
	if !ValidOperation(op) {
		return "", fmt.Errorf("%w: unknown operation %q", ErrInvalidRequest, op)
	}
	if stamp.FamiliesSchemaVersion == 0 {
		stamp.FamiliesSchemaVersion = FamiliesSchemaVersion
	}
	families := make([]string, len(sel.Families))
	for i, f := range sel.Families {
		families[i] = string(f)
	}
	// normalizeFamilies again defensively: NewSelection normalizes, but a
	// hand-assembled Selection must not produce order-dependent digests.
	sorted := make([]Family, len(families))
	for i, f := range families {
		sorted[i] = Family(f)
	}
	sorted = normalizeFamilies(sorted)
	for i, f := range sorted {
		families[i] = string(f)
	}
	input := digestInput{
		Op:          string(op),
		OrgID:       sel.OrgID,
		TeamID:      sel.TeamID,
		PeriodFrom:  sel.From,
		PeriodTo:    sel.To,
		Families:    families,
		Filters:     sel.Filters,
		SchemaStamp: stamp,
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		// Unreachable for this all-scalar structure, but fail closed rather
		// than digesting a partially encoded selection.
		return "", fmt.Errorf("historyops: encode digest input: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
