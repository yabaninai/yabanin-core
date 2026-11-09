// Example set interchange contract (schema v1).
//
// An example set bundle is the versioned, self-describing document an
// operator exports after preparing a dataset revision (see
// pkg/agenteval/datasets.Prepare). It is a data-only artifact: it embeds the
// exact canonical revision bytes, the SHA-256 content digest over those
// bytes, and the digest-bound provenance sidecar. External runners need only
// this contract, the JSON Schema artifact in ./schema and the schema version
// to verify and consume a bundle — no Yabanin internals.
//
// The interchange layer dereferences nothing: provenance sources are
// attribution metadata, and importing a bundle never reads history, fetches
// media or executes any content found in the document. Validation is
// strict/schema-shaped and implemented without evaluating document content
// (see pkg/qualityeval for the bounded import/export engine).
package evalgate

import (
	_ "embed"

	"github.com/reireirei/yabanin/pkg/agenteval/datasets"
)

// ExampleSetSchemaVersion is the only example set interchange schema this
// package defines; readers must reject other versions fail-closed.
const ExampleSetSchemaVersion = 1

// ExampleSetKind is the fixed type marker inside every v1 bundle. It lets
// external tools detect the document family before interpreting fields.
const ExampleSetKind = "yabanin.example-set"

// ExampleSet is one exportable example set bundle. RevisionJSON carries the
// exact canonical revision document bytes (compact UTF-8 JSON, one trailing
// newline — byte-identical to what the preparation engine hashed), so
// ContentSHA256 equals the preparation-side revision digest and
// Provenance.RevisionSHA256. Every field is required; unknown fields are
// rejected by the importer.
type ExampleSet struct {
	SchemaVersion int                 `json:"schema_version"`
	Kind          string              `json:"kind"`
	SetID         string              `json:"set_id"`
	ContentSHA256 string              `json:"content_sha256"`
	RevisionJSON  string              `json:"revision_json"`
	Provenance    datasets.Provenance `json:"provenance"`
}

// ExampleSetSchemaV1 is the JSON Schema (draft 2020-12) artifact for v1
// bundles. It is documentation and an external validation aid — the Go
// importer validates structurally and never executes or fetches anything the
// schema references (the artifact is fully self-contained: no external
// $refs).
//
//go:embed schema/example-set.v1.schema.json
var ExampleSetSchemaV1 []byte
