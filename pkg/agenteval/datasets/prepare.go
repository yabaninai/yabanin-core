// Preparation composes an immutable, content-addressed dataset revision from
// permitted history reads and imported examples.
//
// History content may enter preparation only through HistoryReader — a
// caller-supplied adapter around the already-authorized history read path
// (services/admin request-detail boundary plus adminstore.RequestPayloadAccess
// and one-time payload grants). Prepare accepts history references, never
// inline history payloads, so a prepared revision structurally cannot contain
// content that did not pass through the permission-checked read. A failed or
// denied read aborts the whole preparation; no partial revision is produced.
//
// All samples (history-derived and imported) obey the same strict validation
// as ReadRevision: non-blank unique IDs and object payloads with unique JSON
// keys. The revision identity is the SHA-256 over the exact canonical bytes
// prepared here; the sidecar Provenance binds that digest to per-source
// attribution. Preparation never fetches media or retained originals by
// itself — it stores exactly what the permitted read returned.
//
// Per-example content policy (applied to every history-derived example):
//
//   - Tenant: a prepared set is a single-tenant artifact. When PrepareRequest
//     OrgID pins the run, every reference must belong to that org; an
//     unpinned run still rejects references spanning two orgs. Cross-tenant
//     assembly is structurally impossible, not silently mixed.
//   - Privacy/originals: by default only processed content enters a set
//     (I63). A sample the authorized reader declares as containing retained
//     original text is rejected unless the run explicitly enables originals
//     — a switch the API boundary may set only for callers holding the
//     separate originals permission (I32).
//   - Media: the metadata-only media default (I62) holds unless the run
//     explicitly enables media persistence: a sample declared as embedding
//     media file bytes is rejected; media otherwise enter as metadata and
//     references only, and nothing is ever fetched to enrich them.
//   - Delete: tombstoned/deleted requests surface as reader errors, and a
//     reader error aborts the whole run — a deleted request can neither
//     enter a set nor be silently skipped into a false success.
//
// The policy state of each admitted history read is recorded in the
// per-source provenance flags (contains_originals / media_bytes, omitted
// when false), so exported sets carry the outcome without embedding policy
// decisions in the opaque sample payloads. Payloads are never inspected:
// the declarations come from the trusted authorized read path.
package datasets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidPrepare reports a preparation request that cannot produce a
// revision. Reader denials and read failures are wrapped reader errors, not
// this sentinel, so callers can distinguish "bad request" from "not allowed".
var ErrInvalidPrepare = errors.New("invalid dataset preparation request")

// HistoryRef identifies one stored request offered for dataset preparation.
// Both fields are required: preparation is tenant-scoped by construction.
type HistoryRef struct {
	OrgID     string `json:"org_id"`
	RequestID string `json:"request_id"`
}

// HistorySample is the result of one permitted history read. Payload is
// exactly what the authorized read returned (processed text by the default
// content policy; retained originals only when the caller held the separate
// originals permission). Ref must echo the requested reference.
//
// The declaration flags are the per-example content-policy enforcement
// point: ContainsOriginals and MediaBytes report payload properties the
// engine cannot verify from opaque JSON (no content inspection happens
// here). A reader that returns original text or media bytes without the
// matching declaration violates the HistoryReader contract in the same way
// as returning content from a denied read.
type HistorySample struct {
	Ref     HistoryRef      `json:"ref"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
	// ContainsOriginals reports that Payload includes retained original
	// text (possible only when the underlying read held the separate
	// originals permission). Prepare rejects such a sample unless the run
	// explicitly enables originals retention.
	ContainsOriginals bool `json:"contains_originals,omitempty"`
	// MediaBytes reports that Payload embeds inline media file bytes
	// (base64 or data URLs) instead of metadata and references only.
	// Prepare rejects such a sample unless the run explicitly enables
	// media persistence; the metadata-only media default otherwise holds.
	MediaBytes bool `json:"media_bytes,omitempty"`
}

// HistoryReader resolves history references through the authorized read path.
// Implementations must enforce tenant, history-permission, originals and
// delete (tombstone) rules exactly as the request-detail API does; Prepare
// performs no permission logic of its own and treats every reader error —
// denials and deleted/tombstoned requests alike — as fatal for the whole
// request. Readers must declare ContainsOriginals and MediaBytes truthfully:
// those declarations drive the per-example content-policy enforcement.
type HistoryReader interface {
	ReadHistorySample(ctx context.Context, ref HistoryRef) (HistorySample, error)
}

// HistoryReaderFunc adapts a function to HistoryReader.
type HistoryReaderFunc func(ctx context.Context, ref HistoryRef) (HistorySample, error)

// ReadHistorySample implements HistoryReader.
func (f HistoryReaderFunc) ReadHistorySample(ctx context.Context, ref HistoryRef) (HistorySample, error) {
	return f(ctx, ref)
}

// ImportBatch carries examples obtained outside stored history (a transfer
// import, a prior export, or operator-authored cases). Digest is the optional
// SHA-256 hex of the exact source bytes when the batch came from a file.
type ImportBatch struct {
	Samples []Sample `json:"samples"`
	Digest  string   `json:"digest,omitempty"`
}

// PrepareRequest describes one preparation run. CreatedAt is stamped into the
// provenance as RFC3339 with second precision; finer precision is truncated
// so identical inputs always yield identical artifacts.
//
// The run-level policy switches apply to every history-derived example in
// the set. They are the core simple on/off switches (I62/I63); advanced
// conditional retention and enterprise media persistence are separate
// product features and have no knob here.
type PrepareRequest struct {
	DatasetID string
	Creator   string
	CreatedAt time.Time
	// OrgID pins the tenant of the prepared set. When set, every history
	// reference must belong to exactly this org; when empty, the
	// references must still share a single org, so a prepared set can
	// never span tenants. Imports are operator-supplied inert content and
	// are not tenant-pinned (a bundle may travel between tenants).
	OrgID string
	// AllowOriginals is the run-level originals retention switch (I63 core
	// simple switch). False — the default — rejects any sample the reader
	// declares as containing retained original text: by default only
	// processed content enters a prepared set. True is a caller-side
	// authorization decision: the API boundary must set it only for
	// operators holding the separate originals permission (I32).
	AllowOriginals bool
	// AllowMediaBytes is the run-level media persistence switch (I62
	// metadata-only media default). False — the default — rejects any
	// sample the reader declares as embedding media file bytes; media
	// otherwise enter as metadata and references only. True mirrors the
	// optional persistence feature and never triggers fetching: samples
	// contain exactly what the permitted read returned.
	AllowMediaBytes bool
	History         []HistoryRef
	Imports         []ImportBatch
}

// Prepared is the immutable result of one preparation run. RevisionData is
// the canonical revision document (compact JSON with one trailing newline);
// RevisionID is the SHA-256 hex over exactly those bytes.
type Prepared struct {
	Revision     Revision
	RevisionData []byte
	RevisionID   string
	Provenance   Provenance
}

// maxPrepareSources bounds history references and import batches per request.
const maxPrepareSources = maxSamples

// Prepare composes history samples (resolved in request order through reader)
// and imported samples (batch order preserved) into one validated immutable
// revision plus its digest-bound provenance. Duplicate sample IDs across all
// sources, duplicate references, and invalid payloads reject the whole run
// with ErrInvalidPrepare; reader errors propagate wrapped and abort it.
func Prepare(ctx context.Context, reader HistoryReader, req PrepareRequest) (Prepared, error) {
	if strings.TrimSpace(req.DatasetID) == "" {
		return Prepared{}, fmt.Errorf("%w: dataset id is required", ErrInvalidPrepare)
	}
	if req.Creator == "" || len(req.Creator) > maxProvenanceCreatorLength || strings.TrimSpace(req.Creator) == "" {
		return Prepared{}, fmt.Errorf("%w: creator must be 1..%d characters", ErrInvalidPrepare, maxProvenanceCreatorLength)
	}
	if req.CreatedAt.IsZero() {
		return Prepared{}, fmt.Errorf("%w: created_at is required", ErrInvalidPrepare)
	}
	if len(req.History) > maxPrepareSources || len(req.Imports) > maxPrepareSources {
		return Prepared{}, fmt.Errorf("%w: too many sources (max %d each)", ErrInvalidPrepare, maxPrepareSources)
	}
	if len(req.History) > 0 && reader == nil {
		return Prepared{}, fmt.Errorf("%w: history references require a history reader", ErrInvalidPrepare)
	}
	if req.OrgID != "" && strings.TrimSpace(req.OrgID) == "" {
		return Prepared{}, fmt.Errorf("%w: dataset tenant must be a non-blank identifier", ErrInvalidPrepare)
	}

	sources := make([]ProvenanceSource, 0, len(req.History)+len(req.Imports))
	samples := make([]Sample, 0, len(req.History)+len(req.Imports))
	seenIDs := make(map[string]struct{}, len(req.History)+len(req.Imports))
	seenRefs := make(map[HistoryRef]struct{}, len(req.History))
	var runOrg string

	for _, ref := range req.History {
		if err := validateHistoryRef(ref); err != nil {
			return Prepared{}, err
		}
		if req.OrgID != "" && ref.OrgID != req.OrgID {
			return Prepared{}, fmt.Errorf("%w: history reference %s/%s is outside the dataset tenant %s", ErrInvalidPrepare, ref.OrgID, ref.RequestID, req.OrgID)
		}
		if runOrg == "" {
			runOrg = ref.OrgID
		} else if ref.OrgID != runOrg {
			return Prepared{}, fmt.Errorf("%w: history references span tenants %s and %s; a prepared example set is a single-tenant artifact", ErrInvalidPrepare, runOrg, ref.OrgID)
		}
		if _, dup := seenRefs[ref]; dup {
			return Prepared{}, fmt.Errorf("%w: duplicate history reference %s/%s", ErrInvalidPrepare, ref.OrgID, ref.RequestID)
		}
		seenRefs[ref] = struct{}{}
		sample, err := reader.ReadHistorySample(ctx, ref)
		if err != nil {
			// Includes deleted/tombstoned requests: the read path refuses
			// them, and a refusal aborts the whole run — a deleted request
			// can neither enter the set nor be silently skipped.
			return Prepared{}, fmt.Errorf("dataset preparation: history %s/%s: %w", ref.OrgID, ref.RequestID, err)
		}
		if sample.Ref != ref {
			return Prepared{}, fmt.Errorf("%w: history reader returned mismatched reference for %s/%s", ErrInvalidPrepare, ref.OrgID, ref.RequestID)
		}
		if sample.ContainsOriginals && !req.AllowOriginals {
			return Prepared{}, fmt.Errorf("%w: history sample %s/%s contains retained original content; originals retention must be explicitly enabled for the run by a caller holding the originals permission", ErrInvalidPrepare, ref.OrgID, ref.RequestID)
		}
		if sample.MediaBytes && !req.AllowMediaBytes {
			return Prepared{}, fmt.Errorf("%w: history sample %s/%s embeds media file bytes; the metadata-only media default requires explicit media persistence for the run", ErrInvalidPrepare, ref.OrgID, ref.RequestID)
		}
		if err := validatePreparedSample(sample.ID, sample.Payload); err != nil {
			return Prepared{}, fmt.Errorf("%w: history sample %s/%s: %v", ErrInvalidPrepare, ref.OrgID, ref.RequestID, err)
		}
		if _, dup := seenIDs[sample.ID]; dup {
			return Prepared{}, fmt.Errorf("%w: duplicate sample id %q from history %s/%s", ErrInvalidPrepare, sample.ID, ref.OrgID, ref.RequestID)
		}
		seenIDs[sample.ID] = struct{}{}
		samples = append(samples, Sample{ID: sample.ID, Payload: sample.Payload})
		sources = append(sources, ProvenanceSource{
			Kind:              SourceHistory,
			OrgID:             ref.OrgID,
			RequestID:         ref.RequestID,
			Samples:           1,
			ContainsOriginals: sample.ContainsOriginals,
			MediaBytes:        sample.MediaBytes,
		})
	}

	for _, batch := range req.Imports {
		if batch.Digest != "" && !isSHA256Hex(batch.Digest) {
			return Prepared{}, fmt.Errorf("%w: import digest must be 64 lowercase hex characters", ErrInvalidPrepare)
		}
		if len(batch.Samples) == 0 {
			return Prepared{}, fmt.Errorf("%w: import batch is empty", ErrInvalidPrepare)
		}
		for _, sample := range batch.Samples {
			if err := validatePreparedSample(sample.ID, sample.Payload); err != nil {
				return Prepared{}, fmt.Errorf("%w: imported sample: %v", ErrInvalidPrepare, err)
			}
			if _, dup := seenIDs[sample.ID]; dup {
				return Prepared{}, fmt.Errorf("%w: duplicate sample id %q from import", ErrInvalidPrepare, sample.ID)
			}
			seenIDs[sample.ID] = struct{}{}
			samples = append(samples, Sample{ID: sample.ID, Payload: sample.Payload})
		}
		sources = append(sources, ProvenanceSource{Kind: SourceImport, ImportDigest: batch.Digest, Samples: len(batch.Samples)})
	}

	if len(samples) == 0 {
		return Prepared{}, fmt.Errorf("%w: at least one history reference or import batch is required", ErrInvalidPrepare)
	}
	if len(samples) > maxSamples {
		return Prepared{}, fmt.Errorf("%w: preparation yields %d samples (max %d)", ErrInvalidPrepare, len(samples), maxSamples)
	}

	revision := Revision{SchemaVersion: SchemaVersion, DatasetID: req.DatasetID, Samples: samples}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(revision); err != nil {
		return Prepared{}, fmt.Errorf("encode prepared revision: %w", err)
	}
	// Re-validate the exact canonical document: bounds, unique keys and IDs
	// for the artifact that will be persisted and hashed.
	validated, digest, err := ReadRevision(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return Prepared{}, err
	}
	provenance := Provenance{
		SchemaVersion:  ProvenanceSchemaVersion,
		RevisionSHA256: digest,
		DatasetID:      req.DatasetID,
		SampleCount:    len(samples),
		CreatedAt:      req.CreatedAt.UTC().Format(time.RFC3339),
		Creator:        req.Creator,
		Sources:        sources,
	}
	if err := validateProvenance(provenance); err != nil {
		return Prepared{}, err
	}
	return Prepared{Revision: validated, RevisionData: buf.Bytes(), RevisionID: digest, Provenance: provenance}, nil
}

func validateHistoryRef(ref HistoryRef) error {
	if strings.TrimSpace(ref.OrgID) == "" || strings.TrimSpace(ref.RequestID) == "" {
		return fmt.Errorf("%w: history reference requires org and request ids", ErrInvalidPrepare)
	}
	return nil
}

// validatePreparedSample applies the same payload discipline as ReadRevision:
// non-blank ID and a JSON object with unique keys, so no duplicate-key
// ambiguity can enter a prepared revision through any source.
func validatePreparedSample(id string, payload json.RawMessage) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("sample id is required")
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("sample payload must be a JSON object")
	}
	if !json.Valid(trimmed) {
		return errors.New("sample payload is not valid JSON")
	}
	if err := validateUniqueJSONKeys(trimmed); err != nil {
		return errors.New("sample payload has ambiguous JSON keys")
	}
	return nil
}

// isSHA256Hex reports whether s is a lowercase 64-character hex digest.
func isSHA256Hex(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
