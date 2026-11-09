// Provenance is the sidecar document that binds a prepared dataset revision
// to its origin: the revision digest, when and by whom it was prepared, and
// the per-source attribution (history references and imported batches,
// including the per-read content-policy flags history sources may carry). It
// is validated and bounded like every other artifact in this package and
// never carries sample content — identifiers, digests and policy flags only.
package datasets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ProvenanceSchemaVersion is the only provenance schema this package writes
// and reads.
const ProvenanceSchemaVersion = 1

// Source kinds recorded in ProvenanceSource.Kind.
const (
	// SourceHistory marks one permitted history read (one sample).
	SourceHistory = "history"
	// SourceImport marks one batch of imported examples.
	SourceImport = "import"
)

const (
	provenanceMaxBytes         = 4 << 20
	maxProvenanceCreatorLength = 256
	maxProvenanceSources       = 2 * maxSamples
	maxProvenanceSourceSamples = maxSamples
)

var (
	// ErrInvalidProvenance reports malformed, unsupported or inconsistent
	// provenance input.
	ErrInvalidProvenance = errors.New("invalid dataset provenance")
	// ErrProvenanceMismatch reports provenance that does not bind the
	// supplied revision document (digest, dataset id or sample count differ).
	ErrProvenanceMismatch = errors.New("dataset provenance does not match revision")
)

// Provenance describes how one immutable revision was prepared. It contains
// identifiers and digests only, never sample payloads.
type Provenance struct {
	SchemaVersion  int                `json:"schema_version"`
	RevisionSHA256 string             `json:"revision_sha256"`
	DatasetID      string             `json:"dataset_id"`
	SampleCount    int                `json:"sample_count"`
	CreatedAt      string             `json:"created_at"`
	Creator        string             `json:"creator"`
	Sources        []ProvenanceSource `json:"sources"`
}

// ProvenanceSource attributes samples to one origin. History sources carry
// exactly one sample, org/request identifiers, and the per-read content-
// policy flags (omitted when false, so default-form documents stay
// byte-stable); import sources carry the batch sample count and, when
// known, the digest of the exact source bytes.
type ProvenanceSource struct {
	Kind         string `json:"kind"`
	OrgID        string `json:"org_id,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	ImportDigest string `json:"import_digest,omitempty"`
	Samples      int    `json:"samples"`
	// ContainsOriginals records that the attributed history sample payload
	// includes retained original text — admitted only because the run
	// explicitly enabled originals retention. Import sources never set it.
	ContainsOriginals bool `json:"contains_originals,omitempty"`
	// MediaBytes records that the attributed history sample payload embeds
	// inline media file bytes — admitted only because the run explicitly
	// enabled media persistence; absent or false means the metadata-only
	// media default held. Import sources never set it.
	MediaBytes bool `json:"media_bytes,omitempty"`
}

// ContentDigest returns the lowercase SHA-256 hex of data — the digest form
// used for revision identities and import-batch digests.
func ContentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// WriteProvenance validates p and writes its canonical JSON document
// (compact, one trailing newline). Partial output is impossible: the
// document is rendered into a bounded buffer first.
func WriteProvenance(w io.Writer, p Provenance) error {
	if err := validateProvenance(p); err != nil {
		return err
	}
	if w == nil {
		return ErrInvalidProvenance
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(p); err != nil {
		return ErrInvalidProvenance
	}
	if buf.Len() > provenanceMaxBytes {
		return ErrInvalidProvenance
	}
	n, err := w.Write(buf.Bytes())
	if err != nil {
		return err
	}
	if n != buf.Len() {
		return io.ErrShortWrite
	}
	return nil
}

// ReadProvenance reads and validates one bounded provenance document with
// strict decode semantics: unknown fields, duplicate keys and trailing data
// are rejected.
func ReadProvenance(r io.Reader) (Provenance, error) {
	if r == nil {
		return Provenance{}, ErrInvalidProvenance
	}
	data, err := io.ReadAll(io.LimitReader(r, provenanceMaxBytes+1))
	if err != nil {
		return Provenance{}, ErrInvalidProvenance
	}
	if len(data) > provenanceMaxBytes {
		return Provenance{}, ErrInvalidProvenance
	}
	if err := validateUniqueJSONKeys(data); err != nil {
		return Provenance{}, ErrInvalidProvenance
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Provenance
	if err := dec.Decode(&p); err != nil {
		return Provenance{}, ErrInvalidProvenance
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Provenance{}, ErrInvalidProvenance
	}
	if err := validateProvenance(p); err != nil {
		return Provenance{}, err
	}
	return p, nil
}

// VerifyProvenance re-validates the exact revision document bytes and checks
// that p binds them: digest, dataset id and sample count must all match. It
// returns the validated revision so callers never re-decode untrusted bytes
// themselves.
func VerifyProvenance(revisionData []byte, p Provenance) (Revision, error) {
	if err := validateProvenance(p); err != nil {
		return Revision{}, err
	}
	revision, digest, err := ReadRevision(bytes.NewReader(revisionData))
	if err != nil {
		return Revision{}, err
	}
	if digest != p.RevisionSHA256 || revision.DatasetID != p.DatasetID || len(revision.Samples) != p.SampleCount {
		return Revision{}, ErrProvenanceMismatch
	}
	return revision, nil
}

func validateProvenance(p Provenance) error {
	if p.SchemaVersion != ProvenanceSchemaVersion {
		return fmt.Errorf("%w: unsupported schema version %d", ErrInvalidProvenance, p.SchemaVersion)
	}
	if !isSHA256Hex(p.RevisionSHA256) {
		return fmt.Errorf("%w: revision_sha256 must be 64 lowercase hex characters", ErrInvalidProvenance)
	}
	if strings.TrimSpace(p.DatasetID) == "" {
		return fmt.Errorf("%w: dataset id is required", ErrInvalidProvenance)
	}
	if p.SampleCount < 1 || p.SampleCount > maxSamples {
		return fmt.Errorf("%w: sample_count must be 1..%d", ErrInvalidProvenance, maxSamples)
	}
	if _, err := time.Parse(time.RFC3339, p.CreatedAt); err != nil {
		return fmt.Errorf("%w: created_at must be RFC3339", ErrInvalidProvenance)
	}
	if p.Creator == "" || len(p.Creator) > maxProvenanceCreatorLength || strings.TrimSpace(p.Creator) == "" {
		return fmt.Errorf("%w: creator must be 1..%d characters", ErrInvalidProvenance, maxProvenanceCreatorLength)
	}
	if len(p.Sources) == 0 || len(p.Sources) > maxProvenanceSources {
		return fmt.Errorf("%w: provenance requires 1..%d sources", ErrInvalidProvenance, maxProvenanceSources)
	}
	total := 0
	seenHistory := make(map[HistoryRef]struct{}, len(p.Sources))
	seenDigest := make(map[string]struct{}, len(p.Sources))
	for _, s := range p.Sources {
		switch s.Kind {
		case SourceHistory:
			if s.Samples != 1 {
				return fmt.Errorf("%w: history source records exactly one sample", ErrInvalidProvenance)
			}
			if strings.TrimSpace(s.OrgID) == "" || strings.TrimSpace(s.RequestID) == "" {
				return fmt.Errorf("%w: history source requires org and request ids", ErrInvalidProvenance)
			}
			if s.ImportDigest != "" {
				return fmt.Errorf("%w: history source must not carry an import digest", ErrInvalidProvenance)
			}
			ref := HistoryRef{OrgID: s.OrgID, RequestID: s.RequestID}
			if _, dup := seenHistory[ref]; dup {
				return fmt.Errorf("%w: duplicate history source %s/%s", ErrInvalidProvenance, s.OrgID, s.RequestID)
			}
			seenHistory[ref] = struct{}{}
		case SourceImport:
			if s.Samples < 1 || s.Samples > maxProvenanceSourceSamples {
				return fmt.Errorf("%w: import source sample count must be 1..%d", ErrInvalidProvenance, maxProvenanceSourceSamples)
			}
			if s.OrgID != "" || s.RequestID != "" {
				return fmt.Errorf("%w: import source must not carry history identifiers", ErrInvalidProvenance)
			}
			if s.ContainsOriginals || s.MediaBytes {
				return fmt.Errorf("%w: import source must not carry history-read policy flags", ErrInvalidProvenance)
			}
			if s.ImportDigest != "" && !isSHA256Hex(s.ImportDigest) {
				return fmt.Errorf("%w: import digest must be 64 lowercase hex characters", ErrInvalidProvenance)
			}
			if _, dup := seenDigest[s.ImportDigest]; dup {
				return fmt.Errorf("%w: duplicate import source digest", ErrInvalidProvenance)
			}
			seenDigest[s.ImportDigest] = struct{}{}
		default:
			return fmt.Errorf("%w: unknown source kind %q", ErrInvalidProvenance, s.Kind)
		}
		total += s.Samples
	}
	if total != p.SampleCount {
		return fmt.Errorf("%w: source sample counts (%d) do not sum to sample_count (%d)", ErrInvalidProvenance, total, p.SampleCount)
	}
	return nil
}
