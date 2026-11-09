// Example set bundles: bounded, data-only import/export of prepared example
// sets (interchange schema v1, see pkg/evalgate and
// docs/example-set-interchange.md).
//
// Export is bound to the preparation engine: BuildSetBundle accepts only a
// datasets.Prepared artifact, so every byte inside the bundle entered through
// the permission-checked history reader or the validated import path — the
// interchange layer cannot bypass history permissions and never resolves
// provenance sources against stored history, media or originals.
//
// Import is strict and inert: it validates the document shape and digests
// (schema-strict, duplicate-key and unknown-field rejecting, bounded to
// 8 MiB and the revision sample cap) and returns plain data. Nothing in a
// bundle is ever executed, templated, fetched or dereferenced: provenance
// sources are carried as attribution metadata exactly as received.
package qualityeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/reireirei/yabanin/pkg/agenteval/datasets"
	"github.com/reireirei/yabanin/pkg/evalgate"
)

// maxSetBundleBytes bounds one bundle document on import and export. The
// embedded revision travels inside a JSON string, so very large revisions may
// exceed this bound even though the revision itself is valid; split such
// datasets into several sets (documented limitation).
const maxSetBundleBytes = 8 << 20

// maxSetIDLength bounds the stable set identifier at the interchange layer.
const maxSetIDLength = 256

// Sentinel errors (A05 error contract): callers branch on the failure class
// without parsing message text.
var (
	// ErrInvalidSetBundle reports a malformed, unsupported or
	// self-inconsistent bundle. Reader/IO failures are wrapped OS errors,
	// not this sentinel.
	ErrInvalidSetBundle = errors.New("invalid example set bundle")
	// ErrSetBundleTooLarge reports a bundle that exceeds 8 MiB.
	ErrSetBundleTooLarge = errors.New("example set bundle exceeds 8 MiB")
)

// BuildSetBundle binds one prepared, permission-vetted example set into a
// versioned interchange bundle. The set id is the prepared dataset id (stable
// across exports); the content hash is the prepared revision digest (SHA-256
// over the exact canonical revision bytes), so re-exporting the same
// preparation is byte-reproducible and any external tool can verify the
// binding from the documentation alone.
func BuildSetBundle(p datasets.Prepared) (evalgate.ExampleSet, error) {
	if _, err := datasets.VerifyProvenance(p.RevisionData, p.Provenance); err != nil {
		return evalgate.ExampleSet{}, fmt.Errorf("%w: prepared artifact does not verify: %w", ErrInvalidSetBundle, err)
	}
	set := evalgate.ExampleSet{
		SchemaVersion: evalgate.ExampleSetSchemaVersion,
		Kind:          evalgate.ExampleSetKind,
		SetID:         p.Provenance.DatasetID,
		ContentSHA256: p.Provenance.RevisionSHA256,
		RevisionJSON:  string(p.RevisionData),
		Provenance:    p.Provenance,
	}
	if _, err := validateSetBundle(set); err != nil {
		return evalgate.ExampleSet{}, err
	}
	return set, nil
}

// WriteSetBundle validates the bundle and emits its deterministic JSON
// document (compact, no HTML escaping, one trailing newline). Partial output
// is impossible: the document is rendered into a bounded buffer first.
func WriteSetBundle(w io.Writer, set evalgate.ExampleSet) error {
	if _, err := validateSetBundle(set); err != nil {
		return err
	}
	if w == nil {
		return ErrInvalidSetBundle
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(set); err != nil {
		return fmt.Errorf("%w: encode bundle: %v", ErrInvalidSetBundle, err)
	}
	if buf.Len() > maxSetBundleBytes {
		return ErrSetBundleTooLarge
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

// ReadSetBundle reads one bounded bundle document and returns it together
// with the validated revision it carries. The reader is consumed once.
// Validation is data-only and strict: unknown fields, duplicate JSON keys,
// trailing data, unsupported schema versions, digest mismatches and
// provenance-binding mismatches reject the whole bundle; document content is
// never executed, dereferenced or fetched.
func ReadSetBundle(r io.Reader) (evalgate.ExampleSet, datasets.Revision, error) {
	var set evalgate.ExampleSet
	if r == nil {
		return set, datasets.Revision{}, ErrInvalidSetBundle
	}
	data, err := io.ReadAll(io.LimitReader(r, maxSetBundleBytes+1))
	if err != nil {
		return set, datasets.Revision{}, fmt.Errorf("read example set bundle: %w", err)
	}
	if len(data) > maxSetBundleBytes {
		return set, datasets.Revision{}, ErrSetBundleTooLarge
	}
	// Ambiguity guard: duplicate keys anywhere in the document change what a
	// naive decoder would see, so they reject before any typed decode.
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return set, datasets.Revision{}, fmt.Errorf("%w: duplicate keys or malformed JSON", ErrInvalidSetBundle)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&set); err != nil {
		return set, datasets.Revision{}, fmt.Errorf("%w: unknown fields or wrong types", ErrInvalidSetBundle)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return set, datasets.Revision{}, fmt.Errorf("%w: trailing data after bundle document", ErrInvalidSetBundle)
	}
	rev, err := validateSetBundle(set)
	if err != nil {
		return evalgate.ExampleSet{}, datasets.Revision{}, err
	}
	return set, rev, nil
}

// validateSetBundle enforces the full v1 contract: schema version, kind,
// set id bounds, content digest over the exact embedded revision bytes and
// the digest-bound provenance (which re-validates the revision document and
// its bounds). It returns the validated revision.
func validateSetBundle(set evalgate.ExampleSet) (datasets.Revision, error) {
	if set.SchemaVersion != evalgate.ExampleSetSchemaVersion {
		return datasets.Revision{}, fmt.Errorf("%w: unsupported schema version %d", ErrInvalidSetBundle, set.SchemaVersion)
	}
	if set.Kind != evalgate.ExampleSetKind {
		return datasets.Revision{}, fmt.Errorf("%w: unknown kind %q", ErrInvalidSetBundle, set.Kind)
	}
	if strings.TrimSpace(set.SetID) == "" || len(set.SetID) > maxSetIDLength {
		return datasets.Revision{}, fmt.Errorf("%w: set_id must be 1..%d characters", ErrInvalidSetBundle, maxSetIDLength)
	}
	if !isSHA256Hex(set.ContentSHA256) {
		return datasets.Revision{}, fmt.Errorf("%w: content_sha256 must be 64 lowercase hex characters", ErrInvalidSetBundle)
	}
	if datasets.ContentDigest([]byte(set.RevisionJSON)) != set.ContentSHA256 {
		return datasets.Revision{}, fmt.Errorf("%w: content_sha256 does not match revision_json bytes", ErrInvalidSetBundle)
	}
	rev, err := datasets.VerifyProvenance([]byte(set.RevisionJSON), set.Provenance)
	if err != nil {
		return datasets.Revision{}, fmt.Errorf("%w: revision/provenance binding: %w", ErrInvalidSetBundle, err)
	}
	if rev.DatasetID != set.SetID {
		return datasets.Revision{}, fmt.Errorf("%w: set_id does not match revision dataset id", ErrInvalidSetBundle)
	}
	return rev, nil
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
