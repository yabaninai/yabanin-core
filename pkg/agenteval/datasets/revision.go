// Package datasets validates local, content-addressed evaluation revisions.
package datasets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	// SchemaVersion is the supported revision document schema.
	SchemaVersion    = 1
	maxRevisionBytes = 8 << 20
	maxSamples       = 10000
)

var (
	// ErrInvalidRevision reports malformed or unsupported revision input.
	ErrInvalidRevision = errors.New("invalid dataset revision")
	// ErrRevisionTooBig reports revision input that exceeds the size limit.
	ErrRevisionTooBig = errors.New("dataset revision exceeds 8 MiB")
)

// Revision is an immutable input document. RevisionID is calculated from the
// exact bytes read, not from a normalized re-encoding of these fields.
type Revision struct {
	SchemaVersion int      `json:"schema_version"`
	DatasetID     string   `json:"dataset_id"`
	Samples       []Sample `json:"samples"`
}

// Sample gives one caller-stable identifier to an opaque JSON payload.
type Sample struct {
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

// ReadRevision reads and validates one JSON revision document, returning its
// SHA-256 over the exact bytes used to decode it. The reader is consumed once.
func ReadRevision(r io.Reader) (Revision, string, error) {
	if r == nil {
		return Revision{}, "", ErrInvalidRevision
	}
	data, err := io.ReadAll(io.LimitReader(r, maxRevisionBytes+1))
	if err != nil {
		return Revision{}, "", ErrInvalidRevision
	}
	if len(data) > maxRevisionBytes {
		return Revision{}, "", ErrRevisionTooBig
	}
	if err := validateUniqueJSONKeys(data); err != nil {
		return Revision{}, "", ErrInvalidRevision
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var revision Revision
	if err := dec.Decode(&revision); err != nil {
		return Revision{}, "", ErrInvalidRevision
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Revision{}, "", ErrInvalidRevision
	}
	if revision.SchemaVersion != SchemaVersion || strings.TrimSpace(revision.DatasetID) == "" || len(revision.Samples) == 0 || len(revision.Samples) > maxSamples {
		return Revision{}, "", ErrInvalidRevision
	}
	seen := make(map[string]struct{}, len(revision.Samples))
	for _, sample := range revision.Samples {
		if strings.TrimSpace(sample.ID) == "" {
			return Revision{}, "", ErrInvalidRevision
		}
		if _, exists := seen[sample.ID]; exists {
			return Revision{}, "", ErrInvalidRevision
		}
		seen[sample.ID] = struct{}{}
		payload := bytes.TrimSpace(sample.Payload)
		if len(payload) == 0 || payload[0] != '{' || !json.Valid(payload) {
			return Revision{}, "", ErrInvalidRevision
		}
	}
	digest := sha256.Sum256(data)
	return revision, hex.EncodeToString(digest[:]), nil
}

func validateUniqueJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	root, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := root.(json.Delim)
	if !ok || delim != '{' {
		return ErrInvalidRevision
	}
	if err := validateObject(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalidRevision
	}
	return nil
}

func validateValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return validateObject(dec)
	case '[':
		for dec.More() {
			if err := validateValue(dec); err != nil {
				return err
			}
		}
		closing, err := dec.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return ErrInvalidRevision
		}
		return nil
	default:
		return ErrInvalidRevision
	}
}

func validateObject(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return ErrInvalidRevision
		}
		if _, exists := seen[key]; exists {
			return ErrInvalidRevision
		}
		seen[key] = struct{}{}
		if err := validateValue(dec); err != nil {
			return err
		}
	}
	closing, err := dec.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return ErrInvalidRevision
	}
	return nil
}
