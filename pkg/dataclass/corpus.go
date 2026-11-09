// Package dataclass — benign RU/EN corpus loader (E04-P01-W05-C01).
//
// The benign corpus is a datasets transfer-JSONL revision (one
// {"schema_version":1,"dataset_id":…,"id":…,"payload":…} row per sample,
// the exact shape pkg/agenteval/datasets WriteTransferJSONL emits) whose
// payload schema is fixed by this file:
//
//	{"lang":"ru"|"en","text_type":<closed five-type set>,"text":…,"expect":"benign"}
//
// LoadBenignCorpus re-uses the datasets importer for the transfer-level
// validation (schema version, one dataset id, unique sample ids, ≤ 8 MiB)
// and adds the corpus-level schema on top, fail-closed: a corpus that is
// missing, malformed, or carries any non-benign expectation is a typed
// error, never a partial corpus and never a skipped test. The returned
// hash is the SHA-256 over the exact bytes read — the same pinning rule as
// datasets.ReadRevision — so tests can commit the hash and fail on any
// unreviewed corpus change.
package dataclass

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/reireirei/yabanin/pkg/agenteval/datasets"
)

// BenignCorpusDatasetID is the dataset id every row of the benign corpus
// must carry; a transfer stream carrying any other id is refused.
const BenignCorpusDatasetID = "dataclass-benign-ru-en"

// CorpusExpectBenign is the only expectation class the benign corpus
// carries. A row with any other expectation is not this corpus.
const CorpusExpectBenign = "benign"

// maxCorpusBytes bounds the corpus read. It mirrors the datasets transfer
// bound (8 MiB) so the hash is computed over the same bounded bytes the
// importer validates.
const maxCorpusBytes = 8 << 20

// ErrCorpusInvalid reports a corpus that is not a valid benign revision:
// unreadable, transfer-invalid, wrong dataset id, or a row violating the
// corpus payload schema. The error message names the offending row id (ids
// are corpus metadata, never payload content); no partial corpus is
// returned with the error.
var ErrCorpusInvalid = errors.New("dataclass: invalid benign corpus")

// CorpusSample is one decoded corpus row: the sample id plus the validated
// payload fields. TextType is the row's caller-declared type from the
// closed five-type set; Text passed ValidateText for that type.
type CorpusSample struct {
	ID       string
	Lang     string // LocaleRU or LocaleEN
	TextType SupportedTextType
	Text     string
	Expect   string // always CorpusExpectBenign
}

// corpusPayload is the strict per-row payload schema. Unknown fields are
// refused so corpus rows cannot smuggle extra metadata past review.
type corpusPayload struct {
	Lang     string `json:"lang"`
	TextType string `json:"text_type"`
	Text     string `json:"text"`
	Expect   string `json:"expect"`
}

// LoadBenignCorpus reads a benign corpus in the datasets transfer-JSONL
// format and returns its samples in file order plus the SHA-256 hex of the
// exact bytes read. Validation is fail-closed on two layers: the datasets
// transfer layer (ReadTransferJSONL) and the corpus payload layer — lang
// ∈ {ru, en}, expect == benign, text_type inside the closed five-type set,
// text valid per ValidateText for that type, and — for json-typed rows —
// text must be a valid JSON document. Every refusal wraps ErrCorpusInvalid
// and names the offending row id where one exists.
func LoadBenignCorpus(r io.Reader) ([]CorpusSample, string, error) {
	if r == nil {
		return nil, "", fmt.Errorf("%w: nil reader", ErrCorpusInvalid)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxCorpusBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("%w: read: %v", ErrCorpusInvalid, err)
	}
	if len(data) > maxCorpusBytes {
		return nil, "", fmt.Errorf("%w: corpus exceeds %d bytes", ErrCorpusInvalid, maxCorpusBytes)
	}
	revision, err := datasets.ReadTransferJSONL(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("%w: transfer: %v", ErrCorpusInvalid, err)
	}
	if revision.DatasetID != BenignCorpusDatasetID {
		return nil, "", fmt.Errorf("%w: dataset_id %q, want %q", ErrCorpusInvalid, revision.DatasetID, BenignCorpusDatasetID)
	}
	samples := make([]CorpusSample, 0, len(revision.Samples))
	for _, s := range revision.Samples {
		cs, err := decodeCorpusSample(s.ID, s.Payload)
		if err != nil {
			return nil, "", err
		}
		samples = append(samples, cs)
	}
	digest := sha256.Sum256(data)
	return samples, hex.EncodeToString(digest[:]), nil
}

// decodeCorpusSample validates one row payload against the corpus schema
// in a fixed order: strict decode (unknown fields and trailing data are
// refusals), lang, expect, text type, text validity, then — for json-typed
// rows — JSON validity of the text itself.
func decodeCorpusSample(id string, payload json.RawMessage) (CorpusSample, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var p corpusPayload
	if err := dec.Decode(&p); err != nil {
		return CorpusSample{}, fmt.Errorf("%w: row %s: payload: %v", ErrCorpusInvalid, id, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return CorpusSample{}, fmt.Errorf("%w: row %s: trailing data after payload", ErrCorpusInvalid, id)
	}
	switch p.Lang {
	case LocaleRU, LocaleEN:
	default:
		return CorpusSample{}, fmt.Errorf("%w: row %s: lang %q not in {%q,%q}", ErrCorpusInvalid, id, p.Lang, LocaleRU, LocaleEN)
	}
	if p.Expect != CorpusExpectBenign {
		return CorpusSample{}, fmt.Errorf("%w: row %s: expect %q, want %q", ErrCorpusInvalid, id, p.Expect, CorpusExpectBenign)
	}
	t, err := ParseTextType(p.TextType)
	if err != nil {
		return CorpusSample{}, fmt.Errorf("%w: row %s: %v", ErrCorpusInvalid, id, err)
	}
	if err := ValidateText(t, p.Text); err != nil {
		return CorpusSample{}, fmt.Errorf("%w: row %s: %v", ErrCorpusInvalid, id, err)
	}
	if t == TextTypeJSON && !json.Valid([]byte(p.Text)) {
		return CorpusSample{}, fmt.Errorf("%w: row %s: json-typed text is not valid JSON", ErrCorpusInvalid, id)
	}
	return CorpusSample{ID: id, Lang: p.Lang, TextType: t, Text: p.Text, Expect: CorpusExpectBenign}, nil
}
