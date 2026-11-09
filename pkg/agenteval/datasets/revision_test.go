package datasets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const validRevisionJSON = `{"schema_version":1,"dataset_id":"demo-corpus","samples":[{"id":"case-a","payload":{"text":"safe sample","type":"demo","expect":"clean"}}]}`

func TestReadRevisionPinsExactInputBytes(t *testing.T) {
	revision, digest, err := ReadRevision(strings.NewReader(validRevisionJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(validRevisionJSON))
	if digest != hex.EncodeToString(want[:]) {
		t.Fatalf("digest = %q, want hash of exact input %q", digest, hex.EncodeToString(want[:]))
	}
	if revision.DatasetID != "demo-corpus" || len(revision.Samples) != 1 || revision.Samples[0].ID != "case-a" {
		t.Fatalf("unexpected decoded revision: %+v", revision)
	}
	spaced := strings.ReplaceAll(validRevisionJSON, `,"dataset_id"`, `, "dataset_id"`)
	_, spacedDigest, err := ReadRevision(strings.NewReader(spaced))
	if err != nil {
		t.Fatal(err)
	}
	if spacedDigest == digest {
		t.Fatal("whitespace-different exact document bytes must have different revision IDs")
	}
}

func TestReadRevisionRejectsMalformedAndAmbiguousDocuments(t *testing.T) {
	cases := map[string]string{
		"non-object root":       `[]`,
		"unknown field":         strings.Replace(validRevisionJSON, `"dataset_id"`, `"secret_field":"not echoed","dataset_id"`, 1),
		"unsupported version":   strings.Replace(validRevisionJSON, `"schema_version":1`, `"schema_version":2`, 1),
		"trailing JSON":         validRevisionJSON + ` {}`,
		"duplicate root key":    strings.Replace(validRevisionJSON, `"dataset_id":"demo-corpus"`, `"dataset_id":"demo-corpus","dataset_id":"other"`, 1),
		"duplicate payload key": strings.Replace(validRevisionJSON, `"text":"safe sample"`, `"text":"safe sample","text":"other"`, 1),
		"empty dataset ID":      strings.Replace(validRevisionJSON, `"demo-corpus"`, `"   "`, 1),
		"empty sample ID":       strings.Replace(validRevisionJSON, `"case-a"`, `" "`, 1),
		"duplicate sample ID":   strings.Replace(validRevisionJSON, `"samples":[{"id":"case-a","payload":{"text":"safe sample","type":"demo","expect":"clean"}}]`, `"samples":[{"id":"case-a","payload":{"text":"safe sample","type":"demo","expect":"clean"}},{"id":"case-a","payload":{"text":"other","type":"demo","expect":"clean"}}]`, 1),
		"non-object payload":    strings.Replace(validRevisionJSON, `"payload":{"text":"safe sample","type":"demo","expect":"clean"}`, `"payload":["safe sample"]`, 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ReadRevision(strings.NewReader(input)); err == nil || err == ErrRevisionTooBig {
				t.Fatalf("ReadRevision error = %v, want invalid revision", err)
			}
		})
	}
}

func TestReadRevisionBoundsInputAndSampleCount(t *testing.T) {
	if _, _, err := ReadRevision(strings.NewReader(strings.Repeat(" ", maxRevisionBytes+1))); err != ErrRevisionTooBig {
		t.Fatalf("oversized revision error = %v, want ErrRevisionTooBig", err)
	}
	// Count validation is exercised with a small valid sample repeated under
	// unique IDs without constructing oversized payloads.
	var samples strings.Builder
	for i := 0; i <= maxSamples; i++ {
		if i > 0 {
			samples.WriteByte(',')
		}
		samples.WriteString(`{"id":"case-`)
		samples.WriteString(strconv.Itoa(i))
		samples.WriteString(`","payload":{"text":"x","type":"t","expect":"clean"}}`)
	}
	input := `{"schema_version":1,"dataset_id":"demo","samples":[` + samples.String() + `]}`
	if _, _, err := ReadRevision(strings.NewReader(input)); err == nil {
		t.Fatal("too many samples must be rejected")
	}
}

func TestReadRevisionUsesOneByteSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revision.json")
	if err := os.WriteFile(path, []byte(validRevisionJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	reader := &replaceAfterReadReader{data: []byte(validRevisionJSON), path: path, replacement: []byte(`not the original revision`)}
	revision, digest, err := ReadRevision(reader)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(validRevisionJSON))
	if digest != hex.EncodeToString(want[:]) || revision.Samples[0].ID != "case-a" {
		t.Fatalf("loaded revision was not bound to original bytes: digest=%s revision=%+v", digest, revision)
	}
	current, err := os.ReadFile(path) //nolint:gosec // fixed filename inside this test's private t.TempDir fixture
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, reader.replacement) {
		t.Fatalf("fixture edit did not occur: %q", current)
	}
}

type replaceAfterReadReader struct {
	data        []byte
	path        string
	replacement []byte
	done        bool
}

func (r *replaceAfterReadReader) Read(dst []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(dst, r.data)
	if err := os.WriteFile(r.path, r.replacement, 0o600); err != nil {
		return n, err
	}
	return n, nil
}
