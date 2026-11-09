package datasets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

var prepareClock = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func historyReaderFunc(t *testing.T, reads map[HistoryRef]HistorySample, failures map[HistoryRef]error) HistoryReaderFunc {
	t.Helper()
	return func(_ context.Context, ref HistoryRef) (HistorySample, error) {
		if err, denied := failures[ref]; denied {
			return HistorySample{}, err
		}
		sample, ok := reads[ref]
		if !ok {
			return HistorySample{}, errors.New("not found")
		}
		return sample, nil
	}
}

func TestPrepareFromPermittedHistoryAndImportsIsDeterministic(t *testing.T) {
	refA := HistoryRef{OrgID: "org-1", RequestID: "req-a"}
	refB := HistoryRef{OrgID: "org-1", RequestID: "req-b"}
	reader := historyReaderFunc(t, map[HistoryRef]HistorySample{
		refA: {Ref: refA, ID: "case-hist-a", Payload: json.RawMessage(`{"text":"processed prompt","media":[]}`)},
		refB: {Ref: refB, ID: "case-hist-b", Payload: json.RawMessage(`{"text":"second permitted read"}`)},
	}, nil)
	transfer := bytes.NewBufferString("")
	revision := Revision{SchemaVersion: SchemaVersion, DatasetID: "imported", Samples: []Sample{
		{ID: "case-import-1", Payload: json.RawMessage(`{"text":"imported example"}`)},
	}}
	if err := WriteTransferJSONL(transfer, revision); err != nil {
		t.Fatal(err)
	}
	sourceBytes := transfer.Bytes()
	imported, err := ReadTransferJSONL(bytes.NewReader(sourceBytes))
	if err != nil {
		t.Fatal(err)
	}

	req := PrepareRequest{
		DatasetID: "eval-2026-10",
		Creator:   "operator@example.com",
		CreatedAt: prepareClock,
		History:   []HistoryRef{refA, refB},
		Imports:   []ImportBatch{{Samples: imported.Samples, Digest: ContentDigest(sourceBytes)}},
	}
	first, err := Prepare(context.Background(), reader, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Prepare(context.Background(), reader, req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.RevisionData, second.RevisionData) || first.RevisionID != second.RevisionID {
		t.Fatal("identical preparation inputs must produce identical revision bytes and id")
	}
	if !reflect.DeepEqual(first.Provenance, second.Provenance) {
		t.Fatalf("provenance not deterministic:\n%+v\n%+v", first.Provenance, second.Provenance)
	}
	if len(first.Revision.Samples) != 3 {
		t.Fatalf("sample count = %d, want 3 (2 history + 1 import)", len(first.Revision.Samples))
	}
	if first.RevisionID == "" || len(first.RevisionID) != 64 {
		t.Fatalf("revision id %q is not a sha256 hex digest", first.RevisionID)
	}
	if first.Provenance.SampleCount != 3 || len(first.Provenance.Sources) != 3 {
		t.Fatalf("unexpected provenance: %+v", first.Provenance)
	}
	if first.Provenance.Sources[0].Kind != SourceHistory || first.Provenance.Sources[0].RequestID != "req-a" || first.Provenance.Sources[0].Samples != 1 {
		t.Fatalf("history source not recorded: %+v", first.Provenance.Sources[0])
	}
	if first.Provenance.Sources[2].Kind != SourceImport || first.Provenance.Sources[2].ImportDigest != ContentDigest(sourceBytes) || first.Provenance.Sources[2].Samples != 1 {
		t.Fatalf("import source not recorded: %+v", first.Provenance.Sources[2])
	}

	// The prepared revision must survive the package's own strict reader and
	// the transfer export path unchanged (round-trip via canonical bytes).
	validated, digest, err := ReadRevision(bytes.NewReader(first.RevisionData))
	if err != nil {
		t.Fatal(err)
	}
	if digest != first.RevisionID {
		t.Fatal("revision id must be the digest of the exact canonical bytes")
	}
	var export bytes.Buffer
	if err := WriteTransferJSONL(&export, validated); err != nil {
		t.Fatal(err)
	}
	roundTripped, err := ReadTransferJSONL(bytes.NewReader(export.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(roundTripped.Samples) != 3 || roundTripped.DatasetID != "eval-2026-10" {
		t.Fatalf("round-trip changed the prepared revision: %+v", roundTripped)
	}

	// Provenance round-trip and binding verification.
	var prov bytes.Buffer
	if err := WriteProvenance(&prov, first.Provenance); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadProvenance(bytes.NewReader(prov.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, first.Provenance) {
		t.Fatalf("provenance round-trip mismatch:\n%+v\n%+v", loaded, first.Provenance)
	}
	if _, err := VerifyProvenance(first.RevisionData, loaded); err != nil {
		t.Fatalf("verify valid binding: %v", err)
	}
	tampered := bytes.Replace(first.RevisionData, []byte(`"text":"processed prompt"`), []byte(`"text":"swapped"`), 1)
	if bytes.Equal(tampered, first.RevisionData) {
		t.Fatal("tamper setup failed")
	}
	if _, err := VerifyProvenance(tampered, loaded); !errors.Is(err, ErrProvenanceMismatch) {
		t.Fatalf("tampered revision error = %v, want ErrProvenanceMismatch", err)
	}
}

func TestPrepareFailsClosedOnReaderDenialAndMismatch(t *testing.T) {
	ref := HistoryRef{OrgID: "org-1", RequestID: "req-denied"}
	reader := historyReaderFunc(t, nil, map[HistoryRef]error{ref: errors.New("payload grant consumed")})
	_, err := Prepare(context.Background(), reader, PrepareRequest{
		DatasetID: "d", Creator: "operator", CreatedAt: prepareClock, History: []HistoryRef{ref},
	})
	if err == nil || errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("reader denial error = %v, want wrapped reader error distinct from ErrInvalidPrepare", err)
	}
	if !strings.Contains(err.Error(), "req-denied") {
		t.Fatalf("denial error must name the reference without leaking payload text: %v", err)
	}

	mismatchedReader := HistoryReaderFunc(func(_ context.Context, _ HistoryRef) (HistorySample, error) {
		return HistorySample{Ref: HistoryRef{OrgID: "org-other", RequestID: "req-x"}, ID: "case", Payload: json.RawMessage(`{"a":1}`)}, nil
	})
	_, err = Prepare(context.Background(), mismatchedReader, PrepareRequest{
		DatasetID: "d", Creator: "operator", CreatedAt: prepareClock, History: []HistoryRef{ref},
	})
	if !errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("mismatched reference error = %v, want ErrInvalidPrepare", err)
	}
}

func TestPrepareValidatesRequestAndSamples(t *testing.T) {
	goodRef := HistoryRef{OrgID: "org-1", RequestID: "req-1"}
	goodReader := historyReaderFunc(t, map[HistoryRef]HistorySample{
		goodRef: {Ref: goodRef, ID: "case-ok", Payload: json.RawMessage(`{"text":"ok"}`)},
	}, nil)
	base := PrepareRequest{DatasetID: "d", Creator: "operator", CreatedAt: prepareClock}

	cases := map[string]struct {
		modify func(*PrepareRequest)
		reader HistoryReader
	}{
		"empty dataset id":       {modify: func(r *PrepareRequest) { r.DatasetID = "  " }, reader: goodReader},
		"blank creator":          {modify: func(r *PrepareRequest) { r.Creator = "   " }, reader: goodReader},
		"oversized creator":      {modify: func(r *PrepareRequest) { r.Creator = strings.Repeat("x", maxProvenanceCreatorLength+1) }, reader: goodReader},
		"zero created at":        {modify: func(r *PrepareRequest) { r.CreatedAt = time.Time{} }, reader: goodReader},
		"history without reader": {modify: func(r *PrepareRequest) { r.History = []HistoryRef{goodRef} }, reader: nil},
		"empty history ref":      {modify: func(r *PrepareRequest) { r.History = []HistoryRef{{OrgID: "org-1"}} }, reader: goodReader},
		"duplicate history ref":  {modify: func(r *PrepareRequest) { r.History = []HistoryRef{goodRef, goodRef} }, reader: goodReader},
		"no sources":             {modify: func(r *PrepareRequest) {}, reader: goodReader},
		"empty import batch":     {modify: func(r *PrepareRequest) { r.Imports = []ImportBatch{{}} }, reader: goodReader},
		"bad import digest": {modify: func(r *PrepareRequest) {
			r.Imports = []ImportBatch{{Samples: []Sample{{ID: "s", Payload: json.RawMessage(`{"a":1}`)}}, Digest: "ZZ"}}
		}, reader: goodReader},
		"duplicate import sample id": {modify: func(r *PrepareRequest) {
			r.Imports = []ImportBatch{{Samples: []Sample{
				{ID: "dup", Payload: json.RawMessage(`{"a":1}`)},
				{ID: "dup", Payload: json.RawMessage(`{"a":2}`)},
			}}}
		}, reader: goodReader},
		"duplicate across batches": {modify: func(r *PrepareRequest) {
			r.Imports = []ImportBatch{
				{Samples: []Sample{{ID: "dup", Payload: json.RawMessage(`{"a":1}`)}}},
				{Samples: []Sample{{ID: "dup", Payload: json.RawMessage(`{"a":2}`)}}},
			}
		}, reader: goodReader},
		"invalid import payload": {modify: func(r *PrepareRequest) {
			r.Imports = []ImportBatch{{Samples: []Sample{{ID: "s2", Payload: json.RawMessage(`[1,2]`)}}}}
		}, reader: goodReader},
		"ambiguous import payload": {modify: func(r *PrepareRequest) {
			r.Imports = []ImportBatch{{Samples: []Sample{{ID: "s3", Payload: json.RawMessage(`{"a":1,"a":2}`)}}}}
		}, reader: goodReader},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := base
			tc.modify(&req)
			prepared, err := Prepare(context.Background(), tc.reader, req)
			if !errors.Is(err, ErrInvalidPrepare) {
				t.Fatalf("Prepare error = %v (prepared=%+v), want ErrInvalidPrepare", err, prepared)
			}
		})
	}

	tooManyRefs := make([]HistoryRef, 0, maxPrepareSources+1)
	for i := 0; i <= maxPrepareSources; i++ {
		tooManyRefs = append(tooManyRefs, HistoryRef{OrgID: "org", RequestID: "req-" + strconv.Itoa(i)})
	}
	if _, err := Prepare(context.Background(), goodReader, PrepareRequest{DatasetID: "d", Creator: "op", CreatedAt: prepareClock, History: tooManyRefs}); !errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("too many history refs error = %v, want ErrInvalidPrepare", err)
	}
}

func TestHistorySampleValidationRejectsBadReaderResults(t *testing.T) {
	cases := map[string]HistorySample{
		"blank id":          {Ref: HistoryRef{OrgID: "o", RequestID: "r"}, ID: "  ", Payload: json.RawMessage(`{"a":1}`)},
		"array payload":     {Ref: HistoryRef{OrgID: "o", RequestID: "r"}, ID: "case", Payload: json.RawMessage(`[1]`)},
		"invalid payload":   {Ref: HistoryRef{OrgID: "o", RequestID: "r"}, ID: "case", Payload: json.RawMessage(`{"a":}`)},
		"duplicate payload": {Ref: HistoryRef{OrgID: "o", RequestID: "r"}, ID: "case", Payload: json.RawMessage(`{"a":1,"a":2}`)},
	}
	for name, sample := range cases {
		t.Run(name, func(t *testing.T) {
			ref := sample.Ref
			reader := HistoryReaderFunc(func(context.Context, HistoryRef) (HistorySample, error) { return sample, nil })
			if _, err := Prepare(context.Background(), reader, PrepareRequest{DatasetID: "d", Creator: "op", CreatedAt: prepareClock, History: []HistoryRef{ref}}); !errors.Is(err, ErrInvalidPrepare) {
				t.Fatalf("Prepare error = %v, want ErrInvalidPrepare", err)
			}
		})
	}
}

func TestProvenanceReadRejectsMalformedDocuments(t *testing.T) {
	valid := Provenance{
		SchemaVersion:  ProvenanceSchemaVersion,
		RevisionSHA256: strings.Repeat("a", 64),
		DatasetID:      "d",
		SampleCount:    2,
		CreatedAt:      "2026-10-28T12:00:00Z",
		Creator:        "operator",
		Sources: []ProvenanceSource{
			{Kind: SourceHistory, OrgID: "org-1", RequestID: "req-1", Samples: 1},
			{Kind: SourceImport, Samples: 1},
		},
	}
	if err := validateProvenance(valid); err != nil {
		t.Fatalf("baseline provenance must validate: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteProvenance(&buf, valid); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte{'\n'}) {
		t.Fatal("canonical provenance document ends with one newline")
	}

	mutations := map[string]func(*Provenance){
		"unsupported version":   func(p *Provenance) { p.SchemaVersion = 2 },
		"digest not hex":        func(p *Provenance) { p.RevisionSHA256 = "XYZ" },
		"digest uppercase":      func(p *Provenance) { p.RevisionSHA256 = strings.Repeat("A", 64) },
		"empty dataset id":      func(p *Provenance) { p.DatasetID = " " },
		"zero sample count":     func(p *Provenance) { p.SampleCount = 0 },
		"bad created at":        func(p *Provenance) { p.CreatedAt = "yesterday" },
		"blank creator":         func(p *Provenance) { p.Creator = "" },
		"no sources":            func(p *Provenance) { p.Sources = nil },
		"unknown source kind":   func(p *Provenance) { p.Sources[1].Kind = "mystery" },
		"sum mismatch":          func(p *Provenance) { p.Sources[1].Samples = 5 },
		"history with digest":   func(p *Provenance) { p.Sources[0].ImportDigest = strings.Repeat("b", 64) },
		"import with org":       func(p *Provenance) { p.Sources[1].OrgID = "org-1" },
		"history without org":   func(p *Provenance) { p.Sources[0].OrgID = "" },
		"duplicate history ref": func(p *Provenance) { p.Sources[1] = p.Sources[0]; p.SampleCount = 2 },
		"oversized creator":     func(p *Provenance) { p.Creator = strings.Repeat("x", maxProvenanceCreatorLength+1) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := valid
			mutate(&p)
			if err := validateProvenance(p); err == nil {
				t.Fatalf("validateProvenance accepted mutated provenance %s: %+v", name, p)
			}
		})
	}

	// Strict document-level decode: unknown fields, duplicate keys, trailing
	// data and truncation are rejected before validation.
	raw := buf.Bytes()
	if _, err := ReadProvenance(bytes.NewReader(raw)); err != nil {
		t.Fatalf("canonical document must read back: %v", err)
	}
	withUnknown := bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1)
	if _, err := ReadProvenance(bytes.NewReader(withUnknown)); err == nil {
		t.Fatal("unknown provenance fields must be rejected")
	}
	withDup := bytes.Replace(raw, []byte(`"creator":"operator"`), []byte(`"creator":"operator","creator":"other"`), 1)
	if _, err := ReadProvenance(bytes.NewReader(withDup)); err == nil {
		t.Fatal("duplicate provenance keys must be rejected")
	}
	if _, err := ReadProvenance(bytes.NewReader(append(append([]byte{}, raw...), ' ', '{', '}'))); err == nil {
		t.Fatal("trailing data must be rejected")
	}
	if _, err := ReadProvenance(bytes.NewReader(raw[:len(raw)/2])); err == nil {
		t.Fatal("truncated documents must be rejected")
	}
	oversized := strings.NewReader(strings.Repeat(" ", provenanceMaxBytes+1))
	if _, err := ReadProvenance(oversized); !errors.Is(err, ErrInvalidProvenance) {
		t.Fatalf("oversized provenance error = %v, want ErrInvalidProvenance", err)
	}
	if _, err := ReadProvenance(nil); err == nil {
		t.Fatal("nil reader must be rejected")
	}
	if err := WriteProvenance(&buf, Provenance{}); err == nil {
		t.Fatal("writing an invalid provenance must fail")
	}
	if err := WriteProvenance(nil, valid); err == nil {
		t.Fatal("writing to a nil writer must fail")
	}
}

func TestVerifyProvenanceRejectsWrongBindings(t *testing.T) {
	prepared, err := Prepare(context.Background(), nil, PrepareRequest{
		DatasetID: "d",
		Creator:   "operator",
		CreatedAt: prepareClock,
		Imports:   []ImportBatch{{Samples: []Sample{{ID: "s1", Payload: json.RawMessage(`{"text":"only import"}`)}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyProvenance(prepared.RevisionData, prepared.Provenance); err != nil {
		t.Fatalf("self-binding must verify: %v", err)
	}
	// Internally consistent provenance for a different dataset binds to
	// nothing: id and sample count both diverge from the supplied revision.
	other, err := Prepare(context.Background(), nil, PrepareRequest{
		DatasetID: "other",
		Creator:   "operator",
		CreatedAt: prepareClock,
		Imports:   []ImportBatch{{Samples: []Sample{{ID: "s2", Payload: json.RawMessage(`{"text":"other dataset"}`)}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyProvenance(prepared.RevisionData, other.Provenance); !errors.Is(err, ErrProvenanceMismatch) {
		t.Fatalf("foreign provenance error = %v, want ErrProvenanceMismatch", err)
	}
	// A consistent but inflated provenance (sources sum to the declared
	// count) still fails binding on sample count.
	wrongCount := prepared.Provenance
	wrongCount.SampleCount = 2
	wrongCount.Sources = append(wrongCount.Sources, ProvenanceSource{Kind: SourceImport, ImportDigest: strings.Repeat("c", 64), Samples: 1})
	if err := validateProvenance(wrongCount); err != nil {
		t.Fatalf("setup: inflated provenance must be internally consistent: %v", err)
	}
	if _, err := VerifyProvenance(prepared.RevisionData, wrongCount); !errors.Is(err, ErrProvenanceMismatch) {
		t.Fatalf("wrong sample count error = %v, want ErrProvenanceMismatch", err)
	}
	wrongID := prepared.Provenance
	wrongID.DatasetID = "other"
	if _, err := VerifyProvenance(prepared.RevisionData, wrongID); !errors.Is(err, ErrProvenanceMismatch) {
		t.Fatalf("wrong dataset id error = %v, want ErrProvenanceMismatch", err)
	}
	wrongDigest := prepared.Provenance
	wrongDigest.RevisionSHA256 = strings.Repeat("0", 64)
	if _, err := VerifyProvenance(prepared.RevisionData, wrongDigest); !errors.Is(err, ErrProvenanceMismatch) {
		t.Fatalf("wrong digest error = %v, want ErrProvenanceMismatch", err)
	}
	if _, err := VerifyProvenance([]byte(`not json`), prepared.Provenance); err == nil || errors.Is(err, ErrProvenanceMismatch) {
		t.Fatalf("invalid revision bytes error = %v, want ReadRevision error", err)
	}
}

func TestContentDigestMatchesSHA256(t *testing.T) {
	data := []byte("dataset bytes")
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	if got := ContentDigest(data); got != want {
		t.Fatalf("ContentDigest = %q, want %q", got, want)
	}
	if !isSHA256Hex(want) || isSHA256Hex("not-a-digest") {
		t.Fatal("digest classification is wrong")
	}
}

type failingWriter struct {
	err   error
	short bool
}

func (w failingWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.err
}

func TestPrepareRejectsDuplicateIDsAcrossHistorySources(t *testing.T) {
	refA := HistoryRef{OrgID: "org-1", RequestID: "req-a"}
	refB := HistoryRef{OrgID: "org-1", RequestID: "req-b"}
	reader := historyReaderFunc(t, map[HistoryRef]HistorySample{
		refA: {Ref: refA, ID: "same-id", Payload: json.RawMessage(`{"text":"first"}`)},
		refB: {Ref: refB, ID: "same-id", Payload: json.RawMessage(`{"text":"second"}`)},
	}, nil)
	_, err := Prepare(context.Background(), reader, PrepareRequest{
		DatasetID: "d", Creator: "operator", CreatedAt: prepareClock, History: []HistoryRef{refA, refB},
	})
	if !errors.Is(err, ErrInvalidPrepare) || !strings.Contains(err.Error(), "same-id") {
		t.Fatalf("cross-history duplicate error = %v, want ErrInvalidPrepare naming the id", err)
	}
}

func TestPrepareBoundsTotalSamples(t *testing.T) {
	samples := make([]Sample, 0, maxSamples+1)
	for i := 0; i <= maxSamples; i++ {
		samples = append(samples, Sample{ID: "case-" + strconv.Itoa(i), Payload: json.RawMessage(`{"text":"x"}`)})
	}
	_, err := Prepare(context.Background(), nil, PrepareRequest{
		DatasetID: "d", Creator: "operator", CreatedAt: prepareClock, Imports: []ImportBatch{{Samples: samples}},
	})
	if !errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("over-bound preparation error = %v, want ErrInvalidPrepare", err)
	}
}

func TestWriteProvenanceSurfacesWriterErrors(t *testing.T) {
	valid := Provenance{
		SchemaVersion:  ProvenanceSchemaVersion,
		RevisionSHA256: strings.Repeat("a", 64),
		DatasetID:      "d",
		SampleCount:    1,
		CreatedAt:      "2026-10-28T12:00:00Z",
		Creator:        "operator",
		Sources:        []ProvenanceSource{{Kind: SourceImport, Samples: 1}},
	}
	if err := WriteProvenance(failingWriter{err: errors.New("disk full")}, valid); err == nil {
		t.Fatal("write error must surface")
	}
	if err := WriteProvenance(failingWriter{short: true}, valid); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v, want io.ErrShortWrite", err)
	}
}

func TestReadProvenanceSurfacesReaderErrors(t *testing.T) {
	if _, err := ReadProvenance(iotest.ErrReader(errors.New("read failure"))); !errors.Is(err, ErrInvalidProvenance) {
		t.Fatalf("reader failure error = %v, want ErrInvalidProvenance", err)
	}
}
