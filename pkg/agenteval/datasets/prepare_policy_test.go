// Per-example content-policy application tests (N14-P01-T04): tenant pin,
// originals rights, metadata-only media default, delete semantics and the
// provenance policy flags that record the outcome per admitted history read.
package datasets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var policyClock = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

// policyReader is a strict single-ref reader: it fails the test when asked
// for a reference outside its reads map, so rejection-before-read is
// observable (the reader must never be consulted for a foreign-tenant ref).
func policyReader(t *testing.T, reads map[HistoryRef]HistorySample) HistoryReaderFunc {
	t.Helper()
	return func(_ context.Context, ref HistoryRef) (HistorySample, error) {
		sample, ok := reads[ref]
		if !ok {
			t.Errorf("reader consulted for unexpected reference %s/%s", ref.OrgID, ref.RequestID)
			return HistorySample{}, errors.New("unexpected reference")
		}
		return sample, nil
	}
}

func policyRequest() PrepareRequest {
	return PrepareRequest{
		DatasetID: "policy-eval",
		Creator:   "operator@example.com",
		CreatedAt: policyClock,
	}
}

func TestPrepareTenantPinRejectsForeignOrgWithoutReading(t *testing.T) {
	foreign := HistoryRef{OrgID: "org-other", RequestID: "req-x"}
	reader := policyReader(t, nil) // any call is a failure
	req := policyRequest()
	req.OrgID = "org-1"
	req.History = []HistoryRef{foreign}
	_, err := Prepare(context.Background(), reader, req)
	if !errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("cross-tenant reference error = %v, want ErrInvalidPrepare", err)
	}
	for _, want := range []string{"org-other", "org-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must name both the foreign tenant and the pin", err)
		}
	}
}

func TestPrepareRejectsMixedTenantHistoryWithoutPin(t *testing.T) {
	refA := HistoryRef{OrgID: "org-1", RequestID: "req-a"}
	refB := HistoryRef{OrgID: "org-2", RequestID: "req-b"}
	reader := policyReader(t, map[HistoryRef]HistorySample{
		refA: {Ref: refA, ID: "case-a", Payload: json.RawMessage(`{"text":"a"}`)},
	})
	req := policyRequest()
	req.History = []HistoryRef{refA, refB}
	_, err := Prepare(context.Background(), reader, req)
	if !errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("mixed-tenant run error = %v, want ErrInvalidPrepare", err)
	}
	if !strings.Contains(err.Error(), "single-tenant") {
		t.Fatalf("error %q must state the single-tenant invariant", err)
	}
}

func TestPrepareTenantPinAcceptsSingleTenantRun(t *testing.T) {
	refA := HistoryRef{OrgID: "org-1", RequestID: "req-a"}
	refB := HistoryRef{OrgID: "org-1", RequestID: "req-b"}
	reader := policyReader(t, map[HistoryRef]HistorySample{
		refA: {Ref: refA, ID: "case-a", Payload: json.RawMessage(`{"text":"a"}`)},
		refB: {Ref: refB, ID: "case-b", Payload: json.RawMessage(`{"text":"b"}`)},
	})
	req := policyRequest()
	req.OrgID = "org-1"
	req.History = []HistoryRef{refA, refB}
	prepared, err := Prepare(context.Background(), reader, req)
	if err != nil {
		t.Fatalf("pinned single-tenant run rejected: %v", err)
	}
	for _, source := range prepared.Provenance.Sources {
		if source.OrgID != "org-1" {
			t.Fatalf("source escaped the pinned tenant: %+v", source)
		}
	}
	// Whitespace-only pin: caller believes the run is pinned; fail closed.
	req.OrgID = "   "
	req.History = []HistoryRef{refA}
	if _, err := Prepare(context.Background(), reader, req); !errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("blank tenant pin error = %v, want ErrInvalidPrepare", err)
	}
}

func TestPrepareDefaultPolicyRejectsOriginalContent(t *testing.T) {
	ref := HistoryRef{OrgID: "org-1", RequestID: "req-orig"}
	reader := policyReader(t, map[HistoryRef]HistorySample{
		ref: {Ref: ref, ID: "case-orig", Payload: json.RawMessage(`{"text":"original prompt"}`), ContainsOriginals: true},
	})
	req := policyRequest()
	req.History = []HistoryRef{ref}
	_, err := Prepare(context.Background(), reader, req)
	if !errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("undeclared-originals run error = %v, want ErrInvalidPrepare", err)
	}
	if !strings.Contains(err.Error(), "original") || !strings.Contains(err.Error(), "explicitly enabled") {
		t.Fatalf("error %q must name the originals switch", err)
	}

	// The explicit switch — set only by a boundary that verified the
	// separate originals permission — admits the sample.
	req.AllowOriginals = true
	prepared, err := Prepare(context.Background(), reader, req)
	if err != nil {
		t.Fatalf("originals-enabled run rejected: %v", err)
	}
	source := prepared.Provenance.Sources[0]
	if !source.ContainsOriginals || source.MediaBytes {
		t.Fatalf("provenance policy flags wrong: %+v", source)
	}
}

func TestPrepareMetadataOnlyMediaDefault(t *testing.T) {
	refMeta := HistoryRef{OrgID: "org-1", RequestID: "req-meta"}
	refBytes := HistoryRef{OrgID: "org-1", RequestID: "req-bytes"}
	reader := policyReader(t, map[HistoryRef]HistorySample{
		// Metadata+references only: admitted under the default.
		refMeta: {Ref: refMeta, ID: "case-meta", Payload: json.RawMessage(`{"media":[{"url":"https://example.invalid/img.png","mime":"image/png"}]}`)},
		// Inline media bytes: rejected under the default.
		refBytes: {Ref: refBytes, ID: "case-bytes", Payload: json.RawMessage(`{"image_data_url":"data:image/png;base64,aGVsbG8="}`), MediaBytes: true},
	})
	req := policyRequest()
	req.History = []HistoryRef{refMeta}
	prepared, err := Prepare(context.Background(), reader, req)
	if err != nil {
		t.Fatalf("metadata-only media sample rejected: %v", err)
	}
	if prepared.Provenance.Sources[0].MediaBytes {
		t.Fatalf("metadata-only source must not carry media_bytes: %+v", prepared.Provenance.Sources[0])
	}

	req.History = []HistoryRef{refBytes}
	_, err = Prepare(context.Background(), reader, req)
	if !errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("media-bytes default error = %v, want ErrInvalidPrepare", err)
	}
	if !strings.Contains(err.Error(), "metadata-only") {
		t.Fatalf("error %q must name the metadata-only media default", err)
	}

	req.AllowMediaBytes = true
	prepared, err = Prepare(context.Background(), reader, req)
	if err != nil {
		t.Fatalf("media-enabled run rejected: %v", err)
	}
	if !prepared.Provenance.Sources[0].MediaBytes || prepared.Provenance.Sources[0].ContainsOriginals {
		t.Fatalf("provenance policy flags wrong: %+v", prepared.Provenance.Sources[0])
	}
}

func TestPrepareDeletedRequestAbortsWholeRun(t *testing.T) {
	refAlive := HistoryRef{OrgID: "org-1", RequestID: "req-alive"}
	refDeleted := HistoryRef{OrgID: "org-1", RequestID: "req-deleted"}
	reader := HistoryReaderFunc(func(_ context.Context, ref HistoryRef) (HistorySample, error) {
		if ref == refDeleted {
			// Delete (tombstone) refusals are reader errors: the whole run
			// must abort, never silently skip into a smaller set.
			return HistorySample{}, errors.New("request deleted (tombstoned)")
		}
		return HistorySample{Ref: ref, ID: "case-alive", Payload: json.RawMessage(`{"text":"alive"}`)}, nil
	})
	req := policyRequest()
	req.History = []HistoryRef{refAlive, refDeleted}
	prepared, err := Prepare(context.Background(), reader, req)
	if err == nil {
		t.Fatalf("deleted request must abort the run, got prepared=%+v", prepared)
	}
	if errors.Is(err, ErrInvalidPrepare) {
		t.Fatalf("delete refusal is a reader error, not ErrInvalidPrepare: %v", err)
	}
	if !strings.Contains(err.Error(), "req-deleted") || !strings.Contains(err.Error(), "tombstoned") {
		t.Fatalf("error %q must name the deleted reference", err)
	}
	if prepared.RevisionID != "" || len(prepared.Revision.Samples) != 0 {
		t.Fatalf("no partial revision may survive a failed run: %+v", prepared)
	}
}

func TestProvenancePolicyFlagsRoundTripAndBindings(t *testing.T) {
	ref := HistoryRef{OrgID: "org-1", RequestID: "req-orig"}
	reader := policyReader(t, map[HistoryRef]HistorySample{
		ref: {Ref: ref, ID: "case-orig", Payload: json.RawMessage(`{"text":"original"}`), ContainsOriginals: true, MediaBytes: true},
	})
	req := policyRequest()
	req.OrgID = "org-1"
	req.AllowOriginals = true
	req.AllowMediaBytes = true
	req.History = []HistoryRef{ref}
	prepared, err := Prepare(context.Background(), reader, req)
	if err != nil {
		t.Fatalf("fully-enabled run rejected: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteProvenance(&buf, prepared.Provenance); err != nil {
		t.Fatal(err)
	}
	doc := buf.String()
	for _, key := range []string{`"contains_originals":true`, `"media_bytes":true`} {
		if !strings.Contains(doc, key) {
			t.Fatalf("provenance document %s lacks %s", doc, key)
		}
	}
	loaded, err := ReadProvenance(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("flags rejected by the strict provenance reader: %v", err)
	}
	if !loaded.Sources[0].ContainsOriginals || !loaded.Sources[0].MediaBytes {
		t.Fatalf("flag round-trip lost policy state: %+v", loaded.Sources[0])
	}
	if _, err := VerifyProvenance(prepared.RevisionData, loaded); err != nil {
		t.Fatalf("policy-flagged provenance binding: %v", err)
	}
}

func TestProvenanceRejectsPolicyFlagsOnImportSource(t *testing.T) {
	base := func() Provenance {
		revision := Revision{SchemaVersion: SchemaVersion, DatasetID: "d", Samples: []Sample{
			{ID: "s", Payload: json.RawMessage(`{"a":1}`)},
		}}
		data, _ := json.Marshal(revision)
		return Provenance{
			SchemaVersion:  ProvenanceSchemaVersion,
			RevisionSHA256: ContentDigest(data),
			DatasetID:      "d",
			SampleCount:    1,
			CreatedAt:      policyClock.Format(time.RFC3339),
			Creator:        "operator",
			Sources:        []ProvenanceSource{{Kind: SourceImport, Samples: 1}},
		}
	}
	cases := map[string]func(*ProvenanceSource){
		"contains_originals": func(s *ProvenanceSource) { s.ContainsOriginals = true },
		"media_bytes":        func(s *ProvenanceSource) { s.MediaBytes = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(&p.Sources[0])
			if err := validateProvenance(p); !errors.Is(err, ErrInvalidProvenance) {
				t.Fatalf("import source policy-flag error = %v, want ErrInvalidProvenance", err)
			}
		})
	}
}

// TestPrepareDefaultRunProvenanceStaysByteStable pins the compatibility
// claim: a run using only pre-policy fields produces a provenance document
// without any policy key, so default-form artifacts stay byte-identical to
// the pre-T04 engine (and to the committed interchange fixtures).
func TestPrepareDefaultRunProvenanceStaysByteStable(t *testing.T) {
	ref := HistoryRef{OrgID: "org-1", RequestID: "req-plain"}
	reader := policyReader(t, map[HistoryRef]HistorySample{
		ref: {Ref: ref, ID: "case-plain", Payload: json.RawMessage(`{"text":"processed"}`)},
	})
	req := policyRequest()
	req.History = []HistoryRef{ref}
	prepared, err := Prepare(context.Background(), reader, req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteProvenance(&buf, prepared.Provenance); err != nil {
		t.Fatal(err)
	}
	doc := buf.String()
	for _, key := range []string{"contains_originals", "media_bytes"} {
		if strings.Contains(doc, key) {
			t.Fatalf("default-run provenance must omit %q: %s", key, doc)
		}
	}
}
