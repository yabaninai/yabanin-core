package qualityeval

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/agenteval/datasets"
	"github.com/reireirei/yabanin/pkg/evalgate"
)

// testPrepared builds one deterministic prepared set: two imported examples
// (no history refs, so the fixture needs no permission doubles) with a fixed
// creation timestamp. The second payload exercises escaping-heavy content
// (HTML markers, quotes, newline) that must survive verbatim.
func testPrepared(t *testing.T, datasetID string) datasets.Prepared {
	t.Helper()
	prepared, err := datasets.Prepare(context.Background(), nil, datasets.PrepareRequest{
		DatasetID: datasetID,
		Creator:   "operator@example.com",
		CreatedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		Imports: []datasets.ImportBatch{
			{Samples: []datasets.Sample{
				{ID: "case-1", Payload: []byte(`{"prompt":"What is the capital of France?","expect_class":"easy"}`)},
				{ID: "case-2", Payload: []byte(`{"prompt":"<b>Escaped</b> & \"quoted\"/multi\nline","expect_class":"hard"}`)},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return prepared
}

func mustBuild(t *testing.T, p datasets.Prepared) evalgate.ExampleSet {
	t.Helper()
	set, err := BuildSetBundle(p)
	if err != nil {
		t.Fatalf("BuildSetBundle: %v", err)
	}
	return set
}

// goodBundleBytes renders one valid bundle for the mutation matrix.
func goodBundleBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSetBundle(&buf, mustBuild(t, testPrepared(t, "eval-demo"))); err != nil {
		t.Fatalf("seed bundle: %v", err)
	}
	return buf.Bytes()
}

// --- build + write: binding and reproducibility --------------------------

func TestBuildSetBundleBindsPreparedArtifacts(t *testing.T) {
	p := testPrepared(t, "eval-demo")
	set := mustBuild(t, p)

	if set.SchemaVersion != evalgate.ExampleSetSchemaVersion || set.Kind != evalgate.ExampleSetKind {
		t.Fatalf("schema version/kind not pinned: %+v", set)
	}
	if set.SetID != "eval-demo" {
		t.Fatalf("set id = %q, want prepared dataset id", set.SetID)
	}
	if set.ContentSHA256 != p.RevisionID {
		t.Fatalf("content hash = %q, want revision id %q", set.ContentSHA256, p.RevisionID)
	}
	if set.RevisionJSON != string(p.RevisionData) {
		t.Fatalf("revision_json must carry the exact prepared bytes")
	}
}

func TestWriteReadSetBundleRoundTripDeterministic(t *testing.T) {
	p := testPrepared(t, "eval-demo")
	set := mustBuild(t, p)

	var first, second bytes.Buffer
	if err := WriteSetBundle(&first, set); err != nil {
		t.Fatalf("WriteSetBundle: %v", err)
	}
	if err := WriteSetBundle(&second, set); err != nil {
		t.Fatalf("WriteSetBundle second: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("export is not byte-reproducible")
	}

	got, rev, err := ReadSetBundle(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatalf("ReadSetBundle: %v", err)
	}
	if got.SetID != set.SetID || got.ContentSHA256 != set.ContentSHA256 {
		t.Fatalf("round trip drifted: %+v", got)
	}
	if len(rev.Samples) != 2 || rev.Samples[0].ID != "case-1" || rev.Samples[1].ID != "case-2" {
		t.Fatalf("revision samples not preserved: %+v", rev.Samples)
	}
	// The canonical encoder escapes <, >, & as \u003c, \u003e, \u0026; the
	// interchange layer carries those canonical bytes verbatim.
	if string(rev.Samples[1].Payload) != `{"prompt":"\u003cb\u003eEscaped\u003c/b\u003e \u0026 \"quoted\"/multi\nline","expect_class":"hard"}` {
		t.Fatalf("payload bytes not preserved verbatim: %s", rev.Samples[1].Payload)
	}

	// Re-export from the imported bundle must be byte-identical: the
	// exported form is canonical, not an encoding accident.
	var reexport bytes.Buffer
	if err := WriteSetBundle(&reexport, got); err != nil {
		t.Fatalf("re-export: %v", err)
	}
	if !bytes.Equal(reexport.Bytes(), first.Bytes()) {
		t.Fatalf("re-export of imported bundle differs from original export")
	}
}

func TestWriteSetBundleRejectsInvalidWriter(t *testing.T) {
	set := mustBuild(t, testPrepared(t, "eval-demo"))
	if err := WriteSetBundle(nil, set); !errors.Is(err, ErrInvalidSetBundle) {
		t.Fatalf("err = %v, want ErrInvalidSetBundle", err)
	}
}

func TestBuildSetBundleRejectsUnvettedArtifacts(t *testing.T) {
	p := testPrepared(t, "eval-demo")

	tests := []struct {
		name  string
		mutde func(p datasets.Prepared) datasets.Prepared
	}{
		{
			name: "tampered revision bytes",
			mutde: func(p datasets.Prepared) datasets.Prepared {
				p.RevisionData = bytes.Replace(p.RevisionData, []byte("capital"), []byte("largest"), 1)
				return p
			},
		},
		{
			name: "provenance rebound to another dataset",
			mutde: func(p datasets.Prepared) datasets.Prepared {
				p.Provenance.DatasetID = "other-set"
				return p
			},
		},
		{
			name: "provenance digest swapped",
			mutde: func(p datasets.Prepared) datasets.Prepared {
				p.Provenance.RevisionSHA256 = strings.Repeat("ab", 32)
				return p
			},
		},
		{
			name: "sample count drift",
			mutde: func(p datasets.Prepared) datasets.Prepared {
				p.Provenance.SampleCount = 3
				return p
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := BuildSetBundle(tt.mutde(p)); !errors.Is(err, ErrInvalidSetBundle) {
				t.Fatalf("err = %v, want ErrInvalidSetBundle", err)
			}
		})
	}
}

// --- import: strict rejection matrix -------------------------------------

func TestReadSetBundleRejectionMatrix(t *testing.T) {
	base := string(goodBundleBytes(t))
	digest := mustBuild(t, testPrepared(t, "eval-demo")).ContentSHA256

	mutations := []struct {
		name string
		// reader builds the input; nil means "mutate base with replace/with".
		reader  func() io.Reader
		replace string
		with    string
	}{
		{name: "nil reader", reader: func() io.Reader { return nil }},
		{name: "empty input", reader: func() io.Reader { return strings.NewReader("") }},
		{name: "truncated json", reader: func() io.Reader { return strings.NewReader(`{"schema_version":1`) }},
		{name: "not an object", reader: func() io.Reader { return strings.NewReader(`[]`) }},
		{
			name: "duplicate top-level key",
			// The bundle ends with `}` + "\n" (canonical encoder); splice a
			// second set_id in before the closing brace.
			reader: func() io.Reader {
				return strings.NewReader(base[:len(base)-2] + `,"set_id":"eval-demo"}` + "\n")
			},
		},
		{
			name: "unknown top-level field",
			reader: func() io.Reader {
				return strings.NewReader(base[:len(base)-2] + `,"exec":"sh -c evil"}` + "\n")
			},
		},
		{
			name:    "wrong schema version",
			replace: `"schema_version":1,"kind"`,
			with:    `"schema_version":2,"kind"`,
		},
		{
			name:    "wrong kind",
			replace: `"kind":"` + evalgate.ExampleSetKind + `"`,
			with:    `"kind":"some.other.kind"`,
		},
		{
			name:    "blank set id",
			replace: `"set_id":"eval-demo"`,
			with:    `"set_id":""`,
		},
		{
			name:    "oversize set id",
			replace: `"set_id":"eval-demo"`,
			with:    `"set_id":"` + strings.Repeat("x", 257) + `"`,
		},
		{
			name:    "set id mismatches revision dataset",
			replace: `"set_id":"eval-demo"`,
			with:    `"set_id":"other-set"`,
		},
		{
			name:    "content hash not hex",
			replace: `"content_sha256":"` + digest + `"`,
			with:    `"content_sha256":"ZZ` + digest[2:] + `"`,
		},
		{
			name:    "content hash uppercase",
			replace: `"content_sha256":"` + digest + `"`,
			with:    `"content_sha256":"` + strings.ToUpper(digest) + `"`,
		},
		{
			name:    "content hash mismatches revision bytes",
			replace: `"content_sha256":"` + digest + `"`,
			with:    `"content_sha256":"` + strings.Repeat("de", 32) + `"`,
		},
		{
			// Matches only inside the escaped revision_json string (payload
			// text), which changes the digested bytes but not the declared
			// hash.
			name:    "revision bytes tampered",
			replace: `capital`,
			with:    `largest`,
		},
		{
			name:    "revision_json not valid json",
			replace: `{\"schema_version\":1,\"dataset_id\"`,
			with:    `{broken`,
		},
		{
			name: "trailing data after document",
			reader: func() io.Reader {
				return strings.NewReader(base + `{"more":1}`)
			},
		},
	}

	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.reader
			if in == nil {
				s := strings.Replace(base, tt.replace, tt.with, 1)
				if s == base {
					t.Fatalf("mutation did not apply: %q", tt.replace)
				}
				in = func() io.Reader { return strings.NewReader(s) }
			}
			_, _, err := ReadSetBundle(in())
			if !errors.Is(err, ErrInvalidSetBundle) {
				t.Fatalf("err = %v, want ErrInvalidSetBundle", err)
			}
		})
	}
}

func TestReadSetBundleTooLarge(t *testing.T) {
	// The size bound rejects with its own sentinel, distinct from the
	// invalid-document sentinel, before any decode runs.
	big := bytes.Repeat([]byte(" "), maxSetBundleBytes+2)
	_, _, err := ReadSetBundle(bytes.NewReader(big))
	if !errors.Is(err, ErrSetBundleTooLarge) {
		t.Fatalf("err = %v, want ErrSetBundleTooLarge", err)
	}
	if errors.Is(err, ErrInvalidSetBundle) {
		t.Fatalf("oversize input must not report ErrInvalidSetBundle")
	}
}

func TestReadSetBundleProvenanceMatrix(t *testing.T) {
	base := string(goodBundleBytes(t))

	tests := []struct {
		name    string
		replace string
		with    string
	}{
		{
			name:    "provenance schema version",
			replace: `"provenance":{"schema_version":1`,
			with:    `"provenance":{"schema_version":2`,
		},
		{
			// "sample_count" exists only inside provenance, so the replace
			// is unambiguous (the revision document has no such key).
			name:    "provenance dataset mismatch",
			replace: `,"dataset_id":"eval-demo","sample_count":2`,
			with:    `,"dataset_id":"other","sample_count":2`,
		},
		{
			name:    "sample count drift",
			replace: `"sample_count":2`,
			with:    `"sample_count":3`,
		},
		{
			name:    "creator blank",
			replace: `"creator":"operator@example.com"`,
			with:    `"creator":""`,
		},
		{
			name:    "created_at not rfc3339",
			replace: `"created_at":"2026-10-30T12:00:00Z"`,
			with:    `"created_at":"yesterday"`,
		},
		{
			name:    "sources empty",
			replace: `"sources":[{"kind":"import","samples":2}]`,
			with:    `"sources":[]`,
		},
		{
			name:    "unknown source kind",
			replace: `"sources":[{"kind":"import","samples":2}]`,
			with:    `"sources":[{"kind":"fetch","samples":2}]`,
		},
		{
			name:    "source sample sum drift",
			replace: `"sources":[{"kind":"import","samples":2}]`,
			with:    `"sources":[{"kind":"import","samples":1}]`,
		},
		{
			name:    "history source without org/request ids",
			replace: `"sources":[{"kind":"import","samples":2}]`,
			with:    `"sources":[{"kind":"history","samples":1},{"kind":"import","samples":1}]`,
		},
		{
			name:    "history source carrying three samples",
			replace: `"sources":[{"kind":"import","samples":2}]`,
			with:    `"sources":[{"kind":"history","org_id":"o","request_id":"r","samples":3}]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := strings.Replace(base, tt.replace, tt.with, 1)
			if s == base {
				t.Fatalf("mutation %q did not apply", tt.replace)
			}
			_, _, err := ReadSetBundle(strings.NewReader(s))
			if !errors.Is(err, ErrInvalidSetBundle) {
				t.Fatalf("err = %v, want ErrInvalidSetBundle", err)
			}
		})
	}
}

// --- negatives required by the card --------------------------------------

// TestPrepareRequiresPermissionedReader pins the assembly boundary: history
// content cannot be named into a set. Without a permission-checked reader the
// preparation fails; the interchange layer has no way around it because
// BuildSetBundle accepts only Prepared artifacts.
func TestPrepareRequiresPermissionedReader(t *testing.T) {
	_, err := datasets.Prepare(context.Background(), nil, datasets.PrepareRequest{
		DatasetID: "eval-demo",
		Creator:   "operator@example.com",
		CreatedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		History:   []datasets.HistoryRef{{OrgID: "org-9", RequestID: "req-9"}},
		Imports: []datasets.ImportBatch{
			{Samples: []datasets.Sample{{ID: "case-1", Payload: []byte(`{"text":"opaque"}`)}}},
		},
	})
	if err == nil {
		t.Fatal("Prepare accepted a history reference without a permission-checked reader")
	}
	if !errors.Is(err, datasets.ErrInvalidPrepare) {
		t.Fatalf("err = %v, want ErrInvalidPrepare", err)
	}
}

// TestReadSetBundleNeverDereferencesSources pins the negative property: a
// bundle whose provenance names stored history (org/request ids) imports as
// inert data. The importer has no reader, fetcher or executor parameter at
// all — sources ride through verbatim and nothing is resolved.
func TestReadSetBundleNeverDereferencesSources(t *testing.T) {
	calls := 0
	reader := datasets.HistoryReaderFunc(func(_ context.Context, ref datasets.HistoryRef) (datasets.HistorySample, error) {
		calls++
		return datasets.HistorySample{Ref: ref, ID: "case-hist", Payload: []byte(`{"text":"processed"}`)}, nil
	})
	p, err := datasets.Prepare(context.Background(), reader, datasets.PrepareRequest{
		DatasetID: "eval-demo",
		Creator:   "operator@example.com",
		CreatedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		History:   []datasets.HistoryRef{{OrgID: "org-1", RequestID: "req-42"}},
		Imports: []datasets.ImportBatch{
			{Samples: []datasets.Sample{{ID: "case-import", Payload: []byte(`{"text":"external"}`)}}},
		},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if calls != 1 {
		t.Fatalf("history reader calls during prepare = %d, want 1", calls)
	}

	set := mustBuild(t, p)
	var buf bytes.Buffer
	if err := WriteSetBundle(&buf, set); err != nil {
		t.Fatalf("WriteSetBundle: %v", err)
	}
	calls = 0
	imported, rev, err := ReadSetBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadSetBundle: %v", err)
	}
	if calls != 0 {
		t.Fatalf("import resolved history sources %d times, want 0", calls)
	}
	if len(imported.Provenance.Sources) != 2 || imported.Provenance.Sources[0].OrgID != "org-1" {
		t.Fatalf("sources not carried as data: %+v", imported.Provenance.Sources)
	}
	if len(rev.Samples) != 2 {
		t.Fatalf("revision samples = %d, want 2", len(rev.Samples))
	}
}

// TestImportTreatsContentAsInertData pins "import executes no code":
// executable-looking payload content imports unchanged as opaque data.
func TestImportTreatsContentAsInertData(t *testing.T) {
	prepared, err := datasets.Prepare(context.Background(), nil, datasets.PrepareRequest{
		DatasetID: "eval-hostile",
		Creator:   "operator@example.com",
		CreatedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		Imports: []datasets.ImportBatch{
			{Samples: []datasets.Sample{
				{ID: "evil-1", Payload: []byte(`{"cmd":"sh -c 'rm -rf /'","tpl":"{{.Env.Secrets}}","note":"<script>alert(1)</script>"}`)},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	set := mustBuild(t, prepared)
	var buf bytes.Buffer
	if err := WriteSetBundle(&buf, set); err != nil {
		t.Fatalf("WriteSetBundle: %v", err)
	}
	_, rev, err := ReadSetBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("hostile-looking content must stay inert data, got: %v", err)
	}
	if !bytes.Contains(rev.Samples[0].Payload, []byte("rm -rf")) {
		t.Fatalf("payload not preserved verbatim: %s", rev.Samples[0].Payload)
	}
}

// TestBundleCarriesNoInterchangeMediaChannel documents I62/I63 at the
// interchange layer: the bundle format has no media or originals field. Any
// media references the permitted read returned live only inside opaque
// sample payloads; the format itself cannot pull hidden originals or media.
func TestBundleCarriesNoInterchangeMediaChannel(t *testing.T) {
	set := mustBuild(t, testPrepared(t, "eval-demo"))
	var buf bytes.Buffer
	if err := WriteSetBundle(&buf, set); err != nil {
		t.Fatalf("WriteSetBundle: %v", err)
	}
	for _, banned := range []string{`"media"`, `"originals"`, `"media_url"`, `"original_text"`} {
		if bytes.Contains(buf.Bytes(), []byte(banned)) {
			t.Fatalf("bundle carries an interchange-level %s channel", banned)
		}
	}
}

// TestSetIDLengthBounds documents the interchange bound interplay: a valid
// set id of exactly the maximum length still round-trips.
func TestSetIDLengthBounds(t *testing.T) {
	long := strings.Repeat("s", maxSetIDLength)
	set := mustBuild(t, testPrepared(t, long))
	var buf bytes.Buffer
	if err := WriteSetBundle(&buf, set); err != nil {
		t.Fatalf("WriteSetBundle: %v", err)
	}
	got, _, err := ReadSetBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadSetBundle: %v", err)
	}
	if got.SetID != long {
		t.Fatalf("set id round trip failed")
	}
}

// TestGoldenRoutingFixtureRoundTrip consumes the committed worked example
// (datasets/eval/routing_example_set.v1.json, generated through the real
// preparation + export path): it must import strictly, verify its own content
// hash and re-export byte-identically — the reproducibility claim an external
// runner relies on.
func TestGoldenRoutingFixtureRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("../../datasets/eval/routing_example_set.v1.json")
	if err != nil {
		// The routing example set is internal-only (datasets/eval); skip
		// with an explicit reason in the public tree instead of failing.
		t.Skipf("eval datasets are not part of the public export (routing fixture absent): %v", err)
	}
	got, rev, err := ReadSetBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadSetBundle: %v", err)
	}
	if got.SetID != "golden-routing-demo" {
		t.Fatalf("set id = %q", got.SetID)
	}
	if len(rev.Samples) != 32 {
		t.Fatalf("samples = %d, want 32", len(rev.Samples))
	}
	if got.Provenance.SampleCount != 32 || len(got.Provenance.Sources) != 1 || got.Provenance.Sources[0].Kind != "import" {
		t.Fatalf("provenance not bound: %+v", got.Provenance)
	}
	var reexport bytes.Buffer
	if err := WriteSetBundle(&reexport, got); err != nil {
		t.Fatalf("re-export: %v", err)
	}
	if !bytes.Equal(reexport.Bytes(), raw) {
		t.Fatalf("committed fixture is not byte-reproducible from its own data")
	}
}
