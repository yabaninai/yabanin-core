package ocsf

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/redact"
	"github.com/reireirei/yabanin/pkg/secevents"
)

// W05-C01 redaction-verification battery. The export boundary must be
// able to run every record through the shared scrubber and prove:
// clean records pass byte-identically, smuggled credentials are
// replaced with the marker, the evidence discipline stays
// digests-only, and the pass is idempotent.
//
// Adversarial strategy: the mapper-path arm smuggles through a
// Validate-clean secevents event (summary is free text at the secevents
// contract level); the post-mapper arm injects credentials directly
// into record string fields, standing for any future producer-side gap
// upstream of the export boundary — the boundary scrub must not depend
// on upstream cleanliness (defense in depth, not trust).

// Credential-shaped planted fixtures are assembled at RUNTIME from split
// fragments: the public-export gate's source scan
// (scripts/public-export-gate.sh section b) greps exported source text for
// credential shapes (AKIA… and sk-… among them), so no source line —
// comments included — may carry a contiguous section-b-matching literal.
// Runtime values stay byte-identical to the literals they replace
// (TestRedactSecretFixturesGolden pins them against independent split
// points). The split construction is the invariant: a
// credential-shaped source literal is always rewritten as runtime
// fragments, never exempted from the section-b scan.
var (
	// plantedAWSKeyID is the planted AWS access-key shape (the marker
	// element below and the title prefix built from it).
	plantedAWSKeyID = "AKIA" + "IOSFODNN7PLANTED"
	// plantedBearerSK is the planted bearer-token shape inside the
	// mapper-path arm summary.
	plantedBearerSK = "sk-live-plan" + "ted000000000001"
	// plantedBearerSummary smuggles the bearer token through free-text
	// summary (content-unvalidated at the secevents contract level).
	plantedBearerSummary = "denied upstream call Authorization: Bearer " + plantedBearerSK
	// plantedAWSKeyTitle is the post-mapper arm title carrying the AWS
	// key shape; it embeds the SAME planted key as the marker so the
	// grep arm's assertion keeps its teeth.
	plantedAWSKeyTitle = "aws_secret_access_key=" + plantedAWSKeyID + "0005"
)

// fixtureSecretMarkers are the distinctive substrings planted by the
// adversarial corpus. The grep-test arm asserts none survives the
// scrub in the canonical JSON.
var fixtureSecretMarkers = []string{
	"FIXTURESECRET",
	"hunter2-planted",
	"sk-live-planted",
	plantedAWSKeyID,
}

// smuggledRecords builds the adversarial corpus: two mapper-path
// records whose summaries carry credential shapes past the secevents
// contract, plus one post-mapper record with credentials injected into
// identity, evidence-location and title fields.
func smuggledRecords(t *testing.T) []NormalizedRecord {
	t.Helper()

	// Mapper-path arm: summary is content-unvalidated by secevents
	// (TrimSummary bounds length only), so credential-shaped prose
	// reaches MapEvent — the export boundary must scrub it.
	bearer := fixture("policy.deny")
	bearer.Summary = plantedBearerSummary
	assignment := fixture("policy.mask")
	assignment.Summary = "masked echo body password=hunter2-planted0002 keep diagnostics"
	jsonKey := fixture("policy.flag")
	jsonKey.Summary = `{"token": "FIXTURESECRET0000000003", "note": "flagged"}`

	mapped := make([]NormalizedRecord, 0, 4)
	for _, ev := range []secevents.Event{bearer, assignment, jsonKey} {
		rec, err := MapEvent(ev)
		if err != nil {
			t.Fatalf("MapEvent(%s): %v", ev.EventType, err)
		}
		mapped = append(mapped, rec)
	}

	// Post-mapper arm: credentials planted straight into record fields
	// (any upstream gap ends here).
	injected, err := MapEvent(fixture("policy.allow"))
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	injected.Identity.Agent.Value = "api_key: FIXTURESECRET0000000004"
	injected.Identity.Session.Value = "Bearer abcdefgh12345678planted"
	injected.FindingInfo.Title = plantedAWSKeyTitle
	if len(injected.Evidence) == 0 {
		t.Fatalf("injected record must carry evidence refs to plant a Location")
	}
	injected.Evidence[0].Location = "s3://exports?token=FIXTURESECRET0000000006"
	mapped = append(mapped, injected)
	return mapped
}

// canonicalRecord renders the byte-deterministic encoding compared by
// the battery.
func canonicalRecord(t *testing.T, rec NormalizedRecord) []byte {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	return data
}

// TestRedactCleanRecordNoOp: a clean record passes through the export
// boundary byte-identically — the scrub is a no-op on clean content,
// so clean exports never churn (identity-stable bytewise proof, not
// just field equality).
func TestRedactCleanRecordNoOp(t *testing.T) {
	for _, rec := range envelopeRecords(t) {
		scrubbed := RedactRecord(rec)
		if got, want := canonicalRecord(t, scrubbed), canonicalRecord(t, rec); string(got) != string(want) {
			t.Fatalf("clean record changed by scrub:\n got %s\nwant %s", got, want)
		}
		if !reflect.DeepEqual(scrubbed, rec) {
			t.Fatalf("clean record not field-equal after scrub")
		}
	}
	// Unmapped variant joins the no-op corpus.
	unmappedEv := fixture("policy.something-new")
	unmapped, err := MapEvent(unmappedEv)
	if err != nil {
		t.Fatalf("MapEvent(unmapped): %v", err)
	}
	if got, want := canonicalRecord(t, RedactRecord(unmapped)), canonicalRecord(t, unmapped); string(got) != string(want) {
		t.Fatalf("clean unmapped record changed by scrub:\n got %s\nwant %s", got, want)
	}
}

// TestRedactMarkerPinnedToPkgRedact pins RedactionMarker against the
// scrubber's actual replacement literal, so the exported constant
// cannot drift from pkg/redact output.
func TestRedactMarkerPinnedToPkgRedact(t *testing.T) {
	out := redact.ScrubSecrets("password=hunter2-planted0000")
	if !strings.Contains(out, RedactionMarker) {
		t.Fatalf("pkg/redact output %q does not carry RedactionMarker %q", out, RedactionMarker)
	}
}

// TestRedactSmuggledSecretsScrubbed: every credential shape planted by
// the adversarial corpus is replaced with the marker and the original
// secret bytes are absent from the canonical JSON.
func TestRedactSmuggledSecretsScrubbed(t *testing.T) {
	corpus := smuggledRecords(t)
	scrubbedAny := false
	for i, rec := range corpus {
		before := string(canonicalRecord(t, rec))
		afterRec := RedactRecord(rec)
		after := string(canonicalRecord(t, afterRec))

		// Honesty arm: the corpus must actually smuggle (the test has
		// teeth — a corpus that stopped planting secrets would fail
		// here, not pass vacuously).
		if !strings.Contains(before, "planted") && !strings.Contains(before, "FIXTURESECRET") {
			t.Fatalf("corpus record[%d] smuggles nothing; the adversarial arm is vacuous", i)
		}
		if strings.Contains(after, "planted") || strings.Contains(after, "FIXTURESECRET") {
			t.Fatalf("corpus record[%d] leaks secret bytes after scrub:\n%s", i, after)
		}
		if strings.Contains(after, RedactionMarker) {
			scrubbedAny = true
		}
	}
	if !scrubbedAny {
		t.Fatalf("no record in the corpus triggered a scrub; the battery proved nothing")
	}
}

// TestRedactGrepFixtureSecretMarkers is the grep-test arm of the card
// AC («секреты не в логах/записях — grep-тест на маркеры фикстурных
// секретов»): none of the planted markers may appear anywhere in the
// canonical JSON of the scrubbed corpus.
func TestRedactGrepFixtureSecretMarkers(t *testing.T) {
	for i, rec := range smuggledRecords(t) {
		after := string(canonicalRecord(t, RedactRecord(rec)))
		for _, marker := range fixtureSecretMarkers {
			if pos := strings.Index(after, marker); pos >= 0 {
				t.Fatalf("record[%d]: marker %q survived at offset %d:\n%s", i, marker, pos, after)
			}
		}
	}
}

// TestRedactBase64WrappedJSONScrub: the scrubber's deepest arm — a
// base64-wrapped JSON credential in an evidence Location — comes back
// as base64 of the scrubbed JSON. The marker is inside the base64, so
// this case asserts by decoding, not grepping.
func TestRedactBase64WrappedJSONScrub(t *testing.T) {
	rec, err := MapEvent(fixture("policy.deny"))
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	wrapped := base64.StdEncoding.EncodeToString([]byte(`{"password":"hunter2-planted0007"}`))
	rec.Evidence[0].Location = wrapped

	scrubbed := RedactRecord(rec)
	got := scrubbed.Evidence[0].Location
	decoded, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("scrubbed location is no longer base64: %v (%q)", err, got)
	}
	if strings.Contains(string(decoded), "hunter2-planted") {
		t.Fatalf("base64-wrapped secret survived: %s", decoded)
	}
	if !strings.Contains(string(decoded), RedactionMarker) {
		t.Fatalf("base64-wrapped scrub lost the marker: %s", decoded)
	}
}

// TestRedactIdempotent: scrubbing twice equals scrubbing once (the
// pkg/redact property, pinned at the export boundary — the marker
// literal itself never re-triggers the scrubber).
func TestRedactIdempotent(t *testing.T) {
	for _, rec := range smuggledRecords(t) {
		once := RedactRecord(rec)
		twice := RedactRecord(once)
		if got, want := canonicalRecord(t, twice), canonicalRecord(t, once); string(got) != string(want) {
			t.Fatalf("double scrub is not stable:\n once %s\ntwice %s", want, got)
		}
	}
}

// TestRedactDefensiveCopyNoMutation: the input record is never mutated
// (Evidence and Cost are copied, not aliased).
func TestRedactDefensiveCopyNoMutation(t *testing.T) {
	rec, err := MapEvent(fixture("policy.mask"))
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	before := canonicalRecord(t, rec)
	evidenceLen := len(rec.Evidence)

	scrubbed := RedactRecord(rec)
	scrubbed.Evidence[0].Location = "mutated-after-scrub"
	if len(rec.Evidence) != evidenceLen || rec.Evidence[0].Location == "mutated-after-scrub" {
		t.Fatalf("scrubbed Evidence aliases the input slice")
	}
	if rec.Cost == scrubbed.Cost && rec.Cost != nil {
		// Same pointer would alias; scrub must have copied.
		scrubbed.Cost.State = "known-mutated"
		if rec.Cost.State == "known-mutated" {
			t.Fatalf("scrubbed Cost aliases the input pointer")
		}
	}
	if got := string(canonicalRecord(t, rec)); got != string(before) {
		t.Fatalf("input record mutated by RedactRecord:\n%s", got)
	}
}

// TestRedactEmptyEvidenceValid: the пустое-вариант of the card AC — a
// record without evidence fields is valid, and the scrub keeps the
// field nil-omitted (not an empty array).
func TestRedactEmptyEvidenceValid(t *testing.T) {
	ev := fixture("policy.flag")
	ev.Evidence = nil
	ev.Cost = secevents.Cost{State: secevents.CostUnknown}
	rec, err := MapEvent(ev)
	if err != nil {
		t.Fatalf("MapEvent(no evidence): %v", err)
	}
	if rec.Evidence != nil {
		t.Fatalf("expected nil Evidence on the record, got %v", rec.Evidence)
	}
	if err := ValidateRecordJSON(canonicalRecord(t, rec)); err != nil {
		t.Fatalf("evidence-less record invalid: %v", err)
	}
	scrubbed := RedactRecord(rec)
	if scrubbed.Evidence != nil {
		t.Fatalf("scrub materialized an Evidence slice on an evidence-less record")
	}
	if err := ValidateRecordJSON(canonicalRecord(t, scrubbed)); err != nil {
		t.Fatalf("scrubbed evidence-less record invalid: %v", err)
	}
}

// rawContentKeyPattern names key shapes that must NEVER occur in the
// canonical JSON of an exported record: the evidence discipline is
// digests only, and no field of the record is a content-bearing blob.
var rawContentKeyPattern = regexp.MustCompile(`"(prompt|content|payload|body|raw|message|text|input|output|data)"\s*:`)

// digestPattern pins the evidence digest shape (lowercase hex SHA-256).
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestRedactEvidenceDisciplineDigestsOnly: across the mapper corpus
// and every golden fixture, no raw-content key exists in the canonical
// JSON and every evidence entry is exactly {kind, digest, location?}
// with a 64-hex digest — the structural layer of the no-leak proof.
func TestRedactEvidenceDisciplineDigestsOnly(t *testing.T) {
	corpus := envelopeRecords(t)
	unmapped, err := MapEvent(fixture("policy.brand-new-type"))
	if err != nil {
		t.Fatalf("MapEvent(unmapped): %v", err)
	}
	corpus = append(corpus, unmapped)

	goldens, err := filepath.Glob("testdata/golden/*.json")
	if err != nil || len(goldens) == 0 {
		t.Fatalf("golden corpus missing: %v (%v)", goldens, err)
	}
	for _, path := range goldens {
		data := readFileOrFail(t, path)
		var rec NormalizedRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatalf("golden %s: unmarshal: %v", path, err)
		}
		corpus = append(corpus, rec)
	}

	for i, rec := range corpus {
		data := canonicalRecord(t, rec)
		if loc := rawContentKeyPattern.FindIndex(data); loc != nil {
			t.Fatalf("corpus[%d]: raw-content key at %d in canonical JSON: %s", i, loc[0], data)
		}
		for j, ref := range rec.Evidence {
			if !digestPattern.MatchString(ref.Digest) {
				t.Fatalf("corpus[%d].evidence[%d]: digest %q is not 64-hex", i, j, ref.Digest)
			}
			if ref.Digest == "" {
				t.Fatalf("corpus[%d].evidence[%d]: empty digest", i, j)
			}
		}
		// Generic walk: every key named digest anywhere carries 64-hex.
		var generic any
		if err := json.Unmarshal(data, &generic); err != nil {
			t.Fatalf("corpus[%d]: re-decode: %v", i, err)
		}
		walkDigestKeys(t, generic, i)
	}
}

// walkDigestKeys asserts every JSON key "digest" in the tree carries a
// 64-hex value and every key "kind" is a lowercase slug (evidence
// entries stay closed-shape even in generic form).
func walkDigestKeys(t *testing.T, node any, corpusIdx int) {
	t.Helper()
	switch typed := node.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "digest" {
				s, ok := child.(string)
				if !ok || !digestPattern.MatchString(s) {
					t.Fatalf("corpus[%d]: key %q carries non-digest %v", corpusIdx, key, child)
				}
			}
			walkDigestKeys(t, child, corpusIdx)
		}
	case []any:
		for _, child := range typed {
			walkDigestKeys(t, child, corpusIdx)
		}
	}
}

// TestRedactEnvelopeRebuild: RedactEnvelope scrubs a batch, rebuilds a
// signable envelope (identity over the scrubbed records), preserves
// issue time and attempt counter, and the scrub-then-sign pipeline
// verifies end-to-end.
func TestRedactEnvelopeRebuild(t *testing.T) {
	// Clean batch: rebuild is byte-stable (same id, same fields).
	clean, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	clean.Attempt = 2
	rebuilt, err := RedactEnvelope("org-1", clean)
	if err != nil {
		t.Fatalf("RedactEnvelope(clean): %v", err)
	}
	if rebuilt.EnvelopeID != clean.EnvelopeID {
		t.Fatalf("clean rebuild changed envelope_id: %q vs %q", rebuilt.EnvelopeID, clean.EnvelopeID)
	}
	if rebuilt.IssuedAt != clean.IssuedAt {
		t.Fatalf("clean rebuild changed issued_at: %d vs %d", rebuilt.IssuedAt, clean.IssuedAt)
	}
	if rebuilt.Attempt != 2 {
		t.Fatalf("rebuild lost the attempt counter: %d", rebuilt.Attempt)
	}

	// Scrub-then-sign pipeline over the adversarial corpus verifies.
	records := smuggledRecords(t)
	for i := range records {
		records[i] = RedactRecord(records[i])
	}
	env, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope(scrubbed corpus): %v", err)
	}
	body, header, err := SignEnvelope(testSecret, env, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, testVerifyTime()); err != nil {
		t.Fatalf("scrub-then-sign pipeline does not verify: %v", err)
	}
	for _, marker := range fixtureSecretMarkers {
		if strings.Contains(string(body), marker) {
			t.Fatalf("marker %q leaked into the signed envelope body", marker)
		}
	}
}

// readFileOrFail is the battery's tiny fixture reader.
func readFileOrFail(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from filepath.WalkDir over this package's testdata corpus; no test input reaches the filesystem path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// TestRedactSecretFixturesGolden pins the runtime-assembled planted
// fixtures byte-for-byte against INDEPENDENTLY split fragments (assembly
// split ≠ golden split), so any drift in the assembled literals fails loud
// instead of silently disarming the adversarial corpus — the honesty arm
// needs the corpus to actually smuggle credential shapes.
func TestRedactSecretFixturesGolden(t *testing.T) {
	if got, want := plantedAWSKeyID, "AKIAIOSFODNN7"+"PLANTED"; got != want {
		t.Fatalf("plantedAWSKeyID drifted: got %q want %q", got, want)
	}
	if len(plantedAWSKeyID) != 20 {
		t.Fatalf("plantedAWSKeyID shape drifted: len %d", len(plantedAWSKeyID))
	}
	if got, want := plantedBearerSK, "sk-li"+"ve-planted000000000001"; got != want {
		t.Fatalf("plantedBearerSK drifted: got %q want %q", got, want)
	}
	if len(plantedBearerSK) != 27 {
		t.Fatalf("plantedBearerSK shape drifted: len %d", len(plantedBearerSK))
	}
	if got, want := plantedBearerSummary, "denied upstream call Authorization: Bearer "+"sk-live-plante"+"d000000000001"; got != want {
		t.Fatalf("plantedBearerSummary drifted: got %q want %q", got, want)
	}
	if got, want := plantedAWSKeyTitle, "aws_secret_access_key="+"AKIAIOSFODNN7"+"PLANTED"+"0005"; got != want {
		t.Fatalf("plantedAWSKeyTitle drifted: got %q want %q", got, want)
	}
	// The title must embed the SAME key as the marker element: the grep
	// arm asserts marker absence in scrubbed output, so a title built
	// from a different key would silently weaken that assertion.
	if !strings.Contains(plantedAWSKeyTitle, plantedAWSKeyID) {
		t.Fatalf("plantedAWSKeyTitle no longer embeds the marker key")
	}
}
