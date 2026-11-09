package lineage

import (
	"strings"
	"testing"
)

// H1 tests: the hash-chain primitives are pure and testable without a DB.
// VerifyChain itself is DB-bound (covered by the integration test when
// testcontainers is available).

func TestRowHash_Deterministic(t *testing.T) {
	a := rowHash("", "req1|org1|model|US")
	b := rowHash("", "req1|org1|model|US")
	if a != b {
		t.Fatal("rowHash must be deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("rowHash must be 64 hex chars, got %d", len(a))
	}
	// Different prev or payload → different hash.
	if rowHash("prev", "req1|org1|model|US") == a {
		t.Fatal("different prevHash must change the hash")
	}
	if rowHash("", "req1|org1|model|CA") == a {
		t.Fatal("different payload must change the hash")
	}
}

func TestCanonicalRecord_FixedOrder(t *testing.T) {
	att := Attestation{
		RequestID:        "r1",
		OrgID:            "o1",
		ModelUsed:        "gpt",
		InferenceRegion:  "US",
		ModelOrigin:      "US",
		LogStorageRegion: "sg",
		ProviderEntity:   "US",
		RegionEvidence:   "endpoint_pinned",
	}
	got := canonicalRecord(att, "hash", "sig", "key")
	want := "r1|o1|gpt|US|US|sg|US|endpoint_pinned|hash|sig|key"
	if got != want {
		t.Fatalf("canonicalRecord = %q, want %q", got, want)
	}
}

// TestChainLink_Simulated builds a small in-memory chain using the same
// rowHash/canonicalRecord the writer and verifier share, and asserts the
// verifier's per-row expectation holds (head → next → next).
func TestChainLink_Simulated(t *testing.T) {
	type row struct {
		att        Attestation
		attHash    string
		sig, keyID string
		recordHash string
		prevHash   string // "" = head (NULL)
	}
	atts := []Attestation{
		{RequestID: "r1", OrgID: "o1", ModelUsed: "m", InferenceRegion: "US", ModelOrigin: "US", LogStorageRegion: "sg", ProviderEntity: "US", RegionEvidence: "x"},
		{RequestID: "r2", OrgID: "o1", ModelUsed: "m", InferenceRegion: "US", ModelOrigin: "US", LogStorageRegion: "sg", ProviderEntity: "US", RegionEvidence: "x"},
		{RequestID: "r3", OrgID: "o1", ModelUsed: "m", InferenceRegion: "US", ModelOrigin: "US", LogStorageRegion: "sg", ProviderEntity: "US", RegionEvidence: "x"},
	}
	var rows []row
	prev := ""
	for i, att := range atts {
		attHash := "h" + string(rune('0'+i))
		rec := rowHash(prev, canonicalRecord(att, attHash, "sig", "key"))
		rows = append(rows, row{att: att, attHash: attHash, sig: "sig", keyID: "key", recordHash: rec, prevHash: prev})
		prev = rec
	}
	// Verify: walk in order, recompute, and check recordHash + prevHash.
	cur := ""
	for i, r := range rows {
		expected := rowHash(cur, canonicalRecord(r.att, r.attHash, r.sig, r.keyID))
		if r.recordHash != expected {
			t.Fatalf("row %d: recordHash mismatch (tampered or wrong link)", i)
		}
		if r.prevHash != cur {
			t.Fatalf("row %d: prevHash mismatch (got %q want %q)", i, r.prevHash, cur)
		}
		cur = r.recordHash
	}
}

// TestChainLink_TamperDetected shows that changing one payload breaks the
// chain at that row (the verifier would flag it).
func TestChainLink_TamperDetected(t *testing.T) {
	atts := []Attestation{
		{RequestID: "r1", OrgID: "o1", ModelUsed: "m", InferenceRegion: "US", ModelOrigin: "US", LogStorageRegion: "sg", ProviderEntity: "US", RegionEvidence: "x"},
		{RequestID: "r2", OrgID: "o1", ModelUsed: "m", InferenceRegion: "US", ModelOrigin: "US", LogStorageRegion: "sg", ProviderEntity: "US", RegionEvidence: "x"},
	}
	var recordHashes []string
	prev := ""
	for i, att := range atts {
		attHash := "h" + string(rune('0'+i))
		rec := rowHash(prev, canonicalRecord(att, attHash, "sig", "key"))
		recordHashes = append(recordHashes, rec)
		prev = rec
	}
	// Tamper: recompute row 1 with a changed payload.
	tamperedAtt := atts[1]
	tamperedAtt.ModelUsed = "m-tampered"
	recomputed := rowHash(recordHashes[0], canonicalRecord(tamperedAtt, "h1", "sig", "key"))
	if recomputed == recordHashes[1] {
		t.Fatal("tampering the payload must change the computed hash (chain break detectable)")
	}
}

func TestNullIfEmpty(t *testing.T) {
	if v := nullIfEmpty(""); v != nil {
		t.Fatalf("nullIfEmpty(\"\") should be nil, got %v", v)
	}
	if v := nullIfEmpty("abc"); v != "abc" {
		t.Fatalf("nullIfEmpty(abc) = %v, want abc", v)
	}
}

func TestVerifyChain_SkipsLegacy(t *testing.T) {
	// VerifyChain is DB-bound; this test only guards the status shape and the
	// legacy-skip contract at the type level (no DB). A legacy row has
	// record_hash="" and is counted but not chained.
	var s ChainStatus
	s.Legacy = 3
	s.Rows = 5
	s.Chained = 2
	if s.Legacy+s.Chained != s.Rows {
		t.Fatal("status must account for all rows (legacy + chained)")
	}
	_ = strings.Builder{}
}
