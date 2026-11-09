package catalogs

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestLoadCatalogDigestStripRefused pins the review fix (CORE-REF-02
// review 2026-11-02, finding F1): LoadCatalog is the fail-closed consumer
// entry point, so it must refuse bytes whose digest field was stripped —
// the frozen schema validation only verifies a digest that is present,
// which would otherwise let a strip-then-tamper file through unverified.
// Three probe cases over the committed pin:
//
//  1. intact pin loads (digest recomputed and matched);
//  2. "digest" stripped from the pin -> load ERROR;
//  3. content tampered while keeping the digest -> still refused.
func TestLoadCatalogDigestStripRefused(t *testing.T) {
	committed := readCorpusFile(t, committedCatalogRel)

	// Case 2 (baseline): the intact pin loads fail-closed and carries the
	// sealed digest it will be verified against.
	intact, err := LoadCatalog(committed)
	if err != nil {
		t.Fatalf("intact pin must load: %v", err)
	}
	if intact.Digest == "" {
		t.Fatal("intact pin must carry its sealed digest after load")
	}

	// Case 1 (F1 vector): strip the "digest" field from the committed pin
	// bytes — the loader must refuse, not silently accept an unverified
	// catalog. Field-level strip keeps every other byte of the pin intact.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(committed, &fields); err != nil {
		t.Fatalf("parse committed pin fields: %v", err)
	}
	if _, ok := fields["digest"]; !ok {
		t.Fatal("committed pin must contain a digest field (probe precondition)")
	}
	delete(fields, "digest")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshal digest-stripped pin: %v", err)
	}
	if bytes.Contains(stripped, []byte(`"digest"`)) {
		t.Fatal("strip probe must remove the digest field (probe precondition)")
	}
	if _, err := LoadCatalog(stripped); err == nil {
		t.Fatal("digest-stripped bytes must be refused by LoadCatalog (fail-closed), got err=nil")
	} else if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("strip refusal must state the digest contract, got %v", err)
	}

	// Case 3 (defense in depth, pre-existing): mutate content while keeping
	// the digest field — the digest-vs-content recomputation must refuse.
	const versionField = `"version":"0.1.0"`
	tampered := bytes.Replace(committed, []byte(versionField), []byte(`"version":"0.1.0-tampered"`), 1)
	if bytes.Equal(tampered, committed) {
		t.Fatal("tamper probe must change the pin bytes (probe precondition)")
	}
	if _, err := LoadCatalog(tampered); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered bytes with the kept digest must be refused (digest vs content), got %v", err)
	}
}
