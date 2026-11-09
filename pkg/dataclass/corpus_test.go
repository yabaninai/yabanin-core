// Package dataclass — benign corpus pins (E04-P01-W05-C01).
//
// The committed corpus is reproducible evidence: its exact bytes are
// pinned by SHA-256 below, and a missing or mutated corpus file FAILS the
// test — it is never skipped. The refusal battery keeps the loader
// fail-closed: every malformed shape is a typed ErrCorpusInvalid, and no
// partial corpus is ever returned.
package dataclass

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// benignCorpusPinnedSHA256 pins the committed corpus bytes. Any corpus
// change must update this constant (and the W05-C02 budget file's
// corpus_sha256) in the same change — that is the corpus-hash watchdog.
const benignCorpusPinnedSHA256 = "69b24ed1e823338ccb3cd78ac785578f290ec739c3fab98ee3d930731c5a6b8e"

// benignCorpusFile reads the committed corpus; a missing corpus is a test
// FAIL (t.Fatalf), never a skip — the corpus is required evidence.
func benignCorpusFile(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/benign_ru_en.jsonl")
	if err != nil {
		t.Fatalf("committed corpus missing or unreadable (FAIL, never skip): %v", err)
	}
	return data
}

// TestCorpusFileHashPinned pins the exact corpus bytes by SHA-256.
func TestCorpusFileHashPinned(t *testing.T) {
	data := benignCorpusFile(t)
	digest := sha256.Sum256(data)
	got := hex.EncodeToString(digest[:])
	if got != benignCorpusPinnedSHA256 {
		t.Fatalf("corpus hash drifted: got %s, pinned %s — update the pin and testdata/benign_budget.json together, in one reviewed change", got, benignCorpusPinnedSHA256)
	}
}

// TestCorpusLoadValid loads the committed corpus through the full loader
// and pins its structural shape: sample count, both languages present,
// every type of the closed set present, every row benign, and loader
// determinism (a second load is identical).
func TestCorpusLoadValid(t *testing.T) {
	data := benignCorpusFile(t)
	samples, hash, err := LoadBenignCorpus(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("LoadBenignCorpus: %v", err)
	}
	if hash != benignCorpusPinnedSHA256 {
		t.Fatalf("loader hash %s != pinned %s", hash, benignCorpusPinnedSHA256)
	}
	if len(samples) != 40 {
		t.Fatalf("corpus sample count = %d, want 40 (20 ru + 20 en)", len(samples))
	}
	langs := map[string]int{}
	types := map[SupportedTextType]int{}
	ids := map[string]bool{}
	for _, s := range samples {
		if ids[s.ID] {
			t.Fatalf("duplicate sample id %s (transfer layer should have refused)", s.ID)
		}
		ids[s.ID] = true
		langs[s.Lang]++
		types[s.TextType]++
		if s.Expect != CorpusExpectBenign {
			t.Fatalf("sample %s: expect %q, want %q", s.ID, s.Expect, CorpusExpectBenign)
		}
	}
	if langs[LocaleRU] != 20 || langs[LocaleEN] != 20 {
		t.Fatalf("language split = ru:%d en:%d, want 20/20", langs[LocaleRU], langs[LocaleEN])
	}
	for _, want := range SupportedTextTypes() {
		if types[want] == 0 {
			t.Fatalf("corpus covers no %q samples (want at least one per closed-set type)", want)
		}
	}
	again, againHash, err := LoadBenignCorpus(bytes.NewReader(data))
	if err != nil || againHash != hash || len(again) != len(samples) {
		t.Fatalf("loader not deterministic on second load: err=%v hash-equal=%v len=%d/%d", err, againHash == hash, len(again), len(samples))
	}
	for i := range again {
		if again[i] != samples[i] {
			t.Fatalf("second load differs at sample %d (%s)", i, samples[i].ID)
		}
	}
}

// TestCorpusHashCoversExactBytes proves the hash pins bytes, not meaning:
// a semantically identical corpus with one byte changed yields a different
// hash (still loading, no longer matching the pin).
func TestCorpusHashCoversExactBytes(t *testing.T) {
	data := benignCorpusFile(t)
	mutated := bytes.Replace(data, []byte("14:30"), []byte("14:31"), 1)
	if bytes.Equal(mutated, data) {
		t.Fatalf("mutation did not change the corpus bytes — pick a real substring")
	}
	_, hash, err := LoadBenignCorpus(bytes.NewReader(mutated))
	if err != nil {
		t.Fatalf("mutated corpus should still load: %v", err)
	}
	if hash == benignCorpusPinnedSHA256 {
		t.Fatalf("hash did not change with the bytes — pin is not over exact bytes")
	}
}

// corpusRow builds one transfer row for refusal tests. The corpus layer
// sits on top of the datasets transfer format, so rows are constructed in
// that exact shape.
func corpusRow(t *testing.T, datasetID, id string, payload string) string {
	t.Helper()
	return `{"schema_version":1,"dataset_id":` + quoteJSON(t, datasetID) + `,"id":` + quoteJSON(t, id) + `,"payload":` + payload + "}"
}

func quoteJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	return string(b)
}

// TestCorpusLoadRefuses walks the fail-closed refusal battery: every
// malformed corpus shape is ErrCorpusInvalid, and no partial result is
// returned.
func TestCorpusLoadRefuses(t *testing.T) {
	badLang := corpusRow(t, BenignCorpusDatasetID, "s1", `{"lang":"fr","text_type":"plain","text":"bonjour","expect":"benign"}`)
	badExpect := corpusRow(t, BenignCorpusDatasetID, "s1", `{"lang":"ru","text_type":"plain","text":"привет","expect":"sensitive"}`)
	badType := corpusRow(t, BenignCorpusDatasetID, "s1", `{"lang":"ru","text_type":"xml","text":"<a/>","expect":"benign"}`)
	emptyText := corpusRow(t, BenignCorpusDatasetID, "s1", `{"lang":"ru","text_type":"plain","text":"   ","expect":"benign"}`)
	badJSONText := corpusRow(t, BenignCorpusDatasetID, "s1", `{"lang":"en","text_type":"json","text":"{not json","expect":"benign"}`)
	unknownField := corpusRow(t, BenignCorpusDatasetID, "s1", `{"lang":"ru","text_type":"plain","text":"привет","expect":"benign","note":"extra"}`)
	trailing := corpusRow(t, BenignCorpusDatasetID, "s1", `{"lang":"ru","text_type":"plain","text":"привет","expect":"benign"}}`)
	wrongDataset := corpusRow(t, "some-other-dataset", "s1", `{"lang":"ru","text_type":"plain","text":"привет","expect":"benign"}`)
	malformedTransfer := "not-json-at-all\n"
	empty := ""

	oversized := corpusRow(t, BenignCorpusDatasetID, "s1", `{"lang":"ru","text_type":"code","text":"`+strings.Repeat("x", maxCorpusBytes+16)+`","expect":"benign"}`)

	cases := []struct {
		name string
		in   string
	}{
		{"wrong dataset id", wrongDataset},
		{"malformed transfer row", malformedTransfer},
		{"empty input", empty},
		{"lang outside ru/en", badLang},
		{"non-benign expectation", badExpect},
		{"text type outside closed set", badType},
		{"whitespace-only text", emptyText},
		{"json-typed text not valid json", badJSONText},
		{"unknown payload field", unknownField},
		{"trailing data after payload", trailing},
		{"corpus over 8 MiB", oversized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			samples, _, err := LoadBenignCorpus(strings.NewReader(tc.in))
			if err == nil {
				t.Fatalf("corpus accepted, want ErrCorpusInvalid refusal")
			}
			if !errors.Is(err, ErrCorpusInvalid) {
				t.Fatalf("error %v does not wrap ErrCorpusInvalid", err)
			}
			if samples != nil {
				t.Fatalf("refusal returned a partial corpus (len %d), want nil", len(samples))
			}
		})
	}

	t.Run("nil reader", func(t *testing.T) {
		if _, _, err := LoadBenignCorpus(nil); !errors.Is(err, ErrCorpusInvalid) {
			t.Fatalf("nil reader: error %v does not wrap ErrCorpusInvalid", err)
		}
	})
}
