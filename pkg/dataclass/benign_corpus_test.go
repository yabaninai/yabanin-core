// Package dataclass — benign-corpus false-positive battery
// (E04-P01-W05-C02).
//
// The battery runs the builtin classifier (the full offline detector pack
// via guardhooks.EvaluateBuiltins) over every committed benign-corpus
// sample, after the deployed default threshold, and enforces a pinned
// per-class false-positive budget from testdata/benign_budget.json:
// default 0, every vocabulary class pinned explicitly. Exceeding any
// class's budget FAILS the test naming the class and the offending
// corpus rows; the budget file pins the corpus SHA-256, so changing the
// corpus without a reviewed budget update breaks the test (the
// corpus-hash watchdog). Reports per class (total and RU/EN split) are
// logged for the W05-C03 closure record.
package dataclass

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// benignBudgetPath is the committed FP-budget file.
const benignBudgetPath = "testdata/benign_budget.json"

// benignBudget is the strict schema of benign_budget.json. Unknown fields
// are refused so the budget cannot grow unreviewed metadata.
type benignBudget struct {
	CorpusSHA256  string         `json:"corpus_sha256"`
	DefaultMaxFPs int            `json:"default_max_false_positives"`
	MaxFPs        map[string]int `json:"max_false_positives"`
}

// loadBenignBattery loads corpus + budget and enforces the cross-pins:
// budget.corpus_sha256 == corpus hash (the watchdog), and the budget's
// per-class rows cover EXACTLY the builtin vocabulary (categoryLabelKeys)
// — a new category without an explicit budget row is a refusal, and so is
// a budget row for a category that no longer exists. Missing files FAIL
// the test, never skip: both files are required evidence.
func loadBenignBattery(t *testing.T) ([]CorpusSample, benignBudget) {
	t.Helper()
	data, err := os.ReadFile("testdata/benign_ru_en.jsonl")
	if err != nil {
		t.Fatalf("committed corpus missing or unreadable (FAIL, never skip): %v", err)
	}
	samples, hash, err := LoadBenignCorpus(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("LoadBenignCorpus: %v", err)
	}
	raw, err := os.ReadFile(benignBudgetPath)
	if err != nil {
		t.Fatalf("budget file missing or unreadable (FAIL, never skip): %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var budget benignBudget
	if err := dec.Decode(&budget); err != nil {
		t.Fatalf("budget file is not valid strict JSON: %v", err)
	}
	if budget.CorpusSHA256 != hash {
		t.Fatalf("corpus-hash watchdog: budget pins %s but corpus hashes %s — update the budget in the same reviewed change as the corpus", budget.CorpusSHA256, hash)
	}
	vocab := benignVocabulary()
	for key := range budget.MaxFPs {
		if _, ok := vocab[key]; !ok {
			t.Fatalf("budget pins class %q which is not in the builtin vocabulary — remove the stale row", key)
		}
	}
	for key := range vocab {
		if _, ok := budget.MaxFPs[key]; !ok {
			t.Fatalf("builtin vocabulary class %q has no explicit budget row — an explicit decision is required for every class", key)
		}
	}
	return samples, budget
}

// benignVocabulary returns the builtin category→label vocabulary as a
// set, sorted deterministically where order matters.
func benignVocabulary() map[string]struct{} {
	out := make(map[string]struct{}, len(categoryLabelKeys))
	for _, key := range categoryLabelKeys {
		out[key] = struct{}{}
	}
	return out
}

// benignFullTaxonomy builds the maximal org taxonomy: every vocabulary
// label, version 1. The battery measures against the full vocabulary so a
// corpus hit on ANY known class is attributable.
func benignFullTaxonomy() Taxonomy {
	keys := make([]string, 0, len(categoryLabelKeys))
	for _, key := range categoryLabelKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	labels := make([]Label, 0, len(keys))
	for _, key := range keys {
		labels = append(labels, Label{Key: key})
	}
	return Taxonomy{OrgID: "benign-corpus-watchdog", Labels: labels, Version: 1}
}

// TestBenignCorpusBudgetPinsCorpusHash is the corpus-hash watchdog pin:
// the budget file must pin the exact committed corpus bytes.
func TestBenignCorpusBudgetPinsCorpusHash(t *testing.T) {
	loadBenignBattery(t)
}

// TestBenignCorpusFalsePositiveBudget is the false-positive battery
// proper. It measures the builtin classifier over the whole benign corpus
// (post-threshold, deployed default), attributes every predicted label to
// its corpus row, enforces the pinned per-class budget (default 0), and
// cross-checks the attribution loop against MeasureQuality — two
// measurement paths must agree exactly.
func TestBenignCorpusFalsePositiveBudget(t *testing.T) {
	samples, budget := loadBenignBattery(t)
	tax := benignFullTaxonomy()
	if err := tax.Validate(); err != nil {
		t.Fatalf("battery taxonomy invalid: %v", err)
	}
	classifier, err := NewBuiltinClassifier(tax)
	if err != nil {
		t.Fatalf("NewBuiltinClassifier: %v", err)
	}
	ctx := context.Background()

	// Attribution loop: every post-threshold predicted label on a benign
	// row is a false positive for its class.
	type hit struct {
		sampleID, lang string
	}
	fps := map[string][]hit{}
	for _, s := range samples {
		res, err := classifier.Classify(ctx, ClassifyRequest{Text: s.Text, TextType: s.TextType, TaxonomyVersion: tax.Version})
		if err != nil {
			t.Fatalf("sample %s refused — a benign corpus row must classify: %v", s.ID, err)
		}
		for _, label := range ApplyThreshold(res, nil).Labels {
			fps[label.Key] = append(fps[label.Key], hit{sampleID: s.ID, lang: s.Lang})
		}
	}

	// Budget enforcement with class + offending rows in the failure.
	for class, hits := range fps {
		allowed, listed := budget.MaxFPs[class]
		if !listed {
			allowed = budget.DefaultMaxFPs
		}
		if len(hits) > allowed {
			ids := make([]string, 0, len(hits))
			for _, h := range hits {
				ids = append(ids, h.sampleID+" ["+h.lang+"]")
			}
			sort.Strings(ids)
			t.Fatalf("false-positive budget exceeded for class %q: %d hits (budget %d) on rows %v", class, len(hits), allowed, ids)
		}
	}

	// Cross-check against MeasureQuality (second measurement path): with
	// ExpectedLabels nil every predicted label is a per-class FP, so the
	// report's per-class FP counts must equal the attribution loop.
	for _, scope := range []struct {
		name          string
		samplesSubset []CorpusSample
	}{
		{"total", samples},
		{"ru", filterCorpusLang(samples, LocaleRU)},
		{"en", filterCorpusLang(samples, LocaleEN)},
	} {
		fixtures := make([]QualityFixture, 0, len(scope.samplesSubset))
		for _, s := range scope.samplesSubset {
			fixtures = append(fixtures, QualityFixture{Text: s.Text, TextType: s.TextType, ExpectedLabels: nil})
		}
		report, err := MeasureQuality(ctx, classifier, tax, fixtures, nil)
		if err != nil {
			t.Fatalf("MeasureQuality(%s): %v", scope.name, err)
		}
		reportFPs := map[string]int{}
		for _, row := range report.Classes {
			if row.FP > 0 {
				reportFPs[row.Class] = row.FP
			}
			t.Logf("%s: class %s fp=%d support=%d", scope.name, row.Class, row.FP, row.Support)
		}
		if scope.name != "total" {
			continue
		}
		loopFPs := map[string]int{}
		for class, hits := range fps {
			if len(hits) > 0 {
				loopFPs[class] = len(hits)
			}
		}
		if len(reportFPs) != len(loopFPs) {
			t.Fatalf("measurement paths disagree: MeasureQuality sees %d fp-classes (%v), attribution loop %d (%v)", len(reportFPs), reportFPs, len(loopFPs), loopFPs)
		}
		for class, n := range reportFPs {
			if loopFPs[class] != n {
				t.Fatalf("class %s: MeasureQuality fp=%d, attribution loop=%d", class, n, loopFPs[class])
			}
		}
	}

	// Honest zero-row evidence for the closure record: every vocabulary
	// class is reported even when nothing fired.
	for _, class := range sortedVocabulary() {
		ru, en := 0, 0
		for _, h := range fps[class] {
			if h.lang == LocaleRU {
				ru++
			} else {
				en++
			}
		}
		t.Logf("closure table: class %s ru_fp=%d en_fp=%d total_fp=%d budget=%d", class, ru, en, ru+en, budget.MaxFPs[class])
	}
}

func filterCorpusLang(samples []CorpusSample, lang string) []CorpusSample {
	out := make([]CorpusSample, 0, len(samples))
	for _, s := range samples {
		if s.Lang == lang {
			out = append(out, s)
		}
	}
	return out
}

func sortedVocabulary() []string {
	vocab := make([]string, 0, len(categoryLabelKeys))
	for _, key := range categoryLabelKeys {
		vocab = append(vocab, key)
	}
	sort.Strings(vocab)
	return vocab
}
