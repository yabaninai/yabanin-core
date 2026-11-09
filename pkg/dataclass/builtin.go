// Package dataclass — the offline builtin classifier (E04-P01-W03-C02).
//
// BuiltinClassifier is the local, zero-transport implementation of the
// SPI: guardhooks detectors are the evidence source, the org taxonomy
// decides which categories become labels. The scan runs through the
// public guardhooks evaluator (EvaluateBuiltins), which wraps exactly
// DefaultDetectors() plus the credential-key rule (credkeys) in one
// versioned envelope — the dispatch's FindAll/DefaultDetectors/credkeys
// anchors — so the classifier and the gateway share ONE detector source
// of truth. guardhooks is consumed through its public API only; no
// guardhooks file is edited from here (dispatch fence E08-P01).
//
// The label vocabulary is opt-in: a guardhooks category fires as a
// label only when the bound taxonomy declares the category's canonical
// key (categoryLabelKeys below). An org that omits "pii.pan" simply
// never gets PAN labels — the evidence is not reported either, because
// the classifier classifies INTO the taxonomy, not past it.
package dataclass

import (
	"context"
	"fmt"
	"sort"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

// categoryLabelKeys maps a guardhooks category to the canonical taxonomy
// label key that carries it. The keys are a fixed, closed vocabulary —
// the bridge between detector categories and org taxonomies. CatPhone
// and CatEmail are included because the RU detectors emit them (format
// confidence 0.8, below the classification default threshold — see
// confidence.go); CatDetectorFailure is excluded: it is an audit marker
// for failed extensions, never classification evidence, and the
// evaluator surfaces extension failures as errors instead.
var categoryLabelKeys = map[guardhooks.Category]string{
	guardhooks.CatINNSNILS:   "pii.innsnils",
	guardhooks.CatPAN:        "pii.pan",
	guardhooks.CatRUPassport: "pii.ru_passport",
	guardhooks.CatOGRN:       "pii.ogrn",
	guardhooks.CatPhone:      "pii.phone",
	guardhooks.CatEmail:      "pii.email",
	guardhooks.CatBR:         "pii.br",
	guardhooks.CatIN:         "pii.in",
	guardhooks.CatMY:         "pii.my",
	guardhooks.CatAE:         "pii.ae",
	guardhooks.CatZA:         "pii.za",
	guardhooks.CatNG:         "pii.ng",
	guardhooks.CatKE:         "pii.ke",
	guardhooks.CatEG:         "pii.eg",
	guardhooks.CatSecret:     "secrets.material",
	guardhooks.CatCredential: "secrets.credential_keys",
	guardhooks.CatInjection:  "injection.prompts",
}

// BuiltinClassifier is the offline Classifier over one bound org
// taxonomy. Construction validates and canonicalizes the taxonomy; the
// bound Version is the pin every ClassifyRequest.TaxonomyVersion must
// match. Classify is deterministic: same bound taxonomy plus same
// request yields a bit-identical result (pinned by the shared SPI
// contract suite and the dedicated batteries below).
type BuiltinClassifier struct {
	taxonomy Taxonomy
	labels   map[guardhooks.Category]string // categories the taxonomy opted into
}

// NewBuiltinClassifier binds a classifier to one taxonomy. The taxonomy
// must be valid (Taxonomy.Validate) — an invalid taxonomy is refused,
// never silently repaired.
func NewBuiltinClassifier(tax Taxonomy) (*BuiltinClassifier, error) {
	if err := tax.Validate(); err != nil {
		return nil, err
	}
	tax = tax.Canonical()
	declared := make(map[string]bool, len(tax.Labels))
	for _, l := range tax.Labels {
		declared[l.Key] = true
	}
	labels := make(map[guardhooks.Category]string, len(categoryLabelKeys))
	for cat, key := range categoryLabelKeys {
		if declared[key] {
			labels[cat] = key
		}
	}
	return &BuiltinClassifier{taxonomy: tax, labels: labels}, nil
}

// TaxonomyVersion returns the bound taxonomy's version pin.
func (b *BuiltinClassifier) TaxonomyVersion() int64 { return b.taxonomy.Version }

// Classify scans the payload through the guardhooks builtin evaluator
// and folds the findings into taxonomy labels. The Finding locale is
// passed through to the spans verbatim (the national detector origin:
// "ru" for the RU PII detectors, "" for locale-less ones). Context
// carries cancellation only: the evaluator checks ctx between detectors
// and a cancellation refuses mid-scan instead of returning half a
// verdict.
func (b *BuiltinClassifier) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error) {
	if err := CheckClassifyRequest(ctx, req, b.taxonomy.Version); err != nil {
		return ClassifyResult{}, err
	}
	evaluation, err := guardhooks.EvaluateBuiltins(guardhooks.Invocation{
		Context: ctx,
		Version: guardhooks.RuntimeVersion,
		Phase:   guardhooks.PhaseBefore,
		Kind:    guardhooks.ContentText,
		Text:    req.Text,
	})
	if err != nil {
		return ClassifyResult{}, fmt.Errorf("dataclass: builtin detector scan: %w", err)
	}
	findings := normalizeFindings(evaluation.Findings)
	spans := make([]Span, 0, len(findings))
	for _, f := range findings {
		label, ok := b.labels[f.Category]
		if !ok {
			continue // the taxonomy did not opt into this category
		}
		spans = append(spans, Span{
			Label:      label,
			Category:   string(f.Category),
			Start:      f.Start,
			End:        f.End,
			Confidence: f.Confidence,
			Locale:     f.Locale,
			Detector:   f.Detector,
		})
	}
	return foldEvidence(spans), nil
}

// normalizeFindings orders findings the FindAll way (Start, End,
// Detector) and reduces overlapping findings of one category to the
// earlier span — the guardhooks FindAll presentation convention,
// restored locally because the versioned evaluator emits per-detector
// findings in detector-identity order. Deterministic for any input.
func normalizeFindings(findings []guardhooks.Finding) []guardhooks.Finding {
	sorted := append([]guardhooks.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End < b.End
		}
		return a.Detector < b.Detector
	})
	kept := make([]guardhooks.Finding, 0, len(sorted))
	lastEnd := make(map[guardhooks.Category]int, len(sorted))
	seen := make(map[guardhooks.Category]bool, len(sorted))
	for _, f := range sorted {
		if seen[f.Category] && f.Start < lastEnd[f.Category] {
			continue
		}
		kept = append(kept, f)
		if !seen[f.Category] || f.End > lastEnd[f.Category] {
			lastEnd[f.Category] = f.End
		}
		seen[f.Category] = true
	}
	return kept
}

// foldEvidence folds evidence spans into the canonical result shape
// documented on ClassifyResult: spans canonically sorted, labels
// aggregated by key with the strongest-finding confidence (the
// combining rule confidence.go fixes), slices never nil, Unknown = no
// label evidenced. (spi_test.go's newClassifyResult mirrors this fold
// for the fake; confidence_test.go pins the two agree.)
func foldEvidence(spans []Span) ClassifyResult {
	sortSpans(spans)
	byKey := make(map[string]*ClassifiedLabel, len(spans))
	keys := make([]string, 0, len(spans))
	for _, s := range spans {
		if _, ok := byKey[s.Label]; !ok {
			byKey[s.Label] = &ClassifiedLabel{Key: s.Label}
			keys = append(keys, s.Label)
		}
		l := byKey[s.Label]
		l.SpanCount++
		if s.Confidence > l.Confidence {
			l.Confidence = s.Confidence
		}
	}
	sortLabelKeys(keys)
	labels := make([]ClassifiedLabel, 0, len(keys))
	for _, k := range keys {
		labels = append(labels, *byKey[k])
	}
	if spans == nil {
		spans = []Span{}
	}
	return ClassifyResult{Labels: labels, Spans: spans, Unknown: len(labels) == 0}
}
