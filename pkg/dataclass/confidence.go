// Package dataclass — confidence combining and thresholds
// (E04-P01-W04-C01).
//
// The evidence vocabulary is the guardhooks detector vocabulary, fixed
// per detector version (finding.go: checksum-confirmed findings are
// confidence 1.0, strict-format matches 0.9; the RU flex detectors emit
// 0.9 for word-gated passport and SNILS format, 0.8 for phone/email
// format, 0.6 for INN/SNILS format-only). One combining rule and one
// comparison rule are pinned here, and the default classification
// threshold sits at 0.9: format-only identifiers (0.6) and contact
// shapes (0.8) never label on their own — classification demands the
// stronger signal, exactly as Scan's threshold keeps regex recall out of
// verdicts.
package dataclass

import "math"

// DefaultMinConfidence is the default per-label minimum confidence: a
// label needs at least this confidence to survive ApplyThreshold
// unless the org overrides its key (thresholds.go).
const DefaultMinConfidence = 0.9

// CombineLabelConfidence folds the confidences of one label's evidence
// spans into the label confidence. The rule is fixed: the strongest
// supporting finding — max, not a weighted blend. A weaker second hit
// never dilutes a strong one, and two weak hits never manufacture a
// pass. (The aggregation inside builtin's fold uses the same rule;
// confidence_test.go pins the two agree.) An empty input folds to 0; a
// NaN input propagates to NaN, which no threshold ever passes — garbage
// confidence fails closed.
func CombineLabelConfidence(confidences []float64) float64 {
	best := 0.0
	for _, c := range confidences {
		if math.IsNaN(c) {
			return math.NaN()
		}
		if c > best {
			best = c
		}
	}
	return best
}

// LabelPassesThreshold reports whether a label confidence clears a
// minimum. The comparison is inclusive at the boundary: exactly-at-
// threshold evidence passes (an override of 0.9 admits a 0.9 finding).
// NaN confidence passes no threshold.
func LabelPassesThreshold(confidence, minConfidence float64) bool {
	return confidence >= minConfidence
}

// ApplyThreshold filters a classify result to the labels whose
// confidence clears their per-key minimum: dropped labels' spans are
// dropped with them, the surviving spans keep their canonical order,
// and Unknown is re-derived (a result whose every label was dropped is
// the explicit unknown verdict — an empty success is never returned as
// a "known nothing" answer). minFor maps a label key to its minimum;
// a nil minFor uses DefaultMinConfidence for every key. The input is
// not mutated; slices in the result are always non-nil.
func ApplyThreshold(res ClassifyResult, minFor func(label string) float64) ClassifyResult {
	if minFor == nil {
		minFor = func(string) float64 { return DefaultMinConfidence }
	}
	kept := make([]ClassifiedLabel, 0, len(res.Labels))
	for _, l := range res.Labels {
		if LabelPassesThreshold(l.Confidence, minFor(l.Key)) {
			kept = append(kept, l)
		}
	}
	surviving := make([]Span, 0, len(res.Spans))
	for _, s := range res.Spans {
		for _, l := range kept {
			if s.Label == l.Key {
				surviving = append(surviving, s)
				break
			}
		}
	}
	if len(kept) == 0 {
		kept = []ClassifiedLabel{}
	}
	if len(surviving) == 0 {
		surviving = []Span{}
	}
	return ClassifyResult{Labels: kept, Spans: surviving, Unknown: len(kept) == 0}
}
