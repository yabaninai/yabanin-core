package dataclass

// E04-P01-W04-C01 battery: the confidence rules — max combining,
// inclusive threshold comparison, threshold application over a result,
// and the cross-check that the builtin fold follows the same combining
// rule as CombineLabelConfidence.

import (
	"math"
	"reflect"
	"testing"
)

func TestCombineLabelConfidenceIsMax(t *testing.T) {
	cases := []struct {
		name  string
		in    []float64
		want  float64
		isNaN bool
	}{
		{"empty folds to zero", nil, 0, false},
		{"single value", []float64{0.6}, 0.6, false},
		{"max of many", []float64{0.6, 1, 0.8, 0.9}, 1, false},
		{"duplicates do not amplify", []float64{0.6, 0.6, 0.6}, 0.6, false},
		{"weak hits never manufacture a pass", []float64{0.6, 0.6, 0.8}, 0.8, false},
		{"sub-zero confidences fold to zero floor", []float64{-1, -2}, 0, false},
		{"nan propagates fail-closed", []float64{0.9, math.NaN()}, 0, true},
	}
	for _, tc := range cases {
		got := CombineLabelConfidence(tc.in)
		if tc.isNaN {
			if !math.IsNaN(got) {
				t.Fatalf("%s: want NaN, got %v", tc.name, got)
			}
			continue
		}
		if got != tc.want {
			t.Fatalf("%s: want %v, got %v", tc.name, tc.want, got)
		}
	}
}

func TestLabelPassesThresholdInclusiveAtBoundary(t *testing.T) {
	cases := []struct {
		name       string
		confidence float64
		min        float64
		want       bool
	}{
		{"exactly at threshold passes", DefaultMinConfidence, DefaultMinConfidence, true},
		{"just below refuses", 0.8999999, 0.9, false},
		{"above passes", 1, 0.9, true},
		{"zero threshold admits zero", 0, 0, true},
		{"format-only INN fails the default", 0.6, DefaultMinConfidence, false},
		{"phone/email format fails the default", 0.8, DefaultMinConfidence, false},
		{"nan passes no threshold", math.NaN(), 0, false},
		{"nan passes no threshold even at negative min", math.NaN(), -1, false},
	}
	for _, tc := range cases {
		if got := LabelPassesThreshold(tc.confidence, tc.min); got != tc.want {
			t.Fatalf("%s: want %v, got %v", tc.name, tc.want, got)
		}
	}
}

func thresholdFixtureResult() ClassifyResult {
	return ClassifyResult{
		Labels: []ClassifiedLabel{
			{Key: "pii.email", Confidence: 0.8, SpanCount: 1},
			{Key: "pii.innsnils", Confidence: 1, SpanCount: 1},
			{Key: "pii.phone", Confidence: 0.8, SpanCount: 1},
			{Key: "pii.ru_passport", Confidence: 0.9, SpanCount: 1},
		},
		Spans: []Span{
			{Label: "pii.email", Start: 0, End: 16, Confidence: 0.8},
			{Label: "pii.innsnils", Start: 20, End: 30, Confidence: 1},
			{Label: "pii.phone", Start: 40, End: 55, Confidence: 0.8},
			{Label: "pii.ru_passport", Start: 60, End: 72, Confidence: 0.9},
		},
	}
}

func TestApplyThresholdDefault(t *testing.T) {
	got := ApplyThreshold(thresholdFixtureResult(), nil)
	want := ClassifyResult{
		Labels: []ClassifiedLabel{
			{Key: "pii.innsnils", Confidence: 1, SpanCount: 1},
			{Key: "pii.ru_passport", Confidence: 0.9, SpanCount: 1},
		},
		Spans: []Span{
			{Label: "pii.innsnils", Start: 20, End: 30, Confidence: 1},
			{Label: "pii.ru_passport", Start: 60, End: 72, Confidence: 0.9},
		},
		Unknown: false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default threshold keeps >=0.9 and drops the rest:\nwant %+v\ngot  %+v", want, got)
	}
}

func TestApplyThresholdDropsSpansOfDroppedLabels(t *testing.T) {
	got := ApplyThreshold(thresholdFixtureResult(), nil)
	for _, s := range got.Spans {
		if s.Label == "pii.email" || s.Label == "pii.phone" {
			t.Fatalf("span of a dropped label survived: %+v", s)
		}
	}
	if len(got.Spans) != 2 {
		t.Fatalf("spans must filter with their labels, got %+v", got.Spans)
	}
}

func TestApplyThresholdPerLabelOverride(t *testing.T) {
	minFor := func(label string) float64 {
		if label == "pii.email" {
			return 0.8 // inclusive: the 0.8 email evidence passes
		}
		return DefaultMinConfidence
	}
	got := ApplyThreshold(thresholdFixtureResult(), minFor)
	if len(got.Labels) != 3 || got.Labels[0].Key != "pii.email" {
		t.Fatalf("email override must admit the email label: %+v", got.Labels)
	}
}

func TestApplyThresholdAllDroppedIsExplicitUnknown(t *testing.T) {
	// Only sub-threshold evidence: the verdict is Unknown, expressed as
	// empty non-nil slices — never an empty "known nothing" success.
	got := ApplyThreshold(ClassifyResult{
		Labels:  []ClassifiedLabel{{Key: "pii.phone", Confidence: 0.8, SpanCount: 1}},
		Spans:   []Span{{Label: "pii.phone", Start: 0, End: 5, Confidence: 0.8}},
		Unknown: false,
	}, nil)
	if !got.Unknown || len(got.Labels) != 0 || len(got.Spans) != 0 {
		t.Fatalf("all-dropped must re-derive Unknown, got %+v", got)
	}
	if got.Labels == nil || got.Spans == nil {
		t.Fatalf("filtered slices must stay non-nil: %+v", got)
	}
}

func TestApplyThresholdKeepsUnknownVerdict(t *testing.T) {
	got := ApplyThreshold(ClassifyResult{Labels: []ClassifiedLabel{}, Spans: []Span{}, Unknown: true}, nil)
	if !got.Unknown {
		t.Fatalf("an unknown verdict stays unknown after thresholding")
	}
}

func TestApplyThresholdDoesNotMutateInput(t *testing.T) {
	in := thresholdFixtureResult()
	_ = ApplyThreshold(in, nil)
	if !reflect.DeepEqual(in, thresholdFixtureResult()) {
		t.Fatalf("ApplyThreshold must not mutate its input")
	}
}

func TestApplyThresholdIdempotent(t *testing.T) {
	minFor := func(label string) float64 {
		if label == "pii.email" {
			return 0.8
		}
		return DefaultMinConfidence
	}
	once := ApplyThreshold(thresholdFixtureResult(), minFor)
	twice := ApplyThreshold(once, minFor)
	if !reflect.DeepEqual(once, twice) {
		t.Fatalf("thresholding must be idempotent:\n%+v\n%+v", once, twice)
	}
}

// TestBuiltinFoldFollowsCombineRule pins the promised cross-check: for
// the real classifier, every label confidence equals
// CombineLabelConfidence over that label's span confidences — builtin's
// fold (foldEvidence) and the published combining rule cannot drift.
func TestBuiltinFoldFollowsCombineRule(t *testing.T) {
	const version = 12
	b := mustBuiltin(t, builtinTaxonomy(t, version, "pii.innsnils", "pii.phone"))
	res := classify(t, b, version, TextTypePlain,
		"ИНН 7707083893, СНИЛС 112-233-445 95, тел. +7 912 345 67 89")
	if len(res.Labels) != 2 {
		t.Fatalf("expected two labels, got %+v", res.Labels)
	}
	for _, l := range res.Labels {
		spanConfidences := make([]float64, 0, l.SpanCount)
		for _, s := range res.Spans {
			if s.Label == l.Key {
				spanConfidences = append(spanConfidences, s.Confidence)
			}
		}
		if len(spanConfidences) != l.SpanCount {
			t.Fatalf("span count inconsistent for %s", l.Key)
		}
		if got := CombineLabelConfidence(spanConfidences); got != l.Confidence {
			t.Fatalf("label %s: builtin fold %v != combine rule %v", l.Key, l.Confidence, got)
		}
	}
	// and the default threshold keeps only the checksum-strong label
	filtered := ApplyThreshold(res, nil)
	if len(filtered.Labels) != 1 || filtered.Labels[0].Key != "pii.innsnils" {
		t.Fatalf("default threshold keeps only confidence-1 evidence here: %+v", filtered.Labels)
	}
}

// TestThresholdSourceConfidencesSanity documents the detector
// vocabulary the default threshold reasons about: checksum 1.0, strict
// format 0.9, contact format 0.8, INN flex format-only 0.6. If a
// detector constant ever shifts, this pin makes the change visible in
// this package's battery too.
func TestThresholdSourceConfidencesSanity(t *testing.T) {
	const version = 13
	b := mustBuiltin(t, builtinTaxonomy(t, version, "pii.innsnils", "pii.phone"))
	res := classify(t, b, version, TextTypePlain, "тел. +7 912 345 67 89")
	if len(res.Spans) != 1 || res.Spans[0].Confidence != 0.8 {
		t.Fatalf("phone format confidence must stay 0.8: %+v", res.Spans)
	}
	// INN 7707083893 is checksum-valid: 1.0.
	res = classify(t, b, version, TextTypePlain, "ИНН 7707083893")
	if len(res.Spans) != 1 || res.Spans[0].Confidence != 1 {
		t.Fatalf("checksum-confirmed INN confidence must stay 1.0: %+v", res.Spans)
	}
}
