package dataclass

// E04-P01-W04-C02 battery: fixture quality measurement. Pure-model
// cases run on the SPI fake (controlled TP/FP/FN without detector
// luck); the builtin case cross-checks real detector semantics under
// the default threshold; the golden JSON pin holds the serialization
// stable.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// qualityFake extends the contract fake with per-fixture overrides so a
// test can force exact predicted sets (including out-of-taxonomy
// predictions the report must still account for).
type qualityFake struct {
	tax        Taxonomy
	forced     map[string][]string // fixture text -> predicted label keys (nil = substring behavior)
	confidence map[string]float64  // predicted label key -> span confidence (default 1)
}

func (f qualityFake) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error) {
	if err := CheckClassifyRequest(ctx, req, f.tax.Version); err != nil {
		return ClassifyResult{}, err
	}
	if forced, ok := f.forced[req.Text]; ok {
		spans := make([]Span, 0, len(forced))
		for _, key := range forced {
			conf := 1.0
			if c, ok := f.confidence[key]; ok {
				conf = c
			}
			spans = append(spans, Span{Label: key, Start: 0, End: 1, Confidence: conf, Detector: "fake:forced"})
		}
		return foldEvidence(spans), nil
	}
	return contractFake{taxonomy: f.tax}.Classify(ctx, req)
}

func qualityTaxonomy(version int64, keys ...string) Taxonomy {
	tax := Taxonomy{OrgID: "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f", Version: version}
	for _, k := range keys {
		tax.Labels = append(tax.Labels, Label{Key: k})
	}
	return tax
}

func TestMeasureQualityPureTallies(t *testing.T) {
	tax := qualityTaxonomy(7, "alpha", "beta")
	fake := qualityFake{
		tax: tax,
		forced: map[string][]string{
			"one":   {"alpha"},         // TP alpha
			"two":   {"alpha", "beta"}, // TP alpha, FP beta (beta not expected)
			"three": {"alpha"},         // TP alpha, FN gamma
		},
	}
	report, err := MeasureQuality(context.Background(), fake, tax, []QualityFixture{
		{Text: "one", TextType: TextTypePlain, ExpectedLabels: []string{"alpha"}},
		{Text: "two", TextType: TextTypePlain, ExpectedLabels: []string{"alpha"}},
		{Text: "three", TextType: TextTypePlain, ExpectedLabels: []string{"alpha", "gamma"}},
	}, nil)
	if err != nil {
		t.Fatalf("MeasureQuality: %v", err)
	}
	if report.Fixtures != 3 {
		t.Fatalf("fixture count wrong: %d", report.Fixtures)
	}
	byClass := map[string]ClassQuality{}
	for _, c := range report.Classes {
		byClass[c.Class] = c
	}
	// alpha: 3 TP, 0 FP, 0 FN, support 3 — perfect.
	if q := byClass["alpha"]; q.TP != 3 || q.FP != 0 || q.FN != 0 || q.Precision != 1 || q.Recall != 1 || q.Support != 3 {
		t.Fatalf("alpha tallies wrong: %+v", q)
	}
	// beta: predicted once, never expected — FP row, support 0, honest zeros.
	if q := byClass["beta"]; q.TP != 0 || q.FP != 1 || q.FN != 0 || q.Precision != 0 || q.Recall != 0 || q.Support != 0 {
		t.Fatalf("beta tallies wrong: %+v", q)
	}
	// gamma: expected once, never predicted — FN row outside the taxonomy.
	if q := byClass["gamma"]; q.TP != 0 || q.FP != 0 || q.FN != 1 || q.Recall != 0 || q.Support != 1 {
		t.Fatalf("gamma tallies wrong: %+v", q)
	}
	// rows are sorted by class
	for i := 1; i < len(report.Classes); i++ {
		if report.Classes[i-1].Class >= report.Classes[i].Class {
			t.Fatalf("classes must sort by class: %+v", report.Classes)
		}
	}
}

func TestMeasureQualityTaxonomyLabelsGetHonestZeroRows(t *testing.T) {
	tax := qualityTaxonomy(7, "alpha", "beta", "delta")
	fake := qualityFake{tax: tax, forced: map[string][]string{"x": {"alpha"}}}
	report, err := MeasureQuality(context.Background(), fake, tax, []QualityFixture{
		{Text: "x", TextType: TextTypePlain, ExpectedLabels: []string{"alpha"}},
	}, nil)
	if err != nil {
		t.Fatalf("MeasureQuality: %v", err)
	}
	if len(report.Classes) != 3 {
		t.Fatalf("every taxonomy label needs a row even at zero: %+v", report.Classes)
	}
	for _, q := range report.Classes {
		if q.Class == "beta" || q.Class == "delta" {
			if q.TP != 0 || q.FP != 0 || q.FN != 0 || q.Support != 0 {
				t.Fatalf("untouched label must be an honest zero row: %+v", q)
			}
		}
	}
}

func TestMeasureQualityMeasuresPostThresholdDecisions(t *testing.T) {
	// "alpha" is predicted with 0.6 confidence: below the default
	// threshold it is NOT a prediction — the measurement sees the
	// deployed decision, so the expected alpha becomes a false negative.
	tax := qualityTaxonomy(7, "alpha")
	fake := qualityFake{
		tax:        tax,
		forced:     map[string][]string{"x": {"alpha"}},
		confidence: map[string]float64{"alpha": 0.6},
	}
	fixtures := []QualityFixture{{Text: "x", TextType: TextTypePlain, ExpectedLabels: []string{"alpha"}}}

	defaultReport, err := MeasureQuality(context.Background(), fake, tax, fixtures, nil)
	if err != nil {
		t.Fatalf("MeasureQuality default: %v", err)
	}
	if q := defaultReport.Classes[0]; q.TP != 0 || q.FN != 1 {
		t.Fatalf("sub-threshold prediction must not count, got %+v", q)
	}

	override := func(string) float64 { return 0.5 }
	overridden, err := MeasureQuality(context.Background(), fake, tax, fixtures, override)
	if err != nil {
		t.Fatalf("MeasureQuality override: %v", err)
	}
	if q := overridden.Classes[0]; q.TP != 1 || q.FN != 0 || q.Precision != 1 || q.Recall != 1 {
		t.Fatalf("admitting 0.6 under a 0.5 override must count, got %+v", q)
	}
}

func TestMeasureQualityRefusedFixtureFailsWholeMeasurement(t *testing.T) {
	tax := qualityTaxonomy(7, "alpha")
	fake := qualityFake{tax: tax, forced: map[string][]string{"ok": {"alpha"}}}
	_, err := MeasureQuality(context.Background(), fake, tax, []QualityFixture{
		{Text: "ok", TextType: TextTypePlain, ExpectedLabels: []string{"alpha"}},
		{Text: "bad", TextType: "xml", ExpectedLabels: nil}, // fixture 1 refuses
	}, nil)
	if err == nil {
		t.Fatalf("a refused fixture must fail the whole measurement")
	}
	if !strings.Contains(err.Error(), "fixture 1") {
		t.Fatalf("error must name the fixture index, got: %v", err)
	}
}

func TestMeasureQualityRefusals(t *testing.T) {
	tax := qualityTaxonomy(7, "alpha")
	fake := qualityFake{tax: tax}
	if _, err := MeasureQuality(context.Background(), fake, tax, nil, nil); err != ErrNoQualityFixtures {
		t.Fatalf("empty fixture set must refuse with ErrNoQualityFixtures, got %v", err)
	}
	invalid := qualityTaxonomy(7, "Not-Canonical")
	if _, err := MeasureQuality(context.Background(), fake, invalid, []QualityFixture{{Text: "x", TextType: TextTypePlain}}, nil); err == nil {
		t.Fatalf("invalid taxonomy must refuse")
	}
}

func TestMeasureQualityGoldenJSON(t *testing.T) {
	tax := qualityTaxonomy(7, "alpha", "beta")
	fake := qualityFake{tax: tax, forced: map[string][]string{
		"one": {"alpha", "beta"},
		"two": {"beta"},
	}}
	report, err := MeasureQuality(context.Background(), fake, tax, []QualityFixture{
		{Text: "one", TextType: TextTypePlain, ExpectedLabels: []string{"alpha"}},
		{Text: "two", TextType: TextTypePlain, ExpectedLabels: []string{"alpha", "beta"}},
	}, nil)
	if err != nil {
		t.Fatalf("MeasureQuality: %v", err)
	}
	got, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	golden := `{"fixtures":2,"classes":[` +
		`{"class":"alpha","tp":1,"fp":0,"fn":1,"precision":1,"recall":0.5,"support":2},` +
		`{"class":"beta","tp":1,"fp":1,"fn":0,"precision":0.5,"recall":1,"support":1}]}`
	if string(got) != golden {
		t.Fatalf("golden JSON drifted:\nwant %s\ngot  %s", golden, got)
	}
}

func TestMeasureQualityBuiltinCrossCheck(t *testing.T) {
	const version = 21
	tax := builtinTaxonomy(t, version, "pii.innsnils", "pii.phone", "pii.pan")
	b := mustBuiltin(t, tax)
	report, err := MeasureQuality(context.Background(), b, tax, []QualityFixture{
		// checksum-valid INN: predicted (1.0 >= 0.9) and expected — TP.
		{Text: "ИНН 7707083893", TextType: TextTypePlain, ExpectedLabels: []string{"pii.innsnils"}},
		// phone-only text under the DEFAULT threshold predicts nothing:
		// 0.8 evidence is format confidence, not a label. The expected
		// innsnils is a false negative; phone stays a zero row.
		{Text: "тел. +7 912 345 67 89", TextType: TextTypePlain, ExpectedLabels: []string{"pii.innsnils"}},
		// Luhn-valid PAN: TP.
		{Text: "card 4111111111111111", TextType: TextTypePlain, ExpectedLabels: []string{"pii.pan"}},
	}, nil)
	if err != nil {
		t.Fatalf("MeasureQuality: %v", err)
	}
	byClass := map[string]ClassQuality{}
	for _, c := range report.Classes {
		byClass[c.Class] = c
	}
	if q := byClass["pii.innsnils"]; q.TP != 1 || q.FN != 1 || q.Recall != 0.5 || q.Support != 2 {
		t.Fatalf("innsnils cross-check wrong: %+v", q)
	}
	if q := byClass["pii.pan"]; q.TP != 1 || q.Precision != 1 || q.Recall != 1 {
		t.Fatalf("pan cross-check wrong: %+v", q)
	}
	if q := byClass["pii.phone"]; q.TP != 0 || q.FP != 0 || q.Support != 0 {
		t.Fatalf("phone must be an honest zero row under the default threshold: %+v", q)
	}
}
