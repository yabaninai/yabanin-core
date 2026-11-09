package dataclass

// E04-P01-W03-C02 battery: the builtin classifier over the guardhooks
// public evaluator. Fixtures carry checksum-valid identifiers only
// (INN 7707083893, SNILS 112-233-445 95 — key 95 under the 9..1
// weights, PAN 4111111111111111 — Luhn), so the pinned confidences are
// detector semantics, not fixture luck.

import (
	"context"
	"reflect"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

func builtinTaxonomy(t *testing.T, version int64, keys ...string) Taxonomy {
	t.Helper()
	tax := Taxonomy{OrgID: "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f", Version: version}
	for _, k := range keys {
		tax.Labels = append(tax.Labels, Label{Key: k})
	}
	if err := tax.Validate(); err != nil {
		t.Fatalf("fixture taxonomy invalid: %v", err)
	}
	return tax
}

func mustBuiltin(t *testing.T, tax Taxonomy) *BuiltinClassifier {
	t.Helper()
	b, err := NewBuiltinClassifier(tax)
	if err != nil {
		t.Fatalf("NewBuiltinClassifier: %v", err)
	}
	return b
}

func classify(t *testing.T, cl Classifier, version int64, textType SupportedTextType, text string) ClassifyResult {
	t.Helper()
	res, err := cl.Classify(context.Background(), ClassifyRequest{
		Text: text, TextType: textType, TaxonomyVersion: version,
	})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	return res
}

func TestBuiltinContractSuite(t *testing.T) {
	// The contract taxonomy (alpha/beta) maps no detector category, so
	// the suite's no-evidence fixture exercises the Unknown path through
	// the real evaluator.
	runClassifierContractSuite(t, mustBuiltin(t, contractTaxonomy()), 7)
}

func TestBuiltinINNAndSNILS(t *testing.T) {
	const version = 12
	b := mustBuiltin(t, builtinTaxonomy(t, version, "pii.innsnils"))
	res := classify(t, b, version, TextTypePlain,
		"ИНН 7707083893, СНИЛС 112-233-445 95")

	if res.Unknown || len(res.Labels) != 1 {
		t.Fatalf("expected the single opted-in label, got %+v", res)
	}
	l := res.Labels[0]
	if l.Key != "pii.innsnils" || l.SpanCount != 2 || l.Confidence != 1 {
		t.Fatalf("aggregate wrong: %+v", l)
	}
	if len(res.Spans) != 2 {
		t.Fatalf("INN fires once (ru:inn/ru:inn10 overlap reduced) and SNILS fires once (ru:snils/ru:snils-flex overlap reduced): %+v", res.Spans)
	}
	for _, s := range res.Spans {
		if s.Label != "pii.innsnils" || s.Category != string(guardhooks.CatINNSNILS) {
			t.Fatalf("span mapping wrong: %+v", s)
		}
		if s.Locale != "ru" || s.Confidence != 1 {
			t.Fatalf("checksum-valid RU identifiers are confidence 1 with locale ru: %+v", s)
		}
	}
	if res.Spans[0].Start >= res.Spans[1].Start {
		t.Fatalf("spans must be sorted by Start: %+v", res.Spans)
	}
}

func TestBuiltinPAN(t *testing.T) {
	const version = 3
	b := mustBuiltin(t, builtinTaxonomy(t, version, "pii.pan"))
	res := classify(t, b, version, TextTypePlain, "card 4111111111111111 end")
	if res.Unknown || len(res.Labels) != 1 || res.Labels[0].Key != "pii.pan" {
		t.Fatalf("expected pii.pan, got %+v", res)
	}
	if res.Labels[0].Confidence != 1 || len(res.Spans) != 1 {
		t.Fatalf("Luhn-valid PAN is one confidence-1 span: %+v", res)
	}
	s := res.Spans[0]
	if s.Locale != "" || s.Category != string(guardhooks.CatPAN) || s.Detector != "luhn:pan" {
		t.Fatalf("span passthrough wrong: %+v", s)
	}
}

func TestBuiltinCredentialKey(t *testing.T) {
	const version = 4
	b := mustBuiltin(t, builtinTaxonomy(t, version, "secrets.credential_keys"))
	res := classify(t, b, version, TextTypeJSON, `{"api_key":"abcdefgh12345678"}`)
	if res.Unknown || len(res.Labels) != 1 || res.Labels[0].Key != "secrets.credential_keys" {
		t.Fatalf("expected secrets.credential_keys, got %+v", res)
	}
	if res.Labels[0].Confidence != 1 || len(res.Spans) != 1 {
		t.Fatalf("credential-key rule is one confidence-1 span: %+v", res)
	}
	if s := res.Spans[0]; s.Detector != "credential:key-value" || s.Locale != "" {
		t.Fatalf("span passthrough wrong: %+v", s)
	}
}

func TestBuiltinCategoryIsOptIn(t *testing.T) {
	const version = 5
	// The taxonomy declares only PAN; the INN/SNILS evidence is not
	// reported — classification happens INTO the taxonomy, not past it.
	b := mustBuiltin(t, builtinTaxonomy(t, version, "pii.pan"))
	res := classify(t, b, version, TextTypePlain, "СНИЛС 112-233-445 95; карта 4111111111111111")
	if res.Unknown || len(res.Labels) != 1 || res.Labels[0].Key != "pii.pan" {
		t.Fatalf("only the opted-in category may label: %+v", res)
	}
	for _, s := range res.Spans {
		if s.Label != "pii.pan" {
			t.Fatalf("unopted evidence leaked into the result: %+v", s)
		}
	}
}

func TestBuiltinPhoneEmailReportedAtDetectorConfidence(t *testing.T) {
	// Phone/email carry format confidence 0.8 — the classifier reports
	// the detector's confidence verbatim; thresholding is a separate,
	// later concern (confidence.go / thresholds.go), not the classifier's.
	const version = 6
	b := mustBuiltin(t, builtinTaxonomy(t, version, "pii.phone", "pii.email"))
	res := classify(t, b, version, TextTypePlain, "тел. +7 912 345 67 89, почта user@example.com")
	if res.Unknown || len(res.Labels) != 2 {
		t.Fatalf("expected phone and email labels, got %+v", res)
	}
	if l := res.Labels[0]; l.Key != "pii.email" || l.Confidence != 0.8 {
		t.Fatalf("email format confidence 0.8: %+v", l)
	}
	if l := res.Labels[1]; l.Key != "pii.phone" || l.Confidence != 0.8 {
		t.Fatalf("phone format confidence 0.8: %+v", l)
	}
	for _, s := range res.Spans {
		if s.Confidence != 0.8 {
			t.Fatalf("detector confidence must pass through unmodified: %+v", s)
		}
	}
}

func TestBuiltinDeterministicAcrossInstances(t *testing.T) {
	const version = 8
	tax := builtinTaxonomy(t, version, "pii.innsnils", "secrets.credential_keys")
	req := ClassifyRequest{
		Text:            `ИНН 7707083893 {"api_key":"abcdefgh12345678"}`,
		TextType:        TextTypePlain,
		TaxonomyVersion: version,
	}
	first := mustBuiltin(t, tax)
	second := mustBuiltin(t, tax) // a second binding of the same taxonomy
	a, err := first.Classify(context.Background(), req)
	if err != nil {
		t.Fatalf("first classify: %v", err)
	}
	b, err := second.Classify(context.Background(), req)
	if err != nil {
		t.Fatalf("second classify: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("same bound taxonomy must yield identical results:\n%#v\n%#v", a, b)
	}
	if a.Unknown || len(a.Labels) != 2 {
		t.Fatalf("expected both labels, got %+v", a)
	}
	ruSpan, credSpan := a.Spans[0], a.Spans[1]
	if ruSpan.Locale != "ru" || credSpan.Locale != "" {
		t.Fatalf("locale passthrough: RU identifier ru, credential-key rule empty: %+v", a.Spans)
	}
}

func TestBuiltinInvalidTaxonomyRefused(t *testing.T) {
	if _, err := NewBuiltinClassifier(Taxonomy{OrgID: "", Version: 1, Labels: []Label{{Key: "pii.pan"}}}); err == nil {
		t.Fatalf("invalid taxonomy must be refused, never silently repaired")
	}
	if _, err := NewBuiltinClassifier(Taxonomy{OrgID: "org", Version: 1, Labels: []Label{{Key: "PII.PAN"}}}); err == nil {
		t.Fatalf("non-canonical label key must be refused")
	}
}

func TestNormalizeFindings(t *testing.T) {
	// Overlapping findings of one category reduce to the earlier span;
	// overlapping findings of different categories both stay.
	in := []guardhooks.Finding{
		{Category: guardhooks.CatINNSNILS, Start: 10, End: 21, Confidence: 1, Detector: "ru:snils-flex"},
		{Category: guardhooks.CatPAN, Start: 5, End: 21, Confidence: 1, Detector: "luhn:pan"},
		{Category: guardhooks.CatINNSNILS, Start: 10, End: 21, Confidence: 1, Detector: "ru:snils"},
	}
	got := normalizeFindings(in)
	if len(got) != 2 {
		t.Fatalf("same-category overlap must reduce, cross-category must stay: %+v", got)
	}
	if got[0].Start != 5 || got[0].Category != guardhooks.CatPAN {
		t.Fatalf("sorted order wrong: %+v", got)
	}
	if got[1].Start != 10 || got[1].Detector != "ru:snils" {
		t.Fatalf("same-category overlap keeps the first by (Start,End,Detector): %+v", got)
	}
}
