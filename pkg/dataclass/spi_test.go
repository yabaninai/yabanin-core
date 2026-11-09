package dataclass

// E04-P01-W03-C01 battery: the classify SPI contract, exercised through
// a deterministic fake (the card's "fake-impl тесты контракта"). The
// suite is a helper, not a copy: builtin_test.go runs the same suite
// against the real classifier, so the contract has exactly one
// definition and two witnesses.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// contractFake is the SPI contract double: a pure, deterministic
// classifier with no I/O, no clock and no randomness. Its fixed rule:
// a taxonomy label is evidenced by one span per occurrence of the label
// key as a substring of the text (confidence 1.0), the way a downstream
// judge would map fixed vocabularies onto spans.
type contractFake struct {
	taxonomy Taxonomy
}

func (f contractFake) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error) {
	if err := CheckClassifyRequest(ctx, req, f.taxonomy.Version); err != nil {
		return ClassifyResult{}, err
	}
	var spans []Span
	for _, l := range f.taxonomy.Labels {
		idx := 0
		for {
			at := strings.Index(req.Text[idx:], l.Key)
			if at < 0 {
				break
			}
			start := idx + at
			spans = append(spans, Span{
				Label:      l.Key,
				Category:   "fake:vocabulary",
				Start:      start,
				End:        start + len(l.Key),
				Confidence: 1,
				Detector:   "fake:substring",
			})
			idx = start + len(l.Key)
		}
	}
	return newClassifyResult(spans), nil
}

// newClassifyResult folds spans into the canonical result shape:
// spans sorted by (Start, End, Label, Category, Detector), labels
// aggregated by key (confidence = max, the confidence.go rule) and
// sorted by key, slices never nil, Unknown = no label evidenced.
func newClassifyResult(spans []Span) ClassifyResult {
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

// runClassifierContractSuite asserts the SPI contract on any
// deterministic implementation bound to a taxonomy whose Version is
// version. It is the single contract definition shared by the fake
// (spi_test.go) and the builtin classifier (builtin_test.go).
func runClassifierContractSuite(t *testing.T, subject Classifier, version int64) {
	t.Helper()

	valid := ClassifyRequest{
		Text:            "plain prose mentioning nothing labelable",
		TextType:        TextTypePlain,
		TaxonomyVersion: version,
	}

	t.Run("deterministic_bit_for_bit", func(t *testing.T) {
		first, err := subject.Classify(context.Background(), valid)
		if err != nil {
			t.Fatalf("valid request refused: %v", err)
		}
		second, err := subject.Classify(context.Background(), valid)
		if err != nil {
			t.Fatalf("identical valid request refused: %v", err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("same input must yield bit-identical results:\nfirst:  %#v\nsecond: %#v", first, second)
		}
		a, _ := json.Marshal(first)
		b, _ := json.Marshal(second)
		if string(a) != string(b) {
			t.Fatalf("same input must yield identical JSON:\n%s\n%s", a, b)
		}
	})

	t.Run("invalid_text_type_is_refusal_not_fallback", func(t *testing.T) {
		for _, bad := range []string{"", "xml", "PLAIN", "binary"} {
			req := valid
			req.TextType = SupportedTextType(bad)
			if _, err := subject.Classify(context.Background(), req); !errors.Is(err, ErrUnsupportedType) {
				t.Fatalf("text type %q must refuse with ErrUnsupportedType, got %v", bad, err)
			}
		}
	})

	t.Run("empty_text_is_refusal_not_empty_success", func(t *testing.T) {
		for _, empty := range []string{"", "   ", "\n\t\r\n "} {
			req := valid
			req.Text = empty
			res, err := subject.Classify(context.Background(), req)
			if !errors.Is(err, ErrEmpty) {
				t.Fatalf("text %q must refuse with ErrEmpty, got %v", empty, err)
			}
			if err == nil && res.Unknown {
				t.Fatalf("empty text surfaced as an empty success — the contract requires the refusal path")
			}
		}
	})

	t.Run("oversized_and_non_utf8_are_typed_refusals", func(t *testing.T) {
		req := valid
		req.Text = strings.Repeat("a", MaxTextBytesPlain+1)
		if _, err := subject.Classify(context.Background(), req); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("oversized payload must refuse with ErrTooLarge, got %v", err)
		}
		req.Text = "недопустимый \xff\xfe payload"
		if _, err := subject.Classify(context.Background(), req); !errors.Is(err, ErrNotUTF8) {
			t.Fatalf("non-UTF-8 payload must refuse with ErrNotUTF8, got %v", err)
		}
	})

	t.Run("taxonomy_version_skew_is_refusal", func(t *testing.T) {
		for _, skew := range []int64{version + 1, version - 1, -1} {
			req := valid
			req.TaxonomyVersion = skew
			if _, err := subject.Classify(context.Background(), req); !errors.Is(err, ErrTaxonomyVersionMismatch) {
				t.Fatalf("version %d must refuse with ErrTaxonomyVersionMismatch, got %v", skew, err)
			}
		}
	})

	t.Run("canceled_context_is_refusal", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := subject.Classify(ctx, valid); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled context must refuse with context.Canceled, got %v", err)
		}
	})

	t.Run("result_shape_never_nil", func(t *testing.T) {
		req := valid // no label of the contract taxonomy occurs in this text
		res, err := subject.Classify(context.Background(), req)
		if err != nil {
			t.Fatalf("valid request refused: %v", err)
		}
		if !res.Unknown {
			t.Fatalf("no evidence must set Unknown, got %+v", res)
		}
		if res.Labels == nil || res.Spans == nil {
			t.Fatalf("Labels and Spans must be non-nil even when empty: %+v", res)
		}
		if len(res.Labels) != 0 || len(res.Spans) != 0 {
			t.Fatalf("no evidence must yield empty slices, got %+v", res)
		}
	})
}

// contractTaxonomy is the fake's bound taxonomy: version 7, two labels,
// neither occurring in the contract suite's valid fixture.
func contractTaxonomy() Taxonomy {
	return Taxonomy{
		OrgID:   "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f",
		Version: 7,
		Labels: []Label{
			{Key: "alpha"},
			{Key: "beta"},
		},
	}
}

func TestSPIContractOnFake(t *testing.T) {
	fake := contractFake{taxonomy: contractTaxonomy()}
	runClassifierContractSuite(t, fake, 7)
}

func TestSPIContractFakeLabelsByOccurrence(t *testing.T) {
	fake := contractFake{taxonomy: contractTaxonomy()}
	res, err := fake.Classify(context.Background(), ClassifyRequest{
		Text:            "alpha appears twice: alpha, beta once",
		TextType:        TextTypePlain,
		TaxonomyVersion: 7,
	})
	if err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	if len(res.Spans) != 3 || len(res.Labels) != 2 || res.Unknown {
		t.Fatalf("expected 3 spans / 2 labels / known, got %+v", res)
	}
	if res.Labels[0].Key != "alpha" || res.Labels[0].SpanCount != 2 || res.Labels[0].Confidence != 1 {
		t.Fatalf("alpha aggregate wrong: %+v", res.Labels[0])
	}
	if res.Labels[1].Key != "beta" || res.Labels[1].SpanCount != 1 {
		t.Fatalf("beta aggregate wrong: %+v", res.Labels[1])
	}
	for _, s := range res.Spans {
		if s.Confidence != 1 || s.Detector != "fake:substring" {
			t.Fatalf("span carries the fake's fixed evidence fields: %+v", s)
		}
	}
}
