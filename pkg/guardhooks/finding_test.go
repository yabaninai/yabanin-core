package guardhooks

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindAll_SpansMatchText(t *testing.T) {
	key := "sk-" + "abcdefghijklmnop12345678"
	text := "pay " + key + " inn 7707083893"
	findings := FindAll(text, DefaultDetectors())
	require.NotEmpty(t, findings)
	var sawSecret, sawINN bool
	for _, f := range findings {
		require.GreaterOrEqual(t, f.Start, 0)
		require.LessOrEqual(t, f.End, len(text))
		span := text[f.Start:f.End]
		require.Equal(t, span, text[f.Start:f.End])
		switch f.Detector {
		case "regex:secret":
			require.Equal(t, key, span)
			require.InDelta(t, 0.9, f.Confidence, 0.001)
			sawSecret = true
		case "ru:inn":
			require.Equal(t, "7707083893", span)
			require.InDelta(t, 1.0, f.Confidence, 0.001)
			require.Equal(t, "ru", f.Locale)
			sawINN = true
		}
		for _, later := range findings {
			if later.Category == f.Category && later.Start > f.Start {
				require.GreaterOrEqual(t, later.Start, f.End)
			}
		}
	}
	require.True(t, sawSecret)
	require.True(t, sawINN)
}

func TestFindAll_DropsSameCategoryOverlap(t *testing.T) {
	ds := []Detector{
		spanDetector{name: "a", category: CatSecret, spans: []Finding{{Category: CatSecret, Start: 0, End: 8, Detector: "a", Confidence: 0.9}}},
		spanDetector{name: "b", category: CatSecret, spans: []Finding{{Category: CatSecret, Start: 4, End: 12, Detector: "b", Confidence: 0.9}}},
		spanDetector{name: "c", category: CatPAN, spans: []Finding{{Category: CatPAN, Start: 4, End: 6, Detector: "c", Confidence: 1}}},
	}
	got := FindAll("0123456789abcdef", ds)
	require.Len(t, got, 2)
	require.Equal(t, "a", got[0].Detector)
	require.Equal(t, CatPAN, got[1].Category)
}

type spanDetector struct {
	name     string
	category Category
	spans    []Finding
}

func (d spanDetector) Name() string { return d.name }

func (d spanDetector) Detect(string) []Finding { return d.spans }

func TestFindAll_CoversDetectors(t *testing.T) {
	for _, d := range DefaultDetectors() {
		require.NotEmpty(t, d.Name())
		require.Nil(t, d.Detect("plain words"))
	}
	inn := FindAll("1234567890", DefaultDetectors())
	for _, f := range inn {
		require.NotEqual(t, "ru:inn", f.Detector)
	}
	card := FindAll("4242 4242 4242 4242 UDAXI3321C", DefaultDetectors())
	var sawPAN, sawIN bool
	for _, f := range card {
		if f.Detector == "luhn:pan" {
			sawPAN = true
		}
		if f.Detector == "in:pan" {
			sawIN = true
		}
	}
	require.True(t, sawPAN)
	require.True(t, sawIN)

	same := FindAll("0123456789", []Detector{
		nil,
		spanDetector{name: "late", spans: []Finding{{Category: CatSecret, Start: 1, End: 4, Detector: "m"}}},
		spanDetector{name: "short", spans: []Finding{{Category: CatInjection, Start: 1, End: 2, Detector: "z"}}},
		spanDetector{name: "early", spans: []Finding{{Category: CatPAN, Start: 1, End: 2, Detector: "a"}}},
	})
	require.Len(t, same, 3)
}
