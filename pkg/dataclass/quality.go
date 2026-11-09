// Package dataclass — fixture quality measurement (E04-P01-W04-C02).
//
// MeasureQuality runs a classifier over a fixed fixture set, applies the
// SAME thresholding a deployment applies (nil minFor = the default
// threshold), and reports per-class precision/recall — measuring the
// decision the product makes, not raw scores. The report is honest
// about absences: every taxonomy label, every expected label and every
// predicted label gets a row, zeros included; nothing is silently
// averaged away. Deterministic by construction: fixtures run in order,
// rows sort by class, JSON marshals stably (slices only, no maps).
package dataclass

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// ErrNoQualityFixtures — a quality measurement over zero fixtures is
// not a measurement; it is refused instead of reported as all zeros.
var ErrNoQualityFixtures = errors.New("dataclass: quality fixture set is empty")

// QualityFixture is one labeled example: the text, its declared type,
// and the exact set of labels a correct classifier must produce for it
// (after thresholding). ExpectedLabels are deduplicated; the empty set
// asserts the explicit unknown verdict.
type QualityFixture struct {
	Text           string
	TextType       SupportedTextType
	ExpectedLabels []string
}

// ClassQuality is the per-class tally over the fixture set. TP/FP/FN
// follow the standard multi-label reading: a predicted label outside
// the expected set is a false positive for its class, an expected label
// the classifier did not produce is a false negative. Precision and
// Recall are 0 when their denominator is 0 (no predictions / no
// expectations — the honest zero, not a division error). Support is the
// number of fixtures that expect the class.
type ClassQuality struct {
	Class     string  `json:"class"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	Support   int     `json:"support"`
}

// QualityReport is the measurement over one fixture set. Classes is
// sorted by Class and contains one row for every taxonomy label,
// expected label and predicted label — a label the classifier invents
// outside the taxonomy shows up with its false positives, it does not
// disappear. JSON marshals deterministically (sorted slices, no maps).
type QualityReport struct {
	Fixtures int            `json:"fixtures"`
	Classes  []ClassQuality `json:"classes"`
}

// MeasureQuality measures one classifier over fixtures. The classifier
// must be bound to the same taxonomy revision as tax (requests are
// issued with TaxonomyVersion = tax.Version). Every fixture must
// classify: a refused fixture (bad type, empty text, version skew,
// canceled context) fails the whole measurement with an error naming
// the fixture index — a skipped fixture would silently inflate quality.
func MeasureQuality(ctx context.Context, cl Classifier, tax Taxonomy, fixtures []QualityFixture, minFor func(string) float64) (QualityReport, error) {
	if err := tax.Validate(); err != nil {
		return QualityReport{}, fmt.Errorf("dataclass: quality taxonomy invalid: %w", err)
	}
	if len(fixtures) == 0 {
		return QualityReport{}, ErrNoQualityFixtures
	}
	tally := make(map[string]*ClassQuality)
	row := func(class string) *ClassQuality {
		if q, ok := tally[class]; ok {
			return q
		}
		q := &ClassQuality{Class: class}
		tally[class] = q
		return q
	}
	for _, l := range tax.Labels {
		_ = row(l.Key) // taxonomy labels get their row even before any fixture runs
	}

	for i, fx := range fixtures {
		expected := dedupeSorted(fx.ExpectedLabels)
		for _, class := range expected {
			q := row(class)
			q.Support++
		}
		res, err := cl.Classify(ctx, ClassifyRequest{
			Text:            fx.Text,
			TextType:        fx.TextType,
			TaxonomyVersion: tax.Version,
		})
		if err != nil {
			return QualityReport{}, fmt.Errorf("dataclass: quality fixture %d refused: %w", i, err)
		}
		predicted := ApplyThreshold(res, minFor)
		predictedSet := make(map[string]bool, len(predicted.Labels))
		for _, l := range predicted.Labels {
			predictedSet[l.Key] = true
			q := row(l.Key)
			if containsString(expected, l.Key) {
				q.TP++
			} else {
				q.FP++
			}
		}
		for _, class := range expected {
			if !predictedSet[class] {
				row(class).FN++
			}
		}
	}

	classes := make([]ClassQuality, 0, len(tally))
	for _, q := range tally {
		classes = append(classes, *q)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].Class < classes[j].Class })
	for i := range classes {
		q := &classes[i]
		q.Precision = ratio(q.TP, q.TP+q.FP)
		q.Recall = ratio(q.TP, q.TP+q.FN)
	}
	return QualityReport{Fixtures: len(fixtures), Classes: classes}, nil
}

// ratio is tp/n with the honest-zero convention (0 when n is 0).
func ratio(tp, n int) float64 {
	if n == 0 {
		return 0
	}
	return float64(tp) / float64(n)
}

// dedupeSorted returns the label set of in as a sorted, duplicate-free
// slice (deterministic set semantics for ExpectedLabels).
func dedupeSorted(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// containsString is the tiny set membership helper (no imports beyond
// the stdlib basics; sorted input not required).
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
