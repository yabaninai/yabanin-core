// Package dataclass — classification SPI (E04-P01-W03-C01).
//
// Classifier is the single seam every classification implementation
// satisfies: the offline builtin (builtin.go), the permission-gated
// external-judge seat (remote_seat.go) and test doubles. The contract:
//
//   - no I/O: an implementation is a pure function of its construction
//     state and the request; ctx carries cancellation only;
//   - determinism: the same request yields a bit-identical result on
//     every call;
//   - fail-closed refusals — typed errors, never a fallback verdict and
//     never a silent empty success: a canceled context refuses with
//     ctx.Err(); a text type outside the closed five-type set refuses
//     with ErrUnsupportedType; an empty/whitespace, non-UTF-8 or
//     oversized payload refuses with ErrEmpty/ErrNotUTF8/ErrTooLarge;
//     a taxonomy version different from the implementation's bound
//     taxonomy refuses with ErrTaxonomyVersionMismatch.
//
// CheckClassifyRequest prechecks everything except cancellation-mid-work
// and implementations MUST call it first, so the contract lives in one
// place instead of being re-implemented (and drifting) per backend.
package dataclass

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// ErrTaxonomyVersionMismatch — the request pins a different taxonomy
// revision than the classifier is bound to. Version skew is a refusal,
// not a best-effort re-run against a stale label set.
var ErrTaxonomyVersionMismatch = errors.New("dataclass: taxonomy version mismatch")

// ClassifyRequest is the input envelope of Classifier.Classify.
type ClassifyRequest struct {
	// Text is the payload to classify (UTF-8, bounded by the type's
	// byte limit, non-empty).
	Text string
	// TextType is the caller-declared type of Text: a DetectType
	// verdict or a caller-declared form type. Values outside the closed
	// five-type set are refused — an implementation never guesses the
	// type it was given.
	TextType SupportedTextType
	// TaxonomyVersion pins the taxonomy revision the caller classified
	// against. It must equal the bound taxonomy's version (0 for a
	// never-written org taxonomy).
	TaxonomyVersion int64
}

// Span is one matched evidence span inside the request text. Start and
// End are byte offsets (0 <= Start < End <= len(Text)); Category,
// Confidence, Locale and Detector carry the guardhooks Finding fields
// the evidence came from (Locale is "" when the detector is not
// national).
type Span struct {
	Label      string
	Category   string
	Start, End int
	Confidence float64
	Locale     string
	Detector   string
}

// ClassifiedLabel aggregates the evidence of one taxonomy label. The
// Confidence field follows the combining rule fixed in confidence.go
// (the strongest supporting finding); SpanCount is the number of
// evidence spans behind the label.
type ClassifiedLabel struct {
	Key        string
	Confidence float64
	SpanCount  int
}

// ClassifyResult is the verdict over one request. Labels and Spans are
// sorted (Labels by key, Spans by Start/End/Label/Category/Detector)
// and NEVER nil: a no-evidence verdict is Unknown=true with empty
// non-nil slices, so callers never distinguish nil from empty.
type ClassifyResult struct {
	Labels []ClassifiedLabel
	Spans  []Span
	// Unknown reports that no taxonomy label has supporting evidence —
	// the explicit unknown verdict (the known/unknown model, the
	// pkg/secevents IDState precedent). It is never expressed as an
	// empty "success".
	Unknown bool
}

// Classifier classifies text against one bound org taxonomy.
type Classifier interface {
	// Classify runs the classification. Contract refusals precede any
	// work via CheckClassifyRequest; implementations return its error
	// unchanged.
	Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error)
}

// CheckClassifyRequest prechecks the shared classify contract in a
// fixed observable order: canceled context, then the payload checks of
// ValidateText (closed type set → UTF-8 → size → emptiness — an empty
// or whitespace-only payload refuses with ErrEmpty, never an empty
// success), then the taxonomy version pin. Implementations MUST call it
// before any work and return its error unchanged; every refusal is
// typed.
func CheckClassifyRequest(ctx context.Context, req ClassifyRequest, boundVersion int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateText(req.TextType, req.Text); err != nil {
		return err
	}
	if req.TaxonomyVersion != boundVersion {
		return fmt.Errorf("%w: request %d, bound taxonomy %d", ErrTaxonomyVersionMismatch, req.TaxonomyVersion, boundVersion)
	}
	return nil
}

// sortSpans brings spans into the canonical result order: Start, End,
// Label, Category, Detector. The comparator is total, so the order is
// deterministic regardless of the detector emission order.
func sortSpans(spans []Span) {
	sort.Slice(spans, func(i, j int) bool {
		a, b := spans[i], spans[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End < b.End
		}
		if a.Label != b.Label {
			return a.Label < b.Label
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Detector < b.Detector
	})
}

// sortLabelKeys brings label keys into the canonical (lexicographic)
// result order.
func sortLabelKeys(keys []string) { sort.Strings(keys) }
