// Attack corpus evaluation harness (N14-P03-T04 authoring side): runs any
// guardrails SPI evaluator over an attack corpus and reports per-class
// coverage and false positives as plain data.
//
// Contract (PRODUCT-CONTRACT §13, owner decisions I07/I66): the corpus and
// this harness record detection quality — they never gate client traffic.
// The harness is fail-closed in the direction that matters for honest
// measurement: a detector error, panic, or cancelled context aborts the run
// with an error (no silent clean scan), an empty binding table is rejected
// (coverage would be silently zero), and findings whose category is not
// bound to an attack class are counted in the report as UnboundFindings
// instead of being dropped.
//
// Semantics:
//   - Every distinct class named by the bindings is reported; corpus labels
//     set each class's positive set.
//   - A positive case counts as detected for class C when at least one
//     finding bound to C fires on it. Cross-class hits (a finding bound to
//     class C firing on a positive labeled for another class) are neither
//     detections for C nor false positives — the corpus cannot know which
//     class the operator would have wanted there.
//   - A benign control (empty classes) with any bound finding counts as a
//     false positive for every class that finding's category binds to —
//     including bound classes with no corpus positives (Coverage 0 by
//     definition), so detector noise on controls is always visible.
//
// Determinism: class rows are sorted by class, id lists are sorted, and the
// same corpus + evaluator + bindings always yield an equal report.
package qualityeval

import (
	"context"
	"fmt"
	"sort"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

// CategoryBindings maps detector finding categories to corpus attack
// classes. Several categories may bind to one class (e.g. the secret and
// credential categories both measure secret_leak); a category binds to at
// most one class per run.
type CategoryBindings map[guardhooks.Category]AttackClass

// AttackClassReport is the measurable outcome for one corpus class.
type AttackClassReport struct {
	Class                AttackClass
	Positives            int
	Detected             int
	Coverage             float64
	MissedCaseIDs        []string
	FalsePositiveCaseIDs []string
}

// AttackCorpusReport is the full corpus run outcome. IDs and rows are
// sorted; the value is plain data suitable for direct serialization.
type AttackCorpusReport struct {
	Cases           int
	Positives       int
	Negatives       int
	Classes         []AttackClassReport
	UnboundFindings int
}

// classAccumulator aggregates per-class detection outcomes for one run.
type classAccumulator struct {
	positives int
	detected  map[string]struct{}
	falsePos  map[string]struct{}
}

// surfaceProjection selects the versioned invocation projection for one
// corpus surface (I66 stages): request/response scan as text in the
// before/after phase, tool arguments/results as their structured kinds.
func surfaceProjection(surface AttackSurface, text string) (guardhooks.Phase, guardhooks.ContentKind, string, []byte) {
	switch surface {
	case SurfaceRequest:
		return guardhooks.PhaseBefore, guardhooks.ContentText, text, nil
	case SurfaceResponse:
		return guardhooks.PhaseAfter, guardhooks.ContentText, text, nil
	case SurfaceToolArguments:
		return guardhooks.PhaseBefore, guardhooks.ContentArguments, "", []byte(text)
	case SurfaceToolResult:
		return guardhooks.PhaseAfter, guardhooks.ContentResult, "", []byte(text)
	}
	return guardhooks.PhaseBefore, guardhooks.ContentText, text, nil
}

// EvaluateAttackCorpus runs the evaluator over every surface of every case
// and returns the coverage/FP report. Errors abort the run: detection
// failures are never folded into a clean report.
func EvaluateAttackCorpus(ctx context.Context, cases []AttackCase, eval *guardhooks.Evaluator, bindings CategoryBindings) (AttackCorpusReport, error) {
	if err := ValidateAttackCases(cases); err != nil {
		return AttackCorpusReport{}, err
	}
	if eval == nil {
		return AttackCorpusReport{}, fmt.Errorf("attack corpus evaluation: nil evaluator")
	}
	if len(bindings) == 0 {
		return AttackCorpusReport{}, fmt.Errorf("attack corpus evaluation: empty category bindings (coverage would be silently zero)")
	}
	if ctx == nil {
		return AttackCorpusReport{}, fmt.Errorf("attack corpus evaluation: nil context")
	}
	for category, class := range bindings {
		if !isKnownAttackClass(class) {
			return AttackCorpusReport{}, fmt.Errorf("attack corpus evaluation: category %q bound to unknown class %q", category, class)
		}
	}

	// Every bound class is reported; corpus labels add positive sets.
	accs := map[AttackClass]*classAccumulator{}
	for _, class := range bindings {
		if accs[class] == nil {
			accs[class] = &classAccumulator{detected: map[string]struct{}{}, falsePos: map[string]struct{}{}}
		}
	}
	positives, negatives := 0, 0
	for _, c := range cases {
		if len(c.Classes) > 0 {
			positives++
			for _, class := range c.Classes {
				if accs[class] == nil {
					accs[class] = &classAccumulator{detected: map[string]struct{}{}, falsePos: map[string]struct{}{}}
				}
				accs[class].positives++
			}
		} else {
			negatives++
		}
	}

	unbound := 0
	for _, c := range cases {
		for _, surface := range c.Surfaces {
			phase, kind, text, bytesArg := surfaceProjection(surface, c.Text)
			in := guardhooks.Invocation{
				Context:   ctx,
				Version:   guardhooks.RuntimeVersion,
				Phase:     phase,
				Kind:      kind,
				Text:      text,
				Arguments: bytesArg,
				Result:    bytesArg,
			}
			evaluation, err := eval.Evaluate(in)
			if err != nil {
				return AttackCorpusReport{}, fmt.Errorf("attack corpus evaluation: case %q surface %q: %w", c.ID, surface, err)
			}
			for _, finding := range evaluation.Findings {
				class, bound := bindings[finding.Category]
				if !bound {
					unbound++
					continue
				}
				acc := accs[class]
				if len(c.Classes) == 0 {
					acc.falsePos[c.ID] = struct{}{}
					continue
				}
				for _, labeled := range c.Classes {
					if labeled == class {
						acc.detected[c.ID] = struct{}{}
					}
				}
			}
		}
	}

	report := AttackCorpusReport{Cases: len(cases), Positives: positives, Negatives: negatives}
	for _, class := range sortedAttackClasses(accs) {
		acc := accs[class]
		row := AttackClassReport{
			Class:     class,
			Positives: acc.positives,
			Detected:  len(acc.detected),
		}
		if acc.positives > 0 {
			row.Coverage = float64(len(acc.detected)) / float64(acc.positives)
		}
		row.MissedCaseIDs = missingPositiveIDs(cases, class, acc.detected)
		for id := range acc.falsePos {
			row.FalsePositiveCaseIDs = append(row.FalsePositiveCaseIDs, id)
		}
		sort.Strings(row.FalsePositiveCaseIDs)
		report.Classes = append(report.Classes, row)
	}
	report.UnboundFindings = unbound
	return report, nil
}

// sortedAttackClasses returns the accumulated classes in stable order.
func sortedAttackClasses(accs map[AttackClass]*classAccumulator) []AttackClass {
	out := make([]AttackClass, 0, len(accs))
	for class := range accs {
		out = append(out, class)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// missingPositiveIDs lists, sorted, the ids of cases labeled class that
// produced no detection for it.
func missingPositiveIDs(cases []AttackCase, class AttackClass, detected map[string]struct{}) []string {
	var missed []string
	for _, c := range cases {
		labeled := false
		for _, labeledClass := range c.Classes {
			if labeledClass == class {
				labeled = true
				break
			}
		}
		if !labeled {
			continue
		}
		if _, ok := detected[c.ID]; !ok {
			missed = append(missed, c.ID)
		}
	}
	sort.Strings(missed)
	return missed
}
