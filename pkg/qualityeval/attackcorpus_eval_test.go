package qualityeval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

// markerDetector is a scripted VersionedDetector: every configured marker
// found in the invocation content becomes one finding for its category.
type markerDetector struct {
	id      guardhooks.RuleVersion
	markers map[string]guardhooks.Category
	err     error
	doPanic bool
	calls   []guardhooks.Invocation
}

func (d *markerDetector) Identity() guardhooks.RuleVersion { return d.id }

func (d *markerDetector) Detect(in guardhooks.Invocation) ([]guardhooks.Finding, error) {
	d.calls = append(d.calls, in)
	if d.err != nil {
		return nil, d.err
	}
	if d.doPanic {
		panic("detector exploded")
	}
	content, err := in.Content()
	if err != nil {
		return nil, err
	}
	var out []guardhooks.Finding
	for marker, category := range d.markers {
		rest := content
		base := 0
		for {
			idx := strings.Index(rest, marker)
			if idx < 0 {
				break
			}
			start := base + idx
			out = append(out, guardhooks.Finding{Category: category, Start: start, End: start + len(marker)})
			rest = rest[idx+len(marker):]
			base = start + len(marker)
		}
	}
	return out, nil
}

func mustEvaluator(t *testing.T, dets ...guardhooks.VersionedDetector) *guardhooks.Evaluator {
	t.Helper()
	eval, err := guardhooks.NewEvaluator(dets...)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return eval
}

// corpusForHarness is a controlled corpus for exact-math assertions.
func corpusForHarness() []AttackCase {
	req := []AttackSurface{SurfaceRequest}
	inj, leak := AttackClassPromptInjection, AttackClassSecretLeak
	return []AttackCase{
		{ID: "p-inj", Text: "MARKINJ override", Surfaces: req, Classes: []AttackClass{inj}},
		{ID: "p-leak", Text: "MARKLEAK dump", Surfaces: req, Classes: []AttackClass{leak}},
		{ID: "p-both", Text: "MARKINJ and MARKLEAK", Surfaces: req, Classes: []AttackClass{inj, leak}},
		{ID: "b-flag", Text: "MARKINJ innocent mention", Surfaces: req},
		{ID: "b-clean", Text: "nothing suspicious here", Surfaces: req},
	}
}

func bindingsForHarness() CategoryBindings {
	return CategoryBindings{
		guardhooks.CatInjection:  AttackClassPromptInjection,
		guardhooks.CatSecret:     AttackClassSecretLeak,
		guardhooks.CatCredential: AttackClassSecretLeak,
	}
}

func findRow(t *testing.T, report AttackCorpusReport, class AttackClass) AttackClassReport {
	t.Helper()
	for _, row := range report.Classes {
		if row.Class == class {
			return row
		}
	}
	t.Fatalf("no report row for class %q: %+v", class, report)
	return AttackClassReport{}
}

// TestEvaluateAttackCorpusExactMath pins coverage/FP accounting: detection
// sets, missed ids, false positives, unbound counting, totals.
func TestEvaluateAttackCorpusExactMath(t *testing.T) {
	det := &markerDetector{
		id: guardhooks.RuleVersion{PackID: "test", PackVersion: "1", RuleID: "markers", RuleVersion: "1"},
		markers: map[string]guardhooks.Category{
			"MARKINJ":  guardhooks.CatInjection,
			"MARKLEAK": guardhooks.CatSecret,
		},
	}
	report, err := EvaluateAttackCorpus(context.Background(), corpusForHarness(), mustEvaluator(t, det), bindingsForHarness())
	if err != nil {
		t.Fatalf("EvaluateAttackCorpus: %v", err)
	}
	if report.Cases != 5 || report.Positives != 3 || report.Negatives != 2 || report.UnboundFindings != 0 {
		t.Fatalf("totals drifted: %+v", report)
	}

	inj := findRow(t, report, AttackClassPromptInjection)
	if inj.Positives != 2 || inj.Detected != 2 || inj.Coverage != 1 || len(inj.MissedCaseIDs) != 0 {
		t.Fatalf("injection row: %+v", inj)
	}
	if !reflect.DeepEqual(inj.FalsePositiveCaseIDs, []string{"b-flag"}) {
		t.Fatalf("injection false positives: %+v", inj.FalsePositiveCaseIDs)
	}

	leak := findRow(t, report, AttackClassSecretLeak)
	if leak.Positives != 2 || leak.Detected != 2 || leak.Coverage != 1 || len(leak.FalsePositiveCaseIDs) != 0 {
		t.Fatalf("secret row: %+v", leak)
	}
}

// TestEvaluateAttackCorpusMissedAndUnbound covers the honest-miss path and
// unbound-category accounting.
func TestEvaluateAttackCorpusMissedAndUnbound(t *testing.T) {
	det := &markerDetector{
		id: guardhooks.RuleVersion{PackID: "test", PackVersion: "1", RuleID: "markers", RuleVersion: "1"},
		markers: map[string]guardhooks.Category{
			"MARKINJ": guardhooks.CatInjection,
			"MARKPAN": guardhooks.CatPAN, // bound to nothing
		},
	}
	cases := []AttackCase{
		{ID: "p-inj-hit", Text: "MARKINJ", Surfaces: []AttackSurface{SurfaceRequest}, Classes: []AttackClass{AttackClassPromptInjection}},
		{ID: "p-inj-miss", Text: "nothing fires here", Surfaces: []AttackSurface{SurfaceRequest}, Classes: []AttackClass{AttackClassPromptInjection}},
		{ID: "b-pan", Text: "MARKPAN but benign", Surfaces: []AttackSurface{SurfaceRequest}},
	}
	bindings := CategoryBindings{guardhooks.CatInjection: AttackClassPromptInjection}
	report, err := EvaluateAttackCorpus(context.Background(), cases, mustEvaluator(t, det), bindings)
	if err != nil {
		t.Fatalf("EvaluateAttackCorpus: %v", err)
	}
	inj := findRow(t, report, AttackClassPromptInjection)
	if inj.Detected != 1 || inj.Coverage != 0.5 || !reflect.DeepEqual(inj.MissedCaseIDs, []string{"p-inj-miss"}) {
		t.Fatalf("miss accounting: %+v", inj)
	}
	if report.UnboundFindings != 1 {
		t.Fatalf("unbound findings = %d, want 1 (dropped findings would hide detector scope gaps)", report.UnboundFindings)
	}
}

// TestEvaluateAttackCorpusCrossClassHit: a bound finding on a positive
// labeled for another class is neither a detection nor a false positive.
func TestEvaluateAttackCorpusCrossClassHit(t *testing.T) {
	det := &markerDetector{
		id:      guardhooks.RuleVersion{PackID: "test", PackVersion: "1", RuleID: "markers", RuleVersion: "1"},
		markers: map[string]guardhooks.Category{"MARKLEAK": guardhooks.CatSecret},
	}
	cases := []AttackCase{
		{ID: "p-inj", Text: "MARKLEAK inside an injection", Surfaces: []AttackSurface{SurfaceRequest}, Classes: []AttackClass{AttackClassPromptInjection}},
		{ID: "b-clean", Text: "clean", Surfaces: []AttackSurface{SurfaceRequest}},
	}
	report, err := EvaluateAttackCorpus(context.Background(), cases, mustEvaluator(t, det), bindingsForHarness())
	if err != nil {
		t.Fatalf("EvaluateAttackCorpus: %v", err)
	}
	leak := findRow(t, report, AttackClassSecretLeak)
	if leak.Detected != 0 || len(leak.FalsePositiveCaseIDs) != 0 || leak.Coverage != 0 {
		t.Fatalf("cross-class hit leaked into FP/detection accounting: %+v", leak)
	}
}

// TestEvaluateAttackCorpusBoundClassWithoutPositives: benign hits on a
// bound class the corpus has no positives for are still recorded as FPs
// (Coverage 0 by definition).
func TestEvaluateAttackCorpusBoundClassWithoutPositives(t *testing.T) {
	det := &markerDetector{
		id:      guardhooks.RuleVersion{PackID: "test", PackVersion: "1", RuleID: "markers", RuleVersion: "1"},
		markers: map[string]guardhooks.Category{"MARKCRED": guardhooks.CatCredential},
	}
	cases := []AttackCase{
		{ID: "b-cred", Text: "MARKCRED mention", Surfaces: []AttackSurface{SurfaceRequest}},
	}
	report, err := EvaluateAttackCorpus(context.Background(), cases, mustEvaluator(t, det), bindingsForHarness())
	if err != nil {
		t.Fatalf("EvaluateAttackCorpus: %v", err)
	}
	leak := findRow(t, report, AttackClassSecretLeak)
	if leak.Positives != 0 || leak.Coverage != 0 || !reflect.DeepEqual(leak.FalsePositiveCaseIDs, []string{"b-cred"}) {
		t.Fatalf("bound-without-positives accounting: %+v", leak)
	}
}

// TestEvaluateAttackCorpusFailClosed: detector errors, panics, cancelled
// contexts and misconfiguration abort the run loudly.
func TestEvaluateAttackCorpusFailClosed(t *testing.T) {
	base := []AttackCase{
		{ID: "p-inj", Text: "MARKINJ", Surfaces: []AttackSurface{SurfaceRequest}, Classes: []AttackClass{AttackClassPromptInjection}},
		{ID: "b-clean", Text: "benign control", Surfaces: []AttackSurface{SurfaceRequest}},
	}
	newDet := func(d *markerDetector) *markerDetector {
		d.id = guardhooks.RuleVersion{PackID: "test", PackVersion: "1", RuleID: "x", RuleVersion: "1"}
		return d
	}

	t.Run("detector error", func(t *testing.T) {
		det := newDet(&markerDetector{err: errors.New("regex compile failed")})
		_, err := EvaluateAttackCorpus(context.Background(), base, mustEvaluator(t, det), bindingsForHarness())
		if err == nil || !strings.Contains(err.Error(), "p-inj") {
			t.Fatalf("detector error not surfaced with case id: %v", err)
		}
	})
	t.Run("detector panic", func(t *testing.T) {
		det := newDet(&markerDetector{doPanic: true})
		_, err := EvaluateAttackCorpus(context.Background(), base, mustEvaluator(t, det), bindingsForHarness())
		if err == nil || !strings.Contains(err.Error(), "p-inj") {
			t.Fatalf("detector panic not surfaced with case id: %v", err)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		det := newDet(&markerDetector{})
		_, err := EvaluateAttackCorpus(ctx, base, mustEvaluator(t, det), bindingsForHarness())
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled context not propagated: %v", err)
		}
	})
	t.Run("nil evaluator", func(t *testing.T) {
		if _, err := EvaluateAttackCorpus(context.Background(), base, nil, bindingsForHarness()); err == nil {
			t.Fatalf("nil evaluator accepted")
		}
	})
	t.Run("empty bindings", func(t *testing.T) {
		det := newDet(&markerDetector{})
		if _, err := EvaluateAttackCorpus(context.Background(), base, mustEvaluator(t, det), CategoryBindings{}); err == nil {
			t.Fatalf("empty bindings accepted (coverage would be silently zero)")
		}
	})
	t.Run("unknown bound class", func(t *testing.T) {
		det := newDet(&markerDetector{})
		bad := CategoryBindings{guardhooks.CatInjection: AttackClass("hypnoattack")}
		if _, err := EvaluateAttackCorpus(context.Background(), base, mustEvaluator(t, det), bad); err == nil {
			t.Fatalf("unknown bound class accepted")
		}
	})
	t.Run("nil context", func(t *testing.T) {
		det := newDet(&markerDetector{})
		//nolint:staticcheck // SA1012: the nil-context rejection path is the contract under test
		if _, err := EvaluateAttackCorpus(nil, base, mustEvaluator(t, det), bindingsForHarness()); err == nil {
			t.Fatalf("nil context accepted")
		}
	})
	t.Run("invalid corpus", func(t *testing.T) {
		det := newDet(&markerDetector{})
		_, err := EvaluateAttackCorpus(context.Background(), nil, mustEvaluator(t, det), bindingsForHarness())
		if !errors.Is(err, ErrInvalidAttackCorpus) {
			t.Fatalf("invalid corpus not rejected with authoring sentinel: %v", err)
		}
	})
}

// TestEvaluateAttackCorpusSurfaceProjections: each corpus surface maps to
// the versioned invocation projection named by I66 (phase + content kind).
func TestEvaluateAttackCorpusSurfaceProjections(t *testing.T) {
	det := &markerDetector{id: guardhooks.RuleVersion{PackID: "test", PackVersion: "1", RuleID: "x", RuleVersion: "1"}}
	cases := []AttackCase{
		{ID: "probe", Text: "PROBE", Surfaces: []AttackSurface{SurfaceRequest, SurfaceResponse, SurfaceToolArguments, SurfaceToolResult}, Classes: []AttackClass{AttackClassPromptInjection}},
		{ID: "benign", Text: "PROBE", Surfaces: []AttackSurface{SurfaceRequest}},
	}
	if _, err := EvaluateAttackCorpus(context.Background(), cases, mustEvaluator(t, det), CategoryBindings{guardhooks.CatInjection: AttackClassPromptInjection}); err != nil {
		t.Fatalf("EvaluateAttackCorpus: %v", err)
	}
	if len(det.calls) != 5 {
		t.Fatalf("invocations = %d, want 5", len(det.calls))
	}
	if det.calls[0].Version != guardhooks.RuntimeVersion {
		t.Fatalf("invocation version %q", det.calls[0].Version)
	}
	counts := map[string]int{}
	for _, call := range det.calls {
		counts[fmt.Sprintf("%s|%s", call.Kind, call.Phase)]++
	}
	want := map[string]int{
		"text|before":      2, // request probes
		"text|after":       1, // response
		"arguments|before": 1, // tool arguments
		"result|after":     1, // tool result
	}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("projection counts: got %+v want %+v", counts, want)
	}
}

// TestEvaluateAttackCorpusDeterministic: case order must not change the
// report; duplicate findings on one case must not inflate detection counts.
func TestEvaluateAttackCorpusDeterministic(t *testing.T) {
	det := &markerDetector{
		id: guardhooks.RuleVersion{PackID: "test", PackVersion: "1", RuleID: "markers", RuleVersion: "1"},
		markers: map[string]guardhooks.Category{
			"MARK": guardhooks.CatInjection, // matches several cases, twice in p-both
		},
	}
	base := corpusForHarness()
	base[2].Text = "MARK twice MARK" // duplicate marker in one case
	ref, err := EvaluateAttackCorpus(context.Background(), base, mustEvaluator(t, det), bindingsForHarness())
	if err != nil {
		t.Fatalf("reference run: %v", err)
	}
	if ref.Classes[0].Detected != 2 { // p-inj, p-both — counted once each
		t.Fatalf("duplicate findings inflated detection: %+v", ref.Classes[0])
	}
	for i := 0; i < 6; i++ {
		shuffled := append([]AttackCase(nil), base...)
		shuffled[i%len(shuffled)], shuffled[(i+2)%len(shuffled)] = shuffled[(i+2)%len(shuffled)], shuffled[i%len(shuffled)]
		got, err := EvaluateAttackCorpus(context.Background(), shuffled, mustEvaluator(t, det), bindingsForHarness())
		if err != nil {
			t.Fatalf("shuffled run %d: %v", i, err)
		}
		if !reflect.DeepEqual(ref, got) {
			t.Fatalf("run %d: report depends on case order:\nref %+v\ngot %+v", i, ref, got)
		}
	}
}

// TestEvaluateAttackCorpusFixtureWithBuiltins: the committed corpus against
// the versioned core pack through the public SPI. Structural assertions
// only — observed coverage/FP numbers are recorded in the packet record;
// they depend on detector quality (T03's unit), not on this harness.
func TestEvaluateAttackCorpusFixtureWithBuiltins(t *testing.T) {
	raw, rev, err := ReadSetBundle(bytes.NewReader(attackFixtureRaw(t)))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	_ = raw
	cases, err := ParseAttackCorpus(rev)
	if err != nil {
		t.Fatalf("parse fixture corpus: %v", err)
	}
	bindings := CategoryBindings{
		guardhooks.CatInjection:  AttackClassPromptInjection,
		guardhooks.CatSecret:     AttackClassSecretLeak,
		guardhooks.CatCredential: AttackClassSecretLeak,
	}
	report, err := EvaluateAttackCorpus(context.Background(), cases, guardhooks.BuiltinEvaluator(), bindings)
	if err != nil {
		t.Fatalf("builtin run: %v", err)
	}
	if report.Cases != 36 || report.Positives != 24 || report.Negatives != 12 {
		t.Fatalf("totals drifted: %+v", report)
	}
	if len(report.Classes) != 3 {
		t.Fatalf("class rows = %d, want 3", len(report.Classes))
	}
	for _, row := range report.Classes {
		if row.Coverage < 0 || row.Coverage > 1 {
			t.Fatalf("coverage out of range for %q: %v", row.Class, row.Coverage)
		}
		for _, id := range append(append([]string{}, row.MissedCaseIDs...), row.FalsePositiveCaseIDs...) {
			if !isFixtureCaseID(id) {
				t.Fatalf("row %q references unknown id %q", row.Class, id)
			}
		}
	}
	abuse := findRow(t, report, AttackClassToolAbuse)
	if abuse.Positives != 8 {
		t.Fatalf("tool abuse positives = %d, want 8", abuse.Positives)
	}
	t.Logf("observed builtin coverage/FP (recorded, not gated): %+v", report)
}

// isFixtureCaseID checks the id against the fixture inventory (inj/leak/
// abuse/neg prefixes).
func isFixtureCaseID(id string) bool {
	for _, prefix := range []string{"inj-", "leak-", "abuse-", "neg-"} {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}
