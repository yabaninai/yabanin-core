package guardhooks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type testVersionedDetector struct {
	id       RuleVersion
	findings []Finding
	err      error
}

func (d testVersionedDetector) Identity() RuleVersion { return d.id }
func (d testVersionedDetector) Detect(_ Invocation) ([]Finding, error) {
	return d.findings, d.err
}

func TestEvaluatorVersionedExtensionAndFailure(t *testing.T) {
	id := RuleVersion{PackID: "custom", PackVersion: "2", RuleID: "secret", RuleVersion: "3"}
	detector := testVersionedDetector{id: id, findings: []Finding{{Category: CatSecret, Start: 0, End: 3}}}
	evaluator, err := NewEvaluator(detector)
	require.NoError(t, err)
	in := Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseAfter, Kind: ContentResult, Result: []byte("key")}
	evaluation, err := evaluator.Evaluate(in)
	require.NoError(t, err)
	require.Equal(t, RuntimeVersion, evaluation.Version)
	require.Equal(t, VerdictAllow, evaluation.Verdict)
	require.Equal(t, CatSecret, evaluation.Findings[0].Category)

	failed, err := NewEvaluator(testVersionedDetector{id: id, err: errors.New("unavailable")})
	require.NoError(t, err)
	_, err = failed.Evaluate(in)
	require.Error(t, err)
	_, _, err = Apply(Evaluation{Version: RuntimeVersion, Findings: []Finding{{Category: CatSecret}}}, VerdictAllow, nil)
	require.NoError(t, err)
	_, _, err = Apply(Evaluation{Version: RuntimeVersion, Findings: []Finding{{Category: CatSecret}}}, VerdictRedact, nil)
	require.Error(t, err)
}

func TestFailureOutcomeKeepsShadowDistinctFromAllow(t *testing.T) {
	err := errors.New("detector unavailable")
	verdict, blocked := FailureOutcome(FailureModeEnforce, err)
	require.Equal(t, VerdictDeny, verdict)
	require.True(t, blocked)
	verdict, blocked = FailureOutcome(FailureModeShadow, err)
	require.Equal(t, VerdictAuditOnly, verdict)
	require.False(t, blocked)
	verdict, blocked = FailureOutcome(FailureModeOff, err)
	require.Equal(t, VerdictDeny, verdict, "an unexpected error cannot become allow in off mode")
	require.True(t, blocked)
	verdict, blocked = FailureOutcome(FailureModeEnforce, nil)
	require.Equal(t, VerdictAllow, verdict)
	require.False(t, blocked)
}

func TestBuiltinEvaluatorUsesVersionedSPI(t *testing.T) {
	credential := "sk-" + strings.Repeat("a", 26)
	evaluation, err := EvaluateBuiltins(Invocation{
		Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentArguments,
		Arguments: []byte(`{"token":"` + credential + `"}`),
	})
	require.NoError(t, err)
	require.Equal(t, RuntimeVersion, evaluation.Version)
	require.NotEmpty(t, evaluation.Findings)
	for _, finding := range evaluation.Findings {
		require.NotContains(t, finding.Detector, "sk-")
	}
}

func TestNewEvaluatorRejectsDuplicateVersionedRules(t *testing.T) {
	id := RuleVersion{PackID: "custom", PackVersion: "1", RuleID: "r", RuleVersion: "1"}
	_, err := NewEvaluator(testVersionedDetector{id: id}, testVersionedDetector{id: id})
	require.Error(t, err)
}

func TestEvaluatorRejectsDetectorSpanOutsideInput(t *testing.T) {
	id := RuleVersion{PackID: "custom", PackVersion: "1", RuleID: "bad-span", RuleVersion: "1"}
	evaluator, err := NewEvaluator(testVersionedDetector{id: id, findings: []Finding{{Start: 0, End: 4}}})
	require.NoError(t, err)
	_, err = evaluator.Evaluate(Invocation{
		Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "abc",
	})
	require.Error(t, err)
}

func TestHookApplyUsesCustomEvaluatorAndPropagatesFailure(t *testing.T) {
	id := RuleVersion{PackID: "custom", PackVersion: "1", RuleID: "r", RuleVersion: "1"}
	match := testVersionedDetector{id: id, findings: []Finding{{Category: CatSecret, Start: 0, End: 3, Confidence: 1}}}
	evaluator, err := NewEvaluator(match)
	require.NoError(t, err)
	hook := NewWithEvaluator(ModeDeny, evaluator)
	_, hits, err := hook.Apply("key")
	require.ErrorIs(t, err, ErrDenied)
	require.Len(t, hits, 1)

	failing, err := NewEvaluator(testVersionedDetector{id: id, err: errors.New("detector failed")})
	require.NoError(t, err)
	_, hits, err = NewWithEvaluator(ModeLog, failing).Apply("unavailable")
	require.NoError(t, err)
	require.Equal(t, []Hit{{Category: CatDetectorFailure, Outcome: OutcomeLog}}, hits)
}
