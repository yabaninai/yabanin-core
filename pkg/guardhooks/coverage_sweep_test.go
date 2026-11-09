package guardhooks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type coverageSweepDetector struct {
	id       RuleVersion
	findings []Finding
	err      error
}

type coverageSweepTextDetector struct{}

func (coverageSweepTextDetector) Name() string { return "coverage:text" }

func (coverageSweepTextDetector) Detect(string) []Finding { return nil }

func (d coverageSweepDetector) Identity() RuleVersion { return d.id }

func (d coverageSweepDetector) Detect(Invocation) ([]Finding, error) {
	return d.findings, d.err
}

func coverageSweepRule(rule string) RuleVersion {
	return RuleVersion{PackID: "coverage", PackVersion: "1", RuleID: rule, RuleVersion: "1"}
}

func TestHookApplyModesAndNoopPaths(t *testing.T) {
	secret := "sk-" + strings.Repeat("a", 16) + "12345678"
	var nilHook *Hook
	mutated, hits, err := nilHook.Apply("secret " + secret)
	require.NoError(t, err)
	require.Nil(t, mutated)
	require.Nil(t, hits)
	require.False(t, New(ModeOff).Enabled())
	require.Equal(t, ModeOff, New(ModeOff).Mode())
	require.True(t, New(ModeLog).Enabled())
	require.Equal(t, ModeLog, New(ModeLog).Mode())

	mutated, hits, err = New(ModeOff).Apply("secret " + secret)
	require.NoError(t, err)
	require.Nil(t, mutated)
	require.Nil(t, hits)

	for _, mode := range []Mode{ModeLog, ModeRedact, ModeDeny} {
		mutated, hits, err = New(mode).Apply("ordinary text")
		require.NoError(t, err)
		require.Nil(t, mutated)
		require.Empty(t, hits)
	}

	input := "credential: " + secret
	mutated, hits, err = New(ModeLog).Apply(input)
	require.NoError(t, err)
	require.Nil(t, mutated)
	require.NotEmpty(t, hits)
	require.Equal(t, OutcomeLog, hits[0].Outcome)

	mutated, hits, err = New(ModeRedact).Apply(input)
	require.NoError(t, err)
	require.NotEmpty(t, hits)
	require.Contains(t, string(mutated), "[REDACTED_SECRET]")
	require.NotContains(t, string(mutated), secret)
}

func TestHookFiltersLowConfidenceAndInvalidINNFindings(t *testing.T) {
	evaluator, err := NewEvaluator(
		coverageSweepDetector{
			id:       coverageSweepRule("low-confidence"),
			findings: []Finding{{Category: CatEmail, Start: 0, End: 3, Confidence: 0.8}},
		},
	)
	require.NoError(t, err)
	mutated, hits, err := NewWithEvaluator(ModeDeny, evaluator).Apply("abc")
	require.NoError(t, err)
	require.Nil(t, mutated)
	require.Empty(t, hits)

	evaluator, err = NewEvaluator(coverageSweepDetector{
		id:       coverageSweepRule("ru:inn10"),
		findings: []Finding{{Category: CatINNSNILS, Start: 0, End: 10, Confidence: 1, Detector: "ru:inn10"}},
	})
	require.NoError(t, err)
	mutated, hits, err = NewWithEvaluator(ModeDeny, evaluator).Apply("1234567890")
	require.NoError(t, err)
	require.Nil(t, mutated)
	require.Empty(t, hits)
}

func TestInvocationContentValidationAndKinds(t *testing.T) {
	cases := []struct {
		name string
		in   Invocation
		want string
		bad  bool
	}{
		{name: "text", in: Invocation{Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "plain"}, want: "plain"},
		{name: "arguments", in: Invocation{Version: RuntimeVersion, Phase: PhaseAfter, Kind: ContentArguments, Arguments: []byte("args")}, want: "args"},
		{name: "result", in: Invocation{Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentResult, Result: []byte("result")}, want: "result"},
		{name: "bad-version", in: Invocation{Version: "future", Phase: PhaseBefore, Kind: ContentText}, bad: true},
		{name: "bad-phase", in: Invocation{Version: RuntimeVersion, Phase: "during", Kind: ContentText}, bad: true},
		{name: "bad-kind", in: Invocation{Version: RuntimeVersion, Phase: PhaseAfter, Kind: "binary"}, bad: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.in.Content()
			if tc.bad {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestNewEvaluatorValidationAndDeterministicOrdering(t *testing.T) {
	_, err := NewEvaluator(nil)
	require.Error(t, err)
	_, err = NewEvaluator(coverageSweepDetector{id: RuleVersion{PackID: "coverage"}})
	require.Error(t, err)

	a := coverageSweepDetector{id: coverageSweepRule("a")}
	b := coverageSweepDetector{id: coverageSweepRule("b")}
	evaluator, err := NewEvaluator(b, a)
	require.NoError(t, err)
	require.Equal(t, "a", evaluator.detectors[0].Identity().RuleID)
	require.Equal(t, "b", evaluator.detectors[1].Identity().RuleID)

	ordered, err := NewEvaluator(
		coverageSweepDetector{id: RuleVersion{PackID: "z", PackVersion: "1", RuleID: "same", RuleVersion: "1"}},
		coverageSweepDetector{id: RuleVersion{PackID: "a", PackVersion: "1", RuleID: "same", RuleVersion: "1"}},
		coverageSweepDetector{id: RuleVersion{PackID: "a", PackVersion: "1", RuleID: "same", RuleVersion: "2"}},
	)
	require.NoError(t, err)
	require.Equal(t, "a", ordered.detectors[0].Identity().PackID)
	require.Equal(t, "2", ordered.detectors[1].Identity().RuleVersion)
	require.Equal(t, "z", ordered.detectors[2].Identity().PackID)
}

func TestEvaluatorRejectsNilContextAndCancellation(t *testing.T) {
	evaluator, err := NewEvaluator(coverageSweepDetector{id: coverageSweepRule("cancel")})
	require.NoError(t, err)
	_, err = evaluator.Evaluate(Invocation{Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText})
	require.Error(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = evaluator.Evaluate(Invocation{Context: ctx, Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText})
	require.ErrorIs(t, err, context.Canceled)

	_, err = EvaluateBuiltins(Invocation{Context: ctx, Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText})
	require.ErrorIs(t, err, context.Canceled)

	_, err = EvaluateBuiltins(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: "invalid", Kind: ContentText})
	require.Error(t, err)
}

func TestHookScanReturnsNoHitsOnEvaluatorFailure(t *testing.T) {
	evaluator, err := NewEvaluator(coverageSweepDetector{
		id:  coverageSweepRule("scan-error"),
		err: errors.New("scan failed"),
	})
	require.NoError(t, err)
	require.Nil(t, NewWithEvaluator(ModeLog, evaluator).Scan("anything"))
}

func TestBuiltinAdapterAndCredentialDetectorValidation(t *testing.T) {
	adapter := builtinAdapter{Detector: coverageSweepTextDetector{}}
	_, err := adapter.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: "invalid", Kind: ContentText})
	require.Error(t, err)
	_, err = adapter.Detect(Invocation{Context: canceledCoverageContext(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText})
	require.ErrorIs(t, err, context.Canceled)

	_, err = (credentialKeyDetector{}).Detect(Invocation{Context: canceledCoverageContext(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText})
	require.ErrorIs(t, err, context.Canceled)
	_, err = (credentialKeyDetector{}).Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: "invalid", Kind: ContentText})
	require.Error(t, err)

	hook := NewWithEvaluator(ModeLog, nil)
	require.NotEmpty(t, hook.Scan(`{"api_key":"private-value"}`))
}

func canceledCoverageContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestEvaluatorRejectsMalformedFindingSpans(t *testing.T) {
	for _, span := range []Finding{
		{Start: -1, End: 0},
		{Start: 2, End: 1},
		{Start: 0, End: 4},
	} {
		evaluator, err := NewEvaluator(coverageSweepDetector{
			id:       coverageSweepRule("bad-span"),
			findings: []Finding{span},
		})
		require.NoError(t, err)
		_, err = evaluator.Evaluate(Invocation{
			Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "abc",
		})
		require.Error(t, err)
	}
}

func TestRuntimeApplyVerdictsAndValidation(t *testing.T) {
	evaluation := Evaluation{Version: RuntimeVersion, Findings: []Finding{{Category: CatSecret}}}
	for _, action := range []Verdict{VerdictAllow, VerdictAuditOnly} {
		output, verdict, err := Apply(evaluation, action, nil)
		require.NoError(t, err)
		require.Nil(t, output)
		require.Equal(t, action, verdict)
	}
	output, verdict, err := Apply(evaluation, VerdictDeny, nil)
	require.NoError(t, err)
	require.Nil(t, output)
	require.Equal(t, VerdictDeny, verdict)

	calls := 0
	output, verdict, err = Apply(evaluation, VerdictRedact, func() []byte {
		calls++
		return []byte("masked")
	})
	require.NoError(t, err)
	require.Equal(t, []byte("masked"), output)
	require.Equal(t, VerdictRedact, verdict)
	require.Equal(t, 1, calls)

	output, verdict, err = Apply(Evaluation{Version: RuntimeVersion}, VerdictRedact, nil)
	require.NoError(t, err)
	require.Nil(t, output)
	require.Equal(t, VerdictAllow, verdict)
	_, _, err = Apply(Evaluation{Version: "future"}, VerdictAllow, nil)
	require.Error(t, err)
	_, _, err = Apply(evaluation, "unknown", nil)
	require.Error(t, err)

	_, err = (*Evaluator)(nil).Evaluate(Invocation{Context: context.Background()})
	require.Error(t, err)

	failing, err := NewEvaluator(coverageSweepDetector{id: coverageSweepRule("failure"), err: errors.New("detector unavailable")})
	require.NoError(t, err)
	_, err = failing.Evaluate(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText})
	require.ErrorContains(t, err, "detector unavailable")
}
