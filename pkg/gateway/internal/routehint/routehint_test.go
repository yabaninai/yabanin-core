package routehint

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// compile registers the factory on a fresh engine and compiles a one-step
// route_hint policy in the given mode (the real load path).
func compile(t *testing.T, mode, target string) (pipeline.Compiled, *pipeline.Engine) {
	t.Helper()
	eng := pipeline.NewEngine()
	require.NoError(t, eng.Steps().Register(FactoryName, Factory))
	yaml := "apiVersion: ypp/v1\nkind: Policy\nname: hint-policy\nmode: " + mode +
		"\nhooks:\n  - pre_upstream\nsteps:\n  - id: hint\n    route_hint: " + target + "\n"
	compiled, err := eng.LoadPolicy([]byte(yaml))
	require.NoError(t, err)
	return compiled, eng
}

func runStep(t *testing.T, mode, target string, ctx context.Context) (*pipeline.Result, *Sink) {
	t.Helper()
	compiled, eng := compile(t, mode, target)
	sink := &Sink{}
	res := eng.Run(WithSink(ctx, sink), []pipeline.Compiled{compiled}, &pipeline.Payload{Kind: pipeline.KindRequest})
	return res, sink
}

// Factory: the reserved target param is required (LOAD failure, fail-closed).
func TestFactory_RequiresTarget(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"missing": {},
		"empty":   {"target": ""},
		"blank":   {"target": "   "},
		"non-str": {"target": 42},
	} {
		_, err := Factory(params)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "target is required", name)
	}
}

// The load path trims the target (the core passes the YAML value through).
func TestFactory_TrimsTarget(t *testing.T) {
	s, err := Factory(map[string]any{"target": "  anthropic  "})
	require.NoError(t, err)
	require.IsType(t, &step{}, s)
	assert.Equal(t, "anthropic", s.(*step).target)
}

// Enforce + sink: the hint is recorded and an allow-ranked finding is
// appended; the verdict stays allow.
func TestRun_RecordsHintAndFinding(t *testing.T) {
	res, sink := runStep(t, "enforce", "anthropic", context.Background())

	assert.Equal(t, "anthropic", sink.Hint())
	require.Len(t, res.Findings, 1)
	f := res.Findings[0]
	assert.Equal(t, "hint", f.Step)
	assert.Equal(t, FindingCategory, f.Category)
	assert.Equal(t, "anthropic", f.Evidence)
	assert.Equal(t, pipeline.ActionAllow, f.Action)
	assert.Equal(t, pipeline.ActionAllow, res.Verdict, "hint must never raise the verdict")
	require.Len(t, res.Trace, 1)
	assert.Equal(t, string(pipeline.StepRan), string(res.Trace[0].Outcome))
}

// Shadow-mode policies must never influence routing.
func TestRun_ShadowModeNoop(t *testing.T) {
	res, sink := runStep(t, "shadow", "anthropic", context.Background())

	assert.Empty(t, sink.Hint())
	assert.Empty(t, res.Findings)
	assert.Equal(t, pipeline.ActionAllow, res.Verdict)
}

// Without a sink (other hooks, runtime off, direct engine use) the step is a
// no-op.
func TestRun_NoSinkNoop(t *testing.T) {
	compiled, eng := compile(t, "enforce", "anthropic")
	res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, &pipeline.Payload{Kind: pipeline.KindRequest})

	assert.Empty(t, res.Findings)
	assert.Equal(t, pipeline.ActionAllow, res.Verdict)
}

// The first recorded hint wins — a later policy cannot silently override the
// highest-priority hint.
func TestSink_FirstHintWins(t *testing.T) {
	sink := &Sink{}
	sink.Record("anthropic")
	sink.Record("openai")
	assert.Equal(t, "anthropic", sink.Hint())
}

// Concurrent Record calls are safe and keep the already-recorded hint.
func TestSink_ConcurrentRecordKeepsFirst(t *testing.T) {
	sink := &Sink{}
	sink.Record("anthropic")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sink.Record("openai")
		}()
	}
	wg.Wait()
	assert.Equal(t, "anthropic", sink.Hint())
}

// Nil sinks and empty targets are no-ops.
func TestSink_NilAndEmptySafe(t *testing.T) {
	var sink *Sink
	sink.Record("anthropic")
	assert.Empty(t, sink.Hint())

	s := &Sink{}
	s.Record("")
	assert.Empty(t, s.Hint())
}

// Context round-trip for sink and hint values.
func TestContextRoundTrip(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, SinkFrom(ctx))
	assert.Empty(t, HintFrom(ctx))

	sink := &Sink{}
	ctx = WithSink(ctx, sink)
	assert.Same(t, sink, SinkFrom(ctx))

	ctx = WithHint(ctx, "anthropic")
	assert.Equal(t, "anthropic", HintFrom(ctx))
}

func TestContextNilSafe(t *testing.T) {
	assert.Nil(t, SinkFrom(context.TODO()))
	assert.Empty(t, HintFrom(context.TODO()))
}
