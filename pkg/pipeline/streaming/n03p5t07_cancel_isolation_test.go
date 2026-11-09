package streaming

// N03-P05-T07 boundary corpus (part 3): the gateway seam Runner (EngineRunner)
// under concurrent runs with independent contexts — the streaming lane of the
// stampede × cancel-isolation × lock-residue boundary.
//
// Pinned contract (runner.go docs + engine composition law 6):
//
//   - a shared engine serves concurrent runs with independent contexts;
//     cancelling one caller's context fails ONLY that run (fail-closed deny
//     via the step error path) and never blocks or corrupts another run —
//     the surviving run's verdict/trace equals a solo reference run;
//   - Run honors ctx: a cancelled run returns promptly (the gate step's
//     release channel would otherwise hold it for the whole test);
//   - the caller's payload is never modified across runs (engine clones);
//   - no cross-call state: each Run enters every compiled step exactly once.

import (
	"context"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gateStep blocks every run until release is closed or the run's context is
// done — one shared instance serves all concurrent runs through the factory,
// which is exactly the engine's step-sharing model.
type gateStep struct {
	release chan struct{}
	entries atomic.Int64
}

func (g *gateStep) Name() string { return "test/gate" }

func (g *gateStep) Run(ctx context.Context, _ *pipeline.Pipeline, _ *pipeline.Payload, out *pipeline.Result) error {
	g.entries.Add(1)
	select {
	case <-g.release:
		out.Findings = append(out.Findings, pipeline.Finding{
			Step: "gate", Category: "test", Severity: "info", Action: pipeline.ActionAllow,
		})
		return nil
	case <-ctx.Done():
		return ctx.Err() // fail-closed deny for THIS run only
	}
}

func t07GateEngine(release chan struct{}) (*pipeline.Engine, *gateStep) {
	gate := &gateStep{release: release}
	eng := pipeline.NewEngine()
	eng.Steps().MustRegister("test/gate", func(map[string]any) (pipeline.Step, error) {
		return gate, nil
	})
	return eng, gate
}

func t07GatePolicy(t *testing.T, eng *pipeline.Engine) pipeline.Compiled {
	t.Helper()
	pol := pipeline.Policy{
		APIVersion: pipeline.APIVersionYPP,
		Kind:       pipeline.KindPolicy,
		Name:       "t07-gate",
		Mode:       pipeline.ModeEnforce,
		Hooks:      []pipeline.Hook{pipeline.HookPreUpstream},
		Steps:      []pipeline.StepSpec{{ID: "gate", Detector: "test/gate"}},
	}
	c, err := eng.CompilePolicy(pol)
	require.NoError(t, err)
	return c
}

func t07Payload() *pipeline.Payload {
	return &pipeline.Payload{
		Kind:     pipeline.KindRequest,
		Endpoint: "chat",
		Messages: []pipeline.Message{{Role: "user", Content: "t07 boundary"}},
		Meta:     &pipeline.RequestMeta{Org: "org-t07", Key: "key-t07", Model: "m", Provider: "prov"},
	}
}

func TestN03P5T07_RunnerCancelIsolation_SharedEngineSurvives(t *testing.T) {
	release := make(chan struct{})
	eng, gate := t07GateEngine(release)
	compiled := t07GatePolicy(t, eng)
	runner := EngineRunner(eng, []pipeline.Compiled{compiled})

	pA, pB := t07Payload(), t07Payload()
	snapA, snapB := t07Payload(), t07Payload() // deep snapshots for the no-mutation pin

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()

	resA := make(chan *pipeline.Result, 1)
	resB := make(chan *pipeline.Result, 1)
	go func() { resA <- runner.Run(ctxA, pA) }()
	go func() { resB <- runner.Run(ctxB, pB) }()

	// Both runs reached the gate (2 entries) — the shared engine is serving
	// both concurrently.
	require.Eventually(t, func() bool { return gate.entries.Load() == 2 },
		5*time.Second, 2*time.Millisecond, "both runs never reached the shared gate")

	// Cancel A mid-run; B stays blocked and untouched.
	cancelA()
	select {
	case res := <-resA:
		require.NotNil(t, res)
		assert.Equal(t, pipeline.ActionDeny, res.Verdict,
			"a cancelled run must fail closed, got: %v", res.Verdict)
		found := false
		for _, tr := range res.Trace {
			if tr.Outcome == pipeline.StepError && strings.Contains(tr.Error, context.Canceled.Error()) {
				found = true
			}
		}
		assert.True(t, found, "cancelled run must trace the ctx error, got: %+v", res.Trace)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled run did not return: Run does not honor ctx")
	}

	// Release the gate: B completes normally.
	close(release)
	var refB *pipeline.Result
	select {
	case refB = <-resB:
	case <-time.After(5 * time.Second):
		t.Fatal("surviving run was disturbed by the cancelled sibling")
	}
	require.NotNil(t, refB)
	assert.Equal(t, pipeline.ActionAllow, refB.Verdict,
		"the surviving run must complete normally, got: %v (trace %+v)", refB.Verdict, refB.Trace)

	// Solo reference through the (now open) gate: B must equal it — no
	// cross-call state, no cancel bleed.
	solo := runner.Run(context.Background(), t07Payload())
	assert.Equal(t, solo.Verdict, refB.Verdict, "solo vs concurrent verdict")
	require.Len(t, refB.Trace, len(solo.Trace))
	for i := range solo.Trace {
		assert.Equal(t, solo.Trace[i].Step, refB.Trace[i].Step)
		assert.Equal(t, solo.Trace[i].Outcome, refB.Trace[i].Outcome)
	}
	assert.Equal(t, int64(3), gate.entries.Load(),
		"each Run enters the compiled step exactly once (no cross-call state)")

	// Caller payloads untouched (engine clones per run).
	assert.True(t, reflect.DeepEqual(snapA, pA), "run A must not modify the caller payload")
	assert.True(t, reflect.DeepEqual(snapB, pB), "run B must not modify the caller payload")
}
