package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRun_LinearPass(t *testing.T) {
	eng := registryFor(nil)
	pl := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "a", Detector: "builtin/noop"},
		StepSpec{ID: "b", Detector: "builtin/noop"},
		StepSpec{ID: "c", Detector: "builtin/noop"},
	))
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	if res.Verdict != ActionAllow {
		t.Errorf("verdict = %q, want allow", res.Verdict)
	}
	if res.Mutated != nil {
		t.Errorf("Mutated = %+v, want nil", res.Mutated)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %v, want none", res.Findings)
	}
	assertTraceComplete(t, res, pl)
	for _, id := range []string{"a", "b", "c"} {
		tr := traceOf(t, res, id)
		if tr.Outcome != StepRan {
			t.Errorf("step %q outcome = %q, want ran", id, tr.Outcome)
		}
		if tr.Duration < 0 {
			t.Errorf("step %q negative duration", id)
		}
		if tr.Error != "" {
			t.Errorf("step %q unexpected error %q", id, tr.Error)
		}
	}
}

func TestRun_DetectorSeesMutatedPayload(t *testing.T) {
	rec := &bodyRecorder{}
	eng := registryFor(map[string]Step{"test/rec": rec})
	pl := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "mut1", Mutator: "test/mutator"},
		StepSpec{ID: "rec", Detector: "test/rec"},
	))
	in := chatPayload()
	res := runPipelines(t, eng, []Compiled{pl}, in)

	bodies := rec.bodies()
	if len(bodies) != 1 || !strings.HasSuffix(bodies[0], "M") {
		t.Fatalf("detector saw body %q, want mutated (M suffix)", bodies)
	}
	if res.Mutated == nil || !strings.HasSuffix(string(res.Mutated.Body), "M") {
		t.Fatalf("Mutated = %+v, want payload with marker", res.Mutated)
	}
	// Law: the caller's payload is never modified.
	if strings.HasSuffix(string(in.Body), "M") {
		t.Fatal("caller payload was modified in place")
	}
}

func TestRun_MutatorChainOrder(t *testing.T) {
	rec := &bodyRecorder{}
	eng := registryFor(map[string]Step{"test/rec": rec})
	pl := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "mut1", Mutator: "test/mutator"},
		StepSpec{ID: "mut2", Mutator: "test/mutator"},
		StepSpec{ID: "rec", Detector: "test/rec"},
	))
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	if got := string(res.Mutated.Body); !strings.HasSuffix(got, "MM") {
		t.Errorf("final body = %q, want double marker", got)
	}
}

func TestRun_DenyShortCircuit(t *testing.T) {
	eng := registryFor(map[string]Step{"test/deny": detector("deny", ActionDeny)})
	pl := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "check", Detector: "builtin/noop"},
		StepSpec{ID: "deny", Detector: "test/deny"},
		StepSpec{ID: "after", Detector: "builtin/noop"},
	))
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	if res.Verdict != ActionDeny {
		t.Errorf("verdict = %q, want deny", res.Verdict)
	}
	assertTraceComplete(t, res, pl)
	if tr := traceOf(t, res, "deny"); tr.Outcome != StepRan {
		t.Errorf("deny step outcome = %q, want ran", tr.Outcome)
	}
	if tr := traceOf(t, res, "after"); tr.Outcome != StepSkipped || tr.Error != skipReasonDeny {
		t.Errorf("post-deny step = %+v, want skipped (%q)", tr, skipReasonDeny)
	}
}

func TestRun_ParallelJoin(t *testing.T) {
	starts, ends := newSyncMapInt64(), newSyncMapInt64()
	eng := registryFor(nil)
	eng.Steps().MustRegister("test/clock", func(params map[string]any) (Step, error) {
		return &clock{id: params["id"].(string), startN: starts, endN: ends}, nil
	})
	p := policyOf(ModeEnforce,
		StepSpec{ID: "head", Detector: "test/clock", Parallel: []string{"slow"}},
		StepSpec{ID: "slow", Detector: "test/clock"},
		StepSpec{ID: "after", Detector: "test/clock"},
	)
	p.Steps[0].Params = map[string]any{"id": "head"}
	p.Steps[1].Params = map[string]any{"id": "slow"}
	p.Steps[2].Params = map[string]any{"id": "after"}

	pl := mustCompileOf(t, eng, p)
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())
	assertTraceComplete(t, res, pl)

	if headEnd, afterStart := ends.Get("head"), starts.Get("after"); afterStart < headEnd {
		t.Errorf("after started at %d before head finished at %d — no join", afterStart, headEnd)
	}
	if slowEnd, afterStart := ends.Get("slow"), starts.Get("after"); afterStart < slowEnd {
		t.Errorf("after started at %d before slow member finished at %d — no join", afterStart, slowEnd)
	}
}

func TestRun_ParallelFindingsMergeDeclarationOrder(t *testing.T) {
	eng := registryFor(map[string]Step{
		"test/mask": detector("m2", ActionMask),
		"test/flag": detector("m3", ActionFlag),
	})
	p := policyOf(ModeEnforce,
		StepSpec{ID: "m2", Detector: "test/mask", Parallel: []string{"m3"}},
		StepSpec{ID: "m3", Detector: "test/flag"},
		StepSpec{ID: "tail", Detector: "builtin/noop"},
	)
	pl := mustCompileOf(t, eng, p)
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	if len(res.Findings) != 2 {
		t.Fatalf("findings = %v, want 2", res.Findings)
	}
	if res.Findings[0].Step != "m2" || res.Findings[1].Step != "m3" {
		t.Errorf("findings order = [%s, %s], want declaration order [m2, m3]",
			res.Findings[0].Step, res.Findings[1].Step)
	}
	if res.Verdict != ActionMask {
		t.Errorf("verdict = %q, want mask", res.Verdict)
	}
	assertTraceComplete(t, res, pl)
	// Trace order: head first, then member, then tail.
	if res.Trace[0].Step != "m2" || res.Trace[1].Step != "m3" {
		t.Errorf("trace order = [%s, %s], want [m2, m3]", res.Trace[0].Step, res.Trace[1].Step)
	}
}

func TestRun_StepTimeoutClips(t *testing.T) {
	eng := registryFor(map[string]Step{
		"test/slow": &sleeper{id: "slow", d: 200 * time.Millisecond},
	})
	p := policyOf(ModeEnforce,
		StepSpec{ID: "slow", Detector: "test/slow", Timeout: "5ms", OnError: OnErrorFailOpen},
		StepSpec{ID: "after", Detector: "builtin/noop"},
	)
	pl := mustCompileOf(t, eng, p)

	start := time.Now()
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())
	elapsed := time.Since(start)

	tr := traceOf(t, res, "slow")
	if tr.Outcome != StepTimeout {
		t.Errorf("outcome = %q, want timeout", tr.Outcome)
	}
	if tr.Error == "" {
		t.Error("timeout trace must carry the error message")
	}
	if tr.Duration > 100*time.Millisecond {
		t.Errorf("timeout clipped late: %v", tr.Duration)
	}
	// Bounded fuzzing of the clip: total run must not wait for the sleeper.
	if elapsed > time.Second {
		t.Errorf("run took %v — timeout did not bound the run", elapsed)
	}
	// fail_open: the run continues.
	if tr2 := traceOf(t, res, "after"); tr2.Outcome != StepRan {
		t.Errorf("post-timeout step = %q, want ran (fail_open)", tr2.Outcome)
	}
	if res.Verdict != ActionAllow {
		t.Errorf("verdict = %q, want allow (fail_open)", res.Verdict)
	}
}

func TestOnError_FailClosed(t *testing.T) {
	eng := registryFor(map[string]Step{"test/err": &errorStep{}})
	pl := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "boom", Detector: "test/err", OnError: OnErrorFailClosed},
		StepSpec{ID: "after", Detector: "builtin/noop"},
	))
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	if res.Verdict != ActionDeny {
		t.Errorf("verdict = %q, want deny", res.Verdict)
	}
	tr := traceOf(t, res, "boom")
	if tr.Outcome != StepError || !strings.Contains(tr.Error, "detector exploded") {
		t.Errorf("trace = %+v, want error with message", tr)
	}
	if tr2 := traceOf(t, res, "after"); tr2.Outcome != StepSkipped {
		t.Errorf("post-fail step = %q, want skipped", tr2.Outcome)
	}
	if len(res.Findings) != 0 {
		t.Errorf("fail_closed must not synthesize findings, got %v", res.Findings)
	}
}

func TestOnError_FailOpen(t *testing.T) {
	eng := registryFor(map[string]Step{"test/err": &errorStep{}})
	pl := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "boom", Detector: "test/err", OnError: OnErrorFailOpen},
		StepSpec{ID: "after", Detector: "builtin/noop"},
	))
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	if res.Verdict != ActionAllow {
		t.Errorf("verdict = %q, want allow", res.Verdict)
	}
	if tr := traceOf(t, res, "boom"); tr.Outcome != StepError || tr.Error == "" {
		t.Errorf("fail_open must still record the error: %+v", tr)
	}
	if tr := traceOf(t, res, "after"); tr.Outcome != StepRan {
		t.Errorf("fail_open must continue: %+v", tr)
	}
	if len(res.Findings) != 0 {
		t.Errorf("fail_open must not synthesize findings, got %v", res.Findings)
	}
}

func TestOnError_FailOpenFlag(t *testing.T) {
	eng := registryFor(map[string]Step{"test/err": &errorStep{}})
	pl := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "boom", Detector: "test/err", OnError: OnErrorFailOpenFlag},
		StepSpec{ID: "after", Detector: "builtin/noop"},
	))
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	if res.Verdict != ActionFlag {
		t.Errorf("verdict = %q, want flag", res.Verdict)
	}
	var flagged bool
	for _, f := range res.Findings {
		if f.Step == "boom" && f.Category == stepErrorCategory && f.Severity == stepErrorSeverity &&
			f.Action == ActionFlag && strings.Contains(f.Evidence, "detector exploded") {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("fail_open+flag must synthesize the flag finding, got %v", res.Findings)
	}
	if tr := traceOf(t, res, "after"); tr.Outcome != StepRan {
		t.Errorf("fail_open+flag must continue: %+v", tr)
	}
}

func TestRun_PanicRecovered(t *testing.T) {
	eng := registryFor(map[string]Step{"test/panic": &panicStep{}})
	pl := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "boom", Detector: "test/panic", OnError: OnErrorFailOpen},
		StepSpec{ID: "after", Detector: "builtin/noop"},
	))
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	tr := traceOf(t, res, "boom")
	if tr.Outcome != StepError || !strings.Contains(tr.Error, "panic in step: boom") {
		t.Fatalf("panic must be recorded: %+v", tr)
	}
	if tr2 := traceOf(t, res, "after"); tr2.Outcome != StepRan {
		t.Errorf("fail_open after panic must continue: %+v", tr2)
	}
}

func TestRun_WhenCondition(t *testing.T) {
	eng := registryFor(nil)
	eng.Scripts().MustRegister("test", newTestEngine().Compile)
	pl, err := eng.LoadPolicy([]byte(`
apiVersion: ypp/v1
kind: Policy
name: cond
mode: enforce
hooks: [pre_upstream]
steps:
  - id: never
    detector: builtin/noop
    when: "false"
  - id: always
    detector: builtin/noop
    when: "true"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	assertTraceComplete(t, res, pl)
	if tr := traceOf(t, res, "never"); tr.Outcome != StepSkipped {
		t.Errorf("false condition: outcome = %q, want skipped", tr.Outcome)
	}
	if tr := traceOf(t, res, "always"); tr.Outcome != StepRan {
		t.Errorf("true condition: outcome = %q, want ran", tr.Outcome)
	}
}

func TestRun_WhenEvalErrorFollowsOnError(t *testing.T) {
	eng := registryFor(nil)
	eng.Scripts().MustRegister("test", newTestEngine().Compile)
	src := strings.Replace(`
apiVersion: ypp/v1
kind: Policy
name: cond
mode: enforce
hooks: [pre_upstream]
steps:
  - id: cond_boom
    detector: builtin/noop
    when: "ERR"
    on_error: ONERR
  - id: after
    detector: builtin/noop
`, "ONERR", string(OnErrorFailClosed), 1)
	pl, err := eng.LoadPolicy([]byte(src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	res := runPipelines(t, eng, []Compiled{pl}, chatPayload())

	if res.Verdict != ActionDeny {
		t.Errorf("verdict = %q, want deny (fail_closed on when-error)", res.Verdict)
	}
	tr := traceOf(t, res, "cond_boom")
	if tr.Outcome != StepError || !strings.Contains(tr.Error, "when: eval failed") {
		t.Errorf("trace = %+v, want when-error recorded", tr)
	}
}

func TestRun_CompositionUnionAndMostRestrictive(t *testing.T) {
	eng := registryFor(map[string]Step{
		"test/flag": detector("flagger", ActionFlag),
		"test/mask": detector("shadow_masker", ActionMask),
	})
	engRaise := registryFor(map[string]Step{"decide": &verdictStep{action: ActionMask}})

	piFlag := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "flagger", Detector: "test/flag"},
	))
	// Shadow masker: its finding unions but must NOT raise the verdict.
	piShadow := mustCompileOf(t, eng, policyOf(ModeShadow,
		StepSpec{ID: "shadow_masker", Detector: "test/mask"},
	))
	piRaise := mustCompileOf(t, engRaise, policyOf(ModeEnforce,
		StepSpec{ID: "raiser", Decide: "x"},
	))

	res := runPipelines(t, eng, []Compiled{piFlag, piShadow, piRaise}, chatPayload())

	if res.Verdict != ActionMask {
		t.Errorf("verdict = %q, want mask (most restrictive of enforce contributions)", res.Verdict)
	}
	steps := map[string]bool{}
	for _, f := range res.Findings {
		steps[f.Step] = true
	}
	if !steps["flagger"] || !steps["shadow_masker"] {
		t.Errorf("findings must union across policies, got %v", res.Findings)
	}
	assertTraceComplete(t, res, piFlag, piShadow, piRaise)
}

func TestRun_CompositionDenyShortCircuitsLaterPolicies(t *testing.T) {
	eng := registryFor(map[string]Step{"test/deny": detector("denier", ActionDeny)})
	piDeny := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "denier", Detector: "test/deny"},
	))
	piLater := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "never_runs", Detector: "builtin/noop"},
	))
	res := runPipelines(t, eng, []Compiled{piDeny, piLater}, chatPayload())

	if res.Verdict != ActionDeny {
		t.Errorf("verdict = %q, want deny", res.Verdict)
	}
	assertTraceComplete(t, res, piDeny, piLater)
	if tr := traceOf(t, res, "never_runs"); tr.Outcome != StepSkipped || tr.Error != skipReasonDeny {
		t.Errorf("later policy step = %+v, want skipped after deny", tr)
	}
}

func TestRun_CompositionMutatorsApplyInPipelineOrder(t *testing.T) {
	// org-policy mutator runs first (caller order = attachment priority).
	orgMutEng := registryFor(nil)
	orgMutEng.Steps().MustRegister("test/orgmut", func(map[string]any) (Step, error) {
		return &mutatorStep{marker: "O"}, nil
	})
	keyMutEng := registryFor(nil)
	keyMutEng.Steps().MustRegister("test/keymut", func(map[string]any) (Step, error) {
		return &mutatorStep{marker: "K"}, nil
	})
	rec := &bodyRecorder{}
	recEng := registryFor(map[string]Step{"test/rec": rec})

	piOrg := mustCompileOf(t, orgMutEng, policyOf(ModeEnforce, StepSpec{ID: "org_mut", Mutator: "test/orgmut"}))
	piKey := mustCompileOf(t, keyMutEng, policyOf(ModeEnforce, StepSpec{ID: "key_mut", Mutator: "test/keymut"}))
	piRec := mustCompileOf(t, recEng, policyOf(ModeEnforce, StepSpec{ID: "rec", Detector: "test/rec"}))

	res := runPipelines(t, orgMutEng, []Compiled{piOrg, piKey, piRec}, chatPayload())

	// Detectors observe the latest mutated payload across policy boundaries.
	bodies := rec.bodies()
	if len(bodies) != 1 || !strings.HasSuffix(bodies[0], "OK") {
		t.Fatalf("final detector saw %q, want OK suffix (org then key mutator)", bodies)
	}
	if res.Mutated == nil || !strings.HasSuffix(string(res.Mutated.Body), "OK") {
		t.Fatalf("Mutated body = %+v, want OK", res.Mutated)
	}
}

func TestRun_ShadowNeverMutatesNeverDenies(t *testing.T) {
	rec := &bodyRecorder{}
	eng := registryFor(map[string]Step{
		"test/rec":  rec,
		"test/deny": detector("sh_deny", ActionDeny),
	})
	piShadow := mustCompileOf(t, eng, policyOf(ModeShadow,
		StepSpec{ID: "sh_mut", Mutator: "test/mutator"},
		StepSpec{ID: "sh_rec", Detector: "test/rec"},
		StepSpec{ID: "sh_deny", Detector: "test/deny"},
	))
	piEnforce := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "noop", Detector: "builtin/noop"},
	))
	in := chatPayload()
	res := runPipelines(t, eng, []Compiled{piShadow, piEnforce}, in)

	if res.Verdict != ActionAllow {
		t.Errorf("verdict = %q, want allow (shadow never denies)", res.Verdict)
	}
	if res.Mutated != nil {
		t.Errorf("Mutated = %+v, want nil (shadow never mutates)", res.Mutated)
	}
	var denyFinding bool
	for _, f := range res.Findings {
		if f.Step == "sh_deny" && f.Action == ActionDeny {
			denyFinding = true
		}
	}
	if !denyFinding {
		t.Errorf("shadow findings must be recorded, got %v", res.Findings)
	}
	// Shadow mutators DO apply to the shadow's own clone: its detectors see
	// the mutated text (that is what the "what would have happened" report
	// needs) — but the clone is discarded afterwards.
	if bodies := rec.bodies(); len(bodies) != 1 || !strings.HasSuffix(bodies[0], "M") {
		t.Errorf("shadow-internal detector should see the mutated clone: %q", bodies)
	}
	if strings.HasSuffix(string(in.Body), "M") {
		t.Error("caller payload modified by shadow run")
	}
}

func TestRun_ShadowInternalDenyShortCircuitsOwnSteps(t *testing.T) {
	eng := registryFor(map[string]Step{"test/deny": detector("sh_deny", ActionDeny)})
	piShadow := mustCompileOf(t, eng, policyOf(ModeShadow,
		StepSpec{ID: "sh_deny", Detector: "test/deny"},
		StepSpec{ID: "sh_late", Detector: "builtin/noop"},
	))
	res := runPipelines(t, eng, []Compiled{piShadow}, chatPayload())

	assertTraceComplete(t, res, piShadow)
	if tr := traceOf(t, res, "sh_late"); tr.Outcome != StepSkipped {
		t.Errorf("shadow internal deny must skip own remaining steps: %+v", tr)
	}
	if res.Verdict != ActionAllow {
		t.Errorf("internal shadow deny must not leak: verdict = %q", res.Verdict)
	}
}

// CORE-TRACE-05: the shadow would-have verdict must be explicit. A shadow
// deny keeps the composed verdict at allow while ShadowVerdict records the
// action enforce mode would have taken — including an explicit step verdict,
// which raises no finding and therefore cannot be reconstructed from
// findings alone.
func TestRun_ShadowWouldHaveVerdictRecorded(t *testing.T) {
	t.Run("detector deny", func(t *testing.T) {
		eng := registryFor(map[string]Step{"test/deny": detector("sh_deny", ActionDeny)})
		piShadow := mustCompileOf(t, eng, policyOf(ModeShadow,
			StepSpec{ID: "sh_deny", Detector: "test/deny"},
			StepSpec{ID: "sh_late", Detector: "builtin/noop"},
		))
		res := runPipelines(t, eng, []Compiled{piShadow}, chatPayload())

		if res.Verdict != ActionAllow {
			t.Errorf("verdict = %q, want allow (shadow never denies)", res.Verdict)
		}
		if got := res.ShadowAction(); got != ActionDeny {
			t.Errorf("ShadowVerdict = %q, want deny (would-have action)", got)
		}
	})
	t.Run("explicit step verdict without findings", func(t *testing.T) {
		eng := registryFor(map[string]Step{"decide": &verdictStep{action: ActionMask}})
		piShadow := mustCompileOf(t, eng, policyOf(ModeShadow,
			StepSpec{ID: "decider", Decide: "mask"},
		))
		res := runPipelines(t, eng, []Compiled{piShadow}, chatPayload())

		if res.Verdict != ActionAllow {
			t.Errorf("verdict = %q, want allow", res.Verdict)
		}
		if len(res.Findings) != 0 {
			t.Errorf("findings = %v, want none (explicit verdict raises no finding)", res.Findings)
		}
		if got := res.ShadowAction(); got != ActionMask {
			t.Errorf("ShadowVerdict = %q, want mask (findings cannot reconstruct this)", got)
		}
	})
	t.Run("enforce leaves shadow verdict at allow", func(t *testing.T) {
		eng := registryFor(map[string]Step{"test/deny": detector("denier", ActionDeny)})
		pi := mustCompileOf(t, eng, policyOf(ModeEnforce,
			StepSpec{ID: "denier", Detector: "test/deny"},
		))
		res := runPipelines(t, eng, []Compiled{pi}, chatPayload())

		if res.Verdict != ActionDeny {
			t.Errorf("verdict = %q, want deny", res.Verdict)
		}
		if got := res.ShadowAction(); got != ActionAllow {
			t.Errorf("ShadowVerdict = %q, want allow (no shadow pipeline ran)", got)
		}
	})
	t.Run("mixed accumulate most restrictive shadow action", func(t *testing.T) {
		eng := registryFor(map[string]Step{
			"test/flag": detector("flagger", ActionFlag),
			"test/mask": detector("sh_masker", ActionMask),
		})
		piEnforce := mustCompileOf(t, eng, policyOf(ModeEnforce,
			StepSpec{ID: "flagger", Detector: "test/flag"},
		))
		piShadow := mustCompileOf(t, eng, policyOf(ModeShadow,
			StepSpec{ID: "sh_masker", Detector: "test/mask"},
		))
		res := runPipelines(t, eng, []Compiled{piEnforce, piShadow}, chatPayload())

		if res.Verdict != ActionFlag {
			t.Errorf("verdict = %q, want flag (shadow must not raise)", res.Verdict)
		}
		if got := res.ShadowAction(); got != ActionMask {
			t.Errorf("ShadowVerdict = %q, want mask (most restrictive shadow would-have)", got)
		}
	})
	t.Run("zero value result reads as allow", func(t *testing.T) {
		var r Result
		if got := r.ShadowAction(); got != ActionAllow {
			t.Errorf("zero-result ShadowAction = %q, want allow", got)
		}
		var rp *Result
		if got := rp.ShadowAction(); got != ActionAllow {
			t.Errorf("nil-result ShadowAction = %q, want allow", got)
		}
	})
}

func TestRun_DecideRaisesVerdictOnlyUpward(t *testing.T) {
	eng := registryFor(map[string]Step{
		"test/mask": detector("masker", ActionMask),
		"decide":    &verdictStep{action: ActionAllow},
	})
	pi := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "masker", Detector: "test/mask"},
		StepSpec{ID: "decider", Decide: "allow"},
	))
	res := runPipelines(t, eng, []Compiled{pi}, chatPayload())

	if res.Verdict != ActionMask {
		t.Errorf("verdict = %q, want mask (a step cannot lower the verdict)", res.Verdict)
	}
}

func TestRun_NilPayloadFailsClosed(t *testing.T) {
	eng := registryFor(nil)
	pi := mustCompileOf(t, eng, policyOf(ModeEnforce, StepSpec{ID: "a", Detector: "builtin/noop"}))
	res := runPipelines(t, eng, []Compiled{pi}, nil)

	if res.Verdict != ActionDeny {
		t.Errorf("verdict = %q, want deny", res.Verdict)
	}
	if len(res.Trace) != 1 || res.Trace[0].Outcome != StepError {
		t.Errorf("trace = %+v, want single engine error entry", res.Trace)
	}
}

func TestRun_NoPipelinesAllows(t *testing.T) {
	eng := registryFor(nil)
	res := runPipelines(t, eng, nil, chatPayload())
	if res.Verdict != ActionAllow || res.Mutated != nil || len(res.Trace) != 0 {
		t.Errorf("empty composition = %+v, want pristine allow", res)
	}
}

func TestRun_CancelledContextSkipsRemaining(t *testing.T) {
	eng := registryFor(nil)
	pi := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "a", Detector: "builtin/noop"},
		StepSpec{ID: "b", Detector: "builtin/noop"},
	))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := eng.Run(ctx, []Compiled{pi}, chatPayload())

	assertTraceComplete(t, res, pi)
	for _, id := range []string{"a", "b"} {
		tr := traceOf(t, res, id)
		if tr.Outcome != StepSkipped || !strings.Contains(tr.Error, "context canceled") {
			t.Errorf("step %q = %+v, want skipped with context reason", id, tr)
		}
	}
	if res.Verdict != ActionAllow {
		t.Errorf("verdict = %q, want allow (cancellation is not a policy denial)", res.Verdict)
	}
}

func TestRun_ConcurrentRunsAreIsolated(t *testing.T) {
	eng := registryFor(nil)
	pi := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "mut", Mutator: "test/mutator"},
		StepSpec{ID: "det", Detector: "builtin/noop"},
	))
	in := chatPayload()

	done := make(chan *Result, 16)
	for i := 0; i < 16; i++ {
		go func() { done <- eng.Run(context.Background(), []Compiled{pi}, in) }()
	}
	for i := 0; i < 16; i++ {
		res := <-done
		if res.Mutated == nil || string(res.Mutated.Body) != string(in.Body)+"M" {
			t.Fatalf("concurrent run produced %+v", res.Mutated)
		}
	}
	if string(in.Body) != `{"model":"m"}` {
		t.Fatalf("caller payload corrupted: %q", in.Body)
	}
}

func TestRun_TraceDurationsRecorded(t *testing.T) {
	eng := registryFor(map[string]Step{"test/slow": &sleeper{id: "slow", d: 15 * time.Millisecond}})
	eng.Scripts().MustRegister("test", newTestEngine().Compile)
	pi := mustCompileOf(t, eng, policyOf(ModeEnforce,
		StepSpec{ID: "slow", Detector: "test/slow"},
		StepSpec{ID: "skip", Detector: "builtin/noop", When: "false", WhenEngine: "test"},
	))
	res := runPipelines(t, eng, []Compiled{pi}, chatPayload())

	if tr := traceOf(t, res, "slow"); tr.Duration < 10*time.Millisecond {
		t.Errorf("duration = %v, want ≥ ~15ms", tr.Duration)
	}
	tr := traceOf(t, res, "skip")
	if tr.Outcome != StepSkipped || tr.Duration < 0 {
		t.Errorf("skipped trace = %+v", tr)
	}
}
