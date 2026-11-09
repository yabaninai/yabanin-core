package streaming

// N03-P03-T10 independent invariant verification (packet card: «Проверить
// права, ограничение ресурсов, данные и отрицательный сценарий; закрыть
// actionable findings»). T05 proved the carry split space, T06 the joint
// stream, T07 the boundaries, T08 the recovery, T09 the consumer views; this
// file re-derives the same guarantees from the RISK side, as four independent
// invariant groups, each stated so a violation fails loudly:
//
//   - RIGHTS: the final stage can never deny for any engine-reachable verdict
//     nor any infrastructure failure (deny degrades to flag, the true verdict
//     stays visible); the prefix stage fails closed on every infrastructure
//     path (dead ctx, no runner, runner without a result, nil engine) and
//     releases nothing unverified; the policy rights compose with deny
//     dominance — a flag observes without withholding, a mask rewrites, only
//     a deny withholds, and deny wins over mask on the same buffer;
//   - RESOURCES: the carry hold-back stays within maxLen-1 over a long
//     adversarial tease stream — the bound is independent of stream length,
//     so no adversary can grow the buffer by teasing; the prefix hold is
//     bounded by its config under every parameter set ParsePrefixParams can
//     produce (explicit zeros map to the defaults — a policy can tighten a
//     threshold but never disable one) and goes inert after the decision; the
//     final aggregate absorbs noise frames without growth and merges tool
//     fragments instead of accumulating them;
//   - DATA: a seeded randomized adversary (deterministic PCG corpus) drives
//     the full production chain and the raw primitive — zero reveal of the
//     forbidden spans in every consumer view (decoded client view, raw wire
//     bytes, final audit document), audit parity (the audit sees exactly what
//     shipped), old-vs-new upgrade drift confined to the defined
//     replacements; the mutation domain is choices[0].delta.content only —
//     reasoning and tool-call fragments ride untouched, and the final audit
//     still sees them (observe, flag — never recall);
//   - NEGATIVE: no promise about future tokens — the prefix threshold cannot
//     be stretched by pending-match content (a partial trigger ships at the
//     threshold; the completing tail is only ever seen by the flag backstop),
//     the tease stream releases the incomplete head verbatim at end-of-stream,
//     and a contiguous-span detector does not fire on it.
//
// Findings status of this verification is recorded in the delivery record;
// existing coverage is cited instead of duplicated: the exhaustive split
// space (chunkspans corpus), the hold-bound defect it exposed and its fix,
// the release boundary (n03p3t07), post-release gate inertness
// (TestAdversarial_PostRelease_NoFutureTokenPromise), the consumer-boundary
// negative (n03p3t09), and the constructor refusal surfaces.
//
// Stable IDs: n03p3t10-*.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// n03p3t10VerdictRunner adapts a fixed verdict as the Runner seam result —
// the table drives FinalCheck over every engine-reachable composed verdict
// plus the infrastructure failure shapes.
func n03p3t10VerdictRunner(v pipeline.Action, res **pipeline.Result) Runner {
	return RunnerFunc(func(context.Context, *pipeline.Payload) *pipeline.Result {
		if res != nil {
			return *res
		}
		return &pipeline.Result{Verdict: v}
	})
}

// TestN03P3T10_Rights_FinalStageNeverDenies: for every engine-reachable
// composed verdict and every infrastructure failure the effective action of
// the post-issuance check stays in {allow, flag, mask} — never deny. Deny
// degrades to flag (delivered bytes cannot be recalled) while Result keeps
// the true verdict for the decision-log; infrastructure failures degrade to
// flag with Err set so observability sees the gap.
func TestN03P3T10_Rights_FinalStageNeverDenies(t *testing.T) {
	fa := func() *FinalAggregate {
		agg := NewFinalAggregate()
		agg.AddFrame(chunkFrame(t, "c1", "content under audit"))
		return agg
	}
	denyReal := t08FinalDenyRunner(t, "content") // a REAL compiled deny that will fire

	tests := []struct {
		name      string
		runner    Runner
		ctx       context.Context
		agg       *FinalAggregate
		wantEff   pipeline.Action
		wantErr   bool
		wantVerdz bool // Result must preserve the true (deny) verdict
	}{
		{name: "verdict allow stays allow", runner: n03p3t10VerdictRunner(pipeline.ActionAllow, nil),
			ctx: context.Background(), agg: fa(), wantEff: pipeline.ActionAllow},
		{name: "verdict flag stays flag", runner: n03p3t10VerdictRunner(pipeline.ActionFlag, nil),
			ctx: context.Background(), agg: fa(), wantEff: pipeline.ActionFlag},
		{name: "verdict mask stays mask", runner: n03p3t10VerdictRunner(pipeline.ActionMask, nil),
			ctx: context.Background(), agg: fa(), wantEff: pipeline.ActionMask},
		{name: "verdict deny degrades to flag", runner: n03p3t10VerdictRunner(pipeline.ActionDeny, nil),
			ctx: context.Background(), agg: fa(), wantEff: pipeline.ActionFlag, wantVerdz: true},
		{name: "real compiled deny degrades to flag", runner: denyReal,
			ctx: context.Background(), agg: fa(), wantEff: pipeline.ActionFlag, wantVerdz: true},
		{name: "runner without a result flags with error", runner: n03p3t10VerdictRunner(pipeline.ActionAllow, new(*pipeline.Result)),
			ctx: context.Background(), agg: fa(), wantEff: pipeline.ActionFlag, wantErr: true},
		{name: "nil runner flags with error", runner: nil,
			ctx: context.Background(), agg: fa(), wantEff: pipeline.ActionFlag, wantErr: true},
		{name: "cancelled context flags with error and skips policies", runner: denyReal,
			ctx: func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }(),
			agg: fa(), wantEff: pipeline.ActionFlag, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := FinalCheck(tc.ctx, tc.runner, tc.agg, nil, "chat")
			if out.Effective == pipeline.ActionDeny {
				t.Fatalf("effective = deny — the post-issuance stage must never deny: %+v", out)
			}
			if out.Effective != tc.wantEff {
				t.Fatalf("effective = %q, want %q (+err=%v: %v)", out.Effective, tc.wantEff, tc.wantErr, out.Err)
			}
			if (out.Err != nil) != tc.wantErr {
				t.Fatalf("Err = %v, wantErr = %v", out.Err, tc.wantErr)
			}
			if tc.wantVerdz {
				if out.Result == nil || out.Result.Verdict != pipeline.ActionDeny {
					t.Fatalf("the true deny verdict must stay visible in Result: %+v", out.Result)
				}
			}
			if out.Document == nil {
				t.Fatal("the audit document must be delivered even when the check degrades")
			}
		})
	}
}

// TestN03P3T10_Rights_PrefixFailClosed: every infrastructure failure of the
// prefix stage aborts — unverified buffered content is never forwarded. The
// dead-context guard precedes the engine (a runner that records invocation
// proves the policies never run on a dead ctx), a runner without a result
// aborts, a missing runner aborts, and the nil-engine adapter fail-closes
// with a deny verdict instead of panicking.
func TestN03P3T10_Rights_PrefixFailClosed(t *testing.T) {
	invoked := 0
	counting := RunnerFunc(func(context.Context, *pipeline.Payload) *pipeline.Result {
		invoked++
		return &pipeline.Result{Verdict: pipeline.ActionAllow}
	})
	nilResult := new(*pipeline.Result) // a *pipeline.Result variable holding nil
	deadCtx := func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }()

	tests := []struct {
		name  string
		cfg   PrefixConfig
		ctx   context.Context
		wantE bool // Err set (infrastructure failure) vs deny-verdict abort
	}{
		{name: "dead context aborts before any policy run", cfg: PrefixConfig{Runner: counting}, ctx: deadCtx, wantE: true},
		{name: "missing runner with a live context aborts", cfg: PrefixConfig{}, ctx: context.Background(), wantE: true},
		{name: "runner returning no result aborts", cfg: PrefixConfig{Runner: n03p3t10VerdictRunner(pipeline.ActionAllow, nilResult)},
			ctx: context.Background(), wantE: true},
		{name: "nil engine adapter fails closed with deny", cfg: PrefixConfig{Runner: EngineRunner(nil, nil)},
			ctx: context.Background(), wantE: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewPrefixGate(tc.cfg)
			g.Ingest("payload that would pass an honest engine")
			out := g.Flush(tc.ctx)
			if out.Decision != PrefixAbort {
				t.Fatalf("decision = %q, want fail-closed abort", out.Decision)
			}
			if out.Text != "" {
				t.Fatalf("aborted buffer leaked %q", out.Text)
			}
			if (out.Err != nil) != tc.wantE {
				t.Fatalf("Err = %v, wantErr = %v", out.Err, tc.wantE)
			}
			if !tc.wantE {
				if out.Result == nil || out.Result.Verdict != pipeline.ActionDeny {
					t.Fatalf("nil-engine abort must carry the deny verdict: %+v", out.Result)
				}
			}
		})
	}
	if invoked != 0 {
		t.Fatalf("policies ran %d times on infrastructure failures — fail-closed must precede the engine", invoked)
	}
}

// TestN03P3T10_Rights_PrefixCompositionMatrix: policy rights compose at the
// prefix stage with deny dominance, through REAL compiled policies on one
// shared engine (the engine clones the payload per run). Flag observes
// without withholding; mask rewrites the released buffer; only deny
// withholds, and a deny wins even when a mask mutation is available — the
// denied buffer never ships in any form.
func TestN03P3T10_Rights_PrefixCompositionMatrix(t *testing.T) {
	eng := newTestEngine(t)
	denyPol := mustCompile(t, eng, prefixDenyPolicy)
	maskPol := mustCompile(t, eng, prefixMaskPolicy)
	flagPol := mustCompile(t, eng, prefixFlagPolicy)
	runner := func(pols ...pipeline.Compiled) Runner { return EngineRunner(eng, pols) }

	tests := []struct {
		name    string
		pols    []pipeline.Compiled
		content string
		abort   bool
		want    string // exact released text when not aborted
	}{
		{
			name: "flag only observes and ships unchanged", pols: []pipeline.Compiled{flagPol},
			content: "чистый текст", want: "чистый текст",
		},
		{
			name: "flag on trigger content still ships", pols: []pipeline.Compiled{flagPol},
			content: "привет " + testInjectionTrigger, want: "привет " + testInjectionTrigger,
		},
		{
			name: "mask only rewrites", pols: []pipeline.Compiled{maskPol},
			content: "код: " + testSecretTrigger, want: "код: " + testSecretMask,
		},
		{
			name: "mask silent passes through", pols: []pipeline.Compiled{maskPol},
			content: "ничего секретного", want: "ничего секретного",
		},
		{
			name: "deny only aborts on trigger", pols: []pipeline.Compiled{denyPol},
			content: "пожалуйста " + testInjectionTrigger, abort: true,
		},
		{
			name: "deny silent releases", pols: []pipeline.Compiled{denyPol},
			content: "код: " + testSecretTrigger, want: "код: " + testSecretTrigger,
		},
		{
			name: "deny dominates mask on the same buffer", pols: []pipeline.Compiled{maskPol, denyPol},
			content: "код: " + testSecretTrigger + " и " + testInjectionTrigger, abort: true,
		},
		{
			name: "mask works beside a silent deny", pols: []pipeline.Compiled{maskPol, denyPol},
			content: "код: " + testSecretTrigger, want: "код: " + testSecretMask,
		},
		{
			name: "all three on clean content", pols: []pipeline.Compiled{flagPol, maskPol, denyPol},
			content: "совершенно чисто", want: "совершенно чисто",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewPrefixGate(PrefixConfig{Runner: runner(tc.pols...)})
			g.Ingest(tc.content)
			out := g.Flush(context.Background())
			if tc.abort {
				if out.Decision != PrefixAbort || out.Text != "" {
					t.Fatalf("outcome = %+v, want abort with an empty release", out)
				}
				return
			}
			if out.Decision != PrefixRelease {
				t.Fatalf("decision = %q (err %v), want release", out.Decision, out.Err)
			}
			if want := tc.want; out.Text != want {
				t.Fatalf("released %q, want %q", out.Text, want)
			}
		})
	}
}

// TestN03P3T10_Resource_CarryBounded_TeaseStream: a long adversarial stream
// where EVERY chunk ends with a maxLen-1-byte proper head of the longest
// pattern (the maximal tease that never completes). The hold-back must stay
// within maxLen-1 at every step for thousands of steps — the bound is
// independent of stream length, so no adversary can grow the withheld buffer
// by teasing — and the stream must keep releasing (the client view keeps
// advancing to within maxLen-1 bytes of the consumed input). At end-of-stream
// the incomplete head ships verbatim and a contiguous-span detector does not
// fire on it: the pipeline promises nothing about tokens it never received.
func TestN03P3T10_Resource_CarryBounded_TeaseStream(t *testing.T) {
	longSpan, longMask := "конфиденциально-7719", "[КЛЮЧ-1]"
	aliasSpan, aliasMask := "Иванов Иван", "[ОРГ-1]"
	tease := longSpan[:len(longSpan)-1] // proper head, ASCII tail cut: rune-safe
	pairs := [][2]string{{longSpan, longMask}, {aliasSpan, aliasMask}}
	repl := advReplMap(pairs)
	runner := advMultiMaskRunner(t, pairs)

	head := "начало: " + longSpan + " / " + aliasSpan + "." // every pattern complete: the map learns them
	var rest []string
	for i := 0; i < 3000; i++ {
		chunk := fmt.Sprintf("поле-%d: ", i)
		if i%500 == 250 { // real completions keep the replacement path honest
			chunk += "код " + aliasSpan + ", "
		}
		rest = append(rest, chunk+tease)
	}
	full := head + strings.Join(rest, "")
	want := refReplace(full, repl)
	spanSelfCheck(t, "tease", head, strings.Join(rest, ""), pairs, want)
	if !strings.HasSuffix(want, tease) {
		t.Fatal("corpus broken: the incomplete head must survive to the expected text verbatim")
	}

	frames, decoded := n03p3t09NewRun(t, runner, repl, head, rest, want)
	if decoded != want {
		t.Fatalf("decoded = %q, want %q", decoded, want)
	}
	if !strings.HasSuffix(decoded, tease) {
		t.Fatalf("the incomplete head must reach the client verbatim, got %q", decoded)
	}
	wire := n03p3t09Wire(frames)
	for _, p := range pairs {
		if bytes.Contains(wire, []byte(p[0])) || strings.Contains(decoded, p[0]) {
			t.Fatalf("forbidden span %q survived the tease stream", p[0])
		}
	}
	n03p3t09AssertSingleTerminator(t, wire)

	// The negative at the audit boundary: the verbatim incomplete head is not
	// the forbidden value — the detector stays silent (allow), the pipeline
	// never claims the head will be re-checked, masked, or completed later.
	agg, content, _ := n03p3t09Audit(t, frames)
	if content != decoded {
		t.Fatalf("audit content %q != client view %q", content, decoded)
	}
	out := FinalCheck(context.Background(), t08FinalDenyRunner(t, longSpan), agg, nil, "chat")
	if out.Err != nil {
		t.Fatalf("final check error: %v", out.Err)
	}
	if out.Result == nil || out.Result.Verdict != pipeline.ActionAllow || out.Effective != pipeline.ActionAllow {
		t.Fatalf("a contiguous-span detector must not fire on the verbatim head: %+v", out.Result)
	}
}

// TestN03P3T10_Resource_CarryBounded_PrimitiveByteTease: the same tease at
// the ChunkProcessor primitive with byte-level chunks (no SSE framing
// constraint): Held() <= maxLen-1 after every one of the steps and the
// emitted view never outruns the batch replace of the consumed input.
func TestN03P3T10_Resource_CarryBounded_PrimitiveByteTease(t *testing.T) {
	longSpan, longMask := "конфиденциально-7719", "[КЛЮЧ-1]"
	pairs := [][2]string{{longSpan, longMask}}
	repl := advReplMap(pairs)
	maxHold := spanMaxPat(repl) - 1
	tease := longSpan[:len(longSpan)-1]

	cp, err := NewChunkProcessor(repl)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	var full, emitted strings.Builder
	for i := 0; i < 2000; i++ {
		chunk := strconv.Itoa(i%7) + tease
		full.WriteString(chunk)
		emitted.WriteString(cp.Process(chunk))
		if cp.Held() > maxHold {
			t.Fatalf("step %d: Held()=%d exceeds maxLen-1=%d — the tease grew the hold", i, cp.Held(), maxHold)
		}
		if !strings.HasPrefix(refReplace(full.String(), repl), emitted.String()) {
			t.Fatalf("step %d: emitted %q is not a prefix of the batch replace (withheld backlog)", i, emitted.String())
		}
	}
	emitted.WriteString(cp.Flush())
	if cp.Held() != 0 {
		t.Fatalf("flush left %d bytes held", cp.Held())
	}
	if got := emitted.String(); got != refReplace(full.String(), repl) {
		t.Fatalf("primitive tease total = %q, want %q", got, refReplace(full.String(), repl))
	}
}

// TestN03P3T10_Resource_PrefixHoldBounded_LegalParams: the prefix hold is
// bounded under EVERY parameter set ParsePrefixParams can produce. Explicit
// zeros are legal parameter values that resolve per-stage: ParsePrefixParams
// passes them through (they are not errors), and NewPrefixGate re-arms any
// zeroed threshold to the package default — a policy can tighten a
// threshold, never disable one (the memory-bound direction of the T07
// params pin, verified behaviorally). Behaviorally: a token threshold fires
// within its own budget on the real clock; a delay threshold fires exactly
// at first-delta + MaxDelay (arithmetic, no sleeping); the flush releases
// the whole hold; and after the decision the gate is inert — thousands of
// late deltas cannot re-arm it or grow any buffer.
func TestN03P3T10_Resource_PrefixHoldBounded_LegalParams(t *testing.T) {
	tests := []struct {
		name          string
		params        map[string]any
		wantTok       int           // ParsePrefixParams resolution
		wantDelay     time.Duration // ParsePrefixParams resolution
		wantGateTok   int           // NewPrefixGate re-arming
		wantGateDelay time.Duration // NewPrefixGate re-arming
	}{
		{name: "nil params pick the defaults", params: nil,
			wantTok: DefaultPrefixTokens, wantDelay: DefaultPrefixDelay,
			wantGateTok: DefaultPrefixTokens, wantGateDelay: DefaultPrefixDelay},
		{name: "explicit zeros stay legal and re-arm to the defaults", params: map[string]any{ParamPrefixTokens: 0, ParamPrefixDelayMS: 0},
			wantTok: 0, wantDelay: 0,
			wantGateTok: DefaultPrefixTokens, wantGateDelay: DefaultPrefixDelay},
		{name: "tight tokens with zero delay keep a default delay", params: map[string]any{ParamPrefixTokens: 4, ParamPrefixDelayMS: 0},
			wantTok: 4, wantDelay: 0,
			wantGateTok: 4, wantGateDelay: DefaultPrefixDelay},
		{name: "delay only re-arms the default token budget", params: map[string]any{ParamPrefixTokens: 0, ParamPrefixDelayMS: 50},
			wantTok: 0, wantDelay: 50 * time.Millisecond,
			wantGateTok: DefaultPrefixTokens, wantGateDelay: 50 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokens, delay, err := ParsePrefixParams(tc.params)
			if err != nil {
				t.Fatalf("params %v: %v", tc.params, err)
			}
			if tokens != tc.wantTok || delay != tc.wantDelay {
				t.Fatalf("resolved (%d, %v), want (%d, %v)", tokens, delay, tc.wantTok, tc.wantDelay)
			}
			cfg := PrefixConfig{
				MaxTokens: tokens, MaxDelay: delay,
				TokenCounter: counter(),
				Runner: RunnerFunc(func(context.Context, *pipeline.Payload) *pipeline.Result {
					return &pipeline.Result{Verdict: pipeline.ActionAllow}
				}),
			}
			g := NewPrefixGate(cfg)
			if g.cfg.MaxTokens != tc.wantGateTok || g.cfg.MaxDelay != tc.wantGateDelay {
				t.Fatalf("gate resolved (%d, %v), want (%d, %v)", g.cfg.MaxTokens, g.cfg.MaxDelay, tc.wantGateTok, tc.wantGateDelay)
			}
			if g.cfg.MaxTokens <= 0 || g.cfg.MaxDelay <= 0 {
				t.Fatalf("a legal param set disabled a threshold: tokens=%d delay=%v — a policy may tighten, never disable", g.cfg.MaxTokens, g.cfg.MaxDelay)
			}

			// (a) The token threshold fires within its own budget on the real
			// clock: one token per delta, so the hold must release by delta
			// budget — content cannot stretch it.
			budget := g.cfg.MaxTokens
			fired := false
			for i := 0; i < budget+1; i++ {
				g.Ingest(strconv.Itoa(i) + " ")
				if g.ShouldFlush(time.Now()) {
					fired = true
					break
				}
			}
			if !fired {
				t.Fatalf("the token threshold never fired within %d+1 deltas — an unbounded hold", budget)
			}
			if _, tk := g.Buffered(); tk > budget {
				t.Fatalf("threshold fired late: %d buffered tokens exceeds the %d budget", tk, budget)
			}

			// (b) The delay threshold fires exactly at first-delta + MaxDelay.
			h := NewPrefixGate(cfg)
			h.Ingest("почти ") // one delta, far under any token budget
			deadline, ok := h.Deadline()
			if !ok {
				t.Fatal("no deadline armed for a delay-bounded hold")
			}
			if h.ShouldFlush(deadline.Add(-time.Nanosecond)) {
				t.Fatal("flushed before the deadline")
			}
			if !h.ShouldFlush(deadline) {
				t.Fatal("the deadline did not fire")
			}

			// (c) The flush releases the whole hold; afterwards the gate is
			// inert: the buffer stays drained and the token count never
			// grows past its decision-time value — the bounded hold cannot
			// be re-armed.
			buf, tk := h.Buffered()
			out := h.Flush(context.Background())
			if out.Decision != PrefixRelease || out.Text != buf {
				t.Fatalf("flush = %+v, want the whole buffered %q released without loss", out, buf)
			}
			for i := 0; i < 10_000; i++ {
				h.Ingest("поздно ")
			}
			if lbuf, ltk := h.Buffered(); lbuf != "" || ltk > tk {
				t.Fatalf("post-decision ingest re-armed the gate: %q (%d tokens), want drained with ≤%d tokens", lbuf, ltk, tk)
			}
			if h.ShouldFlush(time.Now().Add(h.cfg.MaxDelay)) {
				t.Fatal("a decided gate re-armed its threshold")
			}
			again := h.Flush(context.Background())
			if again.Decision != out.Decision || again.Text != out.Text {
				t.Fatalf("post-decision flush changed the outcome: %+v vs %+v", again, out)
			}
		})
	}
}

// TestN03P3T10_Resource_AggregateNoiseBounded: the final aggregate absorbs
// stream noise without growth and merges fragments instead of accumulating
// them — repeated role-only frames, unparseable lines, comments and stray
// terminators add nothing; tool-call fragments sharing an index fold into
// one call; usage is last-wins. The document is exactly the client view.
func TestN03P3T10_Resource_AggregateNoiseBounded(t *testing.T) {
	fa := NewFinalAggregate()
	for i := 0; i < 300; i++ { // role-only frames: no content, no growth
		fa.AddFrame(aggFrame(t, map[string]any{
			"id": "c1", "model": "m1",
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant"}}},
		}))
	}
	for _, noise := range []string{"data: {broken\n\n", ": comment\n\n", "data: [DONE]\n\n", "data: \n\n", "\n\n"} {
		fa.AddFrame([]byte(noise))
	}
	var wantContent strings.Builder
	for i := 0; i < 50; i++ {
		part := fmt.Sprintf("часть-%d ", i)
		wantContent.WriteString(part)
		fa.AddFrame(chunkFrame(t, "c1", part))
	}
	args := `{"city":"Москва","unit":"celsius"}`
	// one call, three argument fragments reassembled verbatim (the cuts stay
	// inside the ASCII tail so the fragments are individually valid bytes of
	// one JSON string)
	for _, frag := range []string{args[:26], args[26:33], args[33:]} {
		b, err := json.Marshal(map[string]any{
			"id": "c1", "model": "m1",
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{
				"tool_calls": []any{map[string]any{
					"index": 0, "id": "call_1", "function": map[string]any{"name": "get_weather", "arguments": frag},
				}},
			}}},
		})
		if err != nil {
			t.Fatalf("marshal tool frame: %v", err)
		}
		fa.AddFrame(append(append([]byte("data: "), b...), '\n', '\n'))
	}
	fa.AddFrame(aggFrame(t, map[string]any{"id": "c1", "model": "m1", "choices": []any{}, "usage": map[string]any{"prompt_tokens": 1}}))
	fa.AddFrame(aggFrame(t, map[string]any{"id": "c1", "model": "m1", "choices": []any{}, "usage": map[string]any{"prompt_tokens": 9, "completion_tokens": 4}}))

	doc := fa.Document()
	if doc == nil {
		t.Fatal("document is nil")
	}
	var got struct {
		Choices []struct {
			Message struct {
				Role      string `json:"role"`
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatalf("document is not valid JSON: %v", err)
	}
	msg := got.Choices[0].Message
	if msg.Content != wantContent.String() {
		t.Fatalf("content = %q, want exactly the client concatenation %q", msg.Content, wantContent.String())
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("tool calls = %d entries, fragments must merge into one call", len(msg.ToolCalls))
	}
	call := msg.ToolCalls[0]
	if call.ID != "call_1" || call.Function.Name != "get_weather" || call.Function.Arguments != args {
		t.Fatalf("merged call = %+v, want one call with args %s", call, args)
	}
	if got.Usage.PromptTokens != 9 || got.Usage.CompletionTokens != 4 {
		t.Fatalf("usage = %+v, want last-wins", got.Usage)
	}
}

// n03p3t10Bases are the disjoint pattern bases of the randomized corpus;
// the filler vocabulary below shares no word with them.
var n03p3t10Bases = []string{"конфиденциально-7719", "account-key-9f2c", "Иванов Иван", "маркер-доступа-42"}

// n03p3t10Corpus is one randomized adversarial corpus row: replacement pairs
// (optionally with a proper-prefix pair for the deferred-match path), the
// buffered head (contains every pattern complete — the carry map learns
// them), the rest text, and its rune cut into chunks.
type n03p3t10Corpus struct {
	pairs     [][2]string
	headExtra []string // standalone short-pattern head segments (deferred-match path)
	head      string
	rest      string
	chunks    []string
	detect    string // one of the bases, for the audit deny/allow rows
}

// n03p3t10GenCorpus draws one deterministic corpus row: 2–4 patterns from
// disjoint bases (every third row adds a proper-prefix pair — at least two
// runes, never degenerate, and with a standalone head occurrence so the
// buffer diff reveals the short pair exactly like production
// deriveReplacements would), filler that shares no word with any pattern,
// 1–3 extra occurrences of each pattern, and a random rune chunking of the
// rest (every 8th row a byte-trickle).
func n03p3t10GenCorpus(rng *rand.Rand, iter int) n03p3t10Corpus {
	n := 2 + rng.IntN(3) // 2..4 patterns
	perm := rng.Perm(len(n03p3t10Bases))
	c := n03p3t10Corpus{}
	mask := 0
	for _, bi := range perm[:n] {
		base := n03p3t10Bases[bi]
		c.detect = base
		if rng.IntN(3) == 0 { // a proper-prefix pair: the deferred-match path
			r := []rune(base)
			short := string(r[:2+rng.IntN(len(r)/2-1)]) // 2..len/2 runes: a real span, never the whole base
			c.pairs = append(c.pairs, [2]string{base, "[МАСКА-" + strconv.Itoa(mask) + "]"})
			c.pairs = append(c.pairs, [2]string{short, "[МАСКА-" + strconv.Itoa(mask+1) + "]"})
			// The standalone occurrence teaches the buffer diff the SHORT
			// pair: the Cyrillic continuation cannot extend the pattern, so
			// the head mutation carries it as its own replaced run.
			c.headExtra = append(c.headExtra, short+"факты")
			mask += 2
		} else {
			c.pairs = append(c.pairs, [2]string{base, "[МАСКА-" + strconv.Itoa(mask) + "]"})
			mask++
		}
	}
	words := []string{"документ", "поле", "заметка", "value", "строка", "notes"}
	filler := func() string { return words[rng.IntN(len(words))] + "-" + strconv.Itoa(rng.IntN(100)) }

	var headSegs, restSegs []string
	for _, p := range c.pairs { // the head learns every pattern complete
		headSegs = append(headSegs, "заголовок: "+p[0]+".")
	}
	for _, extra := range c.headExtra { // and every short pair standalone
		headSegs = append(headSegs, "отрывок: "+extra+".")
	}
	for k := 0; k < 12; k++ {
		seg := filler()
		if rng.IntN(2) == 0 { // 1..3 extra occurrences per pattern family
			p := c.pairs[rng.IntN(len(c.pairs))]
			seg += " упоминаю " + p[0] + ","
		}
		restSegs = append(restSegs, seg)
	}
	c.head = strings.Join(headSegs, " ")
	c.rest = strings.Join(restSegs, " ")

	runes := []rune(c.rest)
	if iter%8 == 0 { // byte-trickle extreme: one rune per chunk
		c.chunks = make([]string, len(runes))
		for i, r := range runes {
			c.chunks[i] = string(r)
		}
		return c
	}
	cuts := make(map[int]struct{}, 1+rng.IntN(8))
	for len(cuts) < 1+rng.IntN(8) {
		cuts[rng.IntN(len(runes))] = struct{}{}
	}
	pos := make([]int, 0, len(cuts))
	for p := range cuts {
		pos = append(pos, p)
	}
	slices.Sort(pos) // the map range order must not matter
	start := 0
	for _, p := range pos {
		c.chunks = append(c.chunks, string(runes[start:p+1]))
		start = p + 1
	}
	c.chunks = append(c.chunks, string(runes[start:]))
	return c
}

// TestN03P3T10_Data_ZeroRevealRandomAdversary — the card acceptance as a
// deterministic property: a seeded randomized adversary (64 corpus rows,
// stable on every machine and run) drives the forbidden spans through the
// full production chain and the raw primitive, and no consumer view ever
// contains a forbidden span:
//
//   - the old configuration is identity — the raw span IS on its wire (the
//     honest reason the seam exists);
//   - the new configuration delivers the batch leftmost-longest replace with
//     the per-step hold bound (asserted by the shared T09 chain helper);
//   - the upgrade changes exactly the defined replacements (no drift);
//   - the audit document equals the client view and is pattern-free; the
//     mutated stream audits clean (allow) while the raw stream honestly
//     denies — degraded to flag after issuance;
//   - the raw primitive over byte-level splits reproduces the batch replace.
func TestN03P3T10_Data_ZeroRevealRandomAdversary(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261029, 1030)) //nolint:gosec // G404: seeded sampler for a reproducible corpus, not a secret
	for iter := 0; iter < 64; iter++ {
		t.Run(fmt.Sprintf("iter-%02d", iter), func(t *testing.T) {
			c := n03p3t10GenCorpus(rng, iter)
			repl := advReplMap(c.pairs)
			want := refReplace(c.head+c.rest, repl)
			spanSelfCheck(t, fmt.Sprintf("iter-%02d", iter), c.head, c.rest, c.pairs, want)
			deny := t08FinalDenyRunner(t, c.detect)

			oldFrames, oldDecoded := n03p3t09OldRun(t, c.head, c.chunks)
			if oldDecoded != c.head+c.rest {
				t.Fatalf("old configuration is not identity: %q", oldDecoded)
			}
			if !strings.Contains(oldDecoded, c.detect) {
				t.Fatal("corpus broken: the raw span must be present in the unprotected stream")
			}

			newFrames, newDecoded := n03p3t09NewRun(t, advMultiMaskRunner(t, c.pairs), repl, c.head, c.chunks, want)
			if newDecoded != want {
				t.Fatalf("decoded = %q, want %q", newDecoded, want)
			}
			if newDecoded != refReplace(oldDecoded, repl) {
				t.Fatal("upgrade drift: the new view is not the batch replace of the old view")
			}
			newWire := n03p3t09Wire(newFrames)
			for _, p := range c.pairs {
				if strings.Contains(newDecoded, p[0]) || bytes.Contains(newWire, []byte(p[0])) {
					t.Fatalf("forbidden span %q survived the new configuration", p[0])
				}
			}
			n03p3t09AssertSingleTerminator(t, newWire)

			agg, content, doc := n03p3t09Audit(t, newFrames)
			if content != newDecoded || bytes.Contains(doc, []byte(c.detect)) {
				t.Fatalf("audit parity broken: content %q vs client %q", content, newDecoded)
			}
			if out := FinalCheck(context.Background(), deny, agg, nil, "chat"); out.Err != nil ||
				out.Result == nil || out.Result.Verdict != pipeline.ActionAllow {
				t.Fatalf("the mutated stream must audit clean: %+v (err %v)", out.Result, out.Err)
			}

			oldAgg, _, _ := n03p3t09Audit(t, oldFrames)
			if out := FinalCheck(context.Background(), deny, oldAgg, nil, "chat"); out.Err != nil ||
				out.Result == nil || out.Result.Verdict != pipeline.ActionDeny || out.Effective != pipeline.ActionFlag {
				t.Fatalf("the raw stream must honestly deny and degrade to flag: %+v (err %v)", out.Result, out.Err)
			}

			// The raw primitive over fresh byte-level splits of the same text
			// (1..3 random cut points; byte cuts may split inside a rune —
			// the primitive is byte-based by contract).
			text := c.head + c.rest
			for family := 1; family <= 3; family++ {
				cuts := make(map[int]struct{}, family)
				for len(cuts) < family {
					cuts[rng.IntN(len(text))] = struct{}{}
				}
				pos := make([]int, 0, len(cuts))
				for p := range cuts {
					pos = append(pos, p)
				}
				slices.Sort(pos)
				var chunks []string
				start := 0
				for _, p := range pos {
					chunks = append(chunks, text[start:p+1])
					start = p + 1
				}
				chunks = append(chunks, text[start:])
				if got := spanFeed(t, fmt.Sprintf("iter-%02d/bytes-%d", iter, family), repl, want, chunks); got != want {
					t.Fatalf("byte split family %d: got %q, want %q", family, got, want)
				}
			}
		})
	}
}

// TestN03P3T10_Data_MutationDomainSecondaryFields: the mutation domain is
// choices[0].delta.content only — a forbidden span inside reasoning_content
// or tool-call arguments is never rewritten by the carry (a frame without a
// content change passes through byte-identical; a mutated frame re-encodes
// the secondary fields verbatim), and the final audit still SEES them: the
// deny verdict degrades to flag — observed, never recalled. The seam's
// honest shape: mask narrows to the content stream, the audit covers
// everything the client received.
func TestN03P3T10_Data_MutationDomainSecondaryFields(t *testing.T) {
	repl := map[string]string{testSecretTrigger: testSecretMask}
	cp, err := NewChunkProcessor(repl)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	fp := NewFrameProcessor(cp)

	reasoning := "мышление о " + testSecretTrigger
	toolArgs := `{"query":"` + testSecretTrigger + `"}`
	frameWith := func(content string) []byte {
		b, err := json.Marshal(map[string]any{
			"id": "c1", "object": "chat.completion.chunk", "created": int64(1), "model": "m1",
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{
				"content": content, "reasoning_content": reasoning,
				"tool_calls": []any{map[string]any{
					"index": 0, "id": "call_1", "function": map[string]any{"name": "search", "arguments": toolArgs},
				}},
			}}},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return append(append([]byte("data: "), b...), '\n', '\n')
	}

	t.Run("untouched content leaves the whole frame byte-identical", func(t *testing.T) {
		raw := frameWith("чистый ответ")
		if out := fp.ProcessFrame(raw); !bytes.Equal(out, raw) {
			t.Fatalf("frame changed without a content mutation: %q", out)
		}
	})

	t.Run("mutated content keeps the secondary fields verbatim", func(t *testing.T) {
		raw := frameWith("ответ: " + testSecretTrigger)
		out := fp.ProcessFrame(raw)
		if bytes.Equal(out, raw) {
			t.Fatal("corpus broken: the content must be mutated")
		}
		text, err := n03p3t06Decode(out)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if strings.Contains(text, testSecretTrigger) || !strings.Contains(text, testSecretMask) {
			t.Fatalf("content not masked: %q", text)
		}
		var top struct {
			Choices []struct {
				Delta struct {
					Reasoning string `json:"reasoning_content"`
					ToolCalls []struct {
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(bytes.TrimPrefix(bytes.TrimSpace(out), []byte("data: ")), &top); err != nil {
			t.Fatalf("re-encoded frame is not valid JSON: %v", err)
		}
		if top.Choices[0].Delta.Reasoning != reasoning {
			t.Fatalf("reasoning_content = %q, want verbatim %q", top.Choices[0].Delta.Reasoning, reasoning)
		}
		if top.Choices[0].Delta.ToolCalls[0].Function.Arguments != toolArgs {
			t.Fatalf("tool arguments = %q, want verbatim %q",
				top.Choices[0].Delta.ToolCalls[0].Function.Arguments, toolArgs)
		}

		// The audit sees the untouched secondary spans and degrades to flag.
		agg := NewFinalAggregate()
		agg.AddFrame(out)
		outcome := FinalCheck(context.Background(), t08FinalDenyRunner(t, testSecretTrigger), agg, nil, "chat")
		if outcome.Err != nil {
			t.Fatalf("final check error: %v", outcome.Err)
		}
		if outcome.Result == nil || outcome.Result.Verdict != pipeline.ActionDeny || outcome.Effective != pipeline.ActionFlag {
			t.Fatalf("the audit must see the secondary-field span and degrade to flag: %+v", outcome.Result)
		}
	})
}

// TestN03P3T10_Negative_ThresholdCannotWaitForCertainty: the prefix hold is
// bounded by its config, not by content — a buffer that MIGHT be forming a
// forbidden span ships at the threshold anyway. With MaxTokens=1 the first
// delta (the first half of the injection trigger) is released before the
// completing tail ever arrives; the tail is neither retained nor
// re-inspected, and the only backstop for the assembled span is the final
// flag. The system never promises to check future tokens before receipt.
func TestN03P3T10_Negative_ThresholdCannotWaitForCertainty(t *testing.T) {
	eng := newTestEngine(t)
	denyPol := mustCompile(t, eng, prefixDenyPolicy)
	g := NewPrefixGate(PrefixConfig{
		MaxTokens: 1, MaxDelay: time.Hour, TokenCounter: counter(),
		Runner: EngineRunner(eng, []pipeline.Compiled{denyPol}),
	})
	g.Ingest("ignore previous") // half the trigger: a live maybe-match
	if !g.ShouldFlush(time.Now()) {
		t.Fatal("the token threshold waited for content certainty — the hold must be config-bounded")
	}
	out := g.Flush(context.Background())
	if out.Decision != PrefixRelease || out.Text != "ignore previous" {
		t.Fatalf("outcome = %+v, want the partial trigger released verbatim", out)
	}

	g.Ingest(" instructions") // the completing tail arrives after the decision
	if buf, _ := g.Buffered(); buf != "" {
		t.Fatalf("the tail was retained after release: %q", buf)
	}
	if again := g.Flush(context.Background()); again.Text != out.Text || again.Decision != out.Decision {
		t.Fatalf("the fixed decision moved: %+v vs %+v", again, out)
	}

	// The client assembles the full span; the final audit is the only backstop
	// and can only flag what already shipped.
	agg := NewFinalAggregate()
	agg.AddFrame(chunkFrame(t, "c1", "ignore previous"))
	agg.AddFrame(chunkFrame(t, "c1", " instructions"))
	check := FinalCheck(context.Background(), t08FinalDenyRunner(t, testInjectionTrigger), agg, nil, "chat")
	if check.Result == nil || check.Result.Verdict != pipeline.ActionDeny || check.Effective != pipeline.ActionFlag {
		t.Fatalf("the assembled span must be flagged, not denied: %+v", check.Result)
	}
	if !bytes.Contains(check.Document, []byte(testInjectionTrigger)) {
		t.Fatal("the audited document is not the client-received aggregate")
	}
}
