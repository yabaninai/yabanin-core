package cli

// OP-4/OP-8 (OUTPLAY-PLAN-2026-10-06 §2.2 п.5): the streaming-policy seam of
// the SSE relay — the wire side of gateway_policy.go. The OP-4 primitives
// (pkg/pipeline/streaming) decide WHAT the stream stage does; this file owns
// the HTTP plumbing: where the PrefixGate hold-back sits in the writer chain,
// when its flush runs, how a prefix deny terminates the stream, and how the
// stream_final verdict reaches the event payload.
//
// Writer-chain order (built in stream.go wrapWriters):
//
//	stream handler → sseToolGateWriter → sseStreamPolicyWriter → RecordingWriter → client
//
// so a policy mutation happens BEFORE the RT-05 cache record (client and
// cache observe the same mutated bytes) and the FinalAggregate audits the
// frames the tool gate actually passes on (the client-received contract of
// the OP-4 doc.go; the FrameProcessor only rewrites delta.content while the
// tool gate only rewrites tool_calls/finish_reason, so the two filters are
// orthogonal).
//
// Carry hygiene (OP-5 contract): a pseudonymize carry=session step writes
// its alias→original carrier into payload.Meta.Labels ("ypp.pseudonyms.v1").
// The carrier NEVER leaves the pipeline payload here: only the extracted
// release text, mutated frames and the aggregate document are forwarded —
// Meta is rebuilt fresh per stream (policyMeta) and never serialized
// upstream, to the client, into the cache or into an event payload.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/streaming"
)

// streamPolicyState is the per-stream record of the streaming policy stages.
// The drain goroutine and the prefix deadline timer both touch it; the mutex
// is the single serializer.
type streamPolicyState struct {
	mu        sync.Mutex
	decisions []policyDecision
	policyAbr bool
	abortMsg  string
}

// addDecisions appends one stage's decision records (thread-safe).
func (s *streamPolicyState) addDecisions(ds []policyDecision) {
	if len(ds) == 0 {
		return
	}
	s.mu.Lock()
	s.decisions = append(s.decisions, ds...)
	s.mu.Unlock()
}

// markAborted records a terminal prefix-stage denial (thread-safe).
func (s *streamPolicyState) markAborted(msg string) {
	s.mu.Lock()
	s.policyAbr = true
	s.abortMsg = msg
	s.mu.Unlock()
}

// aborted reports the denial and its client-facing message.
func (s *streamPolicyState) aborted() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyAbr, s.abortMsg
}

// payloadJSON renders the Event.Policy payload (empty when nothing ran).
func (s *streamPolicyState) payloadJSON() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return marshalPolicyDecisions(s.decisions)
}

// streamPolicyRunner adapts the OP-8 PolicyRuntime to the OP-4 streaming
// Runner seam. Unlike streaming.EngineRunner it routes the run through
// PolicyRuntime.evaluate, so every attached policy keeps its per-policy
// decision record and the gateway_policy_* metrics — the same observability
// contract as the JSON path. The engine composition law (mutations
// propagate, first deny short-circuits) is evaluate's, and the composed
// Result mirrors it for the streaming primitives.
type streamPolicyRunner struct {
	rt    *PolicyRuntime
	orgID string
	q     policyQuery
	state *streamPolicyState
	// final marks the stream_final hook: a deny verdict degrades to flag in
	// the recorded payload — delivered bytes cannot be recalled
	// (FinalOutcome.Effective contract); the true deny stays visible in the
	// finding actions.
	final bool
}

// Run implements streaming.Runner.
func (rn *streamPolicyRunner) Run(ctx context.Context, p *pipeline.Payload) *pipeline.Result {
	decisions, mutated, denied := rn.rt.evaluate(ctx, rn.orgID, rn.q, p)
	if rn.final {
		for i := range decisions {
			if decisions[i].Verdict == string(pipeline.ActionDeny) {
				// OP-4 FinalCheck contract: delivered bytes cannot be recalled,
				// so the request-level deny degrades to a flag. CORE-TRACE-05
				// makes the split explicit instead of leaving it to be guessed
				// from finding actions: verdict and applied_action say what
				// happened (flag — recorded and delivered), effective_action
				// keeps what the policy wanted (deny).
				decisions[i].Verdict = string(pipeline.ActionFlag)
				decisions[i].AppliedAction = string(pipeline.ActionFlag)
			}
		}
	}
	rn.state.addDecisions(decisions)

	res := &pipeline.Result{Verdict: pipeline.ActionAllow, Mutated: mutated}
	for _, d := range decisions {
		if v := pipeline.Action(d.Verdict); v.Rank() > res.Verdict.Rank() {
			res.Verdict = v
		}
		for _, f := range d.Findings {
			res.Findings = append(res.Findings, pipeline.Finding{
				Step: f.Step, Category: f.Category, Severity: f.Severity, Action: pipeline.Action(f.Action),
			})
		}
	}
	if denied {
		res.Verdict = pipeline.ActionDeny
	}
	return res
}

// sseStreamPolicyWriter is the policy filter of the SSE relay. It assembles
// the handlers' line writes into complete `data: …\n\n` events (the
// sseToolGateWriter pattern). While the prefix gate is deciding, complete
// events are HELD; the stage resolves at the gate flush — triggered by a
// token/delay threshold on the write path, by the deadline timer owned here
// (the gate itself owns no timers), or at end-of-stream. After a release the
// stream switches to passthrough, through the FrameProcessor when the prefix
// policies mutated the buffer (the chunk carry-map is derived from the
// prefix diff — see deriveReplacements).
//
// Concurrency: one stream is served by the drain goroutine plus at most the
// deadline-timer goroutine; mu guards every field, so the downstream
// ResponseWriter never sees concurrent writes.
type sseStreamPolicyWriter struct {
	w        http.ResponseWriter
	ctx      context.Context
	cancel   context.CancelFunc
	state    *streamPolicyState
	meta     *pipeline.RequestMeta
	endpoint string

	gate        *streaming.PrefixGate
	finalRunner streaming.Runner
	agg         *streaming.FinalAggregate

	mu        sync.Mutex
	buf       []byte
	held      [][]byte
	fp        *streaming.FrameProcessor
	done      bool
	timer     *time.Timer
	lastID    string
	lastModel string
}

// Header implements http.ResponseWriter.
func (pw *sseStreamPolicyWriter) Header() http.Header { return pw.w.Header() }

// WriteHeader implements http.ResponseWriter.
func (pw *sseStreamPolicyWriter) WriteHeader(code int) { pw.w.WriteHeader(code) }

// Write assembles events and routes them through the policy stages. After a
// prefix abort everything is dropped: the client already holds the
// termination frame.
func (pw *sseStreamPolicyWriter) Write(p []byte) (int, error) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.done {
		return len(p), nil // the caller must not retry
	}
	pw.buf = append(pw.buf, p...)
	pw.flushFrames()
	return len(p), nil
}

// Flush forwards a flush; held events stay held (the handler flushes per
// line, which must not pre-empt the gate).
func (pw *sseStreamPolicyWriter) Flush() {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.done {
		return
	}
	pw.flushFrames()
	if f, ok := pw.w.(http.Flusher); ok {
		f.Flush()
	}
}

// flushFrames processes every complete event in the assembly buffer.
func (pw *sseStreamPolicyWriter) flushFrames() {
	for {
		idx := bytes.Index(pw.buf, []byte("\n\n"))
		if idx < 0 {
			return
		}
		frame := pw.buf[:idx+2]
		pw.buf = pw.buf[idx+2:]
		pw.handleFrame(frame)
		if pw.done {
			return
		}
	}
}

// handleFrame routes one complete event: held while the prefix gate is
// deciding, passthrough after the release.
func (pw *sseStreamPolicyWriter) handleFrame(frame []byte) {
	if pw.gate != nil && !pw.gate.Flushed() {
		pw.holdFrame(frame)
		return
	}
	pw.emitFrame(frame)
}

// holdFrame buffers one event while the prefix gate is deciding, ingests its
// decoded delta text, arms the deadline timer on the first delta, and
// resolves the stage when a threshold fires.
func (pw *sseStreamPolicyWriter) holdFrame(frame []byte) {
	pw.gate.Ingest(frameDeltaContent(frame))
	held := make([]byte, len(frame))
	copy(held, frame)
	pw.held = append(pw.held, held)
	if pw.timer == nil {
		if dl, ok := pw.gate.Deadline(); ok {
			pw.timer = time.AfterFunc(time.Until(dl), pw.prefixTimerFired)
		}
	}
	if pw.gate.ShouldFlush(time.Now()) {
		pw.finishPrefix()
	}
}

// prefixTimerFired is the deadline background of the prefix gate: when the
// upstream goes silent past the delay threshold, the hold-back buffer is
// released instead of waiting for the next frame. The gate owns no timers
// (OP-4 contract) — the middleware owns this one.
func (pw *sseStreamPolicyWriter) prefixTimerFired() {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.done || pw.gate == nil || pw.gate.Flushed() {
		return
	}
	pw.finishPrefix()
}

// finishPrefix fixes the prefix stage. A deny aborts the stream BEFORE any
// buffered byte reaches the client: AbortFrame + terminal state + upstream
// cancel (stop paying for generation the client will never see). Otherwise
// the held events are released — through the FrameProcessor when the
// policies mutated the buffer — and the stream switches to passthrough.
func (pw *sseStreamPolicyWriter) finishPrefix() {
	if pw.timer != nil {
		pw.timer.Stop()
		pw.timer = nil
	}
	buffered, _ := pw.gate.Buffered()
	out := pw.gate.Flush(pw.ctx)
	if out.Decision != streaming.PrefixRelease {
		if out.Err != nil && pw.ctx.Err() != nil {
			// Infra fail-close caused by a dead stream context (client gone
			// or the stream ceiling): the drain-failure path owns the
			// termination — no AbortFrame, no policy-denied event.
			return
		}
		msg := "request blocked by organization policy"
		if out.Err != nil {
			msg = "stream blocked by policy"
		}
		pw.state.markAborted(msg)
		pw.done = true
		pw.held = nil
		_, _ = pw.w.Write(streaming.AbortFrame(msg))
		pw.cancel()
		return
	}
	if out.Text != buffered {
		if repl := deriveReplacements(buffered, out.Text); len(repl) > 0 {
			cp, err := streaming.NewChunkProcessor(repl)
			if err != nil {
				slog.Debug("stream chunk carry-map unavailable", "error", err)
			} else {
				pw.fp = streaming.NewFrameProcessor(cp)
			}
		}
	}
	held := pw.held
	pw.held = nil
	for _, hf := range held {
		pw.emitFrame(hf)
		if pw.done {
			return
		}
	}
}

// emitFrame sends one client-bound event: the [DONE] terminator first
// releases the FrameProcessor's held tail, ordinary events pass through the
// processor when chunk mutation is active; everything the client receives
// feeds the final aggregate, then goes downstream.
//
// G705: this writer IS the streaming relay (the toolgate.go exclusion's
// rationale) — upstream provider frames are forwarded as text/event-stream
// (never an HTML sink), optionally policy-mutated; forwarding upstream bytes
// is the feature, so the Write calls below are flagged taint false
// positives.
func (pw *sseStreamPolicyWriter) emitFrame(frame []byte) {
	// AUDIT-2026-10-28 FIX-11: a malformed upstream may omit the blank
	// separator between an unfinished data event and the [DONE] terminator,
	// so the assembly buffer hands over BOTH glued into one frame. The
	// whole-frame isDone check misses it, the glued head bypasses the frame
	// processor (raw, unpseudonymized content), and the terminal never
	// marks the delivery. Split at the terminator shape: the fused head is
	// dropped — its bytes never passed the gate or the frame processor, so
	// forwarding them would leak unmutated content — and the terminator is
	// delivered standalone.
	if term, fused := splitFusedTerminator(frame); fused {
		frame = term
	}
	if pw.isDone(frame) {
		if pw.fp != nil {
			if tail := pw.fp.FlushFrame(pw.lastID, pw.lastModel); tail != nil {
				if pw.agg != nil {
					pw.agg.AddFrame(tail)
				}
				_, _ = pw.w.Write(tail)
			}
		}
	} else if pw.fp != nil {
		frame = pw.fp.ProcessFrame(frame)
	}
	if pw.agg != nil {
		pw.agg.AddFrame(frame)
	}
	pw.rememberChunkIdentity(frame)
	_, _ = pw.w.Write(frame)
}

// finishStream is the end-of-stream policy boundary, called exactly once
// after the drain: a still-unflushed prefix gate decides here (a short
// stream may end while buffering), the FrameProcessor's held tail is
// flushed ahead of the stream end, and the event assembly buffer is
// dropped.
func (pw *sseStreamPolicyWriter) finishStream() {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.timer != nil {
		pw.timer.Stop()
		pw.timer = nil
	}
	if pw.done {
		return
	}
	if pw.gate != nil && !pw.gate.Flushed() {
		pw.finishPrefix()
	}
	if pw.done {
		return
	}
	// The drain has ended, so a trailing partial event in the assembly
	// buffer can never complete (its blank separator will not arrive). The
	// drain-failure path notifies the client through this same writer chain
	// right after; leaving the partial would glue it to the error frame
	// into ONE corrupted multi-data-line event (an unparseable termination
	// for a live client) — and its bytes never passed the policy stages
	// (an incomplete event is never routed through the gate or the frame
	// processor), so flushing them would leak unmutated content to the
	// client. The success path already never flushed this tail; drop it.
	pw.buf = nil
	if pw.fp != nil {
		if tail := pw.fp.FlushFrame(pw.lastID, pw.lastModel); tail != nil {
			if pw.agg != nil {
				pw.agg.AddFrame(tail)
			}
			_, _ = pw.w.Write(tail)
		}
	}
	if f, ok := pw.w.(http.Flusher); ok {
		f.Flush()
	}
}

// runFinalCheck audits the aggregate of the client-received frames under the
// stream_final hook. A deny degrades to flag post-issuance (FinalCheck
// contract); the decision records were collected by the runner.
func (pw *sseStreamPolicyWriter) runFinalCheck(ctx context.Context) {
	if pw.agg == nil || pw.finalRunner == nil {
		return
	}
	out := streaming.FinalCheck(ctx, pw.finalRunner, pw.agg, pw.meta, pw.endpoint)
	if out.Err != nil {
		slog.Debug("stream_final check degraded to flag", "error", out.Err)
	}
}

// policyAborted reports a terminal prefix-stage denial.
func (pw *sseStreamPolicyWriter) policyAborted() bool {
	a, _ := pw.state.aborted()
	return a
}

// abortMessage is the client-facing denial message.
func (pw *sseStreamPolicyWriter) abortMessage() string {
	_, msg := pw.state.aborted()
	return msg
}

// payloadJSON renders the Event.Policy payload of both stages.
func (pw *sseStreamPolicyWriter) payloadJSON() string { return pw.state.payloadJSON() }

// isDone reports whether the event is the "data: [DONE]" terminator.
func (pw *sseStreamPolicyWriter) isDone(frame []byte) bool {
	return bytes.Equal(bytes.TrimSpace(frame), []byte("data: [DONE]"))
}

// splitFusedTerminator detects an upstream frame that glued an unfinished
// event to the [DONE] terminator (the event's blank separator never
// arrived, AUDIT-2026-10-28 FIX-11). It returns the terminator part and
// ok=true; ok=false means the frame is not fused and must pass through
// untouched. A frame that already trims to a terminator shape is the plain
// terminator, not a fusion; a JSON chunk line always closes with
// structural bytes, so a content delta merely mentioning "data: [DONE]"
// can never end a frame with a terminator shape (same argument as
// isSSEDoneFrame in stream.go).
func splitFusedTerminator(frame []byte) (term []byte, ok bool) {
	trimmed := bytes.TrimSpace(frame)
	for _, shape := range sseDoneFrames {
		if bytes.Equal(trimmed, shape) {
			return frame, false // the plain terminator: nothing fused
		}
	}
	for _, shape := range sseDoneFrames {
		if bytes.HasSuffix(trimmed, shape) {
			lead := len(frame) - len(bytes.TrimLeft(frame, " \t\r\n"))
			cut := lead + len(trimmed) - len(shape)
			return frame[cut:], true
		}
	}
	return frame, false
}

// rememberChunkIdentity keeps the last chunk's id/model so the FrameProcessor's
// synthetic tail frame stays coherent with the stream it terminates.
func (pw *sseStreamPolicyWriter) rememberChunkIdentity(frame []byte) {
	line := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(frame), []byte("data: ")))
	if len(line) == 0 || line[0] != '{' {
		return
	}
	var ch streamCacheChunk
	if err := json.Unmarshal(line, &ch); err != nil {
		return
	}
	if ch.ID != "" {
		pw.lastID = ch.ID
	}
	if ch.Model != "" {
		pw.lastModel = ch.Model
	}
}

// frameDeltaContent decodes the choices[0].delta.content text of one
// assembled SSE event ("" for every other shape) — the PrefixGate's ingest
// unit.
func frameDeltaContent(frame []byte) string {
	line := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(frame), []byte("data: ")))
	if len(line) == 0 || line[0] != '{' {
		return ""
	}
	var ch streamCacheChunk
	if err := json.Unmarshal(line, &ch); err != nil {
		return ""
	}
	if len(ch.Choices) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(ch.Choices[0].Delta.Content, &s); err != nil {
		return ""
	}
	return s
}

// streamPrefixParams resolves the prefix buffer shape over the config
// defaults (plan §2.2 п.5: prefix_tokens / prefix_delay_ms are policy
// parameters). The first stream_prefix step declaring them in
// attachment-priority order wins; a malformed value yields the defaults plus
// an error for the caller to log — one typo must not take the stream down.
func streamPrefixParams(plans []policyPlan) (int, time.Duration, error) {
	for _, pl := range plans {
		for _, st := range pl.compiled.Policy.Steps {
			_, hasTokens := st.Params[streaming.ParamPrefixTokens]
			_, hasDelay := st.Params[streaming.ParamPrefixDelayMS]
			if !hasTokens && !hasDelay {
				continue
			}
			tokens, delay, err := streaming.ParsePrefixParams(st.Params)
			if err != nil {
				return streaming.DefaultPrefixTokens, streaming.DefaultPrefixDelay, err
			}
			return tokens, delay, nil
		}
	}
	return streaming.DefaultPrefixTokens, streaming.DefaultPrefixDelay, nil
}

// deriveReplacements diffs the original prefix buffer against its mutated
// release text and returns the original→replacement pairs the ChunkProcessor
// carries across chunk boundaries (plan §2.2 п.5: the prefix mutation's
// pseudonym map governs the rest of the stream — no reverse substitution,
// originals never released).
//
// This is the minimal OP-4/OP-8 glue: the pipeline Result carries the mutated
// payload but no structured replacement map, so the middleware reconstructs
// the pairs textually. Edits are paired by realigning the two texts at the
// first >= resyncRealign-byte common run after each difference, so
// well-separated edits produce separate exact pairs; a degenerate overlap
// degrades to one coarse pair (over-segmentation is never invented). Pairs
// with an empty original (pure insertions) are unmappable and skipped.
func deriveReplacements(orig, mut string) map[string]string {
	const (
		resyncRealign = 4
		maxDiffInput  = 64 << 10 // bound the quadratic scan; larger buffers fall back to no carry-map
	)
	if orig == "" || mut == "" || orig == mut || len(orig) > maxDiffInput || len(mut) > maxDiffInput {
		return nil
	}
	var pairs [][2]string
	oi, mi := 0, 0
	for oi < len(orig) && mi < len(mut) {
		p := commonPrefixLen(orig[oi:], mut[mi:])
		oi += p
		mi += p
		if oi >= len(orig) || mi >= len(mut) {
			break
		}
		oe, me := editExtent(orig, mut, oi, mi, resyncRealign)
		if oe > oi {
			pairs = append(pairs, [2]string{orig[oi:oe], mut[mi:me]})
		}
		oi, mi = oe, me
	}
	if len(pairs) == 0 {
		return nil
	}
	m := make(map[string]string, len(pairs))
	for _, pr := range pairs {
		if pr[0] == "" || pr[0] == pr[1] {
			continue
		}
		if _, dup := m[pr[0]]; !dup {
			m[pr[0]] = pr[1]
		}
	}
	return m
}

// commonPrefixLen returns the length of the longest common prefix of a and b.
func commonPrefixLen(a, b string) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// editExtent finds the smallest (oe, me) beyond an edit start where the two
// texts realign — a following common run of at least resync bytes — so
// separated edits pair separately. When nothing realigns (adjacent or
// overlapping edits) the whole remainder is one edit.
func editExtent(orig, mut string, oi, mi, resync int) (int, int) {
	for oe := oi + 1; oe <= len(orig); oe++ {
		for me := mi + 1; me <= len(mut); me++ {
			if (oe == len(orig) && me == len(mut)) ||
				commonPrefixLen(orig[oe:], mut[me:]) >= resync {
				return oe, me
			}
		}
	}
	return len(orig), len(mut)
}
