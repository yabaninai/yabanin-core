package cli

// TOOL-02: model-response tool-call gating. When a tool-policy engine is
// wired AND the org defines at least one deny policy, tool_calls the model
// declares in its response are checked against the policy BEFORE the client
// sees them: denied calls are stripped (JSON surface) or suppressed frame
// by frame (SSE surface), so a client-side executor never receives them.
// Denied calls are counted per tool (metrics) and logged — the response
// itself no longer contains them, so the metrics counter is the tracking
// surface for policy denials.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// ssrfAllowList narrows the package import to the surface the guard needs.
type ssrfAllowList = ssrf.AllowList

// agentSubject resolves the policy subject for a request: the yag_ agent id
// when the middleware resolved one, else '*' (org-wide rules only).
func agentSubject(r *http.Request) string {
	if id := r.Header.Get("X-Agent-Id"); id != "" {
		return id
	}
	return "*"
}

// gateToolCallsJSON filters a non-stream chat completion response. Returns
// the (possibly rewritten) body and the denied tool names. Byte-identity is
// preserved when nothing is denied.
func (gw *gateway) filterToolCall(ctx context.Context, orgID, subject string, raw any) (keep bool, denied string, changed bool) {
	call, _ := raw.(map[string]any)
	fn, _ := call["function"].(map[string]any)
	name, _ := fn["name"].(string)
	if name == "" {
		// Contentless wire skeletons are inert; argument-bearing nameless calls
		// are ambiguous declarations and fail closed.
		if string(declaredArgs(fn)) != "{}" {
			return false, "", true
		}
		return true, "", false
	}
	if d := gw.toolPolicies.Decide(ctx, orgID, subject, name); d.Action == toolpolicy.ActionDeny {
		return false, name, true
	}
	if rep := gw.toolPolicies.GuardDeclaredArgs(ctx, orgID, subject, name, declaredArgs(fn)); rep.Denied {
		return false, name, true
	}
	return true, "", false
}

func (gw *gateway) filterToolCallMessage(ctx context.Context, orgID, subject string, choice map[string]any, denied *[]string) bool {
	msg, _ := choice["message"].(map[string]any)
	if msg == nil {
		return false
	}
	calls, _ := msg["tool_calls"].([]any)
	if len(calls) == 0 {
		return false
	}
	kept := make([]any, 0, len(calls))
	changed := false
	for _, raw := range calls {
		keep, name, drop := gw.filterToolCall(ctx, orgID, subject, raw)
		if drop {
			changed = true
			if name != "" {
				*denied = append(*denied, name)
				metrics.ToolPolicyDeniedTotal.WithLabelValues(orgID, name).Inc()
			}
			continue
		}
		if keep {
			kept = append(kept, raw)
		}
	}
	if !changed {
		return false
	}
	if len(kept) > 0 {
		msg["tool_calls"] = kept
		return true
	}
	delete(msg, "tool_calls")
	if reason, _ := choice["finish_reason"].(string); reason == "tool_calls" {
		choice["finish_reason"] = "stop"
	}
	return true
}

func (gw *gateway) gateToolCallsJSON(ctx context.Context, orgID, subject string, resp []byte) ([]byte, []string) {
	if gw.toolPolicies == nil || !gw.toolPolicies.HasDenyPolicies(ctx, orgID) {
		return resp, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(resp, &doc); err != nil {
		return resp, nil // not a completion body — pass through untouched
	}
	choices, _ := doc["choices"].([]any)
	var denied []string
	changed := false
	for _, raw := range choices {
		choice, _ := raw.(map[string]any)
		if choice != nil && gw.filterToolCallMessage(ctx, orgID, subject, choice, &denied) {
			changed = true
		}
	}
	if !changed {
		return resp, nil
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return resp, denied // never fail the response over a filter bug
	}
	return out, denied
}

// declaredArgs extracts the serialized arguments of a model-declared
// tool_call for the args guard. The OpenAI wire carries them as a
// JSON-encoded string; some providers send a plain object — both normalize
// to raw JSON (a malformed string is guarded as-is: it fails any schema and
// deny_regex still scans it). Any other JSON value (array, number,
// boolean) serializes as the consumer receives it: a synthetic "{}" would
// hide content the deny rules must see (SSE-DECL-01). Absent, null and
// blank-string arguments normalize to "{}" (the engine's GuardArgs does
// the same).
func declaredArgs(fn map[string]any) json.RawMessage {
	v, present := fn["arguments"]
	if !present || v == nil {
		return json.RawMessage(`{}`)
	}
	if s, isStr := v.(string); isStr {
		if strings.TrimSpace(s) == "" {
			return json.RawMessage(`{}`)
		}
		return json.RawMessage(s)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}

// sseToolGateWriter is an http.ResponseWriter filter for the SSE surface.
// It buffers writes until a complete `data: {...}\n\n` frame is available,
// filters delta.tool_calls entries by policy (a name-bearing first fragment
// decides for that call — keyed by the full (choice, call index) pair,
// because call indexes are unique only within a choice; a deny is sticky
// for the call's identity, so a later rename cannot un-deny it; later
// argument fragments follow the decision), rewrites finish_reason when
// every call a choice declared across the response was denied, and passes
// everything else through untouched.
//
// gated too. From the first fragment of such a call the frames are held
// (order preserved) until the calls complete — every executing
// choice's finish_reason (SSE-REL-01: one choice's finish never releases
// a sibling's still-accumulating call), the [DONE] sentinel, or an
// unparseable frame (a malformed end DISCARDS still-unresolved calls,
// never releases them) — and the accumulated arguments run
// through GuardDeclaredArgs. A denied call's
// fragments are dropped whole: the client never sees one byte of a call
// whose arguments violate the org rules. A cancelled context fails open
// (D-15): nothing is held, frames pass as before.
type sseToolGateWriter struct {
	w       http.ResponseWriter
	engine  *toolpolicy.Engine
	orgID   string
	subject string
	// ctx is the request context: a client disconnect (or the /v1 stream
	// ceiling) must stop the wait for Decide mid-stream (D-15). On ctx
	// error the policy store is unreachable and Decide fails OPEN — the
	// failure mode is pinned by TestToolPolicyFailsOpenOnCancelledContext.
	ctx context.Context

	buf     []byte
	verdict map[callKey]bool // call identity → name decision
	// seenChoice/keptChoice track each choice response-wide for the finish
	// rewrite: a choice is stranded only when it declared calls and none
	// survived, wherever those calls split across frames.
	seenChoice map[int]bool
	keptChoice map[int]bool
	// executing tracks the choices whose allowed calls may still be
	// accumulating (SSE-REL-01): a finish_reason completes only the choice
	// that carries it, so a sibling's finish must not evaluate and release
	// another choice's still-partial arguments.
	executing map[int]bool
	denied    int
	active    bool

	holding    bool                      // frames are held pending the args verdict
	heldFrames []heldFrame               // held frames in arrival order
	declName   map[callKey]string        // call identity → declared tool name
	declArgs   map[callKey]*bytes.Buffer // call identity → accumulated arguments
	// indexed records that the stream has carried an explicit integer
	// choice index: from then on an absent member is ambiguity (a mixed
	// stream), not a positional fallback.
	indexed bool
}

// heldFrame is one held SSE event with the identity resolution it was
// absorbed under (R4-3): ids/ambiguous are the frame's choice identities
// at absorb time — release reuses them instead of re-resolving after
// later frames changed the stream's indexed state — and touch lists the
// choices whose frames this event carries: a held event streams
// selectively once every choice it touches has finished (R4-1a).
type heldFrame struct {
	frame     []byte
	ids       []int
	ambiguous []bool
	touch     []int
}

// frameRes is one frame's choice-identity resolution.
type frameRes struct {
	ids       []int
	ambiguous []bool
}

// callKey is the streaming identity of one tool call: OpenAI call indexes
// are unique only within a choice, so verdicts, argument tracking and drop
// decisions key on the full (choice index, call index) pair — two choices
// may validly declare index 0. The choice index is the WIRE choice.index
// member (sparse and reordered choices arrays, SSE-IDX-01); the array
// position is only the legacy fallback for consistently unindexed
// streams.
type callKey struct {
	ci  int
	idx int
}

// callKeyFor is the single identity seam for call-scoped state: verdicts,
// argument tracking and drop decisions all resolve a call through it, so
// they can never disagree about what a call is.
func callKeyFor(ci, idx int) callKey { return callKey{ci: ci, idx: idx} }

func newSSEToolGateWriter(ctx context.Context, w http.ResponseWriter, engine *toolpolicy.Engine, orgID, subject string, hasDeny bool) *sseToolGateWriter {
	return &sseToolGateWriter{
		w: w, engine: engine, orgID: orgID, subject: subject, ctx: ctx,
		verdict: map[callKey]bool{}, seenChoice: map[int]bool{}, keptChoice: map[int]bool{}, executing: map[int]bool{}, active: hasDeny,
		declName: map[callKey]string{}, declArgs: map[callKey]*bytes.Buffer{},
	}
}

func (g *sseToolGateWriter) Header() http.Header  { return g.w.Header() }
func (g *sseToolGateWriter) WriteHeader(code int) { g.w.WriteHeader(code) }
func (g *sseToolGateWriter) Flush() {
	g.flushFrames(false)
	if f, ok := g.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *sseToolGateWriter) Write(p []byte) (int, error) {
	g.buf = append(g.buf, p...)
	// The provider writes an SSE data line and its newlines in separate
	// Write calls. A single Write is not the end of an event; forwarding its
	// trailing bytes here can glue the held tool call to the finish frame.
	g.flushFrames(false)
	return len(p), nil // report the full length: the caller must not retry
}

// flushFrames processes every complete frame in the buffer. final=false
// keeps trailing partial data buffered (a frame may split across writes).
func (g *sseToolGateWriter) flushFrames(final bool) {
	for {
		idx := bytes.Index(g.buf, []byte("\n\n"))
		if idx < 0 {
			if final && len(g.buf) > 0 {
				g.writeFrame(g.buf)
				g.buf = nil
			}
			return
		}
		frame := g.buf[:idx+2]
		g.buf = g.buf[idx+2:]
		g.writeFrame(frame)
	}
}

// activateForFrame refreshes applicability on live tool-bearing output:
// admin edits invalidate the org cache, and activation is one-way. Reading
// decoded member names also activates on escaped tool_calls spellings.
func (g *sseToolGateWriter) activateForFrame(frame []byte) {
	if g.active {
		return
	}
	payload, isData := sseDataPayload(frame)
	if !isData || !payloadDeclaresToolCalls(payload) {
		return
	}
	if g.engine != nil && g.engine.HasDenyPolicies(g.ctx, g.orgID) {
		g.active = true
	}
}

func (g *sseToolGateWriter) writeFrame(frame []byte) {
	g.activateForFrame(frame)
	payload, isData := sseDataPayload(frame)
	if !g.active || !isData {
		// A non-data frame (comment, event:/id: field) carries no
		// executable payload; a `data:` line without the optional space is
		// still consumer-readable SSE and still gated (R4-2).
		_, _ = g.w.Write(frame)
		return
	}
	if bytes.Equal(bytes.TrimSpace(payload), []byte("[DONE]")) {
		g.release(false)
		_, _ = g.w.Write(frame)
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		// A malformed end discards still-unresolved executable calls: their
		// partial arguments were never guardable (SSE-REL-01e).
		g.release(true)
		_, _ = g.w.Write(frame)
		return
	}
	// A finish_reason completes only the choice that carries it
	// (SSE-REL-01): a completed choice's held fragments evaluate and
	// stream WITHOUT waiting for every unfinished sibling (R4-1a), and an
	// ambiguous finish completes nothing — it must not release unresolved
	// fragments (R4-1b).
	res := g.frameResolution(doc)
	hold, touch := g.absorb(doc, res)
	if g.holding || (hold && !g.failOpen()) {
		// An allowed-name call is declaring arguments: hold the frames from
		// here until the calls complete, so an args-denied call is dropped
		// before the client ever sees a fragment. The event stores the
		// resolution it was absorbed under; release filters with the same
		// identities the accumulation used (R4-3).
		g.holding = true
		g.heldFrames = append(g.heldFrames, heldFrame{
			frame: frame, ids: res.ids, ambiguous: res.ambiguous, touch: touch,
		})
		if g.completeChoices(doc, res) {
			g.release(false)
		} else {
			g.releaseReady()
		}
		return
	}
	if out, changed := g.filterFrame(frame, doc, res, g.nameDenied); changed {
		_, _ = g.w.Write(out)
		return
	}
	_, _ = g.w.Write(frame)
}

// absorb runs the per-fragment scan of one parsed frame: the name-bearing
// first fragments decide their call's identity, the argument chunks of calls
// that are not name-denied accumulate for the args guard, and the report
// says whether any call in this frame may still be executing — those frames
// must be held until the calls complete.
func (g *sseToolGateWriter) absorb(doc map[string]any, res frameRes) (hold bool, touch []int) {
	choices, _ := doc["choices"].([]any)
	ids, ambiguous := res.ids, res.ambiguous
	for pos, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		calls, _ := delta["tool_calls"].([]any)
		if ambiguous[pos] {
			continue // ambiguous: accumulates nowhere and borrows no permit
		}
		ci := ids[pos]
		touch = append(touch, ci)
		executing := false
		for _, cl := range calls {
			call, _ := cl.(map[string]any)
			if g.absorbCall(ci, call) {
				hold = true
				executing = true
			}
		}
		if executing {
			g.executing[ci] = true
		}
	}
	return hold, touch
}

// absorbCall scans one tool-call fragment under its full (choice, index)
// identity: a name-bearing first fragment decides the verdict for that key,
// an allowed call's argument chunks accumulate for the release args guard,
// and the return reports whether the call may still be executing (its
// frames must be held).
func (g *sseToolGateWriter) absorbCall(ci int, call map[string]any) bool {
	key := callKeyFor(ci, callIndex(call))
	fn, _ := call["function"].(map[string]any)
	name, _ := fn["name"].(string)
	if name != "" {
		g.decideName(key, name)
	}
	if g.nameDenied(ci, key.idx) {
		return false // name-denied: dropped at rewrite time
	}
	if fn == nil {
		return true
	}
	switch fn["arguments"].(type) {
	case nil, string:
		// absent/null normalizes to absent; string chunks accumulate below
	default:
		// A non-string, non-null argument form cannot accumulate under the
		// wire's string-chunk contract. Refusing the identity fail-closed
		// keeps the guard from inspecting a synthetic "{}" while the
		// consumer receives the value (SSE-DECL-01); sticky like a deny.
		g.verdict[key] = false
		return false
	}
	if chunk, _ := fn["arguments"].(string); chunk != "" {
		g.appendArgs(key, chunk)
	}
	return true
}

// decideName runs the name decision for one call identity. The first
// name-bearing fragment decides, and a deny is STICKY for the whole call:
// a later fragment renaming the call to an allowed name must not un-deny
// fragments of a call the policy already rejected (deny-wins per identity),
// nor count the denial twice. The opposite direction stays live — an
// allowed first name can still be denied by a later fragment's rename.
// A later fragment bearing a DIFFERENT allowed name conflicts with the
// first: the release guard would evaluate the accumulated arguments
// under the first name while the consumer executes the last. Conflicting
// declarations are rejected fail-closed and sticky — a form refusal, not
// a policy verdict (SSE-NAME-01); repeating the SAME name is idempotent.
// A deny-direction rename is evaluated and counted before the conflict
// check so both deny directions stay live.
func (g *sseToolGateWriter) decideName(key callKey, name string) {
	if allowed, seen := g.verdict[key]; seen && !allowed {
		return // denied under this identity: sticky, one denial per call
	}
	allowed := true
	if g.engine != nil {
		if d := g.engine.Decide(g.ctx, g.orgID, g.subject, name); d.Action == toolpolicy.ActionDeny {
			allowed = false
			g.denied++
			metrics.ToolPolicyDeniedTotal.WithLabelValues(g.orgID, name).Inc()
		}
	}
	if allowed {
		if prior, tracked := g.declName[key]; tracked && prior != name {
			// SSE-NAME-01: conflicting declaration — see the comment
			// above. The identity is refused fail-closed, sticky.
			g.verdict[key] = false
			return
		}
	}
	g.verdict[key] = allowed
	if allowed {
		if _, tracking := g.declName[key]; !tracking {
			g.declName[key] = name
		}
	}
}

// appendArgs accumulates one argument chunk of a held call.
func (g *sseToolGateWriter) appendArgs(key callKey, chunk string) {
	b := g.declArgs[key]
	if b == nil {
		b = &bytes.Buffer{}
		g.declArgs[key] = b
	}
	b.WriteString(chunk)
}

// filterFrame applies the drop decisions to one parsed frame: tool_calls
// entries whose (choice, index) the drop function rejects are removed, a
// choice left without any call is marked dead (its "tool_calls"
// finish_reason rewrites to "stop"), and the frame re-encodes when anything
// changed. out carries the original frame bytes when nothing changed.
func (g *sseToolGateWriter) filterFrame(frame []byte, doc map[string]any, res frameRes, drop func(ci, idx int) bool) (out []byte, changed bool) {
	choices, _ := doc["choices"].([]any)
	ids, ambiguous := res.ids, res.ambiguous
	for pos, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		ci := ids[pos]
		if ambiguous[pos] {
			// Ambiguous occurrences fail closed: every executable fragment
			// of the choice drops (keyed off any wire identity), the
			// non-executable rest of the frame flows.
			if g.filterChoice(choice, -(pos + 1), func(int, int) bool { return true }) {
				changed = true
			}
			continue
		}
		if g.filterChoice(choice, ci, drop) {
			changed = true
		}
	}
	if !changed {
		return frame, false
	}
	enc, err := json.Marshal(doc)
	if err != nil {
		return frame, false // never fail the stream over a filter bug
	}
	return append(append([]byte("data: "), enc...), '\n', '\n'), true
}

// filterChoice applies the drop decisions to one choice: tool_calls entries
// the drop function rejects are removed, and the choice's seen/kept record
// updates response-wide — a call that survives anywhere keeps the choice's
// tool loop alive even when the frame in hand lost all of its calls. The
// finish rewrite is evaluated AFTER this choice's drops: a frame carrying
// both the call fragments and finish_reason must rewrite in the same pass —
// the split-frame sequence and the JSON surface (gateToolCallsJSON) pin the
// same no-strand contract.
func (g *sseToolGateWriter) filterChoice(choice map[string]any, ci int, drop func(ci, idx int) bool) bool {
	changed := false
	if delta, _ := choice["delta"].(map[string]any); delta != nil {
		if calls, _ := delta["tool_calls"].([]any); len(calls) > 0 {
			g.seenChoice[ci] = true
			kept := make([]any, 0, len(calls))
			anyKept, anyDropped := false, false
			for _, cl := range calls {
				call, _ := cl.(map[string]any)
				if drop(ci, callIndex(call)) {
					anyDropped = true
					continue // suppress this fragment
				}
				anyKept = true
				kept = append(kept, cl)
			}
			if anyKept {
				g.keptChoice[ci] = true
			}
			if anyDropped {
				changed = true
				if anyKept {
					delta["tool_calls"] = kept
				} else {
					delete(delta, "tool_calls")
				}
			}
		}
	}
	if g.strandedFinish(choice, ci) {
		changed = true
	}
	return changed
}

// strandedFinish rewrites the choice's finish reason when every call the
// choice declared across the whole response was denied: a "tool_calls"
// finish with no surviving call would strand the consumer's tool loop, so
// it normalizes to "stop" (the JSON surface pins the same contract). The
// seen/kept record is response-wide, so a survivor in an earlier or later
// frame keeps the loop alive and an all-denied choice normalizes however
// its calls were split.
func (g *sseToolGateWriter) strandedFinish(choice map[string]any, ci int) bool {
	fr, _ := choice["finish_reason"].(string)
	if fr != "tool_calls" || !g.seenChoice[ci] || g.keptChoice[ci] {
		return false
	}
	choice["finish_reason"] = "stop"
	return true
}

// release evaluates every held call's accumulated arguments through the
// chat-path args guard and writes the held frames out (order preserved),
// dropping the fragments of denied calls whole. discardUnresolved (the
// malformed-termination path) also drops every call of a choice that
// never completed: a partial accumulation was never guardable and must
// not stream unchecked.
func (g *sseToolGateWriter) release(discardUnresolved bool) {
	frames := g.heldFrames
	g.heldFrames, g.holding = nil, false
	if len(frames) == 0 {
		return
	}
	drop := g.dropSet()
	discard := map[int]bool{}
	if discardUnresolved {
		for ci := range g.executing {
			discard[ci] = true
		}
	}
	for _, f := range frames {
		g.writeHeld(f, drop, discard)
	}
	g.declName = map[callKey]string{}
	g.declArgs = map[callKey]*bytes.Buffer{}
	g.executing = map[int]bool{}
}

// writeHeld filters one held event through its STORED resolution (R4-3):
// the identities the accumulation used are the identities the drop
// applies — re-resolving after later frames changed the stream's indexed
// state could disagree with what was absorbed. A frame that no longer
// parses passes byte-identically (never fail the stream over a filter
// bug).
func (g *sseToolGateWriter) writeHeld(f heldFrame, drop map[callKey]bool, discard map[int]bool) {
	var doc map[string]any
	if err := json.Unmarshal(framePayload(f.frame), &doc); err != nil {
		_, _ = g.w.Write(f.frame)
		return
	}
	if out, changed := g.filterFrame(f.frame, doc, frameRes{ids: f.ids, ambiguous: f.ambiguous}, func(ci, idx int) bool { return discard[ci] || drop[callKeyFor(ci, idx)] }); changed {
		_, _ = g.w.Write(out)
		return
	}
	_, _ = g.w.Write(f.frame)
}

// releaseReady streams held events whose touched choices have all
// finished (R4-1a): a completed choice's fragments evaluate through the
// release guard and reach the consumer without waiting for every
// unfinished sibling. Two release classes keep the observable order
// sane: an event that TOUCHES executable choices releases selectively
// (each choice is an independent SSE substream; per-choice fragment
// order is preserved even when cross-choice interleaving compacts),
// while an event touching nothing — an error frame, a keepalive — never
// jumps ahead of an earlier still-held event (strict arrival order).
// Completed choices' declaration state clears with their release; name
// verdicts stay sticky for the response lifetime.
func (g *sseToolGateWriter) releaseReady() {
	drop := g.partialDropSet()
	kept := g.heldFrames[:0]
	heldBefore := false
	for _, f := range g.heldFrames {
		releasable := true
		for _, ci := range f.touch {
			if g.executing[ci] {
				releasable = false
				break
			}
		}
		if len(f.touch) == 0 {
			releasable = !heldBefore
		}
		if !releasable {
			kept = append(kept, f)
			heldBefore = true
			continue
		}
		g.writeHeld(f, drop, nil)
	}
	g.heldFrames = kept
	for key := range g.declArgs {
		if !g.executing[key.ci] {
			delete(g.declArgs, key)
		}
	}
	for key := range g.declName {
		if !g.executing[key.ci] {
			delete(g.declName, key)
		}
	}
}

// dropSet computes the release-time drop set over per-call identity: every
// call the name decision denied (verdict — the same criterion the immediate
// path applies, whether the deny was visible on the first fragment or a
// mid-hold rename) plus every surviving held call whose accumulated
// arguments the chat-path args guard denies. An args denial is recorded
// in the verdict map: it is sticky for the response lifetime, so a late
// continuation after the call's own finish never re-opens the call.
func (g *sseToolGateWriter) dropSet() map[callKey]bool        { return g.dropSetGuarded(false) }
func (g *sseToolGateWriter) partialDropSet() map[callKey]bool { return g.dropSetGuarded(true) }

// dropSetGuarded computes the drop set over per-call identity: every
// call the name decision denied (verdict — the same criterion the
// immediate path applies, whether the deny was visible on the first
// fragment or a mid-hold rename) plus every surviving held call whose
// accumulated arguments the chat-path args guard denies. skipExecuting
// (the selective-release form, R4-1a) leaves still-executing choices'
// accumulations unevaluated — the args guard only ever runs on complete
// accumulations — and their frames cannot release anyway. An args denial
// is recorded in the verdict map: it is sticky for the response
// lifetime, so a late continuation after the call's own finish never
// re-opens the call.
func (g *sseToolGateWriter) guardArgsDenied(key callKey, name string, skipExecuting bool) bool {
	if name == "" || g.engine == nil || (skipExecuting && g.executing[key.ci]) {
		return false
	}
	args := json.RawMessage(`{}`)
	if b := g.declArgs[key]; b != nil && b.Len() > 0 {
		args = json.RawMessage(b.Bytes())
	}
	if rep := g.engine.GuardDeclaredArgs(g.ctx, g.orgID, g.subject, name, args); !rep.Denied {
		return false
	}
	g.verdict[key] = false // sticky for the response lifetime (SSE-REL-01f)
	g.denied++
	metrics.ToolPolicyDeniedTotal.WithLabelValues(g.orgID, name).Inc()
	return true
}

func (g *sseToolGateWriter) dropSetGuarded(skipExecuting bool) map[callKey]bool {
	drop := map[callKey]bool{}
	for key, allowed := range g.verdict {
		if !allowed {
			drop[key] = true // name-denied: never in declName, still denied
		}
	}
	for key, name := range g.declName {
		if drop[key] || g.guardArgsDenied(key, name, skipExecuting) {
			drop[key] = true
		}
	}
	for key := range g.declArgs {
		if _, named := g.declName[key]; !named {
			// Accumulated arguments that never faced a name decision: a
			// nameless call carrying content is an ambiguous executable
			// declaration — refuse fail-closed rather than release it
			// unguarded (SSE-DECL-01).
			drop[key] = true
		}
	}
	return drop
}

// nameDenied reports whether the call at (choice, index) was denied by its
// name decision.
func (g *sseToolGateWriter) nameDenied(ci int, idx int) bool {
	allowed, seen := g.verdict[callKeyFor(ci, idx)]
	return seen && !allowed
}

// failOpen reports the D-15 posture: a dead request context means the
// policy store is unreachable — the surface fails open and nothing is held.
func (g *sseToolGateWriter) failOpen() bool {
	return g.ctx != nil && g.ctx.Err() != nil
}

// framePayload strips the SSE envelope from a data frame.
func framePayload(frame []byte) []byte {
	if payload, isData := sseDataPayload(frame); isData {
		return payload
	}
	return bytes.TrimSpace(frame)
}

// sseDataPayload extracts the joined data payload of one complete SSE
// event (R4-2): each data line contributes its value minus ONE optional
// leading space — `data:` and `data: ` are both legal spellings — and
// multiple data lines of one event join with "\n". isData is false for
// frames without a data field (comments, event:/id: fields carry no
// executable payload).
func sseDataPayload(frame []byte) (payload []byte, isData bool) {
	var parts [][]byte
	for _, line := range bytes.Split(frame, []byte("\n")) {
		rest, ok := bytes.CutPrefix(line, []byte("data:"))
		if !ok {
			continue
		}
		if len(rest) > 0 && rest[0] == ' ' {
			rest = rest[1:]
		}
		parts = append(parts, rest)
	}
	if len(parts) == 0 {
		return nil, false
	}
	return bytes.Join(parts, []byte("\n")), true
}

// payloadDeclaresToolCalls reports whether a JSON payload carries a
// "tool_calls" member anywhere, reading DECODED member names (R4-2): a
// literal byte match misses escaped spellings like \u0074ool_calls, and
// activation must never under-detect a declaration. Over-detection is
// harmless — activation only turns filtering on.
func scanToolCallTokens(dec *json.Decoder) bool {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case string:
			if t == "tool_calls" {
				return true
			}
		case json.Delim:
			if (t == '{' || t == '[') && scanToolCallTokens(dec) {
				return true
			}
		}
	}
	_, _ = dec.Token() // consume the container's closing delimiter
	return false
}

func payloadDeclaresToolCalls(payload []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if open, ok := tok.(json.Delim); !ok || (open != '{' && open != '[') {
		return false
	}
	return scanToolCallTokens(dec)
}

// frameTerminal reports whether the frame carries a finish_reason (the
// response's tool_calls are complete once any choice finishes).
func frameTerminal(doc map[string]any) bool {
	choices, _ := doc["choices"].([]any)
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		if fr, _ := choice["finish_reason"].(string); fr != "" {
			return true
		}
	}
	return false
}

// completeChoices records the frame's completions and reports whether
// every held call can release (SSE-REL-01): a finish_reason completes
// only the choice that carries it, so a sibling's finish never evaluates
// and releases another choice's still-accumulating arguments — the args
// guard only ever runs on complete accumulations. An ambiguous finished
// member cannot be attributed to a choice: it completes NOTHING and
// releases nothing (R4-1b) — the still-executing siblings keep the hold
// until their own finish, [DONE], a malformed frame or the final flush.
func (g *sseToolGateWriter) completeChoices(doc map[string]any, res frameRes) bool {
	choices, _ := doc["choices"].([]any)
	for pos, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		if fr, _ := choice["finish_reason"].(string); fr == "" {
			continue
		}
		if res.ambiguous[pos] {
			continue
		}
		delete(g.executing, res.ids[pos])
	}
	return len(g.executing) == 0
}

// callIndex extracts the streaming call index (missing → 0).
func callIndex(call map[string]any) int {
	if v, ok := call["index"].(float64); ok {
		return int(v)
	}
	return 0
}

// resolveIdentities maps one frame's choices to wire identities and flags
// ambiguity per occurrence. An explicit non-negative integer index
// resolves to its wire value (and marks the stream indexed); an absent
// member falls back to the array position ONLY while NEITHER the stream
// NOR the frame in hand has ever carried an index — consistently
// unindexed streams keep their legacy positional behavior (R4-3: the
// whole frame determines the fallback, so a member missing its index
// BEFORE the first explicit index in array order borrows no sibling
// key). Once indexing is in effect, a missing member could denote any
// choice, a fractional or negative value carries no wire meaning, and
// two occurrences resolving to the same index within one frame share
// state — all are ambiguous. Ambiguous executable fragments borrow no
// permit: they are never accumulated under a sibling key and never
// released (SSE-IDX-01).
//
// The resolution is a PURE function of the stream's indexed state before
// the frame: resolveFrameIdentities never mutates receiver state, and
// frameResolution commits g.indexed exactly once per frame, so absorb,
// filter and release always share one resolution per event.
func (g *sseToolGateWriter) frameResolution(doc map[string]any) frameRes {
	choices, _ := doc["choices"].([]any)
	ids, ambiguous, indexed := resolveFrameIdentities(choices, g.indexed)
	g.indexed = indexed
	return frameRes{ids: ids, ambiguous: ambiguous}
}

func resolveChoiceIdentity(choice map[string]any, pos int, firstAt map[int]int, ids []int, ambiguous []bool) bool {
	value, ok := choice["index"].(float64)
	if !ok {
		return false
	}
	if value != math.Trunc(value) || value < 0 {
		ambiguous[pos] = true
		return false
	}
	ci := int(value)
	if first, duplicate := firstAt[ci]; duplicate {
		ambiguous[pos] = true
		ambiguous[first] = true
		return true
	}
	firstAt[ci] = pos
	ids[pos] = ci
	return true
}

func resolveFrameIdentities(choices []any, streamIndexed bool) (ids []int, ambiguous []bool, indexed bool) {
	ids = make([]int, len(choices))
	ambiguous = make([]bool, len(choices))
	indexed = streamIndexed
	frameIndexed := false
	firstAt := map[int]int{} // resolved wire index → first position claiming it
	for pos, raw := range choices {
		choice, _ := raw.(map[string]any)
		ids[pos] = pos
		if choice == nil {
			continue
		}
		if resolveChoiceIdentity(choice, pos, firstAt, ids, ambiguous) {
			frameIndexed = true
		}
	}
	if !frameIndexed && !indexed {
		return ids, ambiguous, indexed // legacy positional stream
	}
	indexed = true
	for pos, raw := range choices {
		choice, _ := raw.(map[string]any)
		if choice == nil {
			continue
		}
		if _, ok := choice["index"]; !ok {
			ambiguous[pos] = true // mixed stream: no sibling-permit borrow
		}
	}
	return ids, ambiguous, indexed
}

// DeniedCount reports suppressed calls (logging/diagnostics).
func (g *sseToolGateWriter) DeniedCount() int { return g.denied }

// toolNamesFromDenied joins names for a log line.
func toolNamesFromDenied(denied []string) string { return strings.Join(denied, ",") }

// execURLGuard validates a fetch target for the built-in executor: http or
// https scheme, a host, no credentials, and the deployment allow-list +
// reserved-IP check (shared with the MCP registry — one dial-out surface).
func execURLGuard(urlStr string, allow ssrfAllowList) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("toolexec: invalid url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("toolexec: url scheme must be http or https (got %q)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("toolexec: url has no host")
	}
	if u.User != nil {
		return fmt.Errorf("toolexec: url must not contain credentials")
	}
	if err := allow.ValidateUpstream(host); err != nil {
		return fmt.Errorf("toolexec: %w", err)
	}
	return nil
}

// policyDeniesTool checks the org policy for one tool call on an invoke
// path. On deny it writes the 403 response, counts the metric, publishes the
// decision record and returns true (the caller must return immediately).
func (gw *gateway) policyDeniesTool(w http.ResponseWriter, r *http.Request, orgID, subject, tool string) bool {
	if gw.toolPolicies == nil {
		return false
	}
	d := gw.toolPolicies.Decide(r.Context(), orgID, subject, tool)
	if d.Action != toolpolicy.ActionDeny {
		return false
	}
	metrics.ToolPolicyDeniedTotal.WithLabelValues(orgID, tool).Inc()
	gw.publishToolPolicyDenial(r, orgID, subject, tool, d)
	if gw.log != nil {
		gw.log.Warn("tool policy denied invoke",
			"org", orgID, "subject", subject, "tool", tool, "policy", d.Policy.Name)
	}
	apierrors.Write(w, http.StatusForbidden, "policy_denied",
		fmt.Sprintf("tool %q is denied by org policy", tool))
	return true
}

// publishToolPolicyDenial emits the CORE-TRACE-05 decision record for a
// tool-policy invoke deny, in the same policyDecision envelope the pipeline
// decisions use. Scope: the invoke path only (pre-dispatch). The
// response-surface gates (gateToolCallsJSON / sseToolGateWriter stripping)
// are enforce actions on already-delivered/partially-delivered model output —
// they need their own decision wiring through the writer chain and are
// tracked as remaining TRACE work, not silently absent here.
//
// The record is honest about its limits: version stays 0 (tool policies
// carry no version column — unknown stays unknown), effective_hash is empty
// (no compiled-policy hashing exists for tool policies), findings/steps are
// absent, and trace_completeness=absent marks the decision type as carrying
// no step instrumentation — never rendered as "no steps ran".
func (gw *gateway) publishToolPolicyDenial(r *http.Request, orgID, subject, tool string, d toolpolicy.Decision) {
	dec := policyDecision{
		PolicyID:      d.Policy.ID,
		Name:          d.Policy.Name,
		EffectiveHash: "",
		Mode:          string(pipeline.ModeEnforce),
		Verdict:       string(pipeline.ActionDeny),

		EnvelopeVersion:   decisionEnvelopeVersion,
		Hook:              string(pipeline.HookToolPre),
		RuleNamespace:     ruleNamespaceToolPolicy,
		Matched:           ptrBool(true),
		EffectiveAction:   string(pipeline.ActionDeny),
		AppliedAction:     string(pipeline.ActionDeny),
		TraceCompleteness: traceCompleteAbsent,
	}
	publishEvent(gw.publisher, logctx.From(r.Context(), gw.log), eventBase{ //nolint:contextcheck // publishEvent detaches from the caller context by design
		EventType:      "request.invalid",
		RequestID:      logctx.RequestID(r.Context()),
		SessionID:      r.Header.Get("X-Session-Id"),
		OrgID:          orgID,
		TeamID:         r.Header.Get("X-Team-Id"),
		ModelRequested: "mcp",
		ModelUsed:      "mcp:" + tool,
		Error:          fmt.Sprintf("tool %q denied by policy %q (subject %q)", tool, dec.Name, subject),
		Policy:         marshalPolicyDecisions([]policyDecision{dec}),
		Labels:         labelsFrom(r.Context()),
	}.build())
}

// ptrBool is the envelope's matched-field helper (*bool so an explicit false
// survives JSON omitempty).
func ptrBool(v bool) *bool { return &v }

// builtinToolInvoke runs a built-in executor tool through the same
// identity/policy/audit discipline as the MCP proxy path.
func (gw *gateway) builtinToolInvoke(w http.ResponseWriter, r *http.Request, orgID string, id mcpagg.Identity, req mcpagg.InvokeRequest) {
	if gw.toolExec == nil {
		apierrors.Write(w, http.StatusServiceUnavailable, "unavailable", "built-in tools are not configured")
		return
	}
	// The policy pre-check runs under BOTH addresses of the EFFECTIVE name
	// (denyBuiltinInvoke → toolexec.PolicyKeys). http_request composes
	// http_<method> so preset names (network-readonly denies http_post)
	// apply naturally.
	if gw.denyBuiltinInvoke(w, r, orgID, id.AgentID, req) {
		return
	}
	start := time.Now()
	// server-aware deny decision and the args rules (schema / max_bytes /
	// deny_regex) BEFORE the tool dispatch (a denied call never reaches the
	// tool), the result post-checks over the serialized body after it.
	res, err := gw.toolExec.ExecuteGuarded(r.Context(), orgID, id.AgentID, req.Tool, req.Params)
	latency := time.Since(start).Milliseconds()
	outcome := mcpagg.OutcomeOK
	status := 0
	upstreamURL := ""
	if res != nil {
		status = res.Status
		upstreamURL = res.UpstreamURL
	}
	var iErr *toolexec.ExecError
	if err != nil {
		var code string
		if errorsAs(err, &iErr) {
			code = iErr.Code
		} else {
			code = toolexec.ErrCodeUpstream
		}
		// Error path: audit without params (the executor's guard already
		// redacted internally; the deny/failure reason rides the message).
		gw.auditBuiltin(r.Context(), orgID, id, req.Tool, nil, code, status, latency, upstreamURL)
		statusByCode := map[string]int{
			toolexec.ErrCodeNotFound:          http.StatusNotFound,
			toolexec.ErrCodeDenied:            http.StatusConflict,
			toolexec.ErrCodeSSRF:              http.StatusBadRequest,
			toolexec.ErrCodeBadReq:            http.StatusBadRequest,
			toolexec.ErrCodeTimeout:           http.StatusGatewayTimeout,
			toolexec.ErrCodeToolBlocked:       http.StatusBadRequest,
			toolexec.ErrCodePolicyUnavailable: http.StatusServiceUnavailable,
		}
		httpStatus := http.StatusBadGateway
		if s, ok := statusByCode[code]; ok {
			httpStatus = s
		}
		msg := err.Error()
		if iErr != nil {
			msg = iErr.Message
		}
		// The builtin route is mounted under /api/mcp: surface the guard
		// denials in the documented invoke vocabulary (mcp_tool_blocked),
		// mirroring mapInvokeError on the native endpoint.
		respCode := code
		if code == toolexec.ErrCodeToolBlocked {
			respCode = mcpagg.ErrCodeToolBlocked
		}
		apierrors.Write(w, httpStatus, respCode, msg)
		return
	}
	gw.auditBuiltin(r.Context(), orgID, id, req.Tool, res.ParamsRedacted, outcome, status, latency, upstreamURL)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(res.Body); err != nil {
		gw.log.Warn("builtin tool: writing response failed", "org", orgID, "error", err)
	}
}

// builtinToolCatalog serves the built-in tool descriptors (agent-only —
// same auth surface as the invoke route; mounted under /api/mcp/yabanin).
func (gw *gateway) builtinToolCatalog(w http.ResponseWriter, r *http.Request) {
	if gw.toolExec == nil {
		apierrors.Write(w, http.StatusServiceUnavailable, "unavailable", "built-in tools are not configured")
		return
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication, "org resolution failed")
		return
	}
	agentID := r.Header.Get("X-Agent-Id")
	if agentID == "" {
		apierrors.Write(w, http.StatusForbidden, "agent_only", "the built-in tool catalog requires an agent-principal (yag_) key")
		return
	}
	// Hide tools the org policy denies: the catalog answers what THIS agent
	// may actually call, not the global list. A deny under either address
	// form (bare name or "yabanin:<name>") hides the tool — PolicyKeys
	// parity with the invoke pre-check and the executor guard.
	cat := toolexec.Catalog()
	out := make([]toolexec.ToolDescriptor, 0, len(cat))
	for _, d := range cat {
		name := d.Name
		if d.EffectiveName != "" {
			continue // composite tools document their effective name inline; hide from the flat catalog
		}
		if gw.toolPolicies != nil && gw.builtinToolHidden(r.Context(), orgID, agentID, name) {
			continue
		}
		out = append(out, d)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

// denyBuiltinInvoke runs the built-in pre-check under every policy address
// of the EFFECTIVE name (toolexec.PolicyKeys — the bare name and
// "yabanin:<name>", the same addresses the executor guard and the catalog
// consult): a deny row in either form refuses the invoke (403 policy_denied
// is written inside policyDeniesTool); an allow row in one form never
// un-denies the other.
func (gw *gateway) denyBuiltinInvoke(w http.ResponseWriter, r *http.Request, orgID, agent string, req mcpagg.InvokeRequest) bool {
	for _, key := range toolexec.PolicyKeys(toolexec.EffectiveToolName(req.Tool, req.Params)) {
		if gw.policyDeniesTool(w, r, orgID, agent, key) {
			return true
		}
	}
	return false
}

// builtinToolHidden reports whether an org deny row hides a built-in tool
// from the agent catalog: the tool is checked under EVERY policy address
// (toolexec.PolicyKeys — the bare name and "yabanin:<name>", the same
// addresses the invoke pre-check and the executor guard consult), so a
// deny row in either form hides it.
func (gw *gateway) builtinToolHidden(ctx context.Context, orgID, agent, tool string) bool {
	for _, key := range toolexec.PolicyKeys(tool) {
		if d := gw.toolPolicies.Decide(ctx, orgID, agent, key); d.Action == toolpolicy.ActionDeny {
			return true
		}
	}
	return false
}

// auditBuiltin records a built-in tool execution on the loggerd trail with
// the mcp: label pair so the existing tool-call surfaces pick it up.
func (gw *gateway) auditBuiltin(ctx context.Context, orgID string, id mcpagg.Identity, tool string, params json.RawMessage, outcome string, status int, latency int64, upstreamURL string) {
	if gw.publisher == nil {
		return
	}
	base := eventBase{
		EventType:      "request.completed",
		RequestID:      id.RequestID,
		OrgID:          orgID,
		TeamID:         id.TeamID,
		ModelRequested: "mcp",
		ModelUsed:      "mcp:yabanin:" + tool,
		UpstreamURL:    upstreamURL,
		StatusCode:     int64(status),
		DurationMs:     latency,
		Method:         "POST",
		AgentID:        id.AgentID,
		TaskID:         id.TaskID,
		Labels:         labelsFrom(ctx),
	}
	if outcome != mcpagg.OutcomeOK {
		base.EventType = "request.failed"
		base.Error = "mcp:" + outcome
		if status > 0 {
			base.Error = fmt.Sprintf("mcp:%s (upstream %d)", outcome, status)
		}
	}
	ev := base.build()
	if len(params) > 0 {
		ev.Payload = string(params)
	}
	publishEvent(gw.publisher, gw.log.With("component", "toolexec-audit"), ev) //nolint:contextcheck // publishEvent detaches from the caller context by design
}

func errorsAs(err error, target **toolexec.ExecError) bool {
	if e, ok := err.(*toolexec.ExecError); ok {
		*target = e
		return true
	}
	return false
}
