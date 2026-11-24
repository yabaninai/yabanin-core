package cli

// TOOL-02 native twin: tool-use gating on the Anthropic-native Messages
// surface (docs/clients/claude-code.md). The chat surface strips denied
// tool_calls (toolgate.go); this file applies the same org policy to the
// native wire, where the model declares tool_use content blocks:
//
//   - JSON surface (messagesNativeJSON): denied tool_use blocks are
//     removed from content, and a "tool_use" stop_reason whose every call
//     was denied or dropped is rewritten to "end_turn" so a client tool
//     loop is never stranded. Nothing removed → byte identity, up to the
//     SSE surface's immediate comment delivery noted below.
//   - SSE surface (messagesNativeStream): a frame-level gate sits between
//     the upstream body and the terminal-hold relay. A denied block's
//     frames are suppressed whole (the client never sees one byte), the
//     content_block indices of everything after the removal point are
//     renumbered so the visible stream stays contiguous, and the
//     message_delta stop_reason is rewritten under the same all-denied
//     rule. An allowed tool_use is held until content_block_stop, where
//     its accumulated input runs through the same args guard as the chat
//     path (GuardDeclaredArgs) before a single frame is released; a
//     start frame that declares a complete input member is guarded at
//     the declaration itself. Keepalive comment lines deliver
//     immediately (relay parity), so a comment inside a held allowed run
//     reaches the client before that run's later release — byte identity
//     holds for the frame sequence, not for interleaved comments.
//
// Frame decoding shares the relay's parser rules (apiformat: LF, CRLF and
// lone-CR terminators; the event name falls back to the data payload's
// type member — nativeEventName), and the stream tail follows the relay's
// salvage rule: a cut that lands exactly after a complete data line
// routes that frame before the error propagates. Activation is a live
// property, re-checked on every tool_use declaration via
// Engine.HasResponseGates (deny rows and declared-args rules both count;
// a loader outage fails open), so a policy change lands without a new
// request — chat activateForFrame parity.
//
// The engine decides lazily: until a frame actually declares a tool_use,
// frames pass through after the light declaration scan and delivered-call
// accounting (no gates → no gating; byte identity apart from comment
// timing).
// Failure modes mirror the chat canon: malformed or interleaved frames
// inside an unresolved run DISCARD the run fail-closed (never released
// unchecked, never converted into an allowed call), a truncated stream
// discards the unresolved run, and a cancelled context fails open (D-15)
// — held allowed frames release through the shifted path (a release after
// earlier removals stays renumbered), decided denials stay dropped.
// Ping and unknown event types touch no state: they cannot orphan a held
// run or slip past a decided denial. Usage accounting is untouched by
// design: the relay's usage comes from message_start/message_delta,
// which the gate never rewrites except the stop_reason member.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"strconv"

	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// emptyNativeInput is the guard input for a tool_use declared with no
// input member at all.
var emptyNativeInput = []byte("{}")

// Bounded-hold caps: an open allowed run buffers its frames until the
// stop resolves the guard, so the buffering needs its own ceiling — a
// pathological or hostile upstream must not grow gateway memory without
// limit. The caps sit far above any legitimate tool input (per-frame
// bytes are already bounded by SSEStreamLineLimit at the line reader).
const (
	nativeHoldMaxArgsBytes   = apiformat.SSEStreamLineLimit
	nativeHoldMaxFrames      = 4096
	nativeHoldMaxFramesBytes = 2 * apiformat.SSEStreamLineLimit
)

// ---- JSON surface ----

// gateNativeToolUseJSON strips tool_use content blocks the org policy
// denies from a buffered native Messages reply. Byte identity is
// preserved when nothing is removed (denials and dropped declarations
// alike); the denied tool names are returned for logging (the per-tool
// metric is the tracking surface).
func (gw *gateway) gateNativeToolUseJSON(ctx context.Context, orgID, subject string, body []byte) ([]byte, []string) {
	if gw.toolPolicies == nil || !gw.toolPolicies.HasResponseGates(ctx, orgID) {
		return body, nil
	}
	doc, blocks, ok := nativeMessageBlocks(body)
	if !ok {
		return body, nil
	}
	kept, denied, keptTools := gw.filterNativeBlocks(ctx, orgID, subject, blocks)
	if len(kept) == len(blocks) {
		return body, denied // nothing removed: byte identity even under args-gate rows
	}
	content, err := json.Marshal(kept)
	if err != nil {
		return body, denied // never fail the response over a filter bug
	}
	doc["content"] = content
	if !keptTools {
		nativeStripToolFinish(doc)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body, denied
	}
	return out, denied
}

// nativeMessageBlocks decodes the raw message envelope and its content
// block array. ok=false means the body is not a shaped native message —
// the gate passes it through untouched.
func nativeMessageBlocks(body []byte) (doc map[string]json.RawMessage, blocks []json.RawMessage, ok bool) {
	doc = map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, false // not a message body — pass through untouched
	}
	if err := json.Unmarshal(doc["content"], &blocks); err != nil || len(blocks) == 0 {
		return nil, nil, false
	}
	return doc, blocks, true
}

// nativeStripToolFinish repairs a stranded finish: with every declared
// call denied, a "tool_use" stop_reason would strand the consumer's tool
// loop, so it normalizes to "end_turn" (the SSE twin rewrites the
// message_delta the same way).
func nativeStripToolFinish(doc map[string]json.RawMessage) {
	if reason, _ := nativeStopReason(doc["stop_reason"]); reason == "tool_use" {
		doc["stop_reason"] = json.RawMessage(`"end_turn"`)
	}
}

// nativeDeniedWarn logs the org-scoped enforcement summary once per reply
// (chat parity); empty denials stay silent.
func nativeDeniedWarn(l *slog.Logger, orgID string, denied []string) {
	if len(denied) == 0 {
		return
	}
	l.Warn("tool policy denied native tool_use", "org", orgID, "tools", toolNamesFromDenied(denied))
}

// filterNativeBlocks applies the policy to every content block: denied
// tool_use blocks drop (counted per tool), everything else passes. keptTools
// reports whether a tool_use block survived — the stop_reason rewrite must
// not strand a loop that still has a live call.
func (gw *gateway) filterNativeBlocks(ctx context.Context, orgID, subject string, blocks []json.RawMessage) (kept []json.RawMessage, denied []string, keptTools bool) {
	kept = make([]json.RawMessage, 0, len(blocks))
	for _, raw := range blocks {
		drop, name, isTool := gw.nativeBlockAllowed(ctx, orgID, subject, raw)
		if drop {
			if name != "" {
				denied = append(denied, name)
				metrics.ToolPolicyDeniedTotal.WithLabelValues(orgID, name).Inc()
			}
			continue
		}
		kept = append(kept, raw)
		keptTools = keptTools || isTool
	}
	return kept, denied, keptTools
}

// nativeBlockAllowed runs the decision for one content block. Non-tool_use
// members and members that do not parse pass; a nameless tool_use is an
// ambiguous executable declaration and fails closed (chat filterToolCall
// parity); a named tool_use faces the deny decision and the declared-args
// guard under the same server="*" addressing as the chat surface.
func (gw *gateway) nativeBlockAllowed(ctx context.Context, orgID, subject string, raw json.RawMessage) (drop bool, name string, isTool bool) {
	var block nativeBlockHead
	if json.Unmarshal(raw, &block) != nil {
		return false, "", false
	}
	if block.Type != "tool_use" {
		return false, "", false
	}
	if block.Name == "" {
		return true, "", true
	}
	if d := gw.toolPolicies.Decide(ctx, orgID, subject, block.Name); d.Action == toolpolicy.ActionDeny {
		return true, block.Name, true
	}
	args := block.Input
	if len(args) == 0 {
		args = emptyNativeInput
	}
	if rep := gw.toolPolicies.GuardDeclaredArgs(ctx, orgID, subject, block.Name, args); rep.Denied {
		return true, block.Name, true
	}
	return false, block.Name, true
}

// nativeBlockHead is the policy-visible shape of one content block.
type nativeBlockHead struct {
	Type  string          `json:"type"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// nativeStopReason reads the top-level stop_reason member of a raw
// message body.
func nativeStopReason(raw json.RawMessage) (string, bool) {
	var reason string
	if err := json.Unmarshal(raw, &reason); err != nil {
		return "", false
	}
	return reason, true
}

// ---- SSE surface ----

// nativeToolRun is one open ALLOWED tool_use content block: from its
// content_block_start until its content_block_stop the gate holds every
// frame of the run, then releases it after the args guard passed over
// the complete input. args accumulates the input_json_delta partials;
// startInput keeps the start frame's declared input member (the guard
// input when no deltas arrive). framesLen tracks the buffered frame
// bytes for the bounded-hold caps.
type nativeToolRun struct {
	rawIdx     int
	name       string
	frames     [][]byte     // buffered wire frames (start + deltas + stop), verbatim
	framesLen  int          // total bytes buffered in frames
	args       bytes.Buffer // accumulated input_json_delta partials
	startInput []byte       // the start frame's declared input (may be empty)
}

// nativeToolGateReader is the SSE-surface tool gate for the native
// Messages relay: an io.Reader over the (idle-wrapped) upstream body that
// emits gated frames to relayAnthropicSSE. Until a frame declares a
// tool_use, bytes pass through untouched; once the gate activates, frames
// are routed per event type. The relay downstream keeps its own parser,
// terminal hold and accounting — this reader only transforms the frame
// stream.
type nativeToolGateReader struct {
	src     *apiformat.SSELineReader
	frames  apiformat.SSEFrameBuffer
	engine  *toolpolicy.Engine
	orgID   string
	subject string
	// ctx is the request context: a client disconnect or the stream
	// ceiling must stop any hold (D-15) — the surface fails open, as the
	// chat SSE gate pins it.
	ctx    context.Context
	out    []byte // gated frames awaiting Read
	eofErr error  // set once the upstream ended (latched)

	active bool // response gates confirmed for this org: frames are routed
	shift  int  // removed content indices (everything after shifts down)
	hold   *nativeToolRun
	// pendingDeny quarantines the wire indices of decided-deny runs until
	// their content_block_stop arrives (or the response protocol ends):
	// their deltas and stops swallow without buffering, and a re-declared
	// index cannot resurrect a decided denial.
	pendingDeny map[int]bool
	removedCnt  int // tool_use blocks removed (denied or discarded)
	keptCnt     int // tool_use blocks that survived
}

// newNativeToolGateReader wraps src for the native stream relay.
func newNativeToolGateReader(ctx context.Context, src io.Reader, engine *toolpolicy.Engine, orgID, subject string) *nativeToolGateReader {
	return &nativeToolGateReader{
		src:    apiformat.NewSSELineReader(bufio.NewReader(src), apiformat.SSEStreamLineLimit),
		engine: engine, orgID: orgID, subject: subject, ctx: ctx,
	}
}

// Read returns gated bytes, pulling and transforming upstream frames as
// needed. An error ends the stream (EOF for a clean end).
func (g *nativeToolGateReader) Read(p []byte) (int, error) {
	for len(g.out) == 0 {
		if g.eofErr != nil {
			return 0, g.eofErr
		}
		if err := g.pull(); err != nil {
			g.eofErr = err
			if len(g.out) == 0 {
				return 0, err
			}
			break
		}
	}
	n := copy(p, g.out)
	g.out = g.out[n:]
	return n, nil
}

// pull reads and routes one upstream frame, or ends the stream: a clean
// end or a cut propagates the reader's error to the relay (which owns the
// torn-tail and terminal synthesis), after the gate settles its hold and
// tail. A nil frame with a nil error is a comment line that already
// forwarded itself — pull returns without routing so Read can flush the
// fresh bytes instead of blocking on the next upstream line.
func (g *nativeToolGateReader) pull() error {
	frame, err := g.nextFrame()
	if err == nil {
		if frame == nil {
			return nil // comment yielded: Read flushes g.out now
		}
		g.route(frame)
		return nil
	}
	g.endStream(frame, err)
	return err
}

// endStream settles the gate at an upstream end. A boundary-aligned cut
// (empty trailing partial) may still salvage the held frame — the relay's
// salvage rule, mirrored so a denial decided at the stream's last instant
// still holds (the relay would have dispatched that frame un-gated). Then
// a cancelled context fails open (D-15): an allowed run's frames release
// through the shifted path (a release after earlier removals stays
// renumbered), decided denials stay dropped. A clean end inside an
// unresolved run discards it fail-closed and delivers nothing held; the
// trailing partial forwards raw in every other case (the relay owns
// torn-tail withholding and terminal synthesis).
func (g *nativeToolGateReader) endStream(trailing []byte, err error) {
	if err != nil && !errors.Is(err, apiformat.ErrSSELineLimit) &&
		len(trailing) == 0 && g.frames.Salvageable() {
		g.route(append(g.frames.Take(), '\r', '\n'))
	}
	if g.ctx.Err() != nil {
		if g.hold != nil {
			g.releaseRun(g.hold) // D-15: held allowed frames release, index-mapped
		}
		g.hold = nil
		g.pendingDeny = nil
	}
	if g.hold != nil {
		g.hold = nil // unresolved run at a clean end: fail-closed, release nothing
		return
	}
	g.forward(trailing)
}

// nextFrame assembles the next complete upstream event (verbatim lines
// plus the separator); a comment line forwards itself and reports a nil
// frame so the caller yields to Read at once. At the stream's end the
// held frame lines stay
// buffered for the tail router's salvage probe, and only the unterminated
// trailing partial is reported, so the gate can tell a boundary-aligned
// end (empty partial) from a cut mid-line.
func (g *nativeToolGateReader) nextFrame() ([]byte, error) {
	for {
		line, err := g.src.ReadLine()
		if err == nil {
			if apiformat.SSECommentLine(line) {
				// Keepalive comments ride no event: forward and yield at
				// once (relay deliverLine parity) — a completed comment
				// reaches the client even while the upstream stalls
				// before its next line, a trailing comment survives a
				// clean end, and g.out stays bounded because control
				// returns to Read after every comment line.
				g.forward(line)
				return nil, nil
			}
			blank, overflow := g.frames.Add(line, apiformat.SSEStreamLineLimit)
			if overflow {
				g.frames.Take() // drop the oversized held frame
				return nil, apiformat.ErrSSELineLimit
			}
			if blank {
				// The separator line itself is not buffered (see
				// SSEFrameBuffer.Add): compose it verbatim so LF, CRLF
				// and CR upstreams all stay byte-identical.
				return append(g.frames.Take(), line...), nil
			}
			continue
		}
		return line, err // trailing partial (nil at a boundary-aligned end)
	}
}

// route dispatches one frame. While inactive, every frame is scanned for
// a tool_use declaration (decoded member values, so escaped spellings
// cannot hide one); a declaration re-queries the org's response gates, so
// a policy change lands mid-stream without a new request (chat
// activateForFrame parity) and an org with no gates passes everything
// verbatim.
func (g *nativeToolGateReader) route(frame []byte) {
	ev, hasData := parseNativeSSEFrame(frame)
	if !g.active {
		if !hasData || !declaresNativeToolUse([]byte(ev.Data)) || !g.applicable() {
			g.forward(frame)
			if hasData {
				g.countDeliveredStart([]byte(ev.Data))
			}
			return
		}
		g.active = true
	}
	g.gateFrame(frame, nativeEventName(ev), []byte(ev.Data))
}

// countDeliveredStart keeps call accounting truthful for frames that
// streamed past an inactive gate: a tool_use start forwarded verbatim is
// a call the client really received, so a later denial of another call
// must not strand the tool loop with a rewritten end_turn.
func (g *nativeToolGateReader) countDeliveredStart(payload []byte) {
	var doc nativeBlockStart
	if json.Unmarshal(payload, &doc) != nil || doc.Block.Type != "tool_use" {
		return
	}
	g.keptCnt++
}

// applicable reports whether the org's policy state gates this stream.
// A loader outage reports no gates (fail open).
func (g *nativeToolGateReader) applicable() bool {
	return g.engine != nil && g.engine.HasResponseGates(g.ctx, g.orgID)
}

// gateFrame routes an active frame by event name. Ping and unknown event
// types never touch gate state.
func (g *nativeToolGateReader) gateFrame(frame []byte, name string, payload []byte) {
	switch name {
	case "content_block_start":
		g.blockStart(frame, payload)
	case "content_block_delta":
		g.blockDelta(frame, payload)
	case "content_block_stop":
		g.blockStop(frame, payload)
	case "message_delta":
		g.messageDelta(frame, payload)
	case "message_stop", "error":
		g.endProtocolFrame(frame, payload)
	default:
		g.passthroughFrame(frame, payload)
	}
}

// protocolViolation handles a block-protocol frame whose payload does
// not parse. A live quarantine swallows first — a decided deny's
// trailing frames may not ride a parse failure past the decision. With
// an open held run the frame has just forced that run's fail-closed
// discard, so it swallows with the run it broke: its own decode failed,
// so neither its index nor its payload is trustworthy, and surfacing it
// headless (index-mapped or not) could only desynchronize the client's
// block sequence. Only a violation with nothing held forwards, the way
// the relay would have delivered it.
func (g *nativeToolGateReader) protocolViolation(frame []byte, payload []byte) {
	if g.quarantinedJunk(payload) {
		return
	}
	heldIdx := -1 // the held run's wire index, saved before the discard drops the hold
	if g.hold != nil {
		heldIdx = g.hold.rawIdx
	}
	g.discardHold()
	if heldIdx >= 0 {
		return // the triggering frame swallows whole with the run it broke
	}
	g.emitShifted(frame, payload)
}

// quarantinedJunk reports whether an unparseable block-protocol frame
// must swallow silently. An index that survives the mangled payload
// swallows only when it belongs to a decided-deny run; an unrecoverable
// one swallows while any quarantine is live, because the window closes
// at the denied run's stop and forwarding mangled bytes then risks
// leaking fragments the decision already withheld.
func (g *nativeToolGateReader) quarantinedJunk(payload []byte) bool {
	if len(g.pendingDeny) == 0 {
		return false
	}
	if members, ok := nativeMembers(payload); ok {
		if idx, ok := nativeIntMember(members["index"]); ok && !g.pendingDeny[idx] {
			return false
		}
	}
	return true
}

// passthroughFrame forwards a frame the gate never acts on (pings,
// unknown event types): hold state stays untouched, so a keepalive
// cannot orphan a held run and a mid-run unknown event cannot bypass a
// decided denial.
func (g *nativeToolGateReader) passthroughFrame(frame []byte, payload []byte) {
	g.emitShifted(frame, payload)
}

// endProtocolFrame closes the response protocol (message_stop, error):
// an unresolved run resolves fail-closed and the deny quarantine clears —
// after a terminal there is no run left to swallow, so a hostile re-use
// of a decided index cannot extend the denial past the response.
func (g *nativeToolGateReader) endProtocolFrame(frame []byte, payload []byte) {
	g.discardHold()
	g.pendingDeny = nil
	g.emitShifted(frame, payload)
}

// nativeBlockStart is the parsed content_block_start payload.
type nativeBlockStart struct {
	Index int             `json:"index"`
	Block nativeBlockHead `json:"content_block"`
}

// blockStart decides a tool_use block at its declaration: a denial drops
// the run at once (its deltas and stop swallow later via the quarantine);
// an allowed run holds its frames until content_block_stop, where the
// args guard runs over the complete accumulation. A start frame whose
// input member already carries a complete document is guarded here.
func (g *nativeToolGateReader) blockStart(frame []byte, payload []byte) {
	var doc nativeBlockStart
	if json.Unmarshal(payload, &doc) != nil {
		g.protocolViolation(frame, payload)
		return
	}
	if g.pendingDeny[doc.Index] {
		return // a decided denial's re-declared index stays swallowed
	}
	if g.hold != nil {
		g.discardHold() // overlapping runs violate the protocol: fail closed
	}
	if doc.Block.Type != "tool_use" {
		g.emitShifted(frame, payload)
		return
	}
	if doc.Block.Name == "" {
		g.denyRun(doc.Index, "") // nameless executable declaration: fail closed
		return
	}
	if d := g.engine.Decide(g.ctx, g.orgID, g.subject, doc.Block.Name); d.Action == toolpolicy.ActionDeny {
		g.denyRun(doc.Index, doc.Block.Name)
		return
	}
	if g.startInputDenied(&doc.Block) {
		g.denyRun(doc.Index, doc.Block.Name)
		return
	}
	g.hold = &nativeToolRun{rawIdx: doc.Index, name: doc.Block.Name, frames: [][]byte{frame}, framesLen: len(frame), startInput: doc.Block.Input}
}

// startInputDenied runs the declared-args guard over a start frame's
// complete input member. A non-empty, non-"{}" input is a complete
// argument document the model may rely on — guarding it closes the gap
// where a denial-hiding payload rides the start frame and no deltas ever
// arrive. Empty and empty-object inputs defer to the stop-time
// accumulation.
func (g *nativeToolGateReader) startInputDenied(block *nativeBlockHead) bool {
	if len(block.Input) == 0 || bytes.Equal(bytes.TrimSpace(block.Input), emptyNativeInput) {
		return false
	}
	rep := g.engine.GuardDeclaredArgs(g.ctx, g.orgID, g.subject, block.Name, block.Input)
	return rep.Denied
}

// nativeBlockDelta is the parsed content_block_delta payload.
type nativeBlockDelta struct {
	Index int `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

// blockDelta accumulates one input_json_delta of the held run, swallows
// the deltas of a quarantined deny run, and forwards deltas of ordinary
// blocks with the visible index. Anything else arriving mid-run
// violates the protocol and resolves the run fail-closed — a frame
// aimed at the discarded run's own index swallows with it (its start
// was never visible), while another block's frame still forwards. A
// delta that would cross the bounded-hold caps discards the run
// fail-closed instead of growing the hold without limit.
func (g *nativeToolGateReader) blockDelta(frame []byte, payload []byte) {
	var doc nativeBlockDelta
	if json.Unmarshal(payload, &doc) != nil {
		g.protocolViolation(frame, payload)
		return
	}
	if g.pendingDeny[doc.Index] {
		return // swallowed whole with its decided-deny run
	}
	if g.hold == nil {
		g.emitShifted(frame, payload)
		return
	}
	if doc.Index != g.hold.rawIdx {
		g.discardHold()               // overlapping runs violate the protocol: fail closed
		g.emitShifted(frame, payload) // another block's delta: its start was visible, quarantined, or not yet declared
		return
	}
	if doc.Delta.Type != "input_json_delta" {
		// The violating frame belongs to the run now discarded: its start
		// was never visible, so it swallows with the run — a mismatched
		// delta must not surface headless under another block's index.
		g.discardHold()
		return
	}
	if !g.holdAccepts(len(doc.Delta.PartialJSON), len(frame)) {
		g.discardHold()
		return
	}
	g.hold.args.WriteString(doc.Delta.PartialJSON)
	g.hold.frames = append(g.hold.frames, frame)
	g.hold.framesLen += len(frame)
}

// holdAccepts reports whether the held run may absorb one more frame:
// args bytes, frame count and total frame bytes each stay under the
// bounded-hold caps.
func (g *nativeToolGateReader) holdAccepts(argsNext, frameNext int) bool {
	run := g.hold
	return run.args.Len()+argsNext <= nativeHoldMaxArgsBytes &&
		len(run.frames)+1 <= nativeHoldMaxFrames &&
		run.framesLen+frameNext <= nativeHoldMaxFramesBytes
}

// blockStop resolves the held run at its content_block_stop: the args
// guard runs over the COMPLETE accumulation, a denial drops the run
// (before the client ever saw a fragment), an allow releases the buffered
// frames with their visible indices. A quarantined index's stop closes
// its swallow.
func (g *nativeToolGateReader) blockStop(frame []byte, payload []byte) {
	var doc struct {
		Index int `json:"index"`
	}
	if json.Unmarshal(payload, &doc) != nil {
		g.protocolViolation(frame, payload)
		return
	}
	if g.pendingDeny[doc.Index] {
		delete(g.pendingDeny, doc.Index) // the denied run is fully consumed
		return
	}
	if g.hold != nil && doc.Index == g.hold.rawIdx {
		g.hold.frames = append(g.hold.frames, frame) // the stop belongs to the release set
		g.hold.framesLen += len(frame)
		g.resolveHold()
		return
	}
	if g.hold != nil {
		g.discardHold()
	}
	g.emitShifted(frame, payload)
}

// resolveHold settles the open allowed run at its content_block_stop:
// the guard input is the delta accumulation when one arrived, else the
// start frame's declared input, else the empty document.
func (g *nativeToolGateReader) resolveHold() {
	run := g.hold
	g.hold = nil
	args := run.args.Bytes()
	if len(args) == 0 {
		args = run.startInput
	}
	if len(args) == 0 {
		args = emptyNativeInput
	}
	if rep := g.engine.GuardDeclaredArgs(g.ctx, g.orgID, g.subject, run.name, args); rep.Denied {
		g.denyRun(run.rawIdx, run.name)
		return
	}
	g.keptCnt++
	g.releaseRun(run)
}

// releaseRun forwards a held run's buffered frames through the normal
// shifted path: a release after earlier removals renumbers indices
// exactly like a resolved keep, so neither a resolved keep nor a D-15
// fail-open release ever exposes a raw wire index the client cannot
// reconcile with the visible sequence.
func (g *nativeToolGateReader) releaseRun(run *nativeToolRun) {
	for _, frame := range run.frames {
		ev, _ := parseNativeSSEFrame(frame)
		g.emitShifted(frame, []byte(ev.Data))
	}
}

// messageDelta rewrites a stranded stop_reason: a "tool_use" finish whose
// every declared call was removed (denied or discarded) would strand the
// consumer's tool loop, so it normalizes to "end_turn" (the JSON surface
// pins the same contract). A survivor anywhere in the stream keeps the
// loop alive.
func (g *nativeToolGateReader) messageDelta(frame []byte, payload []byte) {
	var doc struct {
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
	}
	if json.Unmarshal(payload, &doc) != nil {
		g.forward(frame)
		return
	}
	if g.hold != nil {
		g.discardHold() // a finish inside an unresolved run violates the protocol
	}
	if doc.Delta.StopReason == "tool_use" && g.removedCnt > 0 && g.keptCnt == 0 {
		if out, ok := rewriteNativeStopReason(frame, payload); ok {
			g.forward(out)
			return
		}
	}
	g.forward(frame)
}

// denyRun drops a tool_use block at wire index rawIdx: the removal counts
// immediately (everything after shifts down), the index enters the deny
// quarantine (its trailing deltas and stop swallow), and a named denial
// counts per tool. Nameless declarations fail closed without a metric
// label (chat parity).
func (g *nativeToolGateReader) denyRun(rawIdx int, name string) {
	g.shift++
	g.removedCnt++
	if g.pendingDeny == nil {
		g.pendingDeny = make(map[int]bool)
	}
	g.pendingDeny[rawIdx] = true
	if name != "" {
		metrics.ToolPolicyDeniedTotal.WithLabelValues(g.orgID, name).Inc()
	}
}

// discardHold drops the unresolved allowed run fail-closed: its buffered
// frames were never guardable and release nothing. denyRun marks the
// removal and quarantines the index, so the run's trailing frames swallow.
func (g *nativeToolGateReader) discardHold() {
	if g.hold == nil {
		return
	}
	g.denyRun(g.hold.rawIdx, "")
	g.hold = nil
}

// emitShifted forwards a frame, renumbering its content_block index when
// removals happened before it. Unmodified frames pass byte-identically.
func (g *nativeToolGateReader) emitShifted(frame []byte, payload []byte) {
	if g.shift > 0 {
		if out, ok := rewriteNativeIndex(frame, payload, g.shift); ok {
			g.forward(out)
			return
		}
	}
	g.forward(frame)
}

func (g *nativeToolGateReader) forward(frame []byte) { g.out = append(g.out, frame...) }

// parseNativeSSEFrame splits one complete frame into the apiformat.SSEEvent
// view the relay's parser would produce: the event field and the data
// lines joined with LF. Record splitting and content stripping share the
// package's terminator rules, so LF, CRLF and lone-CR frames decode
// identically.
func parseNativeSSEFrame(frame []byte) (apiformat.SSEEvent, bool) {
	var ev apiformat.SSEEvent
	hasData := false
	for _, line := range apiformat.SSERecordLines(frame) {
		content := apiformat.SSELineContent(line)
		if payload, ok := bytes.CutPrefix(content, []byte("data:")); ok {
			payload = bytes.TrimPrefix(payload, []byte(" "))
			if hasData {
				ev.Data += "\n"
			}
			ev.Data += string(payload)
			hasData = true
			continue
		}
		if name, ok := bytes.CutPrefix(content, []byte("event:")); ok {
			ev.Event = string(bytes.TrimSpace(name))
		}
	}
	return ev, hasData
}

// nativeMembers decodes a payload into its top-level members, keeping
// every member's raw bytes: a surgical re-encode that preserves number
// precision (a map[string]any round-trip would corrupt large int64s into
// floats) and unknown members verbatim.
func nativeMembers(payload []byte) (map[string]json.RawMessage, bool) {
	members := map[string]json.RawMessage{}
	if json.Unmarshal(payload, &members) != nil {
		return nil, false
	}
	return members, true
}

// nativeIntMember reads an integer member tolerantly: exact int64 first,
// then an integral float64 (JSON numbers unmarshal as float64 under a
// plain map decode; the raw form keeps the choice available).
func nativeIntMember(raw json.RawMessage) (int, bool) {
	var n json.Number
	if json.Unmarshal(raw, &n) != nil {
		return 0, false
	}
	if v, err := n.Int64(); err == nil {
		return int(v), true
	}
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) {
		return 0, false
	}
	return int(f), true
}

// rewriteNativeIndex renumbers a frame's top-level index member for the
// shifted visible stream, splicing the re-encoded members into the
// original frame's data line (the rewrite is semantic: member ORDER may
// normalize, but member VALUES stay raw — numbers never lose precision).
// Frames without an index (or with one that predates the removals) pass
// unchanged.
func rewriteNativeIndex(frame []byte, payload []byte, shift int) ([]byte, bool) {
	members, ok := nativeMembers(payload)
	if !ok {
		return frame, false
	}
	idx, ok := nativeIntMember(members["index"])
	if !ok || idx < shift {
		return frame, false
	}
	members["index"] = json.RawMessage(strconv.Itoa(idx - shift))
	return spliceNativeDataLine(frame, members)
}

// rewriteNativeStopReason rewrites a message_delta's stop_reason member to
// end_turn, splicing the re-encoded members into the original frame so
// the rest of the message stays raw (usage rides message_delta).
func rewriteNativeStopReason(frame []byte, payload []byte) ([]byte, bool) {
	members, ok := nativeMembers(payload)
	if !ok {
		return frame, false
	}
	var delta map[string]json.RawMessage
	if json.Unmarshal(members["delta"], &delta) != nil {
		return frame, false
	}
	if _, ok := delta["stop_reason"]; !ok {
		return frame, false
	}
	delta["stop_reason"] = json.RawMessage(`"end_turn"`)
	rewritten, err := json.Marshal(delta)
	if err != nil {
		return frame, false
	}
	members["delta"] = rewritten
	return spliceNativeDataLine(frame, members)
}

// spliceNativeDataLine replaces a frame's data-line run with a single
// data line carrying the re-encoded members, preserving every other
// record line byte-verbatim — event/id/retry/comment lines, their
// terminators, CR-vs-LF style. A frame without a data line passes
// unchanged.
func spliceNativeDataLine(frame []byte, members map[string]json.RawMessage) ([]byte, bool) {
	enc, err := json.Marshal(members)
	if err != nil {
		return frame, false
	}
	var out []byte
	spliced := false
	for _, line := range apiformat.SSERecordLines(frame) {
		content := apiformat.SSELineContent(line)
		if !bytes.HasPrefix(content, []byte("data:")) {
			out = append(out, line...)
			continue
		}
		if spliced {
			continue // later data lines fold into the single spliced one
		}
		out = append(out, "data: "...)
		out = append(out, enc...)
		out = append(out, line[len(content):]...) // the line's own terminator
		spliced = true
	}
	if !spliced {
		return frame, false
	}
	return out, true
}

// declaresNativeToolUse reports whether a JSON payload carries the
// "tool_use" block type anywhere, reading decoded string VALUES (the
// native protocol names blocks through content_block.type). Over-detection
// is harmless — activation only turns filtering on.
func declaresNativeToolUse(payload []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if open, ok := tok.(json.Delim); !ok || (open != '{' && open != '[') {
		return false
	}
	return scanToolUseValues(dec)
}

// scanToolUseValues walks the decoded payload for a "tool_use" string
// value (activation scan; see declaresNativeToolUse).
func scanToolUseValues(dec *json.Decoder) bool {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case string:
			if t == "tool_use" {
				return true
			}
		case json.Delim:
			if (t == '{' || t == '[') && scanToolUseValues(dec) {
				return true
			}
		}
	}
	_, _ = dec.Token() // consume the container's closing delimiter
	return false
}
