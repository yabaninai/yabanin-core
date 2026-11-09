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
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		msg, _ := choice["message"].(map[string]any)
		if msg == nil {
			continue
		}
		calls, _ := msg["tool_calls"].([]any)
		if len(calls) == 0 {
			continue
		}
		kept := make([]any, 0, len(calls))
		for _, cl := range calls {
			call, _ := cl.(map[string]any)
			fn, _ := call["function"].(map[string]any)
			name, _ := fn["name"].(string)
			if name == "" {
				kept = append(kept, cl)
				continue
			}
			if d := gw.toolPolicies.Decide(ctx, orgID, subject, name); d.Action == toolpolicy.ActionDeny {
				denied = append(denied, name)
				changed = true
				metrics.ToolPolicyDeniedTotal.WithLabelValues(orgID, name).Inc()
				continue
			}
			// call run through the chat-path args guard too — a client-side
			// executor must not receive a call whose args violate the org's
			// rules. Degraded (fail-open org outage) keeps the call: the
			// response surface's pinned fail-open posture.
			if rep := gw.toolPolicies.GuardDeclaredArgs(ctx, orgID, subject, name, declaredArgs(fn)); rep.Denied {
				denied = append(denied, name)
				changed = true
				metrics.ToolPolicyDeniedTotal.WithLabelValues(orgID, name).Inc()
				continue
			}
			kept = append(kept, cl)
		}
		if changed {
			if len(kept) == 0 {
				delete(msg, "tool_calls")
				// No calls left: the model's tool-loop finish reason would
				// strand the client — normalize to a plain stop.
				if fr, _ := choice["finish_reason"].(string); fr == "tool_calls" {
					choice["finish_reason"] = "stop"
				}
			} else {
				msg["tool_calls"] = kept
			}
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
// deny_regex still scans it). Empty arguments normalize to "{}" (the
// engine's GuardArgs does the same).
func declaredArgs(fn map[string]any) json.RawMessage {
	switch v := fn["arguments"].(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return json.RawMessage(`{}`)
		}
		return json.RawMessage(v)
	case map[string]any:
		out, err := json.Marshal(v)
		if err != nil {
			return json.RawMessage(`{}`)
		}
		return out
	default:
		return json.RawMessage(`{}`)
	}
}

// sseToolGateWriter is an http.ResponseWriter filter for the SSE surface.
// It buffers writes until a complete `data: {...}\n\n` frame is available,
// filters delta.tool_calls entries by policy (a name-bearing first fragment
// decides for that call index; later argument fragments follow the
// decision), rewrites finish_reason when every call of a choice was denied,
// and passes everything else through untouched.
//
// gated too. From the first fragment of such a call the frames are held
// (order preserved) until the calls complete — a frame carrying a
// finish_reason, the [DONE] sentinel, or an unparseable frame — and the
// accumulated arguments run through GuardDeclaredArgs. A denied call's
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

	buf        []byte
	byIdx      map[int]bool // call index → allowed
	deadChoice map[int]bool // choice index → every call denied (finish rewrite)
	denied     int
	active     bool

	holding    bool                  // frames are held pending the args verdict
	heldFrames [][]byte              // held frames in arrival order
	declName   map[int]string        // call index → declared tool name
	declArgs   map[int]*bytes.Buffer // call index → accumulated arguments
}

func newSSEToolGateWriter(ctx context.Context, w http.ResponseWriter, engine *toolpolicy.Engine, orgID, subject string, hasDeny bool) *sseToolGateWriter {
	return &sseToolGateWriter{
		w: w, engine: engine, orgID: orgID, subject: subject, ctx: ctx,
		byIdx: map[int]bool{}, deadChoice: map[int]bool{}, active: hasDeny,
		declName: map[int]string{}, declArgs: map[int]*bytes.Buffer{},
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

func (g *sseToolGateWriter) writeFrame(frame []byte) {
	if !g.active || !bytes.HasPrefix(bytes.TrimSpace(frame), []byte("data: ")) {
		_, _ = g.w.Write(frame)
		return
	}
	payload := framePayload(frame)
	if bytes.Equal(payload, []byte("[DONE]")) {
		g.release()
		_, _ = g.w.Write(frame)
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		g.release()
		_, _ = g.w.Write(frame)
		return
	}
	// A frame carrying a finish_reason completes the response's tool_calls:
	// whatever is held evaluates and releases (the finish rewrite below
	// then sees the final call set).
	terminal := frameTerminal(doc)
	if g.holding {
		g.heldFrames = append(g.heldFrames, frame)
		g.absorb(doc)
		if terminal {
			g.release()
		}
		return
	}
	if hold := g.absorb(doc); hold && !g.failOpen() {
		// An allowed-name call is declaring arguments: hold the frames from
		// here until the calls complete, so an args-denied call is dropped
		// before the client ever sees a fragment.
		g.holding = true
		g.heldFrames = append(g.heldFrames, frame)
		if terminal {
			g.release()
		}
		return
	}
	if out, changed := g.filterFrame(frame, doc, g.nameDenied); changed {
		_, _ = g.w.Write(out)
		return
	}
	_, _ = g.w.Write(frame)
}

// absorb runs the per-fragment scan of one parsed frame: the name-bearing
// first fragments decide their call index (as before, pinned), the argument
// chunks of calls that are not name-denied accumulate for the args guard,
// and the report says whether any call in this frame may still be executing
// — those frames must be held until the calls complete.
func (g *sseToolGateWriter) absorb(doc map[string]any) (hold bool) {
	choices, _ := doc["choices"].([]any)
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		calls, _ := delta["tool_calls"].([]any)
		for _, cl := range calls {
			call, _ := cl.(map[string]any)
			idx := callIndex(call)
			fn, _ := call["function"].(map[string]any)
			name, _ := fn["name"].(string)
			if name != "" {
				// First fragment: decide for this call index.
				allowed := true
				if g.engine != nil {
					if d := g.engine.Decide(g.ctx, g.orgID, g.subject, name); d.Action == toolpolicy.ActionDeny {
						allowed = false
						g.denied++
						metrics.ToolPolicyDeniedTotal.WithLabelValues(g.orgID, name).Inc()
					}
				}
				g.byIdx[idx] = allowed
				if allowed {
					if _, tracking := g.declName[idx]; !tracking {
						g.declName[idx] = name
					}
				}
			}
			if g.nameDenied(0, idx) {
				continue // name-denied: dropped at rewrite time
			}
			hold = true
			if fn == nil {
				continue
			}
			if chunk, _ := fn["arguments"].(string); chunk != "" {
				b := g.declArgs[idx]
				if b == nil {
					b = &bytes.Buffer{}
					g.declArgs[idx] = b
				}
				b.WriteString(chunk)
			}
		}
	}
	return hold
}

// filterFrame applies the drop decisions to one parsed frame: tool_calls
// entries whose (choice, index) the drop function rejects are removed, a
// choice left without any call is marked dead (its "tool_calls"
// finish_reason rewrites to "stop"), and the frame re-encodes when anything
// changed. out carries the original frame bytes when nothing changed.
func (g *sseToolGateWriter) filterFrame(frame []byte, doc map[string]any, drop func(ci, idx int) bool) (out []byte, changed bool) {
	choices, _ := doc["choices"].([]any)
	for ci, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		// Terminal frame: a choice whose every call was denied must not
		// strand the client in a tool loop — rewrite the finish reason.
		if fr, _ := choice["finish_reason"].(string); fr == "tool_calls" && g.deadChoice[ci] {
			choice["finish_reason"] = "stop"
			changed = true
		}
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		calls, _ := delta["tool_calls"].([]any)
		if len(calls) == 0 {
			continue
		}
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
		if anyDropped {
			changed = true
			if anyKept {
				delta["tool_calls"] = kept
			} else {
				delete(delta, "tool_calls")
				g.deadChoice[ci] = true
			}
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

// release evaluates every held call's accumulated arguments through the
// chat-path args guard and writes the held frames out (order preserved),
// dropping the fragments of denied calls whole.
func (g *sseToolGateWriter) release() {
	frames := g.heldFrames
	g.heldFrames, g.holding = nil, false
	if len(frames) == 0 {
		return
	}
	drop := map[int]bool{}
	for idx, name := range g.declName {
		if g.nameDenied(0, idx) {
			drop[idx] = true // name-denied mid-hold
			continue
		}
		if name == "" || g.engine == nil {
			continue
		}
		args := json.RawMessage(`{}`)
		if b := g.declArgs[idx]; b != nil && b.Len() > 0 {
			args = json.RawMessage(b.Bytes())
		}
		if rep := g.engine.GuardDeclaredArgs(g.ctx, g.orgID, g.subject, name, args); rep.Denied {
			drop[idx] = true
			g.denied++
			metrics.ToolPolicyDeniedTotal.WithLabelValues(g.orgID, name).Inc()
		}
	}
	for _, f := range frames {
		var doc map[string]any
		if err := json.Unmarshal(framePayload(f), &doc); err != nil {
			_, _ = g.w.Write(f)
			continue
		}
		if out, changed := g.filterFrame(f, doc, func(_, idx int) bool { return drop[idx] }); changed {
			_, _ = g.w.Write(out)
			continue
		}
		_, _ = g.w.Write(f)
	}
	g.declName = map[int]string{}
	g.declArgs = map[int]*bytes.Buffer{}
}

// nameDenied reports whether the call index was denied by its name decision.
func (g *sseToolGateWriter) nameDenied(_ int, idx int) bool {
	allowed, seen := g.byIdx[idx]
	return seen && !allowed
}

// failOpen reports the D-15 posture: a dead request context means the
// policy store is unreachable — the surface fails open and nothing is held.
func (g *sseToolGateWriter) failOpen() bool {
	return g.ctx != nil && g.ctx.Err() != nil
}

// framePayload strips the SSE envelope from a data frame.
func framePayload(frame []byte) []byte {
	return bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(frame), []byte("data: ")))
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

// callIndex extracts the streaming call index (missing → 0).
func callIndex(call map[string]any) int {
	if v, ok := call["index"].(float64); ok {
		return int(v)
	}
	return 0
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
	// The policy checks the EFFECTIVE name: http_request composes to
	// http_<method> so name presets (network-readonly denies http_post)
	// apply to the built-in executor naturally.
	toolName := "yabanin:" + toolexec.EffectiveToolName(req.Tool, req.Params)
	if gw.policyDeniesTool(w, r, orgID, id.AgentID, toolName) {
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
			toolexec.ErrCodeNotFound:    http.StatusNotFound,
			toolexec.ErrCodeDenied:      http.StatusConflict,
			toolexec.ErrCodeSSRF:        http.StatusBadRequest,
			toolexec.ErrCodeBadReq:      http.StatusBadRequest,
			toolexec.ErrCodeTimeout:     http.StatusGatewayTimeout,
			toolexec.ErrCodeToolBlocked: http.StatusBadRequest,
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
	// may actually call, not the global list.
	cat := toolexec.Catalog()
	out := make([]toolexec.ToolDescriptor, 0, len(cat))
	for _, d := range cat {
		name := d.Name
		if d.EffectiveName != "" {
			continue // composite tools document their effective name inline; hide from the flat catalog
		}
		if gw.toolPolicies != nil {
			if dec := gw.toolPolicies.Decide(r.Context(), orgID, agentID, "yabanin:"+name); dec.Action == toolpolicy.ActionDeny {
				continue
			}
		}
		out = append(out, d)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
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
