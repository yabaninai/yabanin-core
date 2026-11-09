package handlers

// OP-9 (OUTPLAY-PLAN-2026-10-06 §3): admin read API of the policy decision
// log — GET /api/organizations/{id}/policy-decisions. Read-only surface over
// adminstore.ListPolicyDecisions / ListPolicyDecisionRequests (the rows the
// loggerd consumer writes): standard pagination envelope, the
// CORE-TRACE-02 two-way search filters (entity=decisions|requests,
// verdict/mode/policy_id/policy_version/request_id/step/created_from/
// created_to) and the CORE-TRACE-01 findings wire contract; RLS org scoping
// through the mount's org gate plus the store's GUC-pinned read.
//
// Gate: RequireOrgPermissionPoliciesManage (the OP-0b mount middleware,
// shared file policy_pipelines.go) — a foreign org is 404, a member without
// policies.manage is 403, root passes. Decisions are security objects (they
// show what policies did to traffic), the same sensitivity class as the
// policies themselves.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// PolicyDecisionStore is the narrow store capability the decision-log
// handler consumes (*adminstore.Store satisfies it — compile pin).
type PolicyDecisionStore interface {
	ListPolicyDecisions(ctx context.Context, orgID string, filters adminstore.PolicyDecisionFilters) ([]adminstore.PolicyDecision, int64, error)
	// ListPolicyDecisionRequests is the CORE-TRACE-02 distinct-request view
	// (entity=requests): one row per unique request behind the filtered
	// decisions, totals/pagination counted in requests.
	ListPolicyDecisionRequests(ctx context.Context, orgID string, filters adminstore.PolicyDecisionFilters) ([]adminstore.PolicyDecisionRequestSummary, int64, error)
}

// compile pin: the production store implements the narrow capability.
var _ PolicyDecisionStore = (*adminstore.Store)(nil)

// PolicyDecisionHandlers serves the decision-log route. The admin server
// wires it with SetPolicyDecisionHandlers over *adminstore.Store.
type PolicyDecisionHandlers struct {
	store PolicyDecisionStore
}

// NewPolicyDecisionHandlers builds the decision-log handlers over store.
func NewPolicyDecisionHandlers(store PolicyDecisionStore) *PolicyDecisionHandlers {
	return &PolicyDecisionHandlers{store: store}
}

// SetPolicyDecisionHandlers attaches the decision-log handlers to the admin
// router. nil (the default) keeps the route mounted but unwired: it answers
// 503 until the store is wired by the admin server.
func (h *AdminHandlers) SetPolicyDecisionHandlers(o *PolicyDecisionHandlers) {
	h.policyDecisions = o
}

// mountPolicyDecisions registers the decision-log route under the same org
// gate as the policy pipelines. Mounted unconditionally (nil handler answers
// 503): the route inventories pin registration and guarding, not wiring.
func (h *AdminHandlers) mountPolicyDecisions(protected chi.Router) {
	decisions := protected.With(h.RequireOrgPermissionPoliciesManage())
	decisions.Get("/api/organizations/{id}/policy-decisions", h.policyDecisions.handleList)
}

// CORE-TRACE-01: the findings wire contract. The stored findings jsonb is
// valid JSON by storage, but NOT guaranteed to be an array (legacy or buggy
// writer rows may hold null / objects / junk). The read API therefore serves
// a documented shape per row:
//
//	findings        — ALWAYS a JSON array of content-free finding objects
//	                  {step, category, severity, span?, action} (the writer's
//	                  sanitized shape, services/loggerd/consumer); unknown
//	                  element keys and non-contract fields never surface;
//	findings_valid  — false ONLY when the stored value could not be decoded
//	                  into that array (findings is then []). A corrupt or
//	                  legacy-malformed record must never read as a clean
//	                  "the policy found nothing" verdict.
//
// CORE-TRACE-05: the stored value is normally the versioned envelope OBJECT
// (the consumer's storage contract, services/loggerd/consumer) — the
// findings array lives under the "findings" key next to the evaluation
// trace. The view surfaces the envelope fields verbatim (hook, matched,
// effective/applied action split, bounded step traces with totals, and
// trace_completeness). Rows that predate the envelope (bare findings
// arrays), envelopes of an unknown version, and corrupt values all surface
// trace_completeness="unknown" — "no information", never "no steps ran".
//
// No request text and no secrets are added at this layer — the rows stay
// exactly as content-free as the writer stored them.

// policyFindingView is one wire finding — the writer's sanitized, content-free
// element shape (services/loggerd/consumer sanitizePolicyFindings).
type policyFindingView struct {
	Step     string `json:"step"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Span     string `json:"span,omitempty"`
	Action   string `json:"action"`
}

// policyStepView is one wire step of the evaluation trace — the engine's
// content-free StepTrace vocabulary as stored by the consumer (outcome
// ran|skipped|error|timeout; error carries a skip reason or failure
// message, never payload).
type policyStepView struct {
	Step     string `json:"step"`
	Outcome  string `json:"outcome"`
	Duration int64  `json:"duration_ms,omitempty"`
	Error    string `json:"error,omitempty"`
}

// policyDecisionView is the wire row served for one stored decision (the
// store row plus the normalized findings/envelope contract above). The
// envelope fields use absence-is-unknown semantics: envelope_version 0 /
// empty strings / null matched mean the information does not exist for the
// row (legacy producer, unknown envelope version) — never a fabricated
// value. trace_completeness is ALWAYS one of full | partial | absent |
// unknown (anything unknown degrades to "unknown").
type policyDecisionView struct {
	ID            string              `json:"id"`
	OrgID         string              `json:"org_id"`
	RequestID     string              `json:"request_id"`
	PolicyID      string              `json:"policy_id"`
	PolicyVersion int                 `json:"policy_version"`
	Mode          string              `json:"mode"`
	Verdict       string              `json:"verdict"`
	Findings      []policyFindingView `json:"findings"`
	FindingsValid bool                `json:"findings_valid"`
	DurationMs    int64               `json:"duration_ms"`
	CreatedAt     time.Time           `json:"created_at"`

	// CORE-TRACE-05 envelope read model.
	EnvelopeVersion   int              `json:"envelope_version"`
	Hook              string           `json:"hook,omitempty"`
	RuleNamespace     string           `json:"rule_namespace,omitempty"`
	Matched           *bool            `json:"matched"`
	EffectiveAction   string           `json:"effective_action,omitempty"`
	AppliedAction     string           `json:"applied_action,omitempty"`
	Steps             []policyStepView `json:"steps"`
	StepsTotal        int              `json:"steps_total,omitempty"`
	StepsTruncated    bool             `json:"steps_truncated,omitempty"`
	FindingsTotal     int              `json:"findings_total,omitempty"`
	FindingsTruncated bool             `json:"findings_truncated,omitempty"`
	TraceCompleteness string           `json:"trace_completeness"`
}

// decisionViews renders the store rows into the documented wire shape.
func decisionViews(decisions []adminstore.PolicyDecision) []policyDecisionView {
	views := make([]policyDecisionView, 0, len(decisions))
	for _, d := range decisions {
		v := parseStoredEnvelope(d.Findings)
		views = append(views, policyDecisionView{
			ID: d.ID, OrgID: d.OrgID, RequestID: d.RequestID,
			PolicyID: d.PolicyID, PolicyVersion: d.PolicyVersion,
			Mode: d.Mode, Verdict: d.Verdict,
			DurationMs: d.DurationMs, CreatedAt: d.CreatedAt,

			Findings:          v.findings,
			FindingsValid:     v.findingsValid,
			EnvelopeVersion:   v.envelopeVersion,
			Hook:              v.hook,
			RuleNamespace:     v.ruleNamespace,
			Matched:           v.matched,
			EffectiveAction:   v.effectiveAction,
			AppliedAction:     v.appliedAction,
			Steps:             v.steps,
			StepsTotal:        v.stepsTotal,
			StepsTruncated:    v.stepsTruncated,
			FindingsTotal:     v.findingsTotal,
			FindingsTruncated: v.findingsTruncated,
			TraceCompleteness: v.traceCompleteness,
		})
	}
	return views
}

// storedEnvelopeView is the parsed read-model of one stored findings jsonb
// payload (both layouts: the CORE-TRACE-05 envelope object and the legacy
// bare array; junk degrades with findings_valid=false + unknown).
type storedEnvelopeView struct {
	findings          []policyFindingView
	findingsValid     bool
	envelopeVersion   int
	hook              string
	ruleNamespace     string
	matched           *bool
	effectiveAction   string
	appliedAction     string
	steps             []policyStepView
	stepsTotal        int
	stepsTruncated    bool
	findingsTotal     int
	findingsTruncated bool
	traceCompleteness string
}

// storedEnvelopeWire mirrors the consumer's storage envelope for reads
// (decode-only; unknown keys never surface).
type storedEnvelopeWire struct {
	EnvelopeVersion   int               `json:"envelope_version"`
	Findings          []json.RawMessage `json:"findings"`
	Steps             []policyStepView  `json:"steps"`
	StepsTotal        int               `json:"steps_total"`
	StepsTruncated    bool              `json:"steps_truncated"`
	FindingsTotal     int               `json:"findings_total"`
	FindingsTruncated bool              `json:"findings_truncated"`
	TraceCompleteness string            `json:"trace_completeness"`
	Hook              string            `json:"hook"`
	RuleNamespace     string            `json:"rule_namespace"`
	Matched           *bool             `json:"matched"`
	EffectiveAction   string            `json:"effective_action"`
	AppliedAction     string            `json:"applied_action"`
}

// parseStoredEnvelope normalizes the stored findings jsonb into the read
// model. Envelope objects (envelope_version 1) surface their fields with
// the findings array decoded under the element contract; an unknown
// envelope version degrades to findings=[]/findings_valid=false with the
// version surfaced and trace_completeness=unknown — the row reads as "no
// information", never as "nothing was found" or "no steps ran". Legacy
// rows (bare arrays) decode through the same element contract and surface
// unknown completeness. Any deviation — JSON null, a non-array findings
// value, a non-object or mistyped element, truncated JSON, an undecodable
// object — keeps the row readable AND visibly degraded.
func parseStoredEnvelope(raw json.RawMessage) storedEnvelopeView {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return unknownEnvelope(0, false)
	}
	if trimmed[0] == '{' {
		var env storedEnvelopeWire
		if err := json.Unmarshal(trimmed, &env); err != nil {
			return unknownEnvelope(0, false)
		}
		if env.EnvelopeVersion != 1 {
			// Unknown producer version: the consumer stored the stripped
			// marker — nothing inside is interpreted, the version stays
			// visible.
			v := unknownEnvelope(env.EnvelopeVersion, false)
			if env.EnvelopeVersion > 0 {
				return v
			}
			// A junk object without a version is simply degraded.
			return unknownEnvelope(0, false)
		}
		findings, valid := decodeFindingElements(env.Findings)
		completeness := env.TraceCompleteness
		if completeness == "" {
			completeness = "unknown"
		}
		steps := env.Steps
		if steps == nil {
			steps = []policyStepView{}
		}
		return storedEnvelopeView{
			findings:          findings,
			findingsValid:     valid,
			envelopeVersion:   env.EnvelopeVersion,
			hook:              env.Hook,
			ruleNamespace:     env.RuleNamespace,
			matched:           env.Matched,
			effectiveAction:   env.EffectiveAction,
			appliedAction:     env.AppliedAction,
			steps:             steps,
			stepsTotal:        env.StepsTotal,
			stepsTruncated:    env.StepsTruncated,
			findingsTotal:     env.FindingsTotal,
			findingsTruncated: env.FindingsTruncated,
			traceCompleteness: completeness,
		}
	}
	// Legacy layout: the bare sanitized findings array (pre-envelope rows).
	findings, valid := decodeFindingArray(trimmed)
	v := unknownEnvelope(0, valid)
	v.findings = findings
	return v
}

// unknownEnvelope is the degraded-but-honest view: the envelope fields are
// absent, completeness reads unknown. findingsValid carries whether the
// payload could be decoded AT ALL (a corrupt row stays visibly degraded).
func unknownEnvelope(envelopeVersion int, findingsValid bool) storedEnvelopeView {
	return storedEnvelopeView{
		findings:          []policyFindingView{},
		findingsValid:     findingsValid,
		envelopeVersion:   envelopeVersion,
		steps:             []policyStepView{},
		traceCompleteness: "unknown",
	}
}

// decodeFindingElements validates a decoded findings array under the
// element contract (every element a contract-shaped object; unknown keys
// dropped exactly like the writer strips them). A single bad element
// degrades the whole array to invalid — a partially decoded list must not
// read as complete evidence.
func decodeFindingElements(elements []json.RawMessage) ([]policyFindingView, bool) {
	invalid := func() ([]policyFindingView, bool) { return []policyFindingView{}, false }
	if elements == nil {
		// Absent findings key inside a v1 envelope: the producer recorded a
		// clean "no findings", not a decode failure.
		return []policyFindingView{}, true
	}
	out := make([]policyFindingView, 0, len(elements))
	for _, el := range elements {
		if t := bytes.TrimSpace(el); len(t) == 0 || t[0] != '{' {
			return invalid()
		}
		var f policyFindingView
		if err := json.Unmarshal(el, &f); err != nil {
			return invalid()
		}
		out = append(out, f)
	}
	return out, true
}

// decodeFindingArray parses one stored legacy findings ARRAY payload under
// the element contract (the CORE-TRACE-01 behavior, unchanged).
func decodeFindingArray(raw json.RawMessage) ([]policyFindingView, bool) {
	trimmed := bytes.TrimSpace(raw)
	// JSON null decodes into a slice as a no-op — the literal must be
	// rejected explicitly or a null legacy row would read as a clean [].
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []policyFindingView{}, false
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(trimmed, &elements); err != nil {
		return []policyFindingView{}, false
	}
	return decodeFindingElements(elements)
}

// validDecisionVerdicts is the pipeline action vocabulary (pkg/pipeline:
// deny > mask > flag > allow) the verdict filter accepts.
var validDecisionVerdicts = map[string]bool{
	"allow": true, "flag": true, "mask": true, "deny": true,
}

// handleList serves GET /api/organizations/{id}/policy-decisions.
//
// CORE-TRACE-02: `entity` selects the searched side of the rule↔request
// relation —
//
//	entity=decisions (default)  one row per stored policy EVALUATION (the
//	                            original log; totals count evaluations);
//	entity=requests             one row per DISTINCT request behind the
//	                            filtered decisions ({request_id, evaluations,
//	                            first_seen_at, last_seen_at}); totals and
//	                            pagination count unique REQUESTS.
//
// Filters, all org-scoped, combine freely: verdict, mode, policy_id
// (pre-existing, unchanged), plus policy_version (exact, int32 range —
// beyond it is a 400, review F1; 0 is a real
// "unknown legacy version"), request_id (exact), step (decisions whose
// findings carry a finding with this step), and created_from/created_to
// (inclusive RFC3339 window). Unknown values are 400, never silently
// ignored.
func (o *PolicyDecisionHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	if o == nil || o.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "policy decision store not configured"})
		return
	}
	orgID := r.PathValue("id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org id is required"})
		return
	}
	filters, ok := o.parseDecisionFilters(w, r)
	if !ok {
		return
	}

	switch r.URL.Query().Get("entity") {
	case "", "decisions":
		decisions, total, err := o.store.ListPolicyDecisions(r.Context(), orgID, filters)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal error"})
			return
		}
		// CORE-TRACE-01: the wire carries the documented findings contract,
		// not the raw stored bytes (a []byte/jsonb passthrough would leak
		// base64 or null into a typed frontend).
		writePaginated(w, filters.PageFilter, decisionViews(decisions), total)
	case "requests":
		requests, total, err := o.store.ListPolicyDecisionRequests(r.Context(), orgID, filters)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal error"})
			return
		}
		writePaginated(w, filters.PageFilter, requests, total)
	default:
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid entity filter (decisions|requests)"})
	}
}

// parseDecisionFilters parses the shared query filters into the store shape,
// writing the 400 itself (and returning false) on an invalid value. Every
// accepted value is bound by the store — nothing is interpolated.
func (o *PolicyDecisionHandlers) parseDecisionFilters(w http.ResponseWriter, r *http.Request) (adminstore.PolicyDecisionFilters, bool) {
	filters := adminstore.PolicyDecisionFilters{PageFilter: parsePage(r)}
	badRequest := func(msg string) (adminstore.PolicyDecisionFilters, bool) {
		writeJSON(w, http.StatusBadRequest, apiError{Error: msg})
		return adminstore.PolicyDecisionFilters{}, false
	}
	if v := r.URL.Query().Get("verdict"); v != "" {
		if !validDecisionVerdicts[v] {
			return badRequest("invalid verdict filter (allow|flag|mask|deny)")
		}
		filters.Verdict = v
	}
	if m := r.URL.Query().Get("mode"); m != "" {
		if m != "shadow" && m != "enforce" {
			return badRequest("invalid mode filter (shadow|enforce)")
		}
		filters.Mode = m
	}
	if p := r.URL.Query().Get("policy_id"); p != "" {
		filters.PolicyID = p
	}
	if p := r.URL.Query().Get("policy_version"); p != "" {
		// Review F1 (2026-11-01): parse in the int32 range, not full int
		// width. The store column is integer (migration 0001) and pgx v5.10
		// binds a wider Go int through its int4 encoder, which HARD-ERRORS on
		// values past 2^31-1 (pgtype/int.go:745 "is greater than maximum
		// value for int4") — a full-width Atoi turned e.g. 99999999999999
		// into a store-bound 500 instead of the documented 400.
		v64, err := strconv.ParseInt(p, 10, 32)
		if err != nil || v64 < 0 {
			return badRequest("invalid policy_version filter (non-negative integer)")
		}
		v := int(v64)
		filters.PolicyVersion = &v
	}
	if q := r.URL.Query().Get("request_id"); q != "" {
		filters.RequestID = q
	}
	if s := r.URL.Query().Get("step"); s != "" {
		filters.Step = s
	}
	if v := r.URL.Query().Get("created_from"); v != "" {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return badRequest("invalid created_from filter (RFC3339)")
		}
		filters.CreatedFrom = &ts
	}
	if v := r.URL.Query().Get("created_to"); v != "" {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return badRequest("invalid created_to filter (RFC3339)")
		}
		filters.CreatedTo = &ts
	}
	if filters.CreatedFrom != nil && filters.CreatedTo != nil && filters.CreatedFrom.After(*filters.CreatedTo) {
		return badRequest("created_from must not be after created_to")
	}
	return filters, true
}
