package consumer

// OP-9 (OUTPLAY-PLAN-2026-10-06 §3): the policy decision log writer. The
// gateway pipeline (OP-8) attaches its evaluation to the event's `policy`
// field — a JSON ARRAY of decision objects, one per executed policy, in
// execution order: [{policy_id, version, mode, verdict, findings[],
// duration_ms}] — and this writer lands each decision in policy_decisions
// (migration 0009) inside the SAME delivery transaction as the request log,
// so the decisions and the request they belong to commit or retry together.
//
// CORE-TRACE-05 storage envelope: every decision lands as a versioned
// envelope OBJECT in the findings jsonb column (additive — no migration;
// the legacy top-level findings ARRAY remains readable wherever it was
// already stored). The envelope carries the content-free evaluation trace
// the producer stamped (hook, matched/effective/applied split, bounded
// steps, truncation markers) plus the consumer's own bounds: clipping is
// always stamped with explicit *_total/*_truncated markers, never silent.
// trace_completeness vocabulary: full | partial | absent | unknown —
// unknown marks legacy producer payloads (no envelope) and MUST be
// surfaced as "no information", never as "no steps ran". An unknown
// envelope_version degrades to the stripped version marker: the row lands
// (the request keeps its decision) but nothing inside an unknown version
// is interpreted — the marker keeps the limitation visible instead of
// guessing where evidence might hide.
//
// Contracts:
//   - absent/empty `policy` is the LEGACY event shape (pre-OP-8): skip
//     silently, never an error. A malformed payload skips too (counted in
//     policyDecodeErrors) — a bad producer must never wedge the delivery.
//     decision) and the legacy single object (one row) — early OP-8 events
//     and tests predate the array. A valid array element never dies with an
//     invalid sibling: each element is decoded, validated and inserted on
//     its own; unusable elements are counted and skipped individually.
//   - NO CONTENT: finding evidence (content excerpts the pipeline may quote)
//     is stripped here regardless of what the producer sent; only step /
//     category / severity / span / action survive. The decision log is the
//     90d-retention, content-free observability surface (owner decision).
//     Step traces carry engine-generated, value-free skip reasons/errors,
//     clipped to the same bounds.
//   - RLS: policy_decisions carries the 0002/0007 org_isolation posture
//     (ENABLE+FORCE); the insert pins the app.current_org GUC to the event's
//     org inside the delivery tx, so the write passes WITH CHECK under the
//     application role. Events without org_id are skipped (nothing to scope
//     the row to).

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// policyDecodeErrors counts `policy` payloads that failed to decode or
// failed validation (same tolerance family as reservations/labels).
var policyDecodeErrors atomic.Uint64

// Bounds of the sanitized decision row. A hostile or buggy producer must not
// be able to bloat the log via one event.
const (
	// policyDecisionMaxFindings caps the sanitized findings array.
	policyDecisionMaxFindings = 64
	// policyDecisionFieldMax bounds one sanitized string field.
	policyDecisionFieldMax = 256
	// policyDecisionMaxDecisions caps the decisions per event (the producer
	// emits one per executed policy; a buggy or hostile array is truncated
	// tail-first, mirroring the findings cap).
	policyDecisionMaxDecisions = 64
	// policyDecisionMaxSteps caps the stored step trace (same bound the
	// producer applies; re-enforced here against a buggy producer).
	policyDecisionMaxSteps = 64
)

// CORE-TRACE-05 envelope vocabulary (storage side). Producer completeness
// values pass through; anything else (legacy producers, empty, unknown
// words) degrades to traceCompleteUnknown.
const (
	policyStoredEnvelopeVersion = 1
	traceCompleteUnknown        = "unknown"
)

// policyDecisionEvent is one validated decision ready for insert. Findings
// carries the storage envelope (the jsonb payload), not a bare array.
type policyDecisionEvent struct {
	PolicyID   string
	Version    int64
	Mode       string // shadow | enforce
	Verdict    string
	Findings   json.RawMessage
	DurationMs int64
}

// policyFindingWire mirrors the producer's finding shape. Evidence is
// decoded ONLY to be dropped: the struct field makes the strip explicit and
// greppable; unknown producer fields never survive the decode either.
type policyFindingWire struct {
	Step     string `json:"step"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Span     string `json:"span,omitempty"`
	Action   string `json:"action"`
	Evidence string `json:"-"`
}

// policyStepWire mirrors the producer's CORE-TRACE-05 step trace: the
// engine's StepTrace vocabulary, content-free (Outcome ran|skipped|error|
// timeout; Error carries a skip reason or failure message, never payload).
type policyStepWire struct {
	Step     string `json:"step"`
	Outcome  string `json:"outcome"`
	Duration int64  `json:"duration_ms,omitempty"`
	Error    string `json:"error,omitempty"`
}

// policyDecisionWire mirrors the producer's `policy` payload. The CORE-TRACE-05
// envelope fields decode additively: absent fields (legacy producers) stay
// zero/nil and buildStoredEnvelope renders them as absent, never fabricated.
type policyDecisionWire struct {
	PolicyID   string              `json:"policy_id"`
	Version    int64               `json:"version"`
	Mode       string              `json:"mode"`
	Verdict    string              `json:"verdict"`
	Findings   []policyFindingWire `json:"findings"`
	DurationMs int64               `json:"duration_ms"`

	EnvelopeVersion   int              `json:"envelope_version"`
	Hook              string           `json:"hook"`
	RuleNamespace     string           `json:"rule_namespace"`
	Matched           *bool            `json:"matched"`
	EffectiveAction   string           `json:"effective_action"`
	AppliedAction     string           `json:"applied_action"`
	Steps             []policyStepWire `json:"steps"`
	StepsTotal        int              `json:"steps_total"`
	StepsTruncated    bool             `json:"steps_truncated"`
	FindingsTotal     int              `json:"findings_total"`
	FindingsTruncated bool             `json:"findings_truncated"`
	TraceCompleteness string           `json:"trace_completeness"`
}

// parsePolicyDecision decodes and validates the event's `policy` field and
// returns one sanitized decision per producer entry. BOTH shapes decode:
// the OP-8 JSON array (one decision per executed policy) and the legacy
// single object. An empty array is the producer's "nothing evaluated" —
// zero rows, not an error. nil/empty = skip (absent = legacy event; anything
// unusable is counted in policyDecodeErrors and skipped).
func parsePolicyDecision(fields map[string]interface{}) []policyDecisionEvent {
	raw, ok := fields["policy"]
	if !ok || raw == nil {
		return nil // legacy event (pre-OP-8): the normal path today
	}
	text, ok := raw.(string)
	if !ok || text == "" {
		return nil
	}
	// The OP-8 producer shape: an array of decision objects. Elements are
	// decoded independently — a valid decision never dies with an invalid
	// sibling (each unusable element counts, the rest land).
	var elements []json.RawMessage
	if err := json.Unmarshal([]byte(text), &elements); err == nil {
		if len(elements) > policyDecisionMaxDecisions {
			elements = elements[:policyDecisionMaxDecisions]
		}
		out := make([]policyDecisionEvent, 0, len(elements))
		for _, el := range elements {
			var wire policyDecisionWire
			if err := json.Unmarshal(el, &wire); err != nil {
				countPolicyDecodeError()
				continue
			}
			if ev, ok := validatePolicyDecision(wire); ok {
				out = append(out, ev)
			} else {
				countPolicyDecodeError()
			}
		}
		return out
	}
	// Legacy single-object shape (early OP-8 producers/tests).
	var wire policyDecisionWire
	if err := json.Unmarshal([]byte(text), &wire); err != nil {
		countPolicyDecodeError()
		return nil
	}
	ev, ok := validatePolicyDecision(wire)
	if !ok {
		countPolicyDecodeError()
		return nil
	}
	return []policyDecisionEvent{ev}
}

// countPolicyDecodeError records one unusable `policy` payload (or array
// element) in the same tolerance family as reservations/labels.
func countPolicyDecodeError() {
	policyDecodeErrors.Add(1)
	metrics.SilentFailure("audit_ingest_decode", "policy")
}

// validatePolicyDecision applies the shared field validation and
// sanitization to one decoded producer decision. false = unusable (the
// caller counts it); the sanitization contract is parsePolicyDecision's.
func validatePolicyDecision(wire policyDecisionWire) (policyDecisionEvent, bool) {
	if wire.PolicyID == "" || wire.Verdict == "" {
		return policyDecisionEvent{}, false
	}
	switch wire.Mode {
	case modeShadow, modeEnforce:
	default:
		return policyDecisionEvent{}, false
	}

	ev := policyDecisionEvent{
		PolicyID:   clipPolicyField(wire.PolicyID),
		Version:    max64(wire.Version, 0),
		Mode:       wire.Mode,
		Verdict:    clipPolicyField(wire.Verdict),
		DurationMs: max64(wire.DurationMs, 0),
	}
	ev.Findings = buildStoredEnvelope(wire)
	return ev, true
}

// storedEnvelope is the CORE-TRACE-05 storage payload of the findings jsonb
// column: a versioned, content-free evaluation record. Every field is
// omitted when unknown — absence means "no information", never a fabricated
// value; findings/steps carry explicit totals and truncation markers.
type storedEnvelope struct {
	EnvelopeVersion   int            `json:"envelope_version"`
	Findings          []cleanFinding `json:"findings,omitempty"`
	Steps             []cleanStep    `json:"steps,omitempty"`
	StepsTotal        int            `json:"steps_total,omitempty"`
	StepsTruncated    bool           `json:"steps_truncated,omitempty"`
	FindingsTotal     int            `json:"findings_total,omitempty"`
	FindingsTruncated bool           `json:"findings_truncated,omitempty"`
	TraceCompleteness string         `json:"trace_completeness,omitempty"`
	Hook              string         `json:"hook,omitempty"`
	RuleNamespace     string         `json:"rule_namespace,omitempty"`
	Matched           *bool          `json:"matched,omitempty"`
	EffectiveAction   string         `json:"effective_action,omitempty"`
	AppliedAction     string         `json:"applied_action,omitempty"`
}

type cleanFinding struct {
	Step     string `json:"step"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Span     string `json:"span,omitempty"`
	Action   string `json:"action"`
}

// cleanStep mirrors the wire step trace after the consumer's bounds.
type cleanStep struct {
	Step     string `json:"step"`
	Outcome  string `json:"outcome"`
	Duration int64  `json:"duration_ms,omitempty"`
	Error    string `json:"error,omitempty"`
}

// buildStoredEnvelope renders one validated decision's storage envelope.
// Producer envelopes (v1) are re-rendered content-free under the consumer's
// bounds — a producer envelope is honored, never trusted: totals describe
// the original evaluation (kept from the wire), truncation flags only ever
// grow (a consumer clip re-stamps them), and completeness words outside the
// known vocabulary degrade to unknown. Legacy payloads (no envelope) are
// wrapped with trace_completeness=unknown. Unknown producer envelope
// versions degrade to the stripped version marker — the row lands, nothing
// inside is interpreted, and the counter keeps the gap observable.
func buildStoredEnvelope(wire policyDecisionWire) json.RawMessage {
	if wire.EnvelopeVersion > policyStoredEnvelopeVersion {
		metrics.SilentFailure("audit_ingest_policy_envelope", "unknown_version")
		body, err := json.Marshal(storedEnvelope{EnvelopeVersion: wire.EnvelopeVersion})
		if err != nil {
			return json.RawMessage(`{"envelope_version":0}`)
		}
		return body
	}

	env := storedEnvelope{EnvelopeVersion: policyStoredEnvelopeVersion}
	if wire.EnvelopeVersion == 0 {
		// Legacy producer (pre-envelope): fabricate ONLY the wrapper. The
		// findings array is the sanitized evidence-free list; everything
		// else about the evaluation is genuinely unknown.
		findings, total, truncated := sanitizePolicyFindings(wire.Findings)
		env.Findings = findings
		env.FindingsTotal = total
		env.FindingsTruncated = truncated
		env.TraceCompleteness = traceCompleteUnknown
		return marshalStoredEnvelope(env)
	}

	findings, total, truncated := sanitizePolicyFindings(wire.Findings)
	if wire.FindingsTotal > total {
		total = wire.FindingsTotal
	}
	if wire.FindingsTruncated {
		truncated = true
	}
	env.Findings, env.FindingsTotal, env.FindingsTruncated = findings, total, truncated

	steps, stepsTotal, stepsTruncated := sanitizePolicySteps(wire.Steps)
	if wire.StepsTotal > stepsTotal {
		stepsTotal = wire.StepsTotal
	}
	if wire.StepsTruncated {
		stepsTruncated = true
	}
	env.Steps, env.StepsTotal, env.StepsTruncated = steps, stepsTotal, stepsTruncated

	switch wire.TraceCompleteness {
	case "full", "partial", "absent":
		env.TraceCompleteness = wire.TraceCompleteness
	default:
		env.TraceCompleteness = traceCompleteUnknown
	}
	env.Hook = clipPolicyField(wire.Hook)
	env.RuleNamespace = clipPolicyField(wire.RuleNamespace)
	env.Matched = wire.Matched
	env.EffectiveAction = clipPolicyField(wire.EffectiveAction)
	env.AppliedAction = clipPolicyField(wire.AppliedAction)
	return marshalStoredEnvelope(env)
}

// marshalStoredEnvelope renders the envelope, falling back to the version
// marker (never a lost row) if rendering itself fails.
func marshalStoredEnvelope(env storedEnvelope) json.RawMessage {
	body, err := json.Marshal(env)
	if err != nil {
		return json.RawMessage(`{"envelope_version":1}`)
	}
	return body
}

// sanitizePolicySteps re-renders the step trace content-free under the
// consumer bounds (skip reasons and error strings are engine-generated but
// still clipped). More than policyDecisionMaxSteps entries are dropped
// tail-first — the caller stamps the truncation.
func sanitizePolicySteps(steps []policyStepWire) (out []cleanStep, total int, truncated bool) {
	total = len(steps)
	clipped := steps
	if total > policyDecisionMaxSteps {
		clipped = steps[:policyDecisionMaxSteps]
		truncated = true
	}
	out = make([]cleanStep, 0, len(clipped))
	for _, s := range clipped {
		out = append(out, cleanStep{
			Step:     clipPolicyField(s.Step),
			Outcome:  clipPolicyField(s.Outcome),
			Duration: max64(s.Duration, 0),
			Error:    clipPolicyField(s.Error),
		})
	}
	return out, total, truncated
}

// sanitizePolicyFindings re-renders the findings array content-free: every
// finding keeps step/category/severity/span/action (each clipped), evidence
// and unknown fields never survive. More than policyDecisionMaxFindings
// entries are dropped tail-first — the caller stamps the truncation.
func sanitizePolicyFindings(findings []policyFindingWire) (out []cleanFinding, total int, truncated bool) {
	total = len(findings)
	clipped := findings
	if total > policyDecisionMaxFindings {
		clipped = findings[:policyDecisionMaxFindings]
		truncated = true
	}
	out = make([]cleanFinding, 0, len(clipped))
	for _, f := range clipped {
		out = append(out, cleanFinding{
			Step:     clipPolicyField(f.Step),
			Category: clipPolicyField(f.Category),
			Severity: clipPolicyField(f.Severity),
			Span:     clipPolicyField(f.Span),
			Action:   clipPolicyField(f.Action),
		})
	}
	return out, total, truncated
}

// clipPolicyField bounds one sanitized string field.
func clipPolicyField(s string) string {
	if len(s) > policyDecisionFieldMax {
		return s[:policyDecisionFieldMax]
	}
	return s
}

func max64(v, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}

// insertPolicyDecision writes one policy_decisions row PER producer decision
// inside the delivery transaction (same commit as the request log). Absent
// policy field, empty org or request-less legacy shapes skip silently; a DB
// error fails the delivery (the retry re-delivers the decisions together
// with their request log, exactly like the request_logs path).
func (c *StreamConsumer) insertPolicyDecision(ctx context.Context, tx InboxTx, ev requestEvent) error {
	decisions := parsePolicyDecision(ev.raw)
	if len(decisions) == 0 || ev.orgID == "" {
		return nil
	}
	// Pin the org_isolation GUC (tx-local) before the inserts: under the
	// FORCE RLS posture the WITH CHECK arm rejects rows whose org does not
	// match the session org — the pin makes the writes pass under the
	// application role and a wrong-org row impossible.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", ev.orgID); err != nil {
		return fmt.Errorf("pin policy decision org GUC: %w", err)
	}
	for i := range decisions {
		decision := decisions[i]
		if _, err := tx.Exec(ctx,
			`INSERT INTO policy_decisions
				 (org_id, request_id, policy_id, policy_version, mode, verdict, findings, duration_ms, created_at)
				 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)`,
			ev.orgID, ev.requestID, decision.PolicyID, decision.Version,
			decision.Mode, decision.Verdict, []byte(decision.Findings), decision.DurationMs, ev.createdAt,
		); err != nil {
			return fmt.Errorf("insert policy decision: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Retention (OP-9, owner decision: 90d hot retention for the decision log).
// Same discipline as purgeExpiredRequestLogs (services/run/loggerd.go):
// bounded batches (LIMIT), ctx-aware early stop — but per-ORG, because
// policy_decisions carries the org_isolation FORCE RLS posture and a global
// DELETE without the org GUC would see zero rows (fail closed). Each batch
// runs in its own short transaction with the app.current_org GUC pinned, so
// the purge is RLS-clean under the application role and never holds a long
// transaction.
// ---------------------------------------------------------------------------

// PolicyDecisionsRetentionDays is the owner-decided hot window.
const PolicyDecisionsRetentionDays = 90

// DefaultPurgeBatch mirrors purgeBatchSize (run side); re-declared here so
// the consumer stays the single owner of the decision-log purge.
const defaultPolicyPurgeBatch = 5000

// PurgeExpiredPolicyDecisions deletes policy_decisions older than `days` in
// bounded per-org batches and returns the total deleted. It stops early when
// ctx is cancelled — shutdown must not wait out a multi-batch backlog.
func PurgeExpiredPolicyDecisions(ctx context.Context, pool *pgxpool.Pool, batchSize, days int) (int64, error) {
	if pool == nil {
		return 0, fmt.Errorf("purge policy decisions: nil db pool")
	}
	if batchSize <= 0 {
		batchSize = defaultPolicyPurgeBatch
	}
	if days <= 0 {
		days = PolicyDecisionsRetentionDays
	}
	cutoff := time.Now().AddDate(0, 0, -days)

	// The org directory carries no org RLS: enumerate orgs, purge each
	// under its own GUC-pinned batch transactions.
	orgs, err := pool.Query(ctx, `SELECT id FROM organizations ORDER BY id`)
	if err != nil {
		return 0, fmt.Errorf("purge policy decisions: enumerate orgs: %w", err)
	}
	defer orgs.Close()

	var total int64
	for orgs.Next() {
		var orgID string
		if err := orgs.Scan(&orgID); err != nil {
			return total, fmt.Errorf("purge policy decisions: scan org: %w", err)
		}
		n, err := purgePolicyDecisionsForOrg(ctx, pool, orgID, cutoff, batchSize)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, orgs.Err()
}

// purgePolicyDecisionsForOrg drains one org's expired rows in bounded batch
// transactions (each pinning the org_isolation GUC), returning the deleted
// count. ctx cancellation stops between batches.
func purgePolicyDecisionsForOrg(ctx context.Context, pool *pgxpool.Pool, orgID string, cutoff time.Time, batchSize int) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return total, fmt.Errorf("purge policy decisions (%s): begin: %w", orgID, err)
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
			_ = tx.Rollback(ctx)
			return total, fmt.Errorf("purge policy decisions (%s): pin org GUC: %w", orgID, err)
		}
		tag, err := tx.Exec(ctx,
			`DELETE FROM policy_decisions WHERE ctid IN (
					SELECT ctid FROM policy_decisions WHERE org_id = $1::uuid AND created_at < $2 LIMIT $3
				)`,
			orgID, cutoff, batchSize)
		if err != nil {
			_ = tx.Rollback(ctx)
			return total, fmt.Errorf("purge policy decisions (%s): batch: %w", orgID, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return total, fmt.Errorf("purge policy decisions (%s): commit: %w", orgID, err)
		}
		deleted := tag.RowsAffected()
		total += deleted
		if deleted < int64(batchSize) {
			return total, nil
		}
	}
}
