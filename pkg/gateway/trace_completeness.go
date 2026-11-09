package cli

// G4 producer-side per-request trace-completeness stamp (owner decision
// 2026-11-04, N13-P01-T02; CORE-TRACE-05).
//
// The vocabulary semantics are owner-binding:
//   - full:    the declared sibling-event cohort for this request is provably
//     complete (every declared event published, no drops, no truncation);
//   - partial: any sibling event was dropped (backlog_full / publish_failed)
//     or an envelope cohort was truncated — the reason codes say which;
//   - absent:  a non-empty sibling cohort was declared and none of it landed
//     (the request row materializes only from completed request events, so
//     "absent" wire-materializes as a missing request_logs row);
//   - unknown: no instrumentation can prove either direction for this
//     surface — the honest default for the plain-LLM class (G5). Never full.
//
// The stamp rides the existing labels wire field as a compact versioned JSON
// envelope, so legacy consumers (labels pass through verbatim) and the
// publisher (arbitrary label values within labels.MaxValueLen) keep working
// without a pkg/eventpublisher change — that package is outside this card's
// lease. Reason codes are a closed, content-free enum: no raw request
// content ever enters the tag surface (CORE-TRACE-05), mirroring the
// producer/consumer identical-caps discipline of the policy-decision
// envelope. The join key stays request_id (I44); this stamp enriches the
// request row's own provenance, it does not re-key anything.

import (
	"context"
	"encoding/json"
	"sync"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/logctx"
)

// traceStampLabelKey is the label key carrying the envelope. It is reserved
// producer telemetry: a client-attributed label with the same key is
// overridden at the funnel (see traceStampEvent).
const traceStampLabelKey = "trace_completeness"

const (
	traceStampVersion    = 1
	traceStampMaxReasons = 3
	// traceStampRegistryMax bounds the per-request tracker registry. One
	// tracker per in-flight request; finished requests claim (and free)
	// theirs at finishRequest, and the cyclic ring evicts the oldest
	// registration under sustained pressure (orphaned audit surfaces).
	traceStampRegistryMax = 4096
)

// Completeness vocabulary: traceCompleteFull / traceCompletePartial /
// traceCompleteAbsent are shared with the per-decision trace_completeness
// field (gateway_policy.go); traceCompleteUnknown is the request-row honest
// default for surfaces without sibling-event instrumentation.
const traceCompleteUnknown = "unknown"

// Closed reason-code enum. Names map 1:1 onto the observable drop/truncation
// facts, so every reason cites a counter a reader can check
// (gateway_silent_failures_total{reason=...}). Grammar: colon-separated
// slugs, printable ASCII, no request content — CORE-TRACE-05.
const (
	traceStampDropBacklogFull      = "drop:event_publish:backlog_full"
	traceStampDropPublishFailed    = "drop:event_publish:publish_failed"
	traceStampTruncPolicySteps     = "truncated:policy_steps"
	traceStampTruncPolicyFindings  = "truncated:policy_findings"
	traceStampReasonsTruncatedCode = "reasons_truncated"
)

// traceStampReasonVocabulary is the closed set a tracker may record. Hostile
// or mistaken inputs at the observe sites are ignored, never stored.
var traceStampReasonVocabulary = map[string]struct{}{
	traceStampDropBacklogFull:      {},
	traceStampDropPublishFailed:    {},
	traceStampTruncPolicySteps:     {},
	traceStampTruncPolicyFindings:  {},
	traceStampReasonsTruncatedCode: {},
}

func traceStampValidReason(reason string) bool {
	_, ok := traceStampReasonVocabulary[reason]
	return ok
}

// traceCompletenessEnvelope is the versioned stamp payload. Additive-only
// evolution: bump traceStampVersion when fields change, and teach the
// loggerd consumer the new version before shipping the producer (the
// consumer strips stamps it cannot interpret).
type traceCompletenessEnvelope struct {
	Version      int      `json:"v"`
	Completeness string   `json:"c"`
	Reasons      []string `json:"r,omitempty"`
}

// marshal renders the envelope as a single-line JSON label value.
func (e traceCompletenessEnvelope) marshal() string {
	out, err := json.Marshal(e)
	if err != nil {
		// Marshal of a struct with string/int fields cannot fail; the guard
		// keeps the function total without inventing vocabulary.
		return `{"v":1,"c":"` + traceCompleteUnknown + `"}`
	}
	return string(out)
}

// marshalBounded keeps the value within labels.MaxValueLen so downstream
// normalization can never reject the stamp itself. With the closed enum the
// worst-case envelope already fits; the eviction loop is future-proofing
// that degrades reasons (oldest first) in favor of the overflow marker
// instead of ever emitting an oversized label.
func (e traceCompletenessEnvelope) marshalBounded() string {
	marked := false
	for {
		value := e.marshal()
		if len(value) <= labels.MaxValueLen {
			return value
		}
		n := len(e.Reasons)
		switch {
		case n == 0:
			// The minimal envelope always fits; unreachable with the closed
			// enum, kept as a total-function guard.
			return value
		case !marked:
			keep := n - 1
			if keep > traceStampMaxReasons {
				keep = traceStampMaxReasons
			}
			e.Reasons = append(e.Reasons[:keep:keep], traceStampReasonsTruncatedCode)
			marked = true
		default:
			// Still oversized with the marker: drop the oldest real reason,
			// keep the marker last.
			e.Reasons = append(e.Reasons[:n-2:n-2], traceStampReasonsTruncatedCode)
		}
	}
}

// traceCompletenessState accumulates one request's sibling-event evidence.
type traceCompletenessState struct {
	mu          sync.Mutex
	expected    int
	published   int
	drops       []string
	truncations []string
}

var (
	traceStampMu       sync.Mutex
	traceStampRegistry = make(map[string]*traceCompletenessState, traceStampRegistryMax)
	traceStampRing     [traceStampRegistryMax]string
	traceStampRingPos  = make(map[string]int, traceStampRegistryMax)
	traceStampRingNext int
)

// traceStampStateFor returns the tracker for requestID, registering a fresh
// one when absent. Eviction is cyclic: when the bound is hit the slot about
// to be overwritten is freed (its request finished long before
// traceStampRegistryMax newer registrations, or it is an orphaned surface
// that never claims).
func traceStampStateFor(requestID string) *traceCompletenessState {
	traceStampMu.Lock()
	defer traceStampMu.Unlock()
	if st, ok := traceStampRegistry[requestID]; ok {
		return st
	}
	if len(traceStampRegistry) >= traceStampRegistryMax {
		victim := traceStampRing[traceStampRingNext]
		delete(traceStampRegistry, victim)
		delete(traceStampRingPos, victim)
	}
	traceStampRing[traceStampRingNext] = requestID
	traceStampRingPos[requestID] = traceStampRingNext
	traceStampRingNext = (traceStampRingNext + 1) % traceStampRegistryMax
	st := &traceCompletenessState{}
	traceStampRegistry[requestID] = st
	return st
}

// traceStampClaim detaches and returns the tracker for requestID, or nil
// when the request never registered sibling-event evidence. Requests
// without a request_id are never tracked (audit surfaces without a request
// scope have no request row to stamp).
func traceStampClaim(requestID string) *traceCompletenessState {
	if requestID == "" {
		return nil
	}
	traceStampMu.Lock()
	defer traceStampMu.Unlock()
	st, ok := traceStampRegistry[requestID]
	if ok {
		delete(traceStampRegistry, requestID)
		delete(traceStampRingPos, requestID)
	}
	return st
}

// envelope derives the owner-binding vocabulary verdict from the evidence.
func (st *traceCompletenessState) envelope() traceCompletenessEnvelope {
	st.mu.Lock()
	defer st.mu.Unlock()
	env := traceCompletenessEnvelope{Version: traceStampVersion}
	reasons := make([]string, 0, len(st.drops)+len(st.truncations))
	reasons = append(reasons, st.drops...)
	reasons = append(reasons, st.truncations...)
	switch {
	case len(reasons) > 0:
		// Any observed drop or truncation is a known history gap: partial
		// wins over every other verdict (owner arm 1 and 2).
		env.Completeness = traceCompletePartial
		env.Reasons = reasons
	case st.expected > 0 && st.published == 0:
		// Declared cohort, nothing landed: the request row will be absent
		// from request_logs by construction.
		env.Completeness = traceCompleteAbsent
	case st.expected > 0 && st.published >= st.expected:
		// Every declared sibling landed and nothing was dropped or
		// truncated: provably complete.
		env.Completeness = traceCompleteFull
	default:
		// Without a declared cohort, "published some but maybe not all"
		// must never upgrade to full — unknown stays the honest default.
		env.Completeness = traceCompleteUnknown
	}
	return env
}

func traceStampAppendUnique(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	if len(reasons) >= traceStampMaxReasons {
		// Overflow: keep the first traceStampMaxReasons and flag that the
		// reason list itself was clipped (marker appended once).
		if len(reasons) == traceStampMaxReasons {
			reasons = append(reasons, traceStampReasonsTruncatedCode)
		}
		return reasons
	}
	return append(reasons, reason)
}

// traceStampObservePublished counts one successfully published sibling.
func traceStampObservePublished(requestID string) {
	if requestID == "" {
		return
	}
	st := traceStampStateFor(requestID)
	st.mu.Lock()
	st.published++
	st.mu.Unlock()
}

// traceStampObserveDrop records a producer-side sibling drop. Reasons outside
// the closed enum are ignored (the tag surface is not an input channel).
func traceStampObserveDrop(requestID, reason string) {
	if requestID == "" || !traceStampValidReason(reason) {
		return
	}
	st := traceStampStateFor(requestID)
	st.mu.Lock()
	st.drops = traceStampAppendUnique(st.drops, reason)
	st.mu.Unlock()
}

// traceStampMarkTruncated records an envelope-cohort truncation for the
// request (decision findings/step traces; owner arm 2).
func traceStampMarkTruncated(requestID, reason string) {
	if requestID == "" || !traceStampValidReason(reason) {
		return
	}
	st := traceStampStateFor(requestID)
	st.mu.Lock()
	st.truncations = traceStampAppendUnique(st.truncations, reason)
	st.mu.Unlock()
}

// traceStampDeclare records the expected sibling-event cohort size. Calls
// with a larger cohort win; a smaller late declaration never erases
// evidence already counted.
func traceStampDeclare(requestID string, expectedSiblings int) {
	if requestID == "" || expectedSiblings < 0 {
		return
	}
	st := traceStampStateFor(requestID)
	st.mu.Lock()
	if expectedSiblings > st.expected {
		st.expected = expectedSiblings
	}
	st.mu.Unlock()
}

// traceStampEvent stamps the finish event with the request's envelope and
// frees the tracker (one stamp per request: the last finish event wins the
// claim). The stamp is authoritative producer telemetry — it overrides any
// client-attributed label under the same key so the tag surface cannot be
// forged into a false completeness claim. The caller's label map is cloned,
// never mutated: shared label maps feed multiple events.
func traceStampEvent(ev *eventpub.Event) {
	if ev == nil || ev.RequestID == "" {
		return
	}
	env := traceCompletenessEnvelope{Version: traceStampVersion, Completeness: traceCompleteUnknown}
	if st := traceStampClaim(ev.RequestID); st != nil {
		env = st.envelope()
	}
	value := env.marshalBounded()
	if ev.Labels == nil {
		ev.Labels = map[string]string{traceStampLabelKey: value}
		return
	}
	clone := make(map[string]string, len(ev.Labels)+1)
	for key, existing := range ev.Labels {
		clone[key] = existing
	}
	clone[traceStampLabelKey] = value
	ev.Labels = clone
}

// traceStampPolicyTruncation marks the request tracker when a decision
// envelope was clipped (owner arm 2), so the request-row stamp cites the
// same fact the decision envelope does. The logctx lookup keeps call sites
// free of plumbing; evaluations without a request id honestly skip the mark.
func traceStampPolicyTruncation(ctx context.Context, stepsTruncated, findingsTruncated bool) {
	requestID := logctx.RequestID(ctx)
	if requestID == "" {
		return
	}
	if stepsTruncated {
		traceStampMarkTruncated(requestID, traceStampTruncPolicySteps)
	}
	if findingsTruncated {
		traceStampMarkTruncated(requestID, traceStampTruncPolicyFindings)
	}
}
