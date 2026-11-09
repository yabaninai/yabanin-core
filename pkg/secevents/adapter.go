// Enterprise adapter (E01-P03-W04).
//
// The adapter converts core request events into security events so an
// enterprise security integration can consume the existing pipeline
// without touching it — and without introducing a proprietary boundary
// (the Apache/enterprise module split is owned by E01-P02; until that
// packet lands, this stays a core SPI exactly like the agent-loop SPI:
// a versioned interface with a core reference implementation).
//
// The security signal of a core request event is its OP-8/OP-9 policy
// decision record (eventpublisher.Event.Policy): a JSON array of decision
// objects whose findings carry categories, severities and actions only —
// NEVER payload content. The adapter emits one security event per
// finding, derives the identity block from the request's principal
// fields, maps the cost dimension through the CostStatus contract
// (unknown_price stays unknown — it must never become a zero cost), and
// references evidence by digest only.
//
// Event identity is deterministic: re-adapting the same core event (for
// example after a DLQ replay redelivers it) yields the same EventID, so
// the ingest path (E01-P03-W05) deduplicates the redelivery — the
// acceptance invariant "redelivery does not double-count events" holds
// end to end.

package secevents

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
)

// AdapterVersion is the adapter contract version (agentloop SPI precedent:
// consumers pin the version they were written against).
const AdapterVersion = "v1"

// Core event types emitted by the reference adapter. Derived from the
// policy finding action, prefixed to keep the namespace explicit.
const (
	eventTypePrefix = "policy."
)

// Adapter converts core events into security events (E01-P03-W04).
// Implementations must be deterministic: the same input event and
// receivedAt must produce identical output events (stable EventIDs).
type Adapter interface {
	// Version returns the adapter contract version this implementation
	// speaks (AdapterVersion).
	Version() string
	// AdaptPublisherEvent derives security events from one core request
	// event. A core event with no policy decision record yields zero
	// security events and no error (no security signal is a normal,
	// explicit outcome — it is not an unknown state). receivedAt is the
	// consumer-side reception time: used only when the core event carries
	// no producer timestamp, and returned verbatim in IngestResult.Skew
	// otherwise.
	AdaptPublisherEvent(ev eventpublisher.Event, receivedAt time.Time) ([]Event, error)
}

// CoreAdapter is the core reference implementation of Adapter.
type CoreAdapter struct{}

// Version implements Adapter.
func (CoreAdapter) Version() string { return AdapterVersion }

// opFinding is one finding of an OP-8 policy decision: categories,
// severities and actions only — never payload content.
type opFinding struct {
	Step     string `json:"step"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
}

// opDecision is one executed policy decision of the OP-8 record.
type opDecision struct {
	PolicyID string      `json:"policy_id"`
	Name     string      `json:"name"`
	Version  int         `json:"version"`
	Mode     string      `json:"mode"`
	Verdict  string      `json:"verdict"`
	Findings []opFinding `json:"findings"`
}

// AdaptPublisherEvent implements Adapter.
func (CoreAdapter) AdaptPublisherEvent(ev eventpublisher.Event, receivedAt time.Time) ([]Event, error) {
	if receivedAt.IsZero() {
		return nil, fmt.Errorf("%w: adapter: receivedAt must be set (deterministic skew anchoring)", ErrInvalidEvent)
	}
	if strings.TrimSpace(ev.Policy) == "" {
		return nil, nil // explicit no-signal outcome
	}
	var decisions []opDecision
	if err := json.Unmarshal([]byte(ev.Policy), &decisions); err != nil {
		return nil, fmt.Errorf("%w: adapter: policy decision record: %v", ErrInvalidEvent, err)
	}

	occurredAt := receivedAt
	if ev.TS != 0 {
		occurredAt = time.UnixMilli(ev.TS).UTC()
	}
	cost := mapCost(ev.CostStatus, ev.EstimatedCostUSD)

	return buildFindingEvents(ev, decisions, occurredAt, cost), nil
}

// buildFindingEvents emits one security event per policy finding.
func buildFindingEvents(ev eventpublisher.Event, decisions []opDecision, occurredAt time.Time, cost Cost) []Event {
	var events []Event
	for di, d := range decisions {
		for fi, f := range d.Findings {
			eventType := eventTypePrefix + strings.ToLower(strings.TrimSpace(f.Action))
			if !validSlug(eventType) {
				// An out-of-contract action must not crash adaptation of
				// sibling findings; skip this finding explicitly.
				continue
			}
			summary := TrimSummary(fmt.Sprintf("policy %s v%d %s: %s category=%s severity=%s action=%s",
				d.Name, d.Version, d.Mode, f.Step, f.Category, f.Severity, f.Action))

			var evidence []EvidenceRef
			if digestShape.MatchString(ev.PromptHash) {
				evidence = append(evidence, EvidenceRef{
					Kind:   EvidencePayloadDigest,
					Digest: ev.PromptHash,
				})
			}
			// The policy decision record itself is evidence (it is the
			// OP-9 contract: categories/severities/actions only), referenced
			// by digest of its exact wire bytes.
			polDigest := sha256.Sum256([]byte(ev.Policy))
			evidence = append(evidence, EvidenceRef{
				Kind:   EvidencePolicyDecision,
				Digest: hex.EncodeToString(polDigest[:]),
			})

			e := Event{wire: wire{
				SchemaVersion: SchemaVersion,
				EventID:       derivedEventID(ev, di, fi, d, f, polDigest[:]),
				EventType:     eventType,
				OrgID:         ev.OrgID,
				OccurredAt:    occurredAt,
				Identity: Identity{
					Agent:   refOf(ev.AgentID),
					Session: refOf(ev.SessionID),
					Task:    refOf(ev.TaskID),
					Tool:    IDRef{State: IDAbsent}, // OP-8 findings carry no tool identity
				},
				Summary:  summary,
				Cost:     cost,
				Evidence: evidence,
			}}
			events = append(events, e)
		}
	}
	return events
}

// derivedEventID builds the deterministic dedup anchor of a finding
// event: SHA-256 over the length-framed derivation tuple — the identity
// tuple (org, request, decision/finding position and ids) plus the digest
// of the FULL policy payload. Determinism is the replay contract: a
// redelivered core event carries byte-identical policy bytes and re-derives
// the same EventID; the ingest path treats it as a duplicate.
//
// v2 (E01-P05-W02-C03, closing the W05 preemption gap): the id is
// "core2-" + hex(SHA-256(...)) over a domain-tagged, length-framed input
// whose final part is the policy-payload digest (polDigest). Two changes
// vs the v1 "core-" derivation, both mandated by the adversarial verdict:
//
//   - folding polDigest makes the id a function of the policy CONTENT, so
//     a forged event with the same identity tuple but divergent Name/Mode/
//     verdict/summary text derives a DIFFERENT id and can no longer
//     pre-empt the genuine document under first-write-wins (W05-C02:
//     REAL-GAP at this seam);
//   - length-framing ("len:bytes" per part) removes the residual
//     concatenation ambiguity of v1's NUL separator (a NUL inside a wire
//     field could alias adjacent parts).
//
// The "core2-" prefix keeps the v1 namespace intact: v1-era rows keep
// their historical "core-*" ids forever (they are stored documents, not
// recomputed), and no v2 event can collide with them — the two namespaces
// are disjoint because they are derived under different domain tags.
func derivedEventID(ev eventpublisher.Event, di, fi int, d opDecision, f opFinding, polDigest []byte) string {
	h := sha256.New()
	for _, part := range []string{
		"yabanin/secevents/derived-event-id/v2",
		ev.OrgID, ev.RequestID, strconv.FormatInt(ev.TS, 10),
		strconv.Itoa(di), d.PolicyID, strconv.Itoa(d.Version),
		strconv.Itoa(fi), f.Step, f.Category, f.Severity, f.Action,
		hex.EncodeToString(polDigest),
	} {
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
	}
	sum := h.Sum(nil)
	return "core2-" + hex.EncodeToString(sum)
}

// refOf maps a core principal value to an IDRef: empty means absent.
func refOf(v string) IDRef {
	if v == "" {
		return IDRef{State: IDAbsent}
	}
	return IDRef{Value: v, State: IDKnown}
}

// mapCost applies the core CostStatus contract (eventpublisher.Event):
//
//	"priced"       → known cost (EstimatedCostUSD, converted to micro)
//	"cache_hit"    → known zero (a known-free request, never "unknown")
//	"unknown_price", "no_usage", "legacy" → unknown (never zero!)
//	anything else (incl. empty) → none (no cost dimension on the event)
func mapCost(status string, usd float64) Cost {
	switch status {
	case "priced":
		return Cost{State: CostKnown, MicroUSD: int64(math.Round(usd * 1e6))}
	case "cache_hit":
		return Cost{State: CostKnown, MicroUSD: 0}
	case "unknown_price", "no_usage", "legacy":
		return Cost{State: CostUnknown}
	default:
		return Cost{State: CostNone}
	}
}
