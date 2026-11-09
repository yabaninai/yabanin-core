package inventory

// E02-P01 W04-C02: folding security events (pkg/secevents, E01-P03) into
// the observation plane.
//
// Identity mapping over the secevents IDRef block (known/unknown/absent —
// the distinction is the point):
//
//   Identity.Agent, State known → touch agent:<value>
//   Identity.Tool,  State known → attribute to the org's tool assets by
//                                  unique suffix match on "/<name>" against
//                                  kind=tool (keys mcp_tool:<server>/<tool>);
//                                  0 or >1 candidates ⇒ NO attribution
//                                  (security noise must never invent or
//                                  re-bind a tool identity)
//   Identity.Session / Identity.Task → observation CONTEXT in the payload
//                                  only — session/task kinds are closed
//                                  (W01-C01)
//   any ref State unknown           → no identity: unknown is a redaction
//                                  statement, not a value; it can neither
//                                  create nor touch an asset
//
// An event whose OrgID is set and differs from the target org is skipped
// and counted (Skipped) — a cross-org fold would be a tenant leak, not an
// observation. Delivery dedup keys on EventID (the secevents identity)
// exactly like ObserveEvent keys on RequestID; the SQL max-semantics keep
// a post-restart replay a no-op.

import (
	"context"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// seceventObservation is the payload folded onto an identity touched by
// security events (payload is write-once: only the creating observation
// persists it, later touches advance last_seen only).
type seceventObservation struct {
	EventIDs   []string  `json:"event_ids"`
	EventTypes []string  `json:"event_types,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	TaskTag    string    `json:"task_tag,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// observeAcc accumulates one identity's touches across a batch before the
// single write (one row per identity per call keeps counts honest).
type observeAcc struct {
	key      string
	kind     AssetKind
	payload  seceventObservation
	lastSeen time.Time
}

// ObserveSecEvents folds a batch of security events into the org's
// registry rows. Nil/empty batch and structurally identity-free events
// are no-ops, never errors.
func (o *Observer) ObserveSecEvents(ctx context.Context, orgID string, evs []*secevents.Event) (*ObserveReport, error) {
	if orgID == "" {
		return nil, ErrOrgRequired
	}
	report := &ObserveReport{}
	if len(evs) == 0 {
		return report, nil
	}

	accs := map[string]*observeAcc{}
	add := func(key string, kind AssetKind, ev *secevents.Event, at time.Time) *observeAcc {
		a, ok := accs[key]
		if !ok {
			a = &observeAcc{key: key, kind: kind,
				payload: seceventObservation{ObservedAt: at}}
			accs[key] = a
		}
		a.payload.EventIDs = append(a.payload.EventIDs, ev.EventID)
		if ev.EventType != "" {
			a.payload.EventTypes = append(a.payload.EventTypes, ev.EventType)
		}
		if a.payload.SessionID == "" && ev.Identity.Session.State == secevents.IDKnown {
			a.payload.SessionID = ev.Identity.Session.Value
		}
		if a.payload.TaskTag == "" && ev.Identity.Task.State == secevents.IDKnown {
			a.payload.TaskTag = ev.Identity.Task.Value
		}
		if at.After(a.lastSeen) {
			a.lastSeen = at
		}
		if at.Before(a.payload.ObservedAt) {
			a.payload.ObservedAt = at
		}
		return a
	}

	// P2 (review2 §3): per-event delivery marks are deferred until the
	// batch write succeeds. The loop only collects the event-ids it
	// would mark; a write failure leaves them all unmarked, so the whole
	// batch is redeliverable — exactly one transaction boundary, exactly
	// one mark boundary. A racing duplicate batch converges through the
	// SQL write-once/max arms (pinned by the battery).
	var pending []string
	dup := func(evID string) bool {
		o.mu.Lock()
		defer o.mu.Unlock()
		if _, d := o.seen[evID]; d {
			return true
		}
		pending = append(pending, evID)
		return false
	}
	takeMarks := func() {
		o.mu.Lock()
		for _, k := range pending {
			o.seen[k] = struct{}{}
		}
		o.mu.Unlock()
	}

	for _, ev := range evs {
		if ev == nil {
			continue
		}
		if ev.OrgID != "" && ev.OrgID != orgID {
			report.Skipped++ // tenant boundary: never fold cross-org
			continue
		}
		if ev.EventID != "" && dup(orgID+"\x00sec\x00"+ev.EventID) {
			report.Deduped = true
			continue // already delivered once, successfully
		}
		at := ev.OccurredAt
		if at.IsZero() {
			at = o.now()
		} else {
			at = at.UTC()
		}
		if ev.Identity.Agent.State == secevents.IDKnown {
			add(AgentKey(ev.Identity.Agent.Value), KindAgent, ev, at)
		}
		if ev.Identity.Tool.State == secevents.IDKnown {
			key, ok, err := o.resolveToolKey(ctx, orgID, ev.Identity.Tool.Value)
			if err != nil {
				return nil, err
			}
			if ok {
				add(key, KindTool, ev, at) // unique suffix ⇒ attribution
			}
			// 0 or >1 candidates: no attribution by design
		}
	}
	if len(accs) == 0 {
		takeMarks() // processed to a confirmed no-op: the ids are consumed
		return report, nil
	}

	var batch []Asset
	for _, a := range accs {
		batch = append(batch, Asset{
			OrgID: orgID, AssetKey: a.key, Kind: a.kind,
			Payload: mustMarshalJSON(a.payload), Source: SourceObservation,
			Confidence: ConfidenceLow, FirstSeen: a.payload.ObservedAt, LastSeen: a.lastSeen,
		})
	}
	if len(batch) == 0 {
		takeMarks()
		return report, nil
	}
	counts, err := o.observeBatch(ctx, batch)
	if err != nil {
		return nil, err // marks stay untaken: the batch is redeliverable
	}
	takeMarks()
	report.Counts = counts
	return report, nil
}

// maxToolScanPages bounds the paged tool scan: 40 pages × MaxPageSize =
// 20 000 tool rows. An org with a larger tool set than that is
// ambiguous-by-volume — resolution refuses rather than guess past the
// bound (the bound also caps the cost of a hypothetical stuck cursor).
const maxToolScanPages = 40

// resolveToolKey maps a bare tool name onto the org's tool assets by
// suffix match (keys are mcp_tool:<server>/<tool>, the secevents wire
// carries only the tool name). ok is false for zero or ambiguous matches.
//
// The scan pages through the org's ENTIRE tool set, following the
// ListAssets cursor to exhaustion: one page is capped at MaxPageSize
// rows, and stopping there would silently treat the in-page candidate
// set as the whole org's — with >MaxPageSize tool rows a suffix whose
// twin lives on page 2 would be mis-attributed to the page-1 match (the
// W04-C02 review defect). A second candidate anywhere refuses
// immediately; hitting maxToolScanPages before exhaustion refuses too
// (ambiguous-by-volume, never a guess).
func (o *Observer) resolveToolKey(ctx context.Context, orgID, tool string) (string, bool, error) {
	if tool == "" {
		return "", false, nil
	}
	suffix := "/" + tool
	var match string
	n := 0
	after := ""
	for page := 0; ; page++ {
		if page >= maxToolScanPages {
			return "", false, nil // tool set beyond the scan bound: refuse, never guess
		}
		rows, next, err := o.store.ListAssets(ctx, orgID, ListParams{
			Kind: KindTool, After: after, IncludeTombstoned: true, Limit: MaxPageSize,
		})
		if err != nil {
			return "", false, err
		}
		for _, r := range rows {
			if strings.HasSuffix(r.AssetKey, suffix) {
				if n++; n > 1 {
					return "", false, nil // twin anywhere ⇒ ambiguous: no attribution
				}
				match = r.AssetKey
			}
		}
		if next == "" {
			return match, n == 1, nil // exhausted: n is the org-wide candidate count
		}
		after = next
	}
}
