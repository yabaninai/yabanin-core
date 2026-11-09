package inventory

// E02-P01 W04-C01: the runtime observation plane.
//
// Gateway events (pkg/eventpublisher.Event — the stream W01 pinned as the
// agent/model identity source) are folded into the registry as LOW
// confidence observations. Identity mapping (the W01 table, authoritative;
// key derivation and convergence rules: dedup.go, W05-C01):
//
//   Event.AgentID       → kind=agent, key agent:<id>
//   Event.ModelRequested/ModelUsed (names, no provider on the wire)
//                       → kind=model, key ResolveModelKey: exactly one
//                         catalog pair ⇒ the canonical model:<provider>/<model>
//                         (converging with the import plane on one asset);
//                         unknown or ambiguous names stay provider-less
//                         model:<name> (0-or->1 ⇒ NO attribution)
//   Event.UpstreamURL   → kind=service, key service:<normalized url>
//                         (NormalizeServiceURL; a URL failing the SSRF-guard
//                         treatment has no stable identity and is dropped)
//   Event.SessionID     → observation CONTEXT inside payloads only — the
//                         session/task kinds were closed by W01-C01
//
// An event carrying no identity at all is a no-op, not an error.
//
// Write semantics (observeTouchSQL): an observation NEVER rewrites the
// identity-bearing fields of an existing row — payload, source, confidence
// and first_seen are written only at creation; afterwards only last_seen
// advances (monotone GREATEST — a late replayed old event cannot move
// last_seen backwards) and a tombstone is cleared. So the observation
// plane cannot downgrade an authoritative import: a high-confidence
// model:<provider>/<model> row keeps its payload and confidence forever,
// while still recording that runtime traffic touched the identity.
//
// Delivery dedup (the pkg/secevents dedupKey precedent, ingest.go:93):
// replayed identical deliveries of one request (same org + RequestID) are
// collapsed in-memory per Observer; the SQL max-semantics make the dedup
// an optimization, not a correctness requirement — a restart loses the
// map and the replay lands as an unchanged no-op instead. Events without
// a RequestID cannot be deduplicated at all; every delivery is processed
// (and is still idempotent at the row level).
//
// Empty-org refusal (obligation ②): ObserveEvent refuses an empty org —
// observations are org-scoped rows, never global writes.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
)

// SourceObservation marks assets born from runtime observation (gateway
// events), the lowest provenance grade.
const SourceObservation Source = "observation"

// observeTouchSQL is the observation write: identity fields are set only
// on INSERT; on conflict only last_seen advances (monotone) and a
// tombstone clears. xmax = 0 classifies created versus touched; no row
// returned means unchanged (replayed observation, nothing moved).
const observeTouchSQL = `INSERT INTO inventory_assets
	(org_id, asset_key, kind, payload, source, confidence, first_seen, last_seen)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	ON CONFLICT (org_id, asset_key, kind) DO UPDATE SET
		last_seen     = GREATEST(inventory_assets.last_seen, EXCLUDED.last_seen),
		tombstone     = false,
		tombstoned_at = NULL
	WHERE inventory_assets.last_seen IS DISTINCT FROM GREATEST(inventory_assets.last_seen, EXCLUDED.last_seen)
	   OR inventory_assets.tombstone
	RETURNING (xmax = 0) AS created`

// ObserveReport is the outcome of one observation delivery.
type ObserveReport struct {
	Counts  ImportCounts
	Deduped bool // replayed delivery of a request/event this Observer already folded
	Skipped int  // secevents only: events refused for a cross-org org_id (tenant boundary)
}

// Observer folds gateway events into the registry (one per process; safe
// for concurrent use).
type Observer struct {
	store   *Store
	catalog ModelCatalogSource
	now     func() time.Time

	mu   sync.Mutex
	seen map[string]struct{}
}

// NewObserver wires the observer over the registry store. The reference
// catalog seam is optional: without it model observations stay
// provider-less (model:<name>); wire it with SetCatalog before the first
// Observe call to enable convergence onto canonical import keys.
func NewObserver(store *Store) (*Observer, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	return &Observer{store: store, seen: map[string]struct{}{},
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// SetCatalog wires the reference catalog seam used by the model-key
// convergence rule (dedup.go). Wire-time only: call before the first
// Observe call; a nil catalog (or no call) keeps provider-less keys.
func (o *Observer) SetCatalog(c ModelCatalogSource) { o.catalog = c }

// AgentKey is the deterministic asset key of one agent identity.
func AgentKey(id string) string { return "agent:" + id }

// ServiceKey is the deterministic asset key of one observed service.
func ServiceKey(url string) string { return "service:" + url }

// observedModelKey is the provider-less observation key of a wire model
// name — the fallback shape of the convergence rule (dedup.go).
func observedModelKey(name string) string { return "model:" + name }

// agentObservation is the payload of an agent asset born from observation.
type agentObservation struct {
	RequestID       string    `json:"request_id,omitempty"`
	SessionID       string    `json:"session_id,omitempty"`
	ModelsRequested []string  `json:"models_requested,omitempty"`
	ModelsUsed      []string  `json:"models_used,omitempty"`
	UpstreamURL     string    `json:"upstream_url,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
}

// modelObservation is the payload of an observed (provider-less) model.
type modelObservation struct {
	RequestID  string    `json:"request_id,omitempty"`
	AgentID    string    `json:"agent_id,omitempty"`
	Used       bool      `json:"used"` // true: served the request; false: only requested
	ObservedAt time.Time `json:"observed_at"`
}

// serviceObservation is the payload of an observed upstream service.
type serviceObservation struct {
	RequestID  string    `json:"request_id,omitempty"`
	AgentID    string    `json:"agent_id,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

func mustMarshalJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// Unreachable for these all-scalar observation payloads; the
		// builder-level marshals stay error-checked.
		return json.RawMessage(`{}`)
	}
	return b
}

// eventTime resolves the observation instant: the event's own TS (ms since
// epoch) when present, else the observer clock.
func eventTime(now func() time.Time, ev *eventpublisher.Event) time.Time {
	if ev.TS > 0 {
		return time.UnixMilli(ev.TS).UTC()
	}
	return now()
}

// ObserveEvent folds one gateway event into the org's registry rows. A nil
// event is a no-op; an event with no identity fields touches nothing;
// neither is an error (harmless traffic, not registry noise).
func (o *Observer) ObserveEvent(ctx context.Context, orgID string, ev *eventpublisher.Event) (*ObserveReport, error) {
	if orgID == "" {
		return nil, ErrOrgRequired
	}
	if ev == nil {
		return &ObserveReport{}, nil
	}
	// P2 (review2 §3): the delivery mark is taken only AFTER a successful
	// write. Marking before the write dropped the event for this
	// observer's whole lifetime whenever the write failed; now a failed
	// fold leaves the request-id unmarked and a redelivery refolds it
	// (the SQL write-once arm makes the concurrent double fold — two
	// deliveries racing past the seen map — converge to the single-fold
	// row state; the battery pins that).
	var markKey string
	if ev.RequestID != "" {
		markKey = orgID + "\x00" + ev.RequestID
		o.mu.Lock()
		if _, dup := o.seen[markKey]; dup {
			o.mu.Unlock()
			return &ObserveReport{Deduped: true}, nil
		}
		o.mu.Unlock()
	}

	at := eventTime(o.now, ev)
	ts := Timestamps{FirstSeen: at, LastSeen: at}
	var batch []Asset
	add := func(key string, kind AssetKind, payload any) {
		if err := validKeyPart("asset_key", key); err != nil {
			return // a key-rule failure drops this one identity, not the event
		}
		batch = append(batch, Asset{
			OrgID: orgID, AssetKey: key, Kind: kind,
			Payload: mustMarshalJSON(payload), Source: SourceObservation,
			Confidence: ConfidenceLow, FirstSeen: ts.FirstSeen, LastSeen: ts.LastSeen,
		})
	}

	// Agent identity: absent AgentID ⇒ no agent asset is created or
	// touched (W01: the event stream cannot invent agent identities).
	if ev.AgentID != "" {
		ao := agentObservation{
			RequestID: ev.RequestID, SessionID: ev.SessionID,
			UpstreamURL: ev.UpstreamURL, ObservedAt: at,
		}
		if ev.ModelRequested != "" {
			ao.ModelsRequested = []string{ev.ModelRequested}
		}
		if ev.ModelUsed != "" {
			ao.ModelsUsed = []string{ev.ModelUsed}
		}
		add(AgentKey(ev.AgentID), KindAgent, ao)
	}
	// Model identities: requested and used are two observations (a request
	// for X served by Y observes both X and Y); one name for both is a
	// single asset that served the request. The key is the convergence
	// rule's answer (dedup.go): canonical when the catalog resolves the
	// name to exactly one pair, provider-less otherwise.
	if ev.ModelRequested != "" {
		used := strings.EqualFold(ev.ModelUsed, ev.ModelRequested)
		add(ResolveModelKey(ev.ModelRequested, o.catalog), KindModel,
			modelObservation{RequestID: ev.RequestID, AgentID: ev.AgentID, Used: used, ObservedAt: at})
	}
	if ev.ModelUsed != "" && !strings.EqualFold(ev.ModelUsed, ev.ModelRequested) {
		add(ResolveModelKey(ev.ModelUsed, o.catalog), KindModel,
			modelObservation{RequestID: ev.RequestID, AgentID: ev.AgentID, Used: true, ObservedAt: at})
	}
	// Service identity (the open slot): the upstream that served the call,
	// keyed by the normalized URL (a URL without a stable identity — not
	// parseable, non-http(s), hostless or carrying userinfo — is dropped;
	// the rest of the event still folds).
	if key, ok := ServiceKeyOf(ev.UpstreamURL); ok {
		add(key, KindService,
			serviceObservation{RequestID: ev.RequestID, AgentID: ev.AgentID, ObservedAt: at})
	}
	if len(batch) == 0 {
		o.markDelivered(markKey)
		return &ObserveReport{}, nil
	}

	counts, err := o.observeBatch(ctx, batch)
	if err != nil {
		return nil, err // the mark stays untaken: a redelivery refolds
	}
	o.markDelivered(markKey)
	return &ObserveReport{Counts: counts}, nil
}

// markDelivered takes the delivery mark after the event folded
// successfully (or was processed to a confirmed no-op). A racing duplicate
// delivery folds too; the store's write-once/max arms converge the row
// state, so the second fold is classified, not corrupting.
func (o *Observer) markDelivered(markKey string) {
	if markKey == "" {
		return
	}
	o.mu.Lock()
	o.seen[markKey] = struct{}{}
	o.mu.Unlock()
}

// observeBatch writes one observation batch in a single transaction,
// classifying each row created / touched (updated) / unchanged.
func (o *Observer) observeBatch(ctx context.Context, batch []Asset) (ImportCounts, error) {
	var counts ImportCounts
	tx, err := o.store.db.Begin(ctx)
	if err != nil {
		return counts, fmt.Errorf("inventory: observe begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for i := range batch {
		a := &batch[i]
		rows, err := tx.Query(ctx, observeTouchSQL,
			a.OrgID, a.AssetKey, string(a.Kind), []byte(a.Payload), string(a.Source),
			string(a.Confidence), a.FirstSeen, a.LastSeen)
		if err != nil {
			return counts, fmt.Errorf("inventory: observe row %s: %w", a.AssetKey, err)
		}
		created, returned := false, false
		for rows.Next() {
			returned = true
			if err := rows.Scan(&created); err != nil {
				rows.Close()
				return counts, fmt.Errorf("inventory: observe row %s: scan: %w", a.AssetKey, err)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return counts, fmt.Errorf("inventory: observe row %s: %w", a.AssetKey, err)
		}
		rows.Close()
		switch {
		case !returned:
			counts.Unchanged++
		case created:
			counts.Created++
		default:
			counts.Updated++ // a pure last_seen advance counts as touched
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return counts, fmt.Errorf("inventory: observe commit: %w", err)
	}
	return counts, nil
}
