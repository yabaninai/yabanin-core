package router

// N09-P04-T03 — sticky session→rollout-version pins (D3/D5 seam).
//
// The D2 hash split is deterministic per session for a FIXED rollout
// version, but a version bump (percent ramp, canary model change) can flip
// a session's arm mid-flight: a session in the base arm at v1 (10%) lands
// in the canary arm at v2 (30%) on its very next request. The pin map below
// gives a session continuity across version changes: once a session is
// resolved against a rollout version, it KEEPS that version's semantics
// (arm, model, percent) until the configured bound (a fixed TTL from the
// first pin) expires — the card acceptance "sticky session keeps the model
// rollout version up to a set bound".
//
// Two hard rules bound what a pin may never do:
//   - A pin never bypasses the filtered pool. When the pinned canary model
//     stops being servable (disabled, tier change, sovereignty filter) the
//     pin is released explicitly and base serves — the filter is never
//     routed around, parity with the hash path.
//   - A pin never outlives its rollout. Manual rollback (enabled=false)
//     removes the rollout from the snapshot; the next resolution releases
//     the pin observably (CanaryPinReleased) and routes base — a rollback
//     is never silently postponed by the TTL (and ReleaseOrg is the
//     explicit operator sweep).
//
// Every pin involvement is surfaced on CanaryDecision (Pin / PinnedVersion /
// ActiveVersion): held pins under a newer active version report BOTH
// versions, so a mixed or stale resolution is always explicit, never silent.

import (
	"sort"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// Canary pin-status vocabulary (CanaryDecision.Pin). The empty string
// (CanaryPinNone) means the pin layer took no part in the decision: the
// feature is unwired, the session has no id, or no rollout matched.
const (
	CanaryPinNone     = ""         // no pin involvement (unwired / sessionless / no rollout)
	CanaryPinNew      = "new"      // resolved by hash now; pin created
	CanaryPinHeld     = "held"     // served from a live pin within the bound
	CanaryPinExpired  = "expired"  // pin passed the bound; re-resolved by hash against the current version
	CanaryPinReleased = "released" // pin dropped: rollout inactive (manual rollback) or pinned model unservable
	CanaryPinRebound  = "rebound"  // live pin belonged to another rollout; re-resolved for the matched one
)

const (
	// canaryPinTTLDefault is the default fixed bound ("up to a set bound"):
	// one pin lives this long from its first resolution, whatever the
	// session traffic in between (a fixed window, not a sliding one — the
	// bound must be reachable under load).
	canaryPinTTLDefault = 30 * time.Minute
	// canaryPinMaxDefault caps the map; eviction drops the oldest-pinned
	// half (SessionAffinity maxEntries parity).
	canaryPinMaxDefault = 10000
)

// canaryPinEntry is one session's pinned rollout-version resolution.
// Immutable after store; replaced (never mutated) on re-pin.
type canaryPinEntry struct {
	rolloutID string
	version   int    // rollout version whose semantics the session keeps
	arm       string // canary | base (the pinned resolution)
	model     string // served model for the pinned arm (canary model, or the base selection)
	percent   int    // the pinned version's percent (what the decision reports while held)
	pinnedAt  time.Time
}

// canaryPinLookupState distinguishes an absent pin from one that just
// crossed the bound: both re-resolve by hash, but the decision must say
// WHICH happened (CanaryPinNew vs CanaryPinExpired) — a missing session
// resolution is explicit, never folded silently into "held".
type canaryPinLookupState int

const (
	pinAbsent canaryPinLookupState = iota
	pinLive
	pinExpired
)

// CanaryVersionPins is the session→rollout-version pin map behind the canary
// stickiness bound. Entries are keyed by org+session (the same sessionID in
// two orgs is two independent pins, SessionAffinity parity). Pure
// in-memory: losing it only costs version stickiness (sessions re-resolve by
// hash), never correctness. Safe for concurrent use.
type CanaryVersionPins struct {
	mu         sync.Mutex
	m          map[string]canaryPinEntry
	ttl        time.Duration
	maxEntries int
	now        func() time.Time // injectable for deterministic tests
}

// NewCanaryVersionPins applies defaults for zero values: ttl=30m,
// maxEntries=10000.
func NewCanaryVersionPins(ttl time.Duration, maxEntries int) *CanaryVersionPins {
	if ttl <= 0 {
		ttl = canaryPinTTLDefault
	}
	if maxEntries <= 0 {
		maxEntries = canaryPinMaxDefault
	}
	return &CanaryVersionPins{
		m:          make(map[string]canaryPinEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// lookup returns the session's pin and whether it is live or just crossed
// the bound (an expired pin is dropped lazily on read, SessionAffinity
// parity). An empty org or session never has a pin.
func (p *CanaryVersionPins) lookup(orgID, sessionID string) (canaryPinEntry, canaryPinLookupState) {
	if orgID == "" || sessionID == "" {
		return canaryPinEntry{}, pinAbsent
	}
	now := p.now()
	key := affinityMapKey(orgID, sessionID)
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[key]
	if !ok {
		return canaryPinEntry{}, pinAbsent
	}
	if now.Sub(e.pinnedAt) > p.ttl {
		delete(p.m, key)
		return e, pinExpired
	}
	return e, pinLive
}

// store (re-)pins the session to one rollout-version resolution. The pin
// timestamp is set here — the caller never forges the clock.
func (p *CanaryVersionPins) store(orgID, sessionID string, e canaryPinEntry) {
	if orgID == "" || sessionID == "" {
		return
	}
	now := p.now()
	key := affinityMapKey(orgID, sessionID)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.m) >= p.maxEntries {
		p.evictLocked()
	}
	e.pinnedAt = now
	p.m[key] = e
}

// release drops one session's pin and reports the dropped entry (false when
// there was nothing to drop). This is the single-session manual un-pin.
func (p *CanaryVersionPins) release(orgID, sessionID string) (canaryPinEntry, bool) {
	if orgID == "" || sessionID == "" {
		return canaryPinEntry{}, false
	}
	key := affinityMapKey(orgID, sessionID)
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[key]
	if !ok {
		return canaryPinEntry{}, false
	}
	delete(p.m, key)
	return e, true
}

// Release drops one session's pin (manual rollback path, single session).
// Reports whether a live pin existed.
func (p *CanaryVersionPins) Release(orgID, sessionID string) bool {
	_, ok := p.release(orgID, sessionID)
	return ok
}

// ReleaseOrg drops every pin of one org — the manual-rollback sweep. After
// the admin rollback (PUT enabled=false) an operator path can clear the
// org's version pins at once instead of waiting for the per-request release
// or the TTL. Returns the number of pins dropped.
func (p *CanaryVersionPins) ReleaseOrg(orgID string) int {
	if orgID == "" {
		return 0
	}
	prefix := orgID + "\x1f" // affinityMapKey separator (not part of identifiers)
	p.mu.Lock()
	defer p.mu.Unlock()
	dropped := 0
	for k := range p.m {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			delete(p.m, k)
			dropped++
		}
	}
	return dropped
}

// Len reports the number of pins held (observability and tests).
func (p *CanaryVersionPins) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}

// evictLocked drops the oldest-pinned half of the entries. Caller holds the
// write lock (SessionAffinity.evictLocked parity).
func (p *CanaryVersionPins) evictLocked() {
	type kv struct {
		key string
		at  time.Time
	}
	items := make([]kv, 0, len(p.m))
	for k, e := range p.m {
		items = append(items, kv{key: k, at: e.pinnedAt})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].at.Before(items[j].at) })
	remove := len(items) / 2
	for i := 0; i < remove; i++ {
		delete(p.m, items[i].key)
	}
}

// WithCanaryVersionPins wires the session→version pin store (nil keeps the
// layer off — applyCanary then resolves every request by the D2 hash alone,
// exactly the pre-pin behavior).
func (tr *TierRouter) WithCanaryVersionPins(p *CanaryVersionPins) *TierRouter {
	tr.pins = p
	return tr
}

// resolveCanaryForSession resolves one MATCHED rollout for a session through
// the pin layer: a live pin on this rollout serves the pinned version's
// semantics up to the bound; anything else (absent, expired, foreign-rollout
// pin) re-resolves by the D2 hash against the CURRENT version and re-pins
// with an explicit status. Never returns a decision whose pin state is
// silent: Pin/PinnedVersion/ActiveVersion are always filled when the layer
// is wired.
func (tr *TierRouter) resolveCanaryForSession(pool []ModelInfo, selected ModelInfo, ro CanaryRollout, orgID, sessionID string) (ModelInfo, CanaryDecision, error) {
	if tr.pins == nil {
		m, dec := applyCanaryHash(pool, selected, ro, sessionID)
		return m, dec, nil
	}
	entry, state := tr.pins.lookup(orgID, sessionID)
	if state == pinLive && entry.rolloutID == ro.RolloutID {
		// Live pin on THIS rollout: the session keeps its version (the
		// acceptance bound) even when a newer version is active — the served
		// version and the current active version both ride the decision.
		return tr.servePinnedCanary(pool, selected, ro, entry, orgID, sessionID)
	}

	// Hash-resolve against the current active version, then pin THAT
	// resolution. A stale (expired) or foreign-rollout pin is replaced, and
	// the decision names the reason — never a silent reuse of the old pin.
	m, dec := applyCanaryHash(pool, selected, ro, sessionID)
	status := CanaryPinNew
	switch state {
	case pinExpired:
		status = CanaryPinExpired
	case pinLive:
		status = CanaryPinRebound
	}
	tr.pins.store(orgID, sessionID, canaryPinEntry{
		rolloutID: ro.RolloutID,
		version:   ro.Version,
		arm:       dec.Arm,
		model:     dec.To,
		percent:   ro.Percent,
	})
	dec.Pin = status
	dec.PinnedVersion = ro.Version
	dec.ActiveVersion = ro.Version
	return m, dec, nil
}

// servePinnedCanary serves the session's pinned resolution. The pinned
// canary model must still be servable from the SAME filtered pool — a pin
// never bypasses the filter (parity with the hash path); when it cannot be
// honored the pin is released explicitly and base serves.
func (tr *TierRouter) servePinnedCanary(pool []ModelInfo, selected ModelInfo, ro CanaryRollout, entry canaryPinEntry, orgID, sessionID string) (ModelInfo, CanaryDecision, error) {
	dec := CanaryDecision{
		RolloutID:     ro.RolloutID,
		Name:          ro.Name,
		Version:       entry.version, // the version the session is pinned to
		Arm:           entry.arm,
		Percent:       entry.percent, // the pinned version's percent
		From:          selected.Name,
		To:            selected.Name,
		Pin:           CanaryPinHeld,
		PinnedVersion: entry.version,
		ActiveVersion: ro.Version, // may differ — reported, never mixed
	}
	if entry.arm != CanaryDecisionArmCanary {
		metrics.CanaryArmTotal.WithLabelValues(CanaryDecisionArmBase, ro.Name, selected.Name).Inc()
		return selected, dec, nil
	}
	for _, m := range pool {
		if m.Name == entry.model {
			dec.To = m.Name
			metrics.CanaryArmTotal.WithLabelValues(CanaryDecisionArmCanary, ro.Name, m.Name).Inc()
			return m, dec, nil
		}
	}
	// The pinned canary model is no longer servable from this pool
	// (disabled, tier-mismatched, filtered by sovereignty): release the pin
	// explicitly and stay on base — the filter is never bypassed for a pin,
	// and the fallback is visible on the decision.
	tr.pins.release(orgID, sessionID)
	tr.canaries.log.Warn("canary pin released: pinned canary model not servable",
		"org_id", orgID, "rollout", canaryRolloutName(ro),
		"pinned_version", entry.version, "model", entry.model)
	dec.Pin = CanaryPinReleased
	dec.To = selected.Name
	metrics.CanaryArmTotal.WithLabelValues(CanaryDecisionArmBase, ro.Name, selected.Name).Inc()
	return selected, dec, nil
}

// releaseCanaryPin drops the session's live pin after NO rollout matched the
// selection — i.e. the rollout was rolled back or disabled between requests.
// The returned decision is inactive (no rollout fields) but carries the pin
// release observably (Pin=released, PinnedVersion) and reports the base
// model it served in From/To: a manual rollback never leaves a session
// silently serving the rolled-back version until a TTL.
func (tr *TierRouter) releaseCanaryPin(poolSelected ModelInfo, orgID, sessionID string) (CanaryDecision, bool) {
	if tr.pins == nil || orgID == "" || sessionID == "" {
		return CanaryDecision{}, false
	}
	entry, released := tr.pins.release(orgID, sessionID)
	if !released {
		return CanaryDecision{}, false
	}
	tr.canaries.log.Info("canary pin released: rollout inactive (manual rollback)",
		"org_id", orgID, "rollout_id", entry.rolloutID, "pinned_version", entry.version)
	return CanaryDecision{
		Pin:           CanaryPinReleased,
		PinnedVersion: entry.version,
		Arm:           entry.arm,
		Percent:       entry.percent,
		From:          poolSelected.Name,
		To:            poolSelected.Name,
	}, true
}
