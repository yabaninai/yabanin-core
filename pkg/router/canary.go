package router

//
//   - D1 per-org: rollouts are org-scoped rows (adminstore canary_rollouts);
//     the resolver below is keyed by org and an org without rollouts takes
//     the zero-overhead path.
//   - D2 hash-sticky by session_id, whole percent: the arm is
//     deterministic per session — hash(session_id)%100 < percent → canary,
//     else base. The same session always lands in the same arm, on every
//     gateway, for the life of the rollout version.
//   - D3/D5: activation and rollback happen in the store (atomic
//     transactions + canarystore:ver:<orgID> version-key invalidation — the
//     activation changes which percent NEW requests see, never a decision
//     already made (the gateway pins the model at routing time).
//
// The split point (contract file map): SelectModelForSession runs the normal
// tier selection and then swaps base→canary when the org has an active
// rollout whose base_model equals the selection, the session hashes into the
// canary arm, and the canary model survived the same filtered pool. A canary
// model outside the pool (disabled, filtered by sovereignty) keeps the
// request on base — the failure is visible in the decision, never a leak
// around the filter.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// Canary arm vocabulary (mirrors adminstore.CanaryArm*).
const (
	CanaryDecisionArmCanary = "canary"
	CanaryDecisionArmBase   = "base"
)

// CanaryRollout is one resolved, immutable rollout version the router may
// apply (the adminstore snapshot projection; produced by the gateway wiring
// from adminstore.LoadCanarySnapshot).
type CanaryRollout struct {
	RolloutID   string
	Name        string
	Version     int
	BaseModel   string
	CanaryModel string
	Percent     int
}

// CanaryDecision reports the rollout that matched this request's selection
// and the arm the session resolved to. Active() is false when no rollout
// matched (the common path — the decision payload then carries no canary
// fields at all, except a released pin after a manual rollback: Pin/
// PinnedVersion then say WHICH session state was dropped, while the rollout
// fields stay empty).
type CanaryDecision struct {
	RolloutID string
	Name      string
	Version   int
	Arm       string // canary | base
	Percent   int
	From      string
	To        string
	// Session→version pin layer (N09-P04-T03). Pin is CanaryPinNone ("")
	// when the layer took no part in the decision (unwired, sessionless, or
	// no rollout matched). When held under a newer active version,
	// Version/PinnedVersion carry the SERVED version and ActiveVersion the
	// org's current one — the difference is reported, never mixed silently.
	Pin           string // CanaryPin* vocabulary
	PinnedVersion int    // the version the session is pinned to (0 = none)
	ActiveVersion int    // the org's current active version for the matched rollout (0 = inactive)
}

// Active reports whether a rollout matched the request.
func (d CanaryDecision) Active() bool { return d.RolloutID != "" }

// Swapped reports whether the canary arm actually changed the model.
func (d CanaryDecision) Swapped() bool {
	return d.Active() && d.Arm == CanaryDecisionArmCanary && d.To != "" && d.To != d.From
}

// CanaryRolloutLoader loads one org's active rollouts (the gateway wiring
// adapts adminstore.LoadCanarySnapshot to this shape).
type CanaryRolloutLoader interface {
	LoadCanaryRollouts(ctx context.Context, orgID string) ([]CanaryRollout, error)
}

// CanaryVersionReader is the version-key probe
// (adminstore.NewCanaryVersionCache over the shared Redis); nil = TTL-only
// invalidation.
type CanaryVersionReader interface {
	GetCanaryVersion(ctx context.Context, orgID string) (int64, error)
}

// canaryCacheTTL bounds the per-org rollout snapshot when the version key is
// unreachable (policyCacheTTL parity — the documented TTL fallback).
const canaryCacheTTL = 30 * time.Second

// canaryMaxOrgs caps the org cache; eviction is oldest-loaded
// (policyMaxOrgs parity).
const canaryMaxOrgs = 4096

// canaryEntry is one org's cached rollout snapshot. Immutable after load;
// replaced (never mutated) on reload.
type canaryEntry struct {
	rollouts []CanaryRollout
	version  int64
	haveVer  bool
	loadedAt time.Time
}

// CanaryRolloutCache is the per-org rollout resolver with version-key
// Resolve probes the org's version key; a bump drops the cache immediately,
// an unreachable key degrades to the hard TTL, and a snapshot loaded across
// a concurrent activation is retried (never installed mixed). Safe for
// concurrent use.
type CanaryRolloutCache struct {
	loader   CanaryRolloutLoader
	versions CanaryVersionReader
	ttl      time.Duration
	now      func() time.Time
	log      *slog.Logger

	mu   sync.Mutex
	orgs map[string]*canaryEntry
}

// NewCanaryRolloutCache builds the resolver over loader. versions may be nil
// (TTL-only). ttl <= 0 defaults to canaryCacheTTL.
func NewCanaryRolloutCache(loader CanaryRolloutLoader, versions CanaryVersionReader, ttl time.Duration, l *slog.Logger) *CanaryRolloutCache {
	if loader == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = canaryCacheTTL
	}
	if l == nil {
		l = slog.Default()
	}
	return &CanaryRolloutCache{
		loader:   loader,
		versions: versions,
		ttl:      ttl,
		now:      time.Now,
		log:      l,
		orgs:     make(map[string]*canaryEntry),
	}
}

// Resolve returns the org's active rollouts (empty when the org has none —
// cached like any other answer, so a no-rollout org costs one snapshot load
// per TTL, not one per request). A load failure after a successful prior
// load keeps the stale entry (fail-open to the last known rollout set,
// bounded by the TTL); with no prior entry it returns the error.
func (c *CanaryRolloutCache) Resolve(ctx context.Context, orgID string) ([]CanaryRollout, error) {
	now := c.now()

	c.mu.Lock()
	e := c.orgs[orgID]
	c.mu.Unlock()

	if e == nil {
		return c.refresh(ctx, orgID, nil, now)
	}

	if c.versions != nil {
		v, err := c.versions.GetCanaryVersion(ctx, orgID)
		switch {
		case err == nil && e.haveVer && v != e.version:
			// A known version change invalidates the cache immediately.
		case err == nil:
			if now.Sub(e.loadedAt) < c.ttl {
				return e.rollouts, nil
			}
		case err != nil:
			c.log.Debug("canary version probe failed; TTL fallback governs", "org_id", orgID)
			if now.Sub(e.loadedAt) < c.ttl {
				return e.rollouts, nil
			}
		}
	} else if now.Sub(e.loadedAt) < c.ttl {
		return e.rollouts, nil
	}
	return c.refresh(ctx, orgID, e, now)
}

// errCanarySnapshotChurn marks a snapshot loaded across a concurrent
// activation (the version key moved between the probes around the load);
// after one retry it surfaces so a mixed snapshot is never installed.
var errCanarySnapshotChurn = errors.New("canary snapshot changed during refresh")

// refresh loads a fresh snapshot, double-probing the version key so an
// activation racing the load cannot pin stale data under a fresh version
// (PolicyRuntime.refreshWithOutcome parity; LoadCanarySnapshot itself is one
// repeatable-read transaction, so a single load is internally consistent).
func (c *CanaryRolloutCache) refresh(ctx context.Context, orgID string, stale *canaryEntry, now time.Time) ([]CanaryRollout, error) {
	for attempt := 0; attempt < 2; attempt++ {
		before, beforeErr := int64(0), error(nil)
		if c.versions != nil {
			before, beforeErr = c.versions.GetCanaryVersion(ctx, orgID)
		}
		rollouts, loadErr := c.loader.LoadCanaryRollouts(ctx, orgID)
		after, afterErr := int64(0), error(nil)
		if c.versions != nil {
			after, afterErr = c.versions.GetCanaryVersion(ctx, orgID)
		}
		if loadErr != nil {
			if stale != nil {
				c.log.Warn("canary rollout load failed, serving stale snapshot", "org_id", orgID, "error", loadErr.Error())
				return stale.rollouts, nil
			}
			return nil, loadErr
		}
		if c.versions != nil && beforeErr == nil && afterErr == nil && before != after {
			if attempt == 0 {
				continue
			}
			if stale != nil {
				c.log.Warn("canary snapshot churn, serving stale snapshot", "org_id", orgID)
				return stale.rollouts, nil
			}
			return nil, errCanarySnapshotChurn
		}
		fresh := &canaryEntry{rollouts: rollouts, loadedAt: now}
		if c.versions != nil && beforeErr == nil && afterErr == nil {
			fresh.version, fresh.haveVer = after, true
		}
		c.mu.Lock()
		c.orgs[orgID] = fresh
		c.evictLocked(now)
		c.mu.Unlock()
		return fresh.rollouts, nil
	}
	if stale != nil {
		return stale.rollouts, nil
	}
	return nil, errCanarySnapshotChurn
}

// evictLocked drops the oldest-loaded entries over the cap (caller holds
// c.mu; policyMaxOrgs parity).
func (c *CanaryRolloutCache) evictLocked(now time.Time) {
	if len(c.orgs) <= canaryMaxOrgs {
		return
	}
	type aged struct {
		id string
		at time.Time
	}
	entries := make([]aged, 0, len(c.orgs))
	for id, e := range c.orgs {
		entries = append(entries, aged{id: id, at: e.loadedAt})
	}
	// Oldest first (insertion sort on loadedAt; the eviction path is cold).
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].at.Before(entries[j-1].at); j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	drop := len(c.orgs) - canaryMaxOrgs
	for _, e := range entries[:drop] {
		delete(c.orgs, e.id)
	}
}

// canaryBucket maps a session to its deterministic percent bucket (0..99).
// SHA-256 over the session id, first 8 bytes big-endian: the 2^64 modulus
// bias against 100 is negligible (the one-byte bucketing used elsewhere in
// this repo is 2.56x coarser and still passes the distribution tests).
func canaryBucket(sessionID string) int {
	h := sha256.Sum256([]byte(sessionID))
	return int(binary.BigEndian.Uint64(h[:8]) % 100)
}

// CanaryArm reports the D2 split for one session:
// hash(session_id)%100 < percent → canary arm. Pure and deterministic — the
// same session resolves to the same arm on every gateway, forever. An empty
// session id has no bucketing identity and is never assigned the canary arm
// (see SelectModelForSession).
func CanaryArm(sessionID string, percent int) bool {
	if sessionID == "" || percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	return canaryBucket(sessionID) < percent
}

// WithCanaryRollouts wires the rollout resolver (nil keeps the feature off —
// SelectModelForSession then behaves exactly like SelectModelWithAffinity).
func (tr *TierRouter) WithCanaryRollouts(c *CanaryRolloutCache) *TierRouter {
	tr.canaries = c
	return tr
}

// SelectModelForSession splits selection when the org has an active rollout whose base_model equals the
// selection and the session hashes into the canary arm, the canary model
// replaces the selection — but only when it is present in the SAME filtered
// pool (tier membership + sovereignty filter). The returned decision is
// inactive when no rollout matched (org has none, selection is not a base
// model, or the session has no id), which is the zero-overhead path: no
// resolver load, no metrics, no decision fields.
func (tr *TierRouter) SelectModelForSession(ctx context.Context, cls classifier.Class, orgID, preferredModel, sessionID string) (ModelInfo, CanaryDecision, error) {
	pool, err := tr.filteredPool(ctx, cls, orgID)
	if err != nil {
		return ModelInfo{}, CanaryDecision{}, err
	}
	selected, err := tr.pickWithAffinity(ctx, pool, orgID, preferredModel)
	if err != nil {
		return ModelInfo{}, CanaryDecision{}, err
	}
	if tr.canaries == nil || orgID == "" || sessionID == "" {
		// Zero-overhead path: feature unwired, no org scope, or no session
		// identity to bucket — base selection stands, no rollout resolution.
		return selected, CanaryDecision{}, nil
	}
	return tr.applyCanary(ctx, pool, selected, orgID, sessionID)
}

// applyCanary resolves the org's rollouts and swaps the selection to the
// canary arm when the D2 split says so. Fail-open to base: a resolver error
// keeps the normal selection (never fails the request on rollout
// infrastructure). When the version-pin layer is wired, the first rollout
// matching the selection is resolved through it (see resolveCanaryForSession);
// when NO rollout matches, a live pin is released observably — that is the
// manual-rollback path on the router side: the rolled-back version never
// keeps serving from behind a pin.
func (tr *TierRouter) applyCanary(ctx context.Context, pool []ModelInfo, selected ModelInfo, orgID, sessionID string) (ModelInfo, CanaryDecision, error) {
	rollouts, err := tr.canaries.Resolve(ctx, orgID)
	if err != nil {
		// Fail-open with the base selection; the error is logged, never
		// surfaced to the request.
		tr.canaries.log.Warn("canary rollout resolution failed, routing base", "org_id", orgID, "error", err.Error())
		return selected, CanaryDecision{}, nil
	}
	for _, ro := range rollouts {
		if ro.BaseModel != selected.Name {
			continue
		}
		return tr.resolveCanaryForSession(pool, selected, ro, orgID, sessionID)
	}
	// No active rollout matched the selection: if the session still holds a
	// pin, its rollout is gone (manual rollback / disable) — release it
	// explicitly instead of silently serving the old version until TTL.
	if dec, released := tr.releaseCanaryPin(selected, orgID, sessionID); released {
		return selected, dec, nil
	}
	return selected, CanaryDecision{}, nil
}

// applyCanaryHash is the D2 hash split for one matched rollout (the
// pre-pin resolution, unchanged): canary arm swaps the selection only within
// the SAME filtered pool; every other outcome stays on base with the arm
// recorded. Pure with respect to the (pool, rollout, session) inputs.
func applyCanaryHash(pool []ModelInfo, selected ModelInfo, ro CanaryRollout, sessionID string) (ModelInfo, CanaryDecision) {
	dec := CanaryDecision{
		RolloutID: ro.RolloutID,
		Name:      ro.Name,
		Version:   ro.Version,
		Arm:       CanaryDecisionArmBase,
		Percent:   ro.Percent,
		From:      selected.Name,
		To:        selected.Name,
	}
	if !CanaryArm(sessionID, ro.Percent) {
		metrics.CanaryArmTotal.WithLabelValues(CanaryDecisionArmBase, ro.Name, selected.Name).Inc()
		return selected, dec
	}
	for _, m := range pool {
		if m.Name == ro.CanaryModel {
			dec.Arm = CanaryDecisionArmCanary
			dec.To = m.Name
			metrics.CanaryArmTotal.WithLabelValues(CanaryDecisionArmCanary, ro.Name, m.Name).Inc()
			return m, dec
		}
	}
	// Canary arm won the hash but the canary model is not servable from
	// this pool (disabled, tier-mismatched, or filtered by sovereignty):
	// stay on base — the filter is never bypassed for a rollout.
	metrics.CanaryArmTotal.WithLabelValues(CanaryDecisionArmBase, ro.Name, selected.Name).Inc()
	return selected, dec
}

// canaryRolloutName is a tiny helper for log/metric labels: rollout name or
// the id prefix when the name is empty.
func canaryRolloutName(ro CanaryRollout) string {
	if ro.Name != "" {
		return ro.Name
	}
	if len(ro.RolloutID) > 8 {
		return ro.RolloutID[:8]
	}
	return ro.RolloutID
}

// CanaryDecisionString renders the decision for logs (compact, stable). Pin
// involvement is appended only when present, so pre-pin log lines stay
// byte-identical; a held pin under a newer active version shows both
// versions (the never-silently-mixed guarantee, visible in logs).
func CanaryDecisionString(d CanaryDecision) string {
	if !d.Active() {
		if d.Pin == CanaryPinReleased {
			return fmt.Sprintf("inactive pin=%s pinned_version=%d", d.Pin, d.PinnedVersion)
		}
		return "inactive"
	}
	s := fmt.Sprintf("rollout=%s version=%d arm=%s percent=%d from=%s to=%s",
		canaryRolloutName(CanaryRollout{RolloutID: d.RolloutID, Name: d.Name}), d.Version, d.Arm, d.Percent, d.From, d.To)
	if d.Pin != CanaryPinNone {
		s += fmt.Sprintf(" pin=%s active_version=%d", d.Pin, d.ActiveVersion)
	}
	return s
}
