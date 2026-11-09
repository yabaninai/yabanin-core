package cli

// credential pool selector. D-1 pool granularity (org, provider, base_url);
// D-2 round-robin; D-3 version-scoped quarantine on upstream 401/429 until
// the end of the current UTC day, with per-request key pinning so active
// attempts survive a rotation-out; D-5 pool state in the DB (RLS) via the
// additive adminstore surface; D-6 additive to the frozen W-BYOK-DB
// OrgCredentialStore (ResolveKey stays the legacy newest-first path).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// OrgCredsPoolStore is the credential store interface (pkg/adminstore). *Store satisfies it structurally once
// the pool methods land — same wiring discipline as OrgKeyResolver: builtin
// or adminstore types only, no type-level coupling in either direction.
// Plaintext from ResolveKeyEntry is used for exactly one provider attempt
// and never cached or logged (only credential id + last-4 mask).
type OrgCredsPoolStore interface {
	ListActiveOrgCredentials(ctx context.Context, orgID, provider, baseURL string) ([]adminstore.OrgCredentialPoolEntry, error)
	ResolveKeyEntry(ctx context.Context, orgID, provider, baseURL, credentialID string) (plaintext string, ok bool, err error)
	QuarantineOrgCredential(ctx context.Context, orgID, credentialID string, until time.Time) error
}

// orgCredentialUse reports WHICH org credential served one provider attempt:
// billing attribution (D-4, masked ref) and the feedback pin for the pool
// (D-3). used=false (zero value) when the attempt authenticated with a
// per-model or global key instead.
type orgCredentialUse struct {
	used    bool
	credID  string // credential id (attribution + quarantine feedback)
	last4   string // store-provided display mask, never key material
	baseURL string // the matched credential candidate URL (feedback invalidation)
}

// ref is the masked D-4 attribution: the first 8 characters of the
// credential id plus the last-4 mask ("3f2ac1b2:9c11"). "" when the attempt
// did not use an org credential. Never plaintext or the full id.
func (u orgCredentialUse) ref() string {
	if !u.used || u.credID == "" {
		return ""
	}
	id := u.credID
	if len(id) > 8 {
		id = id[:8]
	}
	if u.last4 != "" {
		return id + ":" + u.last4
	}
	return id
}

// orgCredsPoolTTL bounds the staleness of the pool snapshots (entries + the
// negative "org holds no credential here" guard). Same bound as the probe it
// complements; the OrgCredsVersionStore contract drops it on CRUD bumps and
// on quarantine writes.
var orgCredsPoolTTL = orgCredsProbeTTL

// orgCredsPoolMaxOrgs caps the per-endpoint pool index (eviction drops
// expired states first, then oldest-loaded) — the probe's unbounded-growth
// guard, mirrored.
const orgCredsPoolMaxOrgs = orgCredsProbeMaxOrgs

// orgCredsPool is the gateway-side selector over one org's active
// credentials per (org, provider, base URL). It caches ONLY secret-free
// metadata (credential id, last-4 mask, versions) with the same
// version/TTL invalidation contract as orgCredsProbe; the plaintext key is
// fetched per attempt through ResolveKeyEntry and lives in the attempt.
type orgCredsPool struct {
	store    OrgCredsPoolStore
	versions OrgCredsVersionStore // nil = TTL-only invalidation
	ttl      time.Duration
	now      func() time.Time
	log      *slog.Logger

	mu     sync.Mutex
	states map[string]*orgCredsPoolState
}

// orgCredsPoolState is the cached snapshot for one endpoint: the eligible
// credential metadata (deterministic store order) plus the round-robin
// cursor. entries may be empty — that is the negative cache (load guard).
type orgCredsPoolState struct {
	entries  []adminstore.OrgCredentialPoolEntry
	cursor   int
	loadedAt time.Time
	version  int64
	haveVer  bool
}

func newOrgCredsPool(store OrgCredsPoolStore, versions OrgCredsVersionStore, ttl time.Duration, l *slog.Logger) *orgCredsPool {
	if ttl <= 0 {
		ttl = orgCredsPoolTTL
	}
	return &orgCredsPool{
		store:    store,
		versions: versions,
		ttl:      ttl,
		now:      time.Now,
		log:      l,
		states:   make(map[string]*orgCredsPoolState),
	}
}

// HOLDS enabled credentials for this endpoint, but every one of them is
// quarantined right now. Distinct from "no credential for the endpoint"
// (ok=false routing miss): there the org never registered a key and the
// chain may continue to the per-model/global key. Here the org did register
// keys — silently routing the GLOBAL key to an org-registered endpoint
// while its own keys are rotated out is the W-PROV leak-hazard posture
// this pool refuses (same stand as the store-error fail-close), and it
// would corrupt BYOK spend attribution. Callers treat it like any pool
// infrastructure error: the attempt fails, no key fall-through.
var errOrgCredsAllQuarantined = errors.New("all org credentials for this endpoint are quarantined")

// eligibleAt reports whether a pool entry may serve NEW attempts at now: no
// version-scoped quarantine row, or one that already expired. The boundary
// mirrors the store SQL (quarantined_until <= now()): a deadline exactly
// equal to now is expired, so a key returns to rotation at the very next
// UTC midnight tick.
func eligibleAt(e adminstore.OrgCredentialPoolEntry, now time.Time) bool {
	return e.QuarantinedUntil.IsZero() || !e.QuarantinedUntil.After(now)
}

// earliestQuarantineReturn is the smallest live deadline across the held
// entries (zero when none is quarantined) — diagnosability for the
// fail-closed error: the operator sees when traffic can come back (or that
// a rotation is needed).
func earliestQuarantineReturn(entries []adminstore.OrgCredentialPoolEntry) time.Time {
	var earliest time.Time
	for _, e := range entries {
		if e.QuarantinedUntil.IsZero() {
			continue
		}
		if earliest.IsZero() || e.QuarantinedUntil.Before(earliest) {
			earliest = e.QuarantinedUntil
		}
	}
	return earliest
}

// advanceLocked is the single selection site of the round-robin (D-2):
// among the snapshot's eligible entries (store order, quarantine evaluated
// at now) it returns entries[cursor % len(eligible)] and advances the
// cursor. ok=false with nil error is the negative miss (the org holds no
// enabled credential for the endpoint); errOrgCredsAllQuarantined when the
// org holds credentials but none is eligible. Caller holds p.mu.
func (p *orgCredsPool) advanceLocked(st *orgCredsPoolState, now time.Time) (adminstore.OrgCredentialPoolEntry, bool, error) {
	eligible := make([]adminstore.OrgCredentialPoolEntry, 0, len(st.entries))
	for _, e := range st.entries {
		if eligibleAt(e, now) {
			eligible = append(eligible, e)
		}
	}
	if len(eligible) == 0 {
		if len(st.entries) > 0 {
			until := earliestQuarantineReturn(st.entries)
			return adminstore.OrgCredentialPoolEntry{}, false,
				fmt.Errorf("%w; earliest return %s", errOrgCredsAllQuarantined, until.UTC().Format(time.RFC3339))
		}
		return adminstore.OrgCredentialPoolEntry{}, false, nil
	}
	sel := st.cursor % len(eligible)
	st.cursor++
	return eligible[sel], true, nil
}

// pick returns the next credential by round-robin (D-2). ok=false (nil
// error) when the org holds no enabled credential for the endpoint — a
// normal routing miss, cached negative like the probe does. A store error
// OR errOrgCredsAllQuarantined is fail-closed: the caller must not fall
// through to the global key while the org plausibly holds credentials for
// this endpoint.
func (p *orgCredsPool) pick(ctx context.Context, orgID, provider, baseURL string) (adminstore.OrgCredentialPoolEntry, bool, error) {
	mapKey := orgID + "\x00" + provider + "\x00" + baseURL
	now := p.now()

	p.mu.Lock()
	st := p.states[mapKey]
	if st != nil && now.Sub(st.loadedAt) < p.ttl {
		entry, ok, err := p.advanceLocked(st, now)
		p.mu.Unlock()
		return entry, ok, err
	}
	var prev orgCredsPoolState
	havePrev := false
	if st != nil {
		prev, havePrev = *st, true
	}
	p.mu.Unlock()

	// Version fast path for positives only (probe parity): an unchanged org
	// version keeps the snapshot without a store round trip. Negatives never
	// take it — a credential added without a version bump must become
	// visible at TTL expiry. Quarantined-but-held snapshots count as
	// positives: eligibility is re-evaluated on every pick, so an expired
	// quarantine returns the key without a store round trip too.
	if havePrev && len(prev.entries) > 0 && p.versions != nil {
		v, verr := p.versions.GetOrgCredsVersion(ctx, orgID)
		if verr == nil && prev.haveVer && v == prev.version {
			p.mu.Lock()
			if cur, ok := p.states[mapKey]; ok && cur == st {
				cur.loadedAt = now
				entry, ok2, err := p.advanceLocked(cur, now)
				p.mu.Unlock()
				return entry, ok2, err
			}
			p.mu.Unlock()
		} else if verr != nil && p.log != nil {
			p.log.Debug("org creds pool version probe failed; re-listing the store", "error", verr)
		}
	}

	entries, err := p.store.ListActiveOrgCredentials(ctx, orgID, provider, baseURL)
	if err != nil {
		return adminstore.OrgCredentialPoolEntry{}, false, fmt.Errorf("list active org credentials: %w", err)
	}
	fresh := &orgCredsPoolState{entries: entries, loadedAt: now}
	if p.versions != nil {
		if v, verr := p.versions.GetOrgCredsVersion(ctx, orgID); verr == nil {
			fresh.version, fresh.haveVer = v, true
		}
	}
	p.mu.Lock()
	p.states[mapKey] = fresh
	p.evictLocked(now)
	entry, ok, err := p.advanceLocked(fresh, now)
	p.mu.Unlock()
	return entry, ok, err
}

// pickAndResolve selects the next credential and resolves ITS plaintext for
// exactly one attempt (per-request pinning). When the pinned entry left
// rotation between selection and resolution (disabled/quarantined/deleted),
// the snapshot is refreshed once and another credential is tried — the
// caller never falls through to a non-org key while eligible org
// credentials remain.
func (p *orgCredsPool) pickAndResolve(ctx context.Context, orgID, provider, baseURL string) (orgCredentialUse, string, bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		entry, ok, err := p.pick(ctx, orgID, provider, baseURL)
		if err != nil || !ok {
			return orgCredentialUse{}, "", false, err
		}
		plain, resolved, rerr := p.store.ResolveKeyEntry(ctx, orgID, provider, baseURL, entry.ID)
		if rerr != nil {
			return orgCredentialUse{}, "", false, fmt.Errorf("resolve pinned org credential: %w", rerr)
		}
		if resolved && plain != "" {
			use := orgCredentialUse{used: true, credID: entry.ID, last4: entry.KeyLast4, baseURL: baseURL}
			if p.log != nil && p.log.Enabled(ctx, slog.LevelDebug) {
				// No secret material in logs: credential ID and mask only.
				p.log.Debug("org credential pool pinned for upstream key",
					"org_id", orgID, "provider", provider,
					"credential_id", entry.ID, "key_last4", entry.KeyLast4)
			}
			return use, plain, true, nil
		}
		// Stale pin: drop the snapshot so the retry re-lists.
		p.invalidate(orgID, provider, baseURL)
	}
	return orgCredentialUse{}, "", false, nil
}

// recordOutcome feeds one attempt's upstream status back to the pool (D-3).
// 401 (invalid/revoked key) and 429 (per-key throttle) quarantine the
// CREDENTIAL until the end of the current UTC day — the per-endpoint circuit
// serving. In-flight attempts are unaffected: they already hold their
// resolved plaintext. Quarantine is bookkeeping: a write failure is logged
// (credential id + mask only) and never fails the request.
func (p *orgCredsPool) recordOutcome(ctx context.Context, orgID, provider string, use orgCredentialUse, statusCode int) {
	if p == nil || !use.used {
		return
	}
	if statusCode != http.StatusUnauthorized && statusCode != http.StatusTooManyRequests {
		return
	}
	until := quarantineDeadline(p.now())
	if err := p.store.QuarantineOrgCredential(ctx, orgID, use.credID, until); err != nil {
		if adminstore.IsNotFound(err) {
			// Deleted mid-flight — nothing left to quarantine.
			return
		}
		if p.log != nil {
			p.log.Warn("org credential quarantine write failed",
				"org_id", orgID, "provider", provider,
				"credential_id", use.credID, "key_last4", use.last4, "error", err)
		}
		return
	}
	// Cross-instance invalidation: same version contract the admin API bumps
	// on CRUD — every gateway (and the probe) drops this org's snapshots.
	if p.versions != nil {
		if err := p.versions.SetOrgCredsVersion(ctx, orgID, p.now().UnixNano()); err != nil && p.log != nil {
			p.log.Debug("org creds version bump after quarantine failed", "org_id", orgID, "error", err)
		}
	}
	p.invalidate(orgID, provider, use.baseURL)
	if p.log != nil {
		p.log.Info("org credential quarantined after upstream rejection",
			"org_id", orgID, "provider", provider,
			"credential_id", use.credID, "key_last4", use.last4,
			"status_code", statusCode, "until", until.UTC().Format(time.RFC3339))
	}
}

// ResetOrgCredential lifts one credential's quarantine ahead of its
// deadline (operator reset from the admin surface). It reuses the existing
// quarantine write path with a past-dated deadline: eligibility treats
// quarantined_until <= now as expired, so the row flips the credential back
// to eligible without a new store method and without widening the frozen
// store surface. The org version bump drops the other gateways' cached
// snapshots, and the local endpoint snapshot is invalidated so the next pick
// re-lists with fresh eligibility.
//
// An unknown credential surfaces as adminstore.ErrNotFound (wrapped); an
// empty credential id is rejected. Reset is idempotent — resetting an
// already eligible credential only rewrites an expired row. Safe for
// concurrent use: concurrent resets converge on the same past-dated row.
func (p *orgCredsPool) ResetOrgCredential(ctx context.Context, orgID, provider, baseURL, credentialID string) error {
	if p == nil {
		return errors.New("org credential pool is not wired")
	}
	if credentialID == "" {
		return errors.New("credential id is required")
	}
	// Past-dated deadline = expired by the store boundary: the lift needs no
	// new quarantine verb and no adminstore change.
	if err := p.store.QuarantineOrgCredential(ctx, orgID, credentialID, p.now().Add(-time.Second)); err != nil {
		return fmt.Errorf("reset org credential %s: %w", credentialID, err)
	}
	// Cross-instance invalidation: the same version contract the quarantine
	// write bumps. A failed bump only costs a TTL-bound stale window.
	if p.versions != nil {
		if err := p.versions.SetOrgCredsVersion(ctx, orgID, p.now().UnixNano()); err != nil && p.log != nil {
			p.log.Debug("org creds version bump after reset failed", "org_id", orgID, "credential_id", credentialID, "error", err)
		}
	}
	p.invalidate(orgID, provider, baseURL)
	if p.log != nil {
		// No secret material: credential id only.
		p.log.Info("org credential quarantine reset",
			"org_id", orgID, "provider", provider,
			"credential_id", credentialID, "base_url", baseURL)
	}
	return nil
}

// invalidate drops the local snapshot of one endpoint so the next pick
// re-lists with fresh quarantine state.
func (p *orgCredsPool) invalidate(orgID, provider, baseURL string) {
	if baseURL == "" {
		return
	}
	mapKey := orgID + "\x00" + provider + "\x00" + baseURL
	p.mu.Lock()
	delete(p.states, mapKey)
	p.mu.Unlock()
}

// evictLocked drops expired states first, then the oldest-loaded ones, while
// the index exceeds orgCredsPoolMaxOrgs. Caller holds p.mu.
func (p *orgCredsPool) evictLocked(now time.Time) {
	if len(p.states) <= orgCredsPoolMaxOrgs {
		return
	}
	for k, st := range p.states {
		if now.Sub(st.loadedAt) >= p.ttl {
			delete(p.states, k)
		}
	}
	for len(p.states) > orgCredsPoolMaxOrgs {
		oldestKey := ""
		var oldest time.Time
		for k, st := range p.states {
			if oldestKey == "" || st.loadedAt.Before(oldest) {
				oldestKey, oldest = k, st.loadedAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(p.states, oldestKey)
	}
}

// quarantineDeadline is the D-3 horizon: the start of the next UTC day —
// "until the end of the current day", at most 24h from now.
func quarantineDeadline(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}
