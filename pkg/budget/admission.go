// Package budget: gateway admission layer for durable budget reservations
// (NEXT-18c, ADR-0001 rev. 3 §5.1/§5.3/§9/§14). The controller owns one
// replica's escrow: it estimates per-scope bounds, pre-checks exhaustion
// against a short-lived state cache, reserves locally from the replica's
// allowance (granting from Postgres on shortage), finalizes actual spend,
// renews leases, returns idle escrow and drains on shutdown.
//
// Pipeline position (§5.1): Plan runs after route+policy and BEFORE the
// cache lookup (a cache hit at exhaustion must be denied too, D7); Reserve
// runs after a cache miss; Finalize runs after the upstream attempt and
// produces the event reserve tuples the settlement worker consumes.
//
// Modes (§9): off reproduces the legacy behavior bit-for-bit (no queries,
// no accounting, no event fields); shadow accounts everything but never
// denies (would-deny observability); enforce denies service when a hard
// scope cannot fund the request bound.
package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
)

// Mode is the §9 reservations mode of an organization.
type Mode string

// §9 modes.
const (
	ModeOff     Mode = "off"
	ModeShadow  Mode = "shadow"
	ModeEnforce Mode = "enforce"
)

// ResolveMode maps a configured mode string to a Mode; any other value
// (including empty) resolves to off — the deployment-wide default must stay
// the bit-identical legacy behavior, so a mistyped env value can never
// activate reservations (fail-safe, like the guard-hooks mode resolver).
func ResolveMode(s string) Mode {
	switch Mode(s) {
	case ModeShadow:
		return ModeShadow
	case ModeEnforce:
		return ModeEnforce
	default:
		return ModeOff
	}
}

// modeRank orders the modes for the deployment-gate clamp: the global env
// switch bounds what an organization can activate (off < shadow < enforce).
// A deployment in shadow degrades every enforce org to shadow until the
// operator raises the gate — the DB carries per-org intent, the env the
// rollout stage.
func modeRank(m Mode) int {
	switch m {
	case ModeEnforce:
		return 2
	case ModeShadow:
		return 1
	default:
		return 0
	}
}

// EffectiveMode applies the deployment gate exactly as admission does: the
// organization may select a mode up to the deployment's rollout ceiling.
// Unknown values resolve to off before this function is called.
func EffectiveMode(global, org Mode) Mode {
	if modeRank(org) > modeRank(global) {
		return global
	}
	return org
}

// Termination is how a reserved request ended (§5.3 Finalize). The values
// are the Finalize contract set the consumer validates.
type Termination string

// The Finalize termination set (§5.3).
const (
	TerminationCompleted    Termination = "completed"
	TerminationClientCancel Termination = "client_cancel"
	TerminationIdleTimeout  Termination = "idle_timeout"
	TerminationUpstreamErr  Termination = "upstream_error"
	TerminationPolicyDenied Termination = "policy_denied"
)

// ValidTermination reports whether t belongs to the Finalize set.
func ValidTermination(t Termination) bool {
	switch t {
	case TerminationCompleted, TerminationClientCancel, TerminationIdleTimeout, TerminationUpstreamErr, TerminationPolicyDenied:
		return true
	default:
		return false
	}
}

// AdmissionConfig carries the §14/§5.1 cycle parameters. Zero fields fall
// back to the defaults.
type AdmissionConfig struct {
	// PreCheckTTL bounds the exhaustion/org-state cache (§5.1: ≤5s).
	PreCheckTTL time.Duration
	// RenewalInterval is how often the replica renews its allowance leases.
	RenewalInterval time.Duration
	// IdleReturn is how long an allowance stays untouched before its unused
	// remainder returns to the scopes.
	IdleReturn time.Duration
	// OrgTTL bounds the per-org settings (mode + default output cap) cache.
	OrgTTL time.Duration
}

// DefaultAdmissionConfig returns the §14/§5.1 defaults.
func DefaultAdmissionConfig() AdmissionConfig {
	return AdmissionConfig{
		PreCheckTTL:     5 * time.Second,
		RenewalInterval: 60 * time.Second,
		IdleReturn:      10 * time.Second,
		OrgTTL:          5 * time.Second,
	}
}

func (c AdmissionConfig) withDefaults() AdmissionConfig {
	def := DefaultAdmissionConfig()
	if c.PreCheckTTL <= 0 {
		c.PreCheckTTL = def.PreCheckTTL
	}
	if c.RenewalInterval <= 0 {
		c.RenewalInterval = def.RenewalInterval
	}
	if c.IdleReturn <= 0 {
		c.IdleReturn = def.IdleReturn
	}
	if c.OrgTTL <= 0 {
		c.OrgTTL = def.OrgTTL
	}
	return c
}

// OrgSettings is the per-org reservation policy read through OrgLoader.
type OrgSettings struct {
	// Mode is the organization's reservations_mode column.
	Mode Mode
	// DefaultOutCapTokens is default_output_cap_tokens (D3a); 0 = unset.
	DefaultOutCapTokens int64
}

// OrgLoader reads an organization's reservation settings. Any error degrades
// to off/0 — the caller treats the org as legacy (fail-closed to the
// bit-identical behavior, never denies without opt-in).
type OrgLoader func(ctx context.Context, orgID string) (OrgSettings, error)

// Request is one admission: identity plus everything the bound estimator
// needs (§4.3). Chain is the billable planned chain (primary + failovers
// after the policy gate; no shadow hops). InputBytes must already exclude
// base64 image payloads; ImageCount prices them flat.
type Request struct {
	OrgID        string
	TeamID       string
	AgentID      string
	SessionKeyID string
	Chain        []ChainHop
	InputBytes   int64
	ImageCount   int64
	MaxTokens    *int64
	Embeddings   bool
	// UnitKind + UnitQty carry a non-token metering request (T02:
	// pricing.UnitPerAudioSecond / UnitPerCharacter / UnitPerImage with the
	// conservative quantity). Empty kind = the per-token path.
	UnitKind string
	UnitQty  *float64
}

// ScopeBound is the estimated bound of one limit area (§4.2 bound_S).
type ScopeBound struct {
	Scope  ScopeKind
	Key    string
	Period string
	Bound  money.MicroUSD
}

// Plan is the pre-check outcome (§5.1, before the cache lookup): the
// effective mode and the per-scope bounds. Reserve turns it into a
// Reservation after a cache miss. WouldDeny collects the refusals shadow
// observed (§9 would_deny observability) — the request proceeds; enforce
// surfaces the same refusals as errors instead.
type Plan struct {
	Mode      Mode
	OrgID     string
	Scopes    []ScopeBound
	WouldDeny []*Denial
}

// Reservation carries the applied reserve tuples of one admitted request
// (§5.3 Finalize). A nil *Reservation is the off-mode no-op.
type Reservation struct {
	OrgID    string
	Mode     Mode
	Scopes   []ScopeReserve
	created  time.Time
	reserved bool
}

// ScopeReserve is one event tuple {scope_kind, scope_key, period,
// allowance_id, bound_micro_usd} (§5.3 Finalize).
type ScopeReserve struct {
	Scope       ScopeKind
	Key         string
	Period      string
	AllowanceID int64
	Bound       money.MicroUSD
}

// tupleJSON is the wire shape the consumer parses from the event's
// `reservations` field (NEXT-18d contract).
type tupleJSON struct {
	ScopeKind     string `json:"scope_kind"`
	ScopeKey      string `json:"scope_key"`
	Period        string `json:"period"`
	AllowanceID   int64  `json:"allowance_id"`
	BoundMicroUSD int64  `json:"bound_micro_usd"`
}

// TuplesJSON renders the event field payload; empty when nothing was
// reserved (off mode, unpriced shadow, refused shadow grant).
func (r *Reservation) TuplesJSON() string {
	if r == nil || len(r.Scopes) == 0 {
		return ""
	}
	tuples := make([]tupleJSON, 0, len(r.Scopes))
	for _, s := range r.Scopes {
		tuples = append(tuples, tupleJSON{
			ScopeKind:     string(s.Scope),
			ScopeKey:      s.Key,
			Period:        s.Period,
			AllowanceID:   s.AllowanceID,
			BoundMicroUSD: int64(s.Bound),
		})
	}
	b, err := json.Marshal(tuples)
	if err != nil {
		return ""
	}
	return string(b)
}

// Denial carries the scope an admission failure belongs to so the gateway
// can answer 402 (wallet) or 429 (budget areas) per §9.
type Denial struct {
	Scope ScopeKind
	Err   error
}

func (d *Denial) Error() string {
	if d == nil {
		return "<nil>"
	}
	return fmt.Sprintf("reservation admission denied (scope %s): %v", d.Scope, d.Err)
}

func (d *Denial) Unwrap() error {
	if d == nil {
		return nil
	}
	return d.Err
}

// ErrNotReserved reports that shadow-mode accounting could not reserve
// (exhaustion, missing capacity source, store outage): the request proceeds
// unreserved and the plan carries the would-deny for the metrics.
var ErrNotReserved = errors.New("reservation: not reserved")

// ledgerKey identifies one escrow slice of this replica.
type ledgerKey struct {
	scope  ScopeKind
	key    string
	period string
}

// ledgerEntry mirrors this replica's allowance: available = granted −
// returned − spent − inflight. granted/returned track the store; spent
// accumulates finalized min(actual, bound) — the exact amounts the
// settlement worker later settles against the same tuples; inflight holds
// the bounds of requests in flight. Idle return recomputes the remainder
// from the database, so any drift self-corrects within one cycle.
type ledgerEntry struct {
	orgID       string
	allowanceID int64
	granted     money.MicroUSD
	returned    money.MicroUSD
	spent       money.MicroUSD
	inflight    money.MicroUSD
	lastUse     time.Time
}

// rateStat feeds the escrow sizing rule (§5.3): the replica's observed
// spend rate and rolling average bound per scope.
type rateStat struct {
	ratePerSecond money.MicroUSD
	avgBound      money.MicroUSD
}

type orgCacheEntry struct {
	settings OrgSettings
	until    time.Time
}

type probeCacheEntry struct {
	free  money.MicroUSD
	until time.Time
}

// Admission is one replica's reservation controller (§5.1/§5.3/§9). A nil
// receiver and a global gate of off keep every method a no-op.
type Admission struct {
	store     *ReservationStore
	rates     ScopedRateSource
	log       *slog.Logger
	cfg       AdmissionConfig
	replicaID string
	global    Mode
	orgs      OrgLoader
	now       func() time.Time
	// history is the N10-P04-T03 durable-history admission gate, armed via
	// SetHistoryAdmission before serving; nil = disarmed (legacy behavior).
	history *HistoryAdmission

	mu        sync.Mutex
	ledger    map[ledgerKey]*ledgerEntry
	spendRate map[ledgerKey]rateStat
	orgCache  map[string]orgCacheEntry
	probes    map[ledgerKey]probeCacheEntry
	exhausted map[ledgerKey]time.Time

	// History-mode admission state (N12-P02-T03, I40/I44/I45) — all
	// guarded by mu. historyMode zero value resolves to the fail-safe
	// reject profile on read (historyProfile). historyCheck nil = ungated.
	historyMode  HistoryMode
	historyCheck HistoryCapacityCheck
	lossLogged   bool
	attempts     map[string]historyAttempt
	attemptOrder []string

	// Failure-recovery bookkeeping (N12-P02-T04, I40/I44/I45) — all guarded
	// by mu; read through RecoverySnapshot. lossAdmissions is the
	// cumulative loss-accepted admission volume (the visible history-gap
	// population, I44); attemptsUncertain counts TTL-reaped unfinished
	// attempt claims (outcome UNKNOWN after owner death/crash — the I45
	// reconciliation population, never re-dispatched, never reported
	// persisted/settled); lossWindowOpen tracks whether the most recent
	// loss has seen a persisted decision since (lastRecoveryAt stamps that
	// recovery).
	lossAdmissions    uint64
	attemptsUncertain uint64
	lossWindowOpen    bool
	lastLossAt        time.Time
	lastRecoveryAt    time.Time
	lastUncertainAt   time.Time

	stop     chan struct{}
	stopOnce sync.Once
}

// NewAdmission builds a controller. replicaID must be unique per process
// instance (it keys the allowance rows); the gateway wires
// hostname+pid+start time. rates prices the bounds (I4).
func NewAdmission(store *ReservationStore, rates ScopedRateSource, log *slog.Logger, replicaID string, global Mode, orgs OrgLoader, cfg AdmissionConfig) *Admission {
	if log == nil {
		log = slog.Default()
	}
	return &Admission{
		store:     store,
		rates:     rates,
		log:       log.With("component", "budget-admission", "replica", replicaID),
		cfg:       cfg.withDefaults(),
		replicaID: replicaID,
		global:    global,
		orgs:      orgs,
		now:       time.Now,
		ledger:    map[ledgerKey]*ledgerEntry{},
		spendRate: map[ledgerKey]rateStat{},
		orgCache:  map[string]orgCacheEntry{},
		probes:    map[ledgerKey]probeCacheEntry{},
		exhausted: map[ledgerKey]time.Time{},
		stop:      make(chan struct{}),
	}
}

// SetClock pins the clock (tests).
func (a *Admission) SetClock(now func() time.Time) { a.now = now }

// Start launches the renewal/idle-return housekeeping loop. It stops when
// ctx is cancelled or Stop is called.
func (a *Admission) Start(ctx context.Context) {
	if a == nil || a.global == ModeOff {
		return
	}
	tick := a.cfg.RenewalInterval / 4
	if tick > time.Second {
		tick = time.Second
	}
	if tick < 100*time.Millisecond {
		tick = 100 * time.Millisecond
	}
	go func() {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		var elapsed time.Duration
		for {
			select {
			case <-ctx.Done():
				return
			case <-a.stop:
				return
			case <-ticker.C:
			}
			elapsed += tick
			renewDue := elapsed >= a.cfg.RenewalInterval
			a.housekeep(ctx, renewDue)
			if renewDue {
				elapsed = 0
			}
		}
	}()
}

// Stop terminates the housekeeping loop.
func (a *Admission) Stop() {
	if a == nil {
		return
	}
	a.stopOnce.Do(func() { close(a.stop) })
}

// housekeep runs one pass: renewal (when due) and idle returns. Each store
// round trip is bounded by its own timeout — a slow DB must not wedge the
// loop past the tick.
func (a *Admission) housekeep(ctx context.Context, renewDue bool) {
	a.mu.Lock()
	idle := make([]ledgerKey, 0, len(a.ledger))
	now := a.now()
	for k, e := range a.ledger {
		if now.Sub(e.lastUse) >= a.cfg.IdleReturn {
			idle = append(idle, k)
		}
	}
	holding := len(a.ledger)
	a.mu.Unlock()

	if renewDue && holding > 0 {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if _, err := a.store.Renewal(rctx, a.replicaID); err != nil {
			a.log.Warn("reservation renewal failed", "error", err)
		}
		cancel()
	}
	for _, k := range idle {
		a.returnIdle(ctx, k)
	}
}

// returnIdle gives back an idle scope's unused remainder. The holdback is
// the replica's full unsettled claim: in-flight bounds plus finalized spend
// the worker has not settled yet (settled spend is already gone from the
// scope row). The entry is dropped before the round trip: a concurrent
// finalize re-grants on its next reserve instead of resurrecting returned
// escrow.
func (a *Admission) returnIdle(ctx context.Context, k ledgerKey) {
	a.mu.Lock()
	e, ok := a.ledger[k]
	if !ok {
		a.mu.Unlock()
		return
	}
	orgID, holdback := e.orgID, e.inflight+e.spent
	delete(a.ledger, k)
	delete(a.spendRate, k)
	a.mu.Unlock()

	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := a.store.ReturnRemaining(rctx, orgID, a.replicaID, []RemainingRequest{{
		Scope: k.scope, Key: k.key, Period: k.period, Holdback: holdback,
	}}); err != nil {
		a.log.Warn("reservation idle return failed",
			"scope", string(k.scope), "key", k.key, "error", err)
	}
}

// Shutdown drains on graceful shutdown (§5.3 Return): flip the replica's
// allowances to draining (renewals stop, reconcile releases zero-remainder
// rows) and return every unused remainder, holding back in-flight bounds
// and their unsettled spend.
func (a *Admission) Shutdown(ctx context.Context) {
	if a == nil || a.global == ModeOff {
		return
	}
	a.Stop()
	if _, err := a.store.MarkDraining(ctx, a.replicaID); err != nil {
		a.log.Warn("reservation mark draining failed", "error", err)
	}
	a.mu.Lock()
	keys := make([]ledgerKey, 0, len(a.ledger))
	for k := range a.ledger {
		keys = append(keys, k)
	}
	a.mu.Unlock()
	dctx := context.WithoutCancel(ctx)
	for _, k := range keys {
		a.returnIdle(dctx, k)
	}
}

// ReapCrashedPredecessors runs automatically at replica start for this replica only: it derives the
// host-family prefix from this controller's own replicaID and flips the
// crashed previous incarnations' lapsed-lease allowances to draining
// (ReservationStore.SelfReapCrashedIncarnations). Call once at boot,
// before serving traffic. The safety window still governs when frozen
// escrow returns (D3) — this sweep only accelerates the status transition
// and the zero-remainder release. A no-op (0) on every subsequent run.
func (a *Admission) ReapCrashedPredecessors(ctx context.Context) (int64, error) {
	if a == nil || a.global == ModeOff {
		return 0, nil
	}
	prefix := selfReapPrefix(a.replicaID)
	if prefix == "" {
		return 0, nil
	}
	n, err := a.store.SelfReapCrashedIncarnations(ctx, prefix)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		a.log.Info("startup sweep reaped crashed predecessors' allowances",
			"replica_id", a.replicaID, "host_prefix", prefix, "drained", n)
	}
	return n, nil
}

// selfReapPrefix strips the trailing "-<pid>-<start nanos>" segments the
// gateway appends to the hostname (reservationReplicaID), leaving the host
// family a startup sweep may treat as its own previous incarnations. A
// replica id without two numeric trailing segments yields "" — nothing can
// be identified as this process's own family, so the sweep safely no-ops.
func selfReapPrefix(replicaID string) string {
	if replicaID == "" {
		return ""
	}
	idx := strings.LastIndex(replicaID, "-")
	if idx <= 0 {
		return ""
	}
	nanos := replicaID[idx+1:]
	rest := replicaID[:idx]
	idx2 := strings.LastIndex(rest, "-")
	if idx2 <= 0 {
		return ""
	}
	pid := rest[idx2+1:]
	if !isAllDigits(pid) || !isAllDigits(nanos) {
		return ""
	}
	return rest[:idx2]
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// orgSettings resolves the effective mode and default output cap for an
// org through the ≤5s cache. A loader error (or a nil loader) degrades to
// off — the bit-identical legacy behavior.
func (a *Admission) orgSettings(ctx context.Context, orgID string) OrgSettings {
	if orgID == "" {
		return OrgSettings{Mode: ModeOff}
	}
	a.mu.Lock()
	cached, ok := a.orgCache[orgID]
	a.mu.Unlock()
	if ok && a.now().Before(cached.until) {
		return cached.settings
	}
	var settings OrgSettings
	if a.orgs != nil {
		if s, err := a.orgs(ctx, orgID); err == nil {
			settings = OrgSettings{
				Mode:                EffectiveMode(a.global, ResolveMode(string(s.Mode))),
				DefaultOutCapTokens: s.DefaultOutCapTokens,
			}
		}
	}
	a.mu.Lock()
	a.orgCache[orgID] = orgCacheEntry{settings: settings, until: a.now().Add(a.cfg.OrgTTL)}
	a.mu.Unlock()
	return settings
}

// estimateBounds computes bound_S for every requested scope (§4.2/§4.3).
// The wallet scope is always requested for an org; team/agent/session ride
// their attribution; session only for keys with a money cap (the caller
// leaves SessionKeyID empty otherwise — D14 refuses uncapped keys).
func (a *Admission) estimateBounds(ctx context.Context, orgID string, req Request, defaultOutCap int64) ([]ScopeBound, error) {
	if len(req.Chain) == 0 {
		return nil, fmt.Errorf("%w: empty planned chain", ErrUnpricedModel)
	}
	estReq := EstimateRequest{
		Chain:         req.Chain,
		InputBytes:    req.InputBytes,
		ImageCount:    req.ImageCount,
		MaxTokens:     req.MaxTokens,
		Embeddings:    req.Embeddings,
		DefaultOutCap: defaultOutCap,
		UnitKind:      req.UnitKind,
		UnitQty:       req.UnitQty,
	}
	now := a.now().UTC()
	scopes := make([]ScopeBound, 0, 4)
	if orgID != "" {
		wallet, err := EstimateBound(ctx, a.rates, PriceScopeWallet, orgID, estReq)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, ScopeBound{Scope: ScopeWallet, Key: orgID, Bound: wallet.BoundMicroUSD})
	}
	if req.TeamID != "" {
		b, err := EstimateBound(ctx, a.rates, PriceScopeTeamMonth, orgID, estReq)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, ScopeBound{
			Scope: ScopeTeamMonth, Key: req.TeamID, Period: now.Format("2006-01"), Bound: b.BoundMicroUSD,
		})
	}
	if req.AgentID != "" {
		b, err := EstimateBound(ctx, a.rates, PriceScopeAgentDay, orgID, estReq)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, ScopeBound{
			Scope: ScopeAgentDay, Key: req.AgentID, Period: now.Format("2006-01-02"), Bound: b.BoundMicroUSD,
		})
	}
	if req.SessionKeyID != "" {
		b, err := EstimateBound(ctx, a.rates, PriceScopeSession, orgID, estReq)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, ScopeBound{
			Scope: ScopeSession, Key: req.SessionKeyID, Period: "", Bound: b.BoundMicroUSD,
		})
	}
	return scopes, nil
}

// Plan estimates the per-scope bounds and pre-checks exhaustion (§5.1 —
// after route+policy, BEFORE the cache lookup). The returned plan is the
// input to Reserve. A non-nil error in enforce mode is a service denial:
//   - ErrUnpricedModel → 403 model_unpriced (I3),
//   - *Denial wrapping ErrInsufficientCapacity → 402/429 per scope,
//   - *Denial wrapping ErrNoCapacitySource → fail-closed denial (D14).
//
// In shadow mode estimation failures and exhaustion are reported on the
// plan (the caller records the would-deny metric) and the request proceeds.
func (a *Admission) Plan(ctx context.Context, req Request) (*Plan, error) {
	if a == nil {
		return &Plan{Mode: ModeOff}, nil
	}
	// N10-P04-T03 (I40/I44): the durable-history gate is a deployment-level
	// setting and runs BEFORE the reservations-mode checks — an outage in
	// the guaranteed-history path denies (default) or is served-with-loss
	// (explicit allow_loss opt-in) even for orgs with reservations off.
	// Callers that already evaluated the history leg (AdmitWithHistory)
	// must go through planAfterHistory instead, so the gate is enforced
	// exactly once per attempt (N12-P02-T03 composition).
	if err := a.history.Admit(ctx); err != nil {
		return nil, err
	}
	return a.planAfterHistory(ctx, req)
}

// planAfterHistory is Plan's estimation and exhaustion pre-check body,
// minus the durable-history consult. It exists as the N12-P02-T03
// composition seam: AdmitWithHistory evaluates the history gate exactly
// once (CheckHistory — delegating to the armed HistoryAdmission when one is
// wired, else to the HistoryCapacityCheck seam) and then runs the money leg
// through here, so arming either history wiring can never gate the same
// request twice.
func (a *Admission) planAfterHistory(ctx context.Context, req Request) (*Plan, error) {
	if a.global == ModeOff || req.OrgID == "" {
		return &Plan{Mode: ModeOff}, nil
	}
	settings := a.orgSettings(ctx, req.OrgID)
	if settings.Mode == ModeOff {
		return &Plan{Mode: ModeOff}, nil
	}
	// §7.2/D17: the synchronous admission overhead this layer adds — the
	// shadow-exit gate reads p95 of this histogram (≤ 5ms, §7.3).
	start := time.Now()
	defer func() { metrics.BudgetAdmissionOverheadSeconds.Observe(time.Since(start).Seconds()) }()
	scopes, err := a.estimateBounds(ctx, req.OrgID, req, settings.DefaultOutCapTokens)
	if err != nil {
		plan := &Plan{Mode: settings.Mode, OrgID: req.OrgID}
		if settings.Mode == ModeShadow {
			// Shadow never denies: record the would-deny, serve unreserved.
			plan.WouldDeny = append(plan.WouldDeny, &Denial{Err: err})
			return plan, nil
		}
		return nil, err
	}
	plan := &Plan{Mode: settings.Mode, OrgID: req.OrgID, Scopes: scopes}
	// Exhaustion pre-check (enforce denies, shadow records): refuse before
	// any work, including a would-be cache hit (D7). The state cache is
	// bounded by PreCheckTTL.
	for _, s := range scopes {
		denial := func(err error) *Denial {
			a.markExhausted([]ScopeBound{s})
			return &Denial{Scope: s.Scope, Err: err}
		}
		if a.recentlyRefused(s) {
			d := denial(fmt.Errorf("%w: scope %s key %s (recent refusal)", ErrInsufficientCapacity, s.Scope, s.Key))
			if settings.Mode == ModeEnforce {
				return nil, d
			}
			plan.WouldDeny = append(plan.WouldDeny, d)
			continue
		}
		free, ok := a.probeCapacity(ctx, req.OrgID, s)
		if ok && free < s.Bound {
			d := denial(fmt.Errorf("%w: scope %s key %s", ErrInsufficientCapacity, s.Scope, s.Key))
			if settings.Mode == ModeEnforce {
				return nil, d
			}
			plan.WouldDeny = append(plan.WouldDeny, d)
		}
	}
	return plan, nil
}

// recentlyRefused reports a grant refusal inside the pre-check TTL.
func (a *Admission) recentlyRefused(s ScopeBound) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.exhausted[ledgerKey{s.Scope, s.Key, s.Period}]
	return ok && a.now().Before(until)
}

// probeCapacity reads a scope's free capacity through the ≤5s cache. ok is
// false when the probe is unavailable (row missing / DB error): the
// pre-check then stays silent — the grant itself stays the authority.
func (a *Admission) probeCapacity(ctx context.Context, orgID string, s ScopeBound) (money.MicroUSD, bool) {
	k := ledgerKey{scope: s.Scope, key: s.Key, period: s.Period}
	a.mu.Lock()
	cached, ok := a.probes[k]
	a.mu.Unlock()
	if ok && a.now().Before(cached.until) {
		return cached.free, true
	}
	free, err := a.store.ProbeFreeCapacity(ctx, orgID, GrantRequest{
		Scope: s.Scope, Key: s.Key, Period: s.Period, Bound: s.Bound,
	})
	if err != nil {
		return 0, false
	}
	a.mu.Lock()
	a.probes[k] = probeCacheEntry{free: free, until: a.now().Add(a.cfg.PreCheckTTL)}
	a.mu.Unlock()
	return free, true
}

// markExhausted records refusals for the pre-check TTL (fast-path denial).
func (a *Admission) markExhausted(scopes []ScopeBound) {
	a.mu.Lock()
	defer a.mu.Unlock()
	until := a.now().Add(a.cfg.PreCheckTTL)
	for _, s := range scopes {
		a.exhausted[ledgerKey{s.Scope, s.Key, s.Period}] = until
	}
}

// Reserve applies the plan after a cache miss (§5.1/§5.3): fit locally from
// the replica's allowances, grant from Postgres for shortages. Enforce
// refusal returns a *Denial; shadow refusal returns (nil, nil) — the
// request proceeds unreserved, accounting only.
func (a *Admission) Reserve(ctx context.Context, plan *Plan) (*Reservation, error) {
	if a == nil || plan == nil || plan.Mode == ModeOff || len(plan.Scopes) == 0 {
		return nil, fmt.Errorf("%w: reservations inactive", ErrNotReserved)
	}
	need := make([]ScopeBound, len(plan.Scopes))
	copy(need, plan.Scopes)
	rsv := &Reservation{OrgID: plan.OrgID, Mode: plan.Mode, created: a.now()}
	// §7.2: Reserve is the second synchronous admission section (D17 §7.3).
	start := time.Now()
	defer func() { metrics.BudgetAdmissionOverheadSeconds.Observe(time.Since(start).Seconds()) }()

	// Fast path: everything fits the local escrow.
	if a.fitLocally(rsv, need) {
		metrics.BudgetLocalAdmitTotal.WithLabelValues(AdmitResultLocal).Inc()
		return rsv, nil
	}

	// Grant only the deficits from Postgres (§5.3 Grant); the fitted scopes
	// stay on the local escrow. Under concurrency the local escrow free is
	// a contended pool: another Reserve can land a grant (raising free) or
	// fit a bound (lowering free) between this caller's lock sections, so
	// the deficit computation and the fit are re-run — bounded at two
	// rounds, fail-closed afterwards. The grant-apply + re-fit itself is
	// one lock hold, so the freshly granted surplus cannot be consumed by
	// a racing fit in between.
	for round := 0; ; round++ {
		deficits := a.localDeficits(need)
		if len(deficits) == 0 {
			// A concurrent grant raised the escrow free past every bound
			// since the fast-path fit missed: re-fit under one lock hold
			// instead of asking the store for a zero-scope grant.
			if !a.applyGrantsAndFit(rsv, plan.OrgID, nil, need) {
				metrics.BudgetLocalAdmitTotal.WithLabelValues(AdmitResultRefused).Inc()
				if plan.Mode == ModeEnforce {
					return nil, &Denial{Scope: need[0].Scope, Err: fmt.Errorf("%w: local escrow short after grant", ErrInsufficientCapacity)}
				}
				return nil, fmt.Errorf("%w: local escrow short after grant", ErrNotReserved)
			}
			break
		}
		grants, err := a.grantScopes(ctx, plan, deficits)
		if err != nil {
			metrics.BudgetLocalAdmitTotal.WithLabelValues(AdmitResultRefused).Inc()
			return nil, err
		}
		if grants == nil {
			// Shadow refusal (insufficient / no source / store outage): the
			// request proceeds unreserved.
			metrics.BudgetLocalAdmitTotal.WithLabelValues(AdmitResultRefused).Inc()
			return nil, fmt.Errorf("%w: grant refused in shadow mode", ErrNotReserved)
		}
		if !a.applyGrantsAndFit(rsv, plan.OrgID, grants, need) {
			if round == 0 {
				// A racing fit consumed a scope that was not a deficit at
				// snapshot time; recompute deficits (the fresh Δ of round 1
				// stays in the ledger as surplus — the store-side reserved
				// µUSD is settled by the idle return, §5.3 Return) and try
				// once more before refusing closed.
				continue
			}
			// Δ ≥ bound for every granted scope and the grant-apply + re-fit
			// is serialized under one admission-lock hold, so no concurrent
			// Reserve can consume the freshly granted surplus in between.
			// Unreachable except under ledger corruption; refuse closed
			// rather than admit against money the escrow does not show.
			metrics.BudgetLocalAdmitTotal.WithLabelValues(AdmitResultRefused).Inc()
			if plan.Mode == ModeEnforce {
				return nil, &Denial{Scope: need[0].Scope, Err: fmt.Errorf("%w: local escrow short after grant", ErrInsufficientCapacity)}
			}
			return nil, fmt.Errorf("%w: local escrow short after grant", ErrNotReserved)
		}
		break
	}
	metrics.BudgetLocalAdmitTotal.WithLabelValues(AdmitResultGrant).Inc()
	return rsv, nil
}

// Admit results for budget_local_admit_total (§7.2).
const (
	AdmitResultLocal   = "local"
	AdmitResultGrant   = "grant"
	AdmitResultRefused = "refused"
)

// Grant results for budget_grants_total{result} (§7.2).
const (
	GrantResultGranted      = "granted"
	GrantResultInsufficient = "insufficient"
	GrantResultNoSource     = "no_source"
	GrantResultError        = "error"
)

// localDeficits lists the scopes the local escrow cannot currently fund.
func (a *Admission) localDeficits(scopes []ScopeBound) []ScopeBound {
	a.mu.Lock()
	defer a.mu.Unlock()
	deficits := make([]ScopeBound, 0, len(scopes))
	for _, s := range scopes {
		e, ok := a.ledger[ledgerKey{s.Scope, s.Key, s.Period}]
		if !ok || e.granted-e.returned-e.spent-e.inflight < s.Bound {
			deficits = append(deficits, s)
		}
	}
	return deficits
}

// fitLocally consumes each scope's bound from the local escrow. It either
// fits every scope or none (a multi-scope request is reserved as a whole,
// mirroring the store's all-or-nothing Grant).
func (a *Admission) fitLocally(rsv *Reservation, scopes []ScopeBound) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fitLocked(rsv, scopes)
}

// fitLocked is fitLocally's core; the caller holds a.mu.
func (a *Admission) fitLocked(rsv *Reservation, scopes []ScopeBound) bool {
	now := a.now()
	for _, s := range scopes {
		e, ok := a.ledger[ledgerKey{s.Scope, s.Key, s.Period}]
		if !ok || e.granted-e.returned-e.spent-e.inflight < s.Bound {
			return false
		}
	}
	for _, s := range scopes {
		k := ledgerKey{s.Scope, s.Key, s.Period}
		e := a.ledger[k]
		e.inflight += s.Bound
		e.lastUse = now
		rsv.Scopes = append(rsv.Scopes, ScopeReserve{
			Scope: s.Scope, Key: s.Key, Period: s.Period, AllowanceID: e.allowanceID, Bound: s.Bound,
		})
	}
	rsv.reserved = true
	return true
}

// grantScopes asks the store for capacity on every requested scope. In
// enforce mode a refusal is a *Denial; in shadow it is a nil-grant miss.
func (a *Admission) grantScopes(ctx context.Context, plan *Plan, scopes []ScopeBound) ([]ScopeGrant, error) {
	reqs := make([]GrantRequest, 0, len(scopes))
	a.mu.Lock()
	for _, s := range scopes {
		st := a.spendRate[ledgerKey{s.Scope, s.Key, s.Period}]
		reqs = append(reqs, GrantRequest{
			Scope: s.Scope, Key: s.Key, Period: s.Period,
			Bound:         s.Bound,
			RatePerSecond: st.ratePerSecond,
			AvgBound:      st.avgBound,
		})
	}
	a.mu.Unlock()

	start := time.Now()
	grants, err := a.store.Grant(ctx, a.replicaID, plan.OrgID, reqs)
	metrics.BudgetGrantDurationSeconds.Observe(time.Since(start).Seconds())
	if err == nil {
		for _, g := range grants {
			metrics.BudgetGrantsTotal.WithLabelValues(string(g.Scope), GrantResultGranted).Inc()
		}
		return grants, nil
	}
	shadowDeny := func(scope ScopeKind, err error) {
		a.log.Warn("reservation grant refused; serving unreserved",
			"mode", string(plan.Mode), "scope", string(scope), "org", plan.OrgID, "error", err)
		plan.WouldDeny = append(plan.WouldDeny, &Denial{Scope: scope, Err: err})
	}
	switch {
	case errors.Is(err, ErrInsufficientCapacity):
		metrics.BudgetGrantsTotal.WithLabelValues(string(refusalScope(reqs)), GrantResultInsufficient).Inc()
		a.markExhausted(scopes)
		if plan.Mode == ModeEnforce {
			return nil, &Denial{Scope: refusalScope(reqs), Err: err}
		}
		shadowDeny(refusalScope(reqs), err)
		return nil, nil
	case errors.Is(err, ErrNoCapacitySource):
		// D14 fail-closed: a hard scope without its capacity row denies.
		metrics.BudgetGrantsTotal.WithLabelValues(string(refusalScope(reqs)), GrantResultNoSource).Inc()
		if plan.Mode == ModeEnforce {
			return nil, &Denial{Scope: refusalScope(reqs), Err: err}
		}
		shadowDeny(refusalScope(reqs), err)
		return nil, nil
	default:
		// Store outage: enforce fails closed (deny), shadow serves
		// unreserved — accounting resumes when the store recovers.
		metrics.BudgetGrantsTotal.WithLabelValues(string(refusalScope(reqs)), GrantResultError).Inc()
		if plan.Mode == ModeEnforce {
			return nil, &Denial{Scope: ScopeWallet, Err: fmt.Errorf("reservation store unavailable: %w", err)}
		}
		a.log.Warn("reservation grant failed; serving unreserved", "error", err, "org", plan.OrgID)
		return nil, nil
	}
}

// refusalScope names the lowest-order requested scope a multi-scope grant
// refusal may belong to (wallet first — the canonical lock order).
func refusalScope(reqs []GrantRequest) ScopeKind {
	for _, r := range reqs {
		if r.Scope == ScopeWallet {
			return ScopeWallet
		}
	}
	if len(reqs) > 0 {
		return reqs[0].Scope
	}
	return ScopeWallet
}

// applyGrantsAndFit records successful grants in the local ledger and
// re-fits the request under ONE hold of the admission lock. The local
// escrow free is a contended pool: if the grant landed and the fit ran in
// two separate critical sections, a concurrent Reserve's fitLocally could
// lawfully consume the freshly granted surplus in between, shorting this
// caller's re-fit and producing a spurious fail-closed denial against a
// wallet that still has real capacity. The store serializes money writers
// per org (pg_advisory_xact_lock); the local grant-apply + fit section is
// serialized the same way. All-or-none on fit failure: rsv is untouched.
// An allowance row reconcile released during a renewal outage starts a
// fresh slice: the grant already re-activated the row and grew
// granted_micro_usd, and the local entry restarts from the new cumulative
// grant.
func (a *Admission) applyGrantsAndFit(rsv *Reservation, orgID string, grants []ScopeGrant, scopes []ScopeBound) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.applyGrantsLocked(orgID, grants)
	return a.fitLocked(rsv, scopes)
}

// applyGrants records successful grants in the local ledger (test and
// seeding helper; Reserve's own path is applyGrantsAndFit).
func (a *Admission) applyGrants(orgID string, grants []ScopeGrant) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.applyGrantsLocked(orgID, grants)
}

// applyGrantsLocked is the grant-apply core; the caller holds a.mu.
func (a *Admission) applyGrantsLocked(orgID string, grants []ScopeGrant) {
	now := a.now()
	for _, g := range grants {
		k := ledgerKey{g.Scope, g.Key, g.Period}
		e, ok := a.ledger[k]
		if !ok || e.allowanceID != g.AllowanceID {
			e = &ledgerEntry{orgID: orgID, allowanceID: g.AllowanceID, lastUse: now}
			a.ledger[k] = e
		}
		e.granted += g.Delta
		e.lastUse = now
		delete(a.exhausted, k)
		delete(a.probes, k)
	}
}

// Finalize settles one finished request against the local escrow (§5.3
// Finalize): in-flight bounds release, actual spend accumulates capped by
// each tuple's bound. walletActual is the resale µUSD the worker will
// charge, budgetActual the base µUSD — both derived from the same event
// fields, so the local ledger and the settle-side decrement stay in step.
// The event tuples (r.TuplesJSON) are attached by the caller.
func (a *Admission) Finalize(r *Reservation, walletActual, budgetActual money.MicroUSD) {
	if a == nil || r == nil || !r.reserved || len(r.Scopes) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	elapsed := now.Sub(r.created)
	if elapsed < time.Second {
		elapsed = time.Second
	}
	for _, s := range r.Scopes {
		k := ledgerKey{s.Scope, s.Key, s.Period}
		e, ok := a.ledger[k]
		if !ok {
			continue
		}
		actual := budgetActual
		if s.Scope == ScopeWallet {
			actual = walletActual
		}
		if actual > s.Bound {
			// §4.2: (actual − bound)+ is the estimation error — the only
			// legitimate source of overspend, measured for the D17 gate.
			metrics.BudgetBoundViolationTotal.WithLabelValues(string(s.Scope)).Inc()
			metrics.BudgetBoundOvershootMicroUSDTotal.WithLabelValues(string(s.Scope)).
				Add(float64(int64(actual - s.Bound)))
		}
		consumed := actual
		if consumed > s.Bound {
			consumed = s.Bound
		}
		e.inflight -= s.Bound
		if e.inflight < 0 {
			e.inflight = 0
		}
		e.spent += consumed
		e.lastUse = now
		a.updateRate(k, consumed, s.Bound, elapsed)
	}
}

// updateRate maintains the escrow-sizing inputs (§5.3): a damped spend rate
// and rolling average bound per scope.
func (a *Admission) updateRate(k ledgerKey, consumed, bound money.MicroUSD, elapsed time.Duration) {
	if consumed > money.MicroUSD(math.MaxInt64/int64(time.Second)) {
		return // overflow guard: keep the previous estimate
	}
	perSecond := int64(consumed) * int64(time.Second) / int64(elapsed)
	st, ok := a.spendRate[k]
	if !ok {
		a.spendRate[k] = rateStat{ratePerSecond: money.MicroUSD(perSecond), avgBound: bound}
		return
	}
	st.ratePerSecond = money.MicroUSD((int64(st.ratePerSecond)*3 + perSecond) / 4)
	st.avgBound = money.MicroUSD((int64(st.avgBound)*3 + int64(bound)) / 4)
	a.spendRate[k] = st
}

// LocalEscrow reports the replica's total unreturned, unspent, idle escrow
// across all scopes (observability/tests).
func (a *Admission) LocalEscrow() money.MicroUSD {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var total int64
	for _, e := range a.ledger {
		total += int64(e.granted - e.returned - e.spent - e.inflight)
	}
	return money.MicroUSD(total)
}

// ---------------------------------------------------------------------------
// ReservationStore extensions for the admission cycle (§5.3 Return with
// in-flight holdback, and the read-only pre-check probe).

// RemainingRequest returns one scope's unused remainder minus Holdback —
// the µUSD this replica still owes: the bounds of requests still in flight
// PLUS their finalized-but-unsettled spend, which the settlement worker
// will claim against the same tuples (§5.4).
type RemainingRequest struct {
	Scope    ScopeKind
	Key      string
	Period   string
	Holdback money.MicroUSD
}

// ReturnRemainingSummary reports one ReturnRemaining pass.
type ReturnRemainingSummary struct {
	ReturnedMicroUSD int64
}

// ReturnRemaining hands back each scope's unused escrow in ONE transaction
// per call: under the per-org advisory lock the remainder is computed as
// granted − returned − holdback. The holdback is the replica's full
// unsettled claim (in-flight bounds + finalized spend not yet settled), so
// a worker settling later can never underflow the scope reserve — and
// because the worker's settle decrements exactly the amounts the replica
// counted as spent, the remainder stays exact under the lock. Missing or
// released allowances are skipped; an over-held remainder returns nothing.
func (s *ReservationStore) ReturnRemaining(ctx context.Context, orgID, replicaID string, reqs []RemainingRequest) (ReturnRemainingSummary, error) {
	if orgID == "" || replicaID == "" {
		return ReturnRemainingSummary{}, fmt.Errorf("%w: org_id and replica_id are required", ErrInvalidRequest)
	}
	if len(reqs) == 0 {
		return ReturnRemainingSummary{}, nil
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return ReturnRemainingSummary{}, fmt.Errorf("return remaining begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return ReturnRemainingSummary{}, fmt.Errorf("return remaining advisory lock: %w", err)
	}

	var summary ReturnRemainingSummary
	for _, req := range reqs {
		if req.Holdback < 0 {
			return ReturnRemainingSummary{}, fmt.Errorf("%w: negative holdback %d", ErrInvalidRequest, req.Holdback)
		}
		returned, err := s.returnRemainingScope(ctx, tx, orgID, replicaID, req)
		if err != nil {
			return ReturnRemainingSummary{}, err
		}
		summary.ReturnedMicroUSD += returned
	}
	if err := tx.Commit(ctx); err != nil {
		return ReturnRemainingSummary{}, fmt.Errorf("return remaining commit: %w", err)
	}
	return summary, nil
}

// returnRemainingScope returns one scope's remainder inside the caller's
// transaction; returns the amount returned (0 when nothing was due).
func (s *ReservationStore) returnRemainingScope(ctx context.Context, tx pgx.Tx, orgID, replicaID string, req RemainingRequest) (int64, error) {
	if req.Holdback < 0 {
		return 0, fmt.Errorf("%w: negative holdback %d", ErrInvalidRequest, req.Holdback)
	}
	var id int64
	var granted, returned int64
	var status string
	err := tx.QueryRow(ctx, `
		SELECT id, granted_micro_usd, returned_micro_usd, status FROM budget_allowances
		WHERE replica_id = $1 AND scope_kind = $2 AND scope_key = $3 AND period = $4
		FOR UPDATE`,
		replicaID, string(req.Scope), req.Key, req.Period).Scan(&id, &granted, &returned, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil // nothing outstanding for this slice
	}
	if err != nil {
		return 0, fmt.Errorf("return remaining allowance read: %w", err)
	}
	if status == AllowanceReleased {
		return 0, nil // reconcile already released; nothing to hand back
	}
	remainder := granted - returned - int64(req.Holdback)
	if remainder <= 0 {
		return 0, nil
	}
	if err := decrementScopeReserve(ctx, tx, orgID, req.Scope, req.Key, req.Period, remainder); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE budget_allowances SET returned_micro_usd = returned_micro_usd + $2, updated_at = now()
		WHERE id = $1`, id, remainder); err != nil {
		return 0, fmt.Errorf("return remaining allowance update: %w", err)
	}
	return remainder, nil
}

// ProbeFreeCapacity reads a scope's current free capacity WITHOUT locking
// rows or creating period rows — the pre-check's stale-tolerant view (§5.1
// state cache). Advisory scopes (soft team budgets, I6) report MaxInt64.
// A missing capacity row is ErrNoCapacitySource; the caller treats a probe
// failure as "unknown, let the grant decide".
func (s *ReservationStore) ProbeFreeCapacity(ctx context.Context, orgID string, req GrantRequest) (money.MicroUSD, error) {
	switch req.Scope {
	case ScopeWallet:
		var balanceCents, remainder, reserved int64
		var floor *int64
		err := s.db.QueryRow(ctx,
			`SELECT balance_cents, remainder_micro_usd, grace_floor_cents, reserved_micro_usd
			 FROM org_credits WHERE org_id = $1`,
			orgID).Scan(&balanceCents, &remainder, &floor, &reserved)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("%w: no wallet for org", ErrNoCapacitySource)
		}
		if err != nil {
			return 0, fmt.Errorf("probe wallet read: %w", err)
		}
		floorCents := s.cfg.DefaultGraceFloorCents
		if floor != nil {
			floorCents = *floor
		}
		balanceMicro, err := centsToMicro(balanceCents)
		if err != nil {
			return 0, fmt.Errorf("probe wallet capacity: %w", err)
		}
		floorMicro, err := centsToMicro(floorCents)
		if err != nil {
			return 0, fmt.Errorf("probe wallet floor: %w", err)
		}
		return money.MicroUSD(balanceMicro - remainder - floorMicro - reserved), nil

	case ScopeTeamMonth:
		var limitMicro int64
		var hardLimit bool
		err := s.db.QueryRow(ctx,
			`SELECT (monthly_limit_usd * 1000000)::bigint, hard_limit
			 FROM team_budgets WHERE team_id = $1::uuid`,
			req.Key).Scan(&limitMicro, &hardLimit)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("%w: no team budget for %s", ErrNoCapacitySource, req.Key)
		}
		if err != nil {
			return 0, fmt.Errorf("probe team read: %w", err)
		}
		if !hardLimit {
			return money.MicroUSD(math.MaxInt64), nil // advisory scope (I6)
		}
		var spendMicro, reserved int64
		if err := s.db.QueryRow(ctx,
			`SELECT spend_micro_usd, reserved_micro_usd FROM team_spend_monthly
			 WHERE team_id = $1::uuid AND period = $2`,
			req.Key, req.Period).Scan(&spendMicro, &reserved); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return money.MicroUSD(limitMicro), nil // no period spend yet
			}
			return 0, fmt.Errorf("probe team period read: %w", err)
		}
		return money.MicroUSD(limitMicro - spendMicro - reserved), nil

	case ScopeAgentDay:
		var limitCents int64
		err := s.db.QueryRow(ctx,
			`SELECT daily_limit_cents FROM agent_budgets WHERE agent_id = $1::uuid`,
			req.Key).Scan(&limitCents)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("%w: no agent budget for %s", ErrNoCapacitySource, req.Key)
		}
		if err != nil {
			return 0, fmt.Errorf("probe agent read: %w", err)
		}
		limitMicro, err := centsToMicro(limitCents)
		if err != nil {
			return 0, fmt.Errorf("probe agent capacity: %w", err)
		}
		var costMicro, reserved int64
		if err := s.db.QueryRow(ctx,
			`SELECT cost_micro_usd, reserved_micro_usd FROM agent_spend_daily
			 WHERE agent_id = $1::uuid AND day = $2::date`,
			req.Key, req.Period).Scan(&costMicro, &reserved); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				costMicro, reserved = 0, 0 // no day spend yet
			} else {
				return 0, fmt.Errorf("probe agent day read: %w", err)
			}
		}
		ownFree := limitMicro - costMicro - reserved
		// AUDIT-P1-03: mirror of the grant-side bound (same helper, same
		// queries) — a delegated child is additionally bounded by its
		// parent's remaining subtree headroom; the probe must agree with
		// the grant or replicas would preflight capacity they can keep.
		parentFree, hasParent, err := agentAncestorFreeMicro(ctx, s.db, req.Key, req.Period)
		if err != nil {
			return 0, err
		}
		if hasParent && parentFree < ownFree {
			return money.MicroUSD(parentFree), nil
		}
		return money.MicroUSD(ownFree), nil

	case ScopeSession:
		var limitMicro *int64
		err := s.db.QueryRow(ctx,
			`SELECT (max_cost_usd * 1000000)::bigint FROM session_keys WHERE id = $1::uuid`,
			req.Key).Scan(&limitMicro)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("%w: no session key %s", ErrNoCapacitySource, req.Key)
		}
		if err != nil {
			return 0, fmt.Errorf("probe session read: %w", err)
		}
		if limitMicro == nil {
			return 0, fmt.Errorf("%w: session key %s has no max_cost_usd", ErrNoCapacitySource, req.Key)
		}
		var spentMicro, reserved int64
		if err := s.db.QueryRow(ctx,
			`SELECT spent_micro_usd, reserved_micro_usd FROM session_spend
			 WHERE session_key_id = $1::uuid`,
			req.Key).Scan(&spentMicro, &reserved); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return money.MicroUSD(*limitMicro), nil // no spend yet
			}
			return 0, fmt.Errorf("probe session spend read: %w", err)
		}
		return money.MicroUSD(*limitMicro - spentMicro - reserved), nil

	default:
		return 0, fmt.Errorf("%w: unknown scope kind %q", ErrInvalidRequest, req.Scope)
	}
}
