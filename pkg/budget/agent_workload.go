package budget

// N06-P07-T04: the workload chargeback dimension. A workload is the unit an
// operator attributes model spend to — a CI job, a service, an agent fleet —
// carried on requests as X-Yabanin-Workload or derived from the identity the
// request already carries. The dimension is deliberately NOT a SaaS billing
// subsystem: attribution rides the settle events' labels (the consumer's
// labels JSONB and its rollups are the durable chargeback record), and this
// file only owns the identity rules plus an opt-in in-memory spend cap with
// the same per-replica, fail-safe shape as the G3 token budgets.

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/money"
)

// ErrWorkloadBudgetExceeded is returned by WorkloadLedger.Admit when a
// workload's windowed spend would pass its configured cap. Callers must
// treat it as fail-closed: the request (or internal hop) does not run.
var ErrWorkloadBudgetExceeded = errors.New("workload budget exceeded")

// workloadKeyPattern is the workload key shape: the same charset and bound
// as the task tag (TaskHeaderPattern) so operators can share one naming
// scheme across both identity headers.
var workloadKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// ValidWorkloadKey reports whether s is a well-formed explicit workload key
// (X-Yabanin-Workload). An empty string is NOT valid as an explicit key —
// callers distinguish "absent" (derive) from "present but malformed" (400).
func ValidWorkloadKey(s string) bool {
	return workloadKeyPattern.MatchString(s)
}

// DeriveWorkloadKey resolves a request's workload identity. An explicit,
// well-formed key always wins; otherwise the key is derived from the
// identity the request already carries, so every request is attributable —
// a batch line synthesized with only X-Yabanin-Task derives task:<id> and
// cannot bypass the dimension. Precedence:
//
//  1. explicit (verbatim — callers validate with ValidWorkloadKey first)
//  2. agent:<agentID>
//  3. team:<teamID>.task:<taskID>
//  4. task:<taskID>
//  5. "" — unattributable; admission allows without tracking (the same
//     allow-on-missing-identity shape the loop budget and the agent
//     enforcer use)
//
// Candidates that do not satisfy ValidWorkloadKey (a caller-supplied agent
// or team id outside the shared charset) are skipped, never truncated.
//
// Namespace note: the composite form team:<teamID>.task:<taskID> is NOT
// injective when a component contains '.' — team "a" + task "b.c" and team
// "a.b" + task "c" both derive "team:a.b.task:b.c" and would share one
// attribution window. That is benign for chargeback (two derivations merge
// into one label, they never cross orgs) and currently unreachable for
// auth-issued ids (UUID-shaped, dot-free), but the composite must not be
// mistaken for a lossless encoding of its parts.
func DeriveWorkloadKey(agentID, teamID, taskID, explicit string) string {
	if ValidWorkloadKey(explicit) {
		return explicit
	}
	if ValidWorkloadKey(agentID) {
		return "agent:" + agentID
	}
	if teamID != "" && ValidWorkloadKey(taskID) {
		candidate := "team:" + teamID + ".task:" + taskID
		if ValidWorkloadKey(candidate) {
			return candidate
		}
	}
	if ValidWorkloadKey(taskID) {
		return "task:" + taskID
	}
	return ""
}

// DefaultWorkloadTTL bounds how long a workload's window entry survives
// inactivity. The TTL is the leak guard: UTC-day windows roll by key
// rewrite, but workloads that stop sending traffic must not pin memory.
// One hour past the window keeps a day's entry alive through the day.
const DefaultWorkloadTTL = 25 * time.Hour

// DefaultWorkloadMaxKeys bounds how many distinct workload windows one
// ledger tracks (the same bound TokenBudget applies per scope). Keys are
// caller-controlled and unlimited in number, so an uncapped map would let a
// tenant cycling distinct names grow memory without bound; at this bound
// the ledger first drops TTL-expired entries, then evicts the
// least-recently-touched half — the same oldest-half LRU shape as
// TokenBudget's eviction. Eviction is lossy by design: it only degrades the
// per-replica cap approximation (a fresh window restarts at zero), never
// attribution (the settle events' labels are the durable record).
const DefaultWorkloadMaxKeys = 10000

// workloadKey namespaces a workload key by the AUTHENTICATED org. A struct,
// never a concatenation ("org"+"a:b" and "org:a"+"b" must stay distinct),
// mirroring the token budgets' budgetKey: workload names are client-chosen
// ("ci", "production"), so without the org component one tenant's charges
// could saturate another tenant's cap. The empty org is its own namespace
// for auth modes without an org identity.
type workloadKey struct {
	org string
	id  string
}

// workloadWindow is one workload's UTC-day spend accumulator.
type workloadWindow struct {
	day      string
	spent    money.MicroUSD
	lastSeen time.Time
}

// WorkloadLedger is the opt-in per-replica chargeback cap: windowed,
// money-denominated spend per (org, workload key), fail-closed at the cap.
// It is in-memory by design — the same per-replica accounting shape as the
// G3 token budgets — so losing it only costs the cap approximation, never
// attribution (the settle events' labels are the durable record). Windows
// are org-namespaced (NEXT-02/F02 precedent): identical workload names from
// different orgs never share a counter, so one tenant's charges can never
// saturate another tenant's window.
//
// A nil *WorkloadLedger, a non-positive cap, or an empty key disable the
// ledger: Admit always allows and Charge records nothing. Deploys opt in by
// wiring a positive cap. An enabled ledger never builds unbounded state:
// distinct keys are bounded by DefaultWorkloadMaxKeys via TTL sweep plus
// oldest-half eviction (see DefaultWorkloadMaxKeys); a bound that cannot
// make room for a new key (degenerate maxKeys <= 1) refuses it fail-closed
// instead of growing past the bound.
type WorkloadLedger struct {
	mu      sync.Mutex
	cap     money.MicroUSD
	ttl     time.Duration
	maxKeys int
	now     func() time.Time
	byKey   map[workloadKey]*workloadWindow
}

// NewWorkloadLedger builds the workload ledger. cap <= 0 disables it; ttl
// <= 0 selects DefaultWorkloadTTL. The key cardinality bound is fixed at
// DefaultWorkloadMaxKeys (the same default TokenBudget uses per scope).
func NewWorkloadLedger(cap money.MicroUSD, ttl time.Duration) *WorkloadLedger {
	if ttl <= 0 {
		ttl = DefaultWorkloadTTL
	}
	return &WorkloadLedger{
		cap:     cap,
		ttl:     ttl,
		maxKeys: DefaultWorkloadMaxKeys,
		now:     time.Now,
		byKey:   make(map[workloadKey]*workloadWindow),
	}
}

// NewWorkloadLedgerBounded is NewWorkloadLedger with an explicit key
// cardinality bound. It exists so deploy seams — and N06-P07-T07's
// fail-closed corpus — can exercise degenerate bounds from outside the
// package: maxKeys < 2 refuses every window after the first instead of
// evicting (the Admit refusal the default bound only reaches under real
// saturation). maxKeys <= 0 falls back to DefaultWorkloadMaxKeys.
func NewWorkloadLedgerBounded(cap money.MicroUSD, ttl time.Duration, maxKeys int) *WorkloadLedger {
	l := NewWorkloadLedger(cap, ttl)
	if maxKeys > 0 {
		l.maxKeys = maxKeys
	}
	return l
}

// Admit reports whether org's workload key may spend planned more this
// window. An empty key is unattributable and allows without tracking; a
// disabled ledger allows everything. The check is fail-closed: once the
// window's spend would reach or pass the cap, the request is refused — a
// workload whose charges filled its cap admits nothing further until the
// window rolls (admission projects planned, which is zero for traffic that
// only checks the cap). Admit is a point-in-time check, not a reservation —
// exact reservation semantics stay with the §5 controller — so concurrent
// admitted requests can overshoot the cap by their in-flight actuals before
// the next check observes them. org is the authenticated org (X-Org-Id as
// set by the auth middleware); the empty org keeps its own namespace.
func (l *WorkloadLedger) Admit(org, key string, planned money.MicroUSD) error {
	if l == nil || l.cap <= 0 || key == "" {
		return nil
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.windowLocked(workloadKey{org: org, id: key}, now)
	if w == nil {
		// N06-P07-T05 negative: the ledger's key bound cannot make room for
		// this new key (degenerate maxKeys <= 1 configuration) — refuse the
		// request instead of growing past the bound. Fail-closed, like every
		// other cap refusal.
		return fmt.Errorf("%w: workload ledger key bound reached (%d windows), refusing new key %q",
			ErrWorkloadBudgetExceeded, l.maxKeys, key)
	}
	if sum, err := w.spent.Add(planned); err != nil || sum >= l.cap {
		return fmt.Errorf("%w: workload %q spent %d of %d micro-USD this window",
			ErrWorkloadBudgetExceeded, key, int64(w.spent), int64(l.cap))
	}
	return nil
}

// Charge records actual settled spend against org's current window for key.
// It is best-effort bookkeeping for the cap: callers charge only quotes they
// would settle (positive or exactly zero, per the consumer's rule — unknown
// quotes contribute nothing). A disabled ledger or an empty key records
// nothing, and so does a NEW key refused at the ledger's key bound
// (degenerate maxKeys <= 1): the bounded-state guarantee wins, and the
// settle events' labels keep the durable attribution.
func (l *WorkloadLedger) Charge(org, key string, actual money.MicroUSD) {
	if l == nil || l.cap <= 0 || key == "" || actual < 0 {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.windowLocked(workloadKey{org: org, id: key}, now)
	if w == nil {
		return // refused at the key bound; see Admit
	}
	if sum, err := w.spent.Add(actual); err == nil {
		w.spent = sum
	} else {
		w.spent = money.MicroUSD(math.MaxInt64) // saturate, never wrap
	}
}

// Spent reports org's current window spend for key (0 for unknown,
// expired, rolled, or disabled). A pure read: it never creates entries and
// never builds state on a disabled ledger.
func (l *WorkloadLedger) Spent(org, key string) money.MicroUSD {
	if l == nil || l.cap <= 0 || key == "" {
		return 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.byKey[workloadKey{org: org, id: key}]
	if !ok {
		return 0
	}
	// Mirror what a fresh window would report: an entry on a past UTC day
	// (day roll) or idle past the TTL is spent out — same-day TTL expiry
	// included, matching the sweep-then-recreate behavior of Admit/Charge.
	if w.day != now.UTC().Format("2006-01-02") || now.Sub(w.lastSeen) > l.ttl {
		return 0
	}
	return w.spent
}

// windowLocked returns the workload key's UTC-day window, rolling it
// forward in place when the day changed or the entry idled past the TTL
// (equivalent to sweep-then-recreate, without the map churn). On a new key
// it enforces the cardinality bound: at maxKeys distinct entries the ledger
// first sweeps TTL-expired windows, then evicts the least-recently-touched
// half before inserting. It returns nil when the bound still cannot make
// room (only maxKeys <= 1 can reach that state: half-eviction has nothing
// to remove) — a NEW key is then refused, never inserted; existing keys are
// unaffected. Caller holds l.mu.
func (l *WorkloadLedger) windowLocked(key workloadKey, now time.Time) *workloadWindow {
	day := now.UTC().Format("2006-01-02")
	w, ok := l.byKey[key]
	if !ok {
		if l.maxKeys > 0 && len(l.byKey) >= l.maxKeys {
			l.sweepLocked(now)
			if len(l.byKey) >= l.maxKeys {
				l.evictLocked(now)
				if len(l.byKey) >= l.maxKeys {
					return nil // fail closed rather than grow past the bound
				}
			}
		}
		w = &workloadWindow{day: day, lastSeen: now}
		l.byKey[key] = w
		return w
	}
	if w.day != day || now.Sub(w.lastSeen) > l.ttl {
		w.day = day
		w.spent = 0
	}
	w.lastSeen = now
	return w
}

// sweepLocked prunes entries idle past the TTL. Caller holds l.mu.
func (l *WorkloadLedger) sweepLocked(now time.Time) {
	for k, w := range l.byKey {
		if now.Sub(w.lastSeen) > l.ttl {
			delete(l.byKey, k)
		}
	}
}

// evictLocked removes the oldest half of the ledger's entries, keyed on
// last access — the same bounded-eviction shape as TokenBudget.evictLocked
// ("unconfigured deployments never build unbounded state"; here: a capped
// ledger never builds unbounded key cardinality). Eviction only costs the
// cap approximation, never attribution. Caller holds l.mu.
func (l *WorkloadLedger) evictLocked(now time.Time) {
	type kv struct {
		key      workloadKey
		lastSeen time.Time
	}
	items := make([]kv, 0, len(l.byKey))
	for key, w := range l.byKey {
		items = append(items, kv{key: key, lastSeen: w.lastSeen})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].lastSeen.Before(items[j].lastSeen) })
	remove := len(items) / 2
	for i := 0; i < remove; i++ {
		delete(l.byKey, items[i].key)
	}
}
