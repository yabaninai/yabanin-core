package cli

import (
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// G3: per-task and per-session token budgets. In-memory, TTL-bounded, default
// OFF (0 = disabled for that scope). Modeled on router.SessionAffinity: the
// same injectable-now, evict-oldest-half-on-overflow shape, but the value is a
// cumulative token total rather than a sticky model. Losing it only costs
// budget accounting, never correctness.
//
// Semantics:
//   - Check(scope, id) before forwarding: ok → proceed (with an 80% warning
//     header when near the cap); exceeded → 429 structured error.
//   - Record(scope, id, tokens) after the response using the FINAL usage, on
//     both the chat and stream surfaces.
//   - 0 cap = the scope is off (never enforced).
//
// NEXT-02 scope note: this is a TENANT-NAMESPACE fix (identical client ids
// across orgs no longer share a counter). It is NOT a durable reservation
// and NOT a hard spend-cap guarantee: the check-then-record window, restart
// and eviction semantics are unchanged; durable reserve/settle semantics
// are a separate decision (see the roadmap's budget ADR).

// TokenBudgetScope is the budget dimension: "task" or "session".
type TokenBudgetScope string

const (
	// TaskBudgetScope budgets by X-Yabanin-Task.
	TaskBudgetScope TokenBudgetScope = "task"
	// SessionBudgetScope budgets by X-Session-Id.
	SessionBudgetScope TokenBudgetScope = "session"
)

// budgetCheck is the result of Check.
type budgetCheck struct {
	// Exceeded is true when the budget is on and the running total already
	// meets/exceeds the cap.
	Exceeded bool
	// Warn is true when the budget is on and the running total is at or above
	// 80% of the cap (below the cap itself).
	Warn bool
}

// ErrTokenBudgetExceeded is returned by Check when the budget cap is reached.
var ErrTokenBudgetExceeded = errors.New("token budget exceeded")

// budgetEntry is one scope/id's running token total.
type budgetEntry struct {
	tokens   int64
	lastSeen time.Time
}

// budgetKey namespaces a client-visible budget id (task or session) by the
// AUTHENTICATED org. A struct, never a concatenation: "org"+"a:b" and
// "org:a"+"b" must stay distinct. The empty org is its own namespace for
// auth modes without an org identity (documented in NEXT-02).
type budgetKey struct {
	org string
	id  string
}

// TokenBudget enforces cumulative token caps per task and per session,
// namespaced by the authenticated org (NEXT-02/F02): identical client ids
// from different orgs are independent budgets.
type TokenBudget struct {
	mu       sync.RWMutex
	task     map[budgetKey]budgetEntry
	session  map[budgetKey]budgetEntry
	ttl      time.Duration
	maxPer   int
	taskCap  int64 // 0 = off
	sessCap  int64 // 0 = off
	warnFrac float64
	now      func() time.Time
}

// NewTokenBudget builds a TokenBudget. taskCap/sessionCap are token caps
// (0 = that scope is off). ttl defaults to 24h; maxPer defaults to 10000
// entries per scope.
func NewTokenBudget(taskCap, sessionCap int64, ttl time.Duration) *TokenBudget {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &TokenBudget{
		task:     make(map[budgetKey]budgetEntry),
		session:  make(map[budgetKey]budgetEntry),
		ttl:      ttl,
		maxPer:   10000,
		taskCap:  taskCap,
		sessCap:  sessionCap,
		warnFrac: 0.8,
		now:      time.Now,
	}
}

func (b *TokenBudget) table(scope TokenBudgetScope) map[budgetKey]budgetEntry {
	if scope == TaskBudgetScope {
		return b.task
	}
	return b.session
}

func (b *TokenBudget) capFor(scope TokenBudgetScope) int64 {
	if scope == TaskBudgetScope {
		return b.taskCap
	}
	return b.sessCap
}

// Check returns the budget state for an org-scoped id without mutating.
// When the cap is 0 (off) it returns an ok, no-warn result. org comes from
// the authenticated identity (X-Org-Id as set by the auth middleware), not
// from a client-supplied value.
func (b *TokenBudget) Check(scope TokenBudgetScope, org, id string) budgetCheck {
	cap := b.capFor(scope)
	if cap <= 0 || id == "" {
		return budgetCheck{}
	}
	key := budgetKey{org: org, id: id}
	now := b.now()
	b.mu.RLock()
	e, ok := b.table(scope)[key]
	b.mu.RUnlock()
	if !ok {
		return budgetCheck{}
	}
	if now.Sub(e.lastSeen) > b.ttl {
		b.mu.Lock()
		if cur, still := b.table(scope)[key]; still && now.Sub(cur.lastSeen) > b.ttl {
			delete(b.table(scope), key)
		}
		b.mu.Unlock()
		return budgetCheck{}
	}
	if e.tokens >= cap {
		return budgetCheck{Exceeded: true}
	}
	if float64(e.tokens) >= b.warnFrac*float64(cap) {
		return budgetCheck{Warn: true}
	}
	return budgetCheck{}
}

// Record adds tokens to an org-scoped id's running total. A cap of 0 (off)
// is a no-op so unconfigured deployments never build unbounded state.
func (b *TokenBudget) Record(scope TokenBudgetScope, org, id string, tokens int64) {
	cap := b.capFor(scope)
	if cap <= 0 || id == "" || tokens <= 0 {
		return
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	tbl := b.table(scope)
	if len(tbl) >= b.maxPer {
		b.evictLocked(tbl, now)
	}
	key := budgetKey{org: org, id: id}
	e := tbl[key]
	e.tokens += tokens
	e.lastSeen = now
	tbl[key] = e
}

// evictLocked removes the oldest half of a scope's entries. Caller holds the
// write lock.
func (b *TokenBudget) evictLocked(tbl map[budgetKey]budgetEntry, now time.Time) {
	type kv struct {
		key      budgetKey
		lastSeen time.Time
	}
	items := make([]kv, 0, len(tbl))
	for key, e := range tbl {
		items = append(items, kv{key: key, lastSeen: e.lastSeen})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].lastSeen.Before(items[j].lastSeen) })
	remove := len(items) / 2
	for i := 0; i < remove; i++ {
		delete(tbl, items[i].key)
	}
}

// checkTokenBudget enforces the task and session token budgets for a request.
// For the session scope it always runs (a session may be budgeted even when the
// task header is absent). For the task scope it runs only when a task id is
// present (an untagged request has no task dimension). On a 429 it writes the
// structured response and returns false. It sets
// X-Yabanin-Budget-Warning when any checked budget is at/near its cap.
// orgID is the AUTHENTICATED org (X-Org-Id as set by the auth middleware
// from the resolved key; the middleware strips any client-supplied copy).
// It namespaces the budget so identical client ids across orgs never share
// a counter (NEXT-02/F02). Empty org keeps its own namespace.
func (gw *gateway) checkTokenBudget(w http.ResponseWriter, r *http.Request, orgID, taskID, sessionID string) bool {
	if gw.tokenBudget == nil {
		return true
	}
	var anyWarn bool
	for _, sc := range []struct {
		scope TokenBudgetScope
		id    string
	}{
		{TaskBudgetScope, taskID},
		{SessionBudgetScope, sessionID},
	} {
		if sc.id == "" {
			continue
		}
		res := gw.tokenBudget.Check(sc.scope, orgID, sc.id)
		if res.Exceeded {
			gw.recordTokenBudget(sc.scope, "exceeded")
			w.Header().Set("Retry-After", "60")
			apierrors.Write(w, http.StatusTooManyRequests, "token_budget_exceeded",
				"per-"+string(sc.scope)+" token budget exceeded — retry later")
			return false
		}
		if res.Warn {
			anyWarn = true
			gw.recordTokenBudget(sc.scope, "warn")
		} else {
			gw.recordTokenBudget(sc.scope, "ok")
		}
	}
	if anyWarn {
		w.Header().Set("X-Yabanin-Budget-Warning", "token budget at or above 80%")
	}
	return true
}

// recordTokenBudget increments the G3 metric for a scope/outcome.
func (gw *gateway) recordTokenBudget(scope TokenBudgetScope, outcome string) {
	metrics.TokenBudgetTotal.WithLabelValues(string(scope), outcome).Inc()
}

// recordTokenBudgetSpend records the final token usage against the budgets on
// both surfaces (chat + stream). tokens is the sum of prompt + completion.
// orgID namespaces the counters (see checkTokenBudget).
func (gw *gateway) recordTokenBudgetSpend(orgID, taskID, sessionID string, tokens int64) {
	if gw.tokenBudget == nil {
		return
	}
	if taskID != "" {
		gw.tokenBudget.Record(TaskBudgetScope, orgID, taskID, tokens)
	}
	if sessionID != "" {
		gw.tokenBudget.Record(SessionBudgetScope, orgID, sessionID, tokens)
	}
}
