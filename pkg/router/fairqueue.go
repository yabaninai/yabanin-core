// Package router — fair admission for tenant isolation under upstream
// saturation.
//
// FairAdmission bounds concurrent in-flight requests per tenant key
// (authenticated org + derived workload) and, on saturation, queues excess
// requests in bounded per-tenant queues granted in FIFO scan order across
// tenants. The per-tenant bound is the isolation guarantee: a noisy tenant
// can never hold more than its own share of slots, so other tenants keep
// making progress while the noisy tenant's excess waits or is shed.
package router

import (
	"container/list"
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// fairShedRandom supplies the draw behind shed-hint jitter. It is a package
// variable so tests can inject a deterministic sequence; production code
// never reassigns it. math/rand (not crypto/rand) is the right source: the
// value spaces client retries, it never protects anything.
var fairShedRandom = rand.Float64

// FairShedReason classifies why fair admission refused a request.
type FairShedReason string

const (
	// ShedCapacity is set when the global in-flight bound is exhausted
	// and the tenant still had queue headroom (queueing disabled).
	ShedCapacity FairShedReason = "capacity"
	// ShedTenantLimit is set when the tenant already holds its per-tenant
	// bound of in-flight slots and queueing is disabled.
	ShedTenantLimit FairShedReason = "tenant_limit"
	// ShedQueueFull is set when the tenant's bounded wait queue is full.
	ShedQueueFull FairShedReason = "queue_full"
	// ShedQueueWait is set when the request waited in queue past the
	// configured WaitTimeout.
	ShedQueueWait FairShedReason = "queue_timeout"
)

// FairShedError describes a request refused by fair admission. Callers map
// it to a 429-class response; RetryAfter, when positive, is the backpressure
// hint for the response's Retry-After header so client retry loops back off
// instead of re-hammering a saturated upstream.
type FairShedError struct {
	Tenant     string         // composed tenant key (see FairTenantKey)
	Reason     FairShedReason // which bound refused the request
	RetryAfter time.Duration  // backpressure hint; 0 = no hint configured
}

// Error implements error.
func (e *FairShedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("fair admission shed request (tenant %q, reason %s, retry after %s)",
			e.Tenant, e.Reason, e.RetryAfter)
	}
	return fmt.Sprintf("fair admission shed request (tenant %q, reason %s)", e.Tenant, e.Reason)
}

// FairAdmissionConfig configures a FairAdmission controller.
type FairAdmissionConfig struct {
	// Capacity is the global bound on concurrently admitted requests.
	// Values <= 0 disable the controller entirely: Admit fails open and
	// every ticket is a no-op, so a misconfiguration can never become a
	// self-inflicted outage.
	Capacity int
	// MaxPerTenant bounds how many slots one tenant may hold at once.
	// It is the isolation bound: with MaxPerTenant < Capacity, a noisy
	// tenant cannot occupy more than its share and other tenants always
	// have headroom. Values <= 0 mean "no per-tenant bound beyond
	// Capacity" (no isolation).
	MaxPerTenant int
	// QueueLimit bounds how many requests one tenant may keep waiting in
	// its queue while saturated. 0 disables waiting entirely: saturated
	// requests are shed immediately (no added request latency).
	QueueLimit int
	// WaitTimeout caps how long a request may sit in queue. Values <= 0
	// let a queued request wait until it is granted or its context ends.
	WaitTimeout time.Duration
	// ShedRetryAfter is the backpressure hint carried by every
	// FairShedError this controller produces. 0 disables the hint.
	ShedRetryAfter time.Duration
	// ShedJitter is the extra spread added to every shed hint as a fraction
	// of ShedRetryAfter, in [0, 1]. 0 keeps hints exact: every shed client
	// then retries at the same instant and the shed wave re-strikes the
	// saturated upstream in lockstep. With j > 0 each hint is widened
	// upward to [base, base×(1+j)) so retries spread across the window
	// while no client is sent earlier than the base backpressure.
	ShedJitter float64
	// MaxTenants bounds the tracked-tenant table. Idle tenants are
	// evicted least-recently-used first; tenants holding in-flight or
	// queued load are never evicted, so the table can transiently exceed
	// the bound only while that many tenants are concurrently active.
	// Values <= 0 fall back to DefaultFairMaxTenants.
	MaxTenants int
}

// DefaultFairMaxTenants bounds the tracked-tenant table when the config
// leaves MaxTenants unset.
const DefaultFairMaxTenants = 1024

// DefaultFairAdmissionConfig returns a config with conservative defaults:
// a quarter of the capacity per tenant at most, bounded queues with a wait
// deadline, and a 1s backpressure hint on shed responses, spread by 20%
// jitter so shed clients do not retry in lockstep.
func DefaultFairAdmissionConfig() FairAdmissionConfig {
	return FairAdmissionConfig{
		Capacity:       256,
		MaxPerTenant:   64,
		QueueLimit:     32,
		WaitTimeout:    2 * time.Second,
		ShedRetryAfter: time.Second,
		ShedJitter:     0.2,
		MaxTenants:     DefaultFairMaxTenants,
	}
}

// FairAdmission is a per-tenant fair admission controller. It bounds global
// and per-tenant in-flight concurrency, queues saturated requests in bounded
// per-tenant queues, and sheds with a backpressure hint when bounds are hit.
// The zero-value is not usable; build one with NewFairAdmission. A nil
// *FairAdmission (or Capacity <= 0) fails open in Admit.
//
// Every admitted request MUST call FairTicket.Release exactly once — a leak
// permanently consumes a slot, the same discipline as the budget escrow
// finalizer on every terminal path.
type FairAdmission struct {
	cfg       FairAdmissionConfig
	perTenant int // effective per-tenant slot bound; Capacity when unbounded

	mu       sync.Mutex
	free     int // free slots; Capacity - sum(inFlight)
	tenants  map[string]*fairTenantLoad
	order    *list.List // tenant recency, front = most recent
	queue    []*fairWaiter
	inFlight prometheus.Gauge
	queued   prometheus.Gauge
}

// fairTenantLoad tracks one tenant's live load. Never evicted while
// inFlight > 0 or queuedWaiters > 0.
type fairTenantLoad struct {
	key           string
	inFlight      int
	queuedWaiters int
	elem          *list.Element // recency element in FairAdmission.order
}

// fairWaiter is one request parked in the queue awaiting a slot.
type fairWaiter struct {
	tenant  *fairTenantLoad
	ready   chan struct{} // closed exactly once, on grant
	granted bool          // guarded by FairAdmission.mu
	// ctx is the waiter's request context, fixed at enqueue time and
	// immutable. The grant scan reads it (under FairAdmission.mu) to retire
	// waiters whose context ended before a slot could reach them.
	ctx context.Context
	// dropped records that the grant scan retired this waiter instead of
	// granting it: the queue place and counters were already settled by the
	// scan, so the waiter's own abandon path must not account again.
	// Guarded by FairAdmission.mu. A dropped waiter is never granted (ready
	// is only closed on grants), so it always wakes through its own
	// ctx.Done — Err() != nil guarantees Done is closed.
	dropped bool
}

var (
	fairDecisions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: "gateway",
			Name:      "fair_admission_decisions_total",
			Help:      "Fair admission outcomes by result: admitted, shed_capacity, shed_tenant_limit, shed_queue_full, shed_queue_timeout, canceled.",
		},
		[]string{"result"},
	)
	fairInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: "gateway",
			Name:      "fair_admission_in_flight",
			Help:      "Fair-admitted requests currently holding a slot.",
		},
	)
	fairQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: "gateway",
			Name:      "fair_admission_queue_depth",
			Help:      "Requests currently waiting in fair-admission queues.",
		},
	)
)

// NewFairAdmission builds a controller. cfg.Capacity <= 0 yields a disabled
// controller that fails open (see FairAdmissionConfig.Capacity).
func NewFairAdmission(cfg FairAdmissionConfig) *FairAdmission {
	fa := &FairAdmission{
		cfg:      cfg,
		tenants:  make(map[string]*fairTenantLoad),
		order:    list.New(),
		inFlight: fairInFlight,
		queued:   fairQueueDepth,
	}
	fa.perTenant = cfg.Capacity
	if cfg.MaxPerTenant > 0 && cfg.MaxPerTenant < fa.perTenant {
		fa.perTenant = cfg.MaxPerTenant
	}
	if cfg.Capacity > 0 {
		fa.free = cfg.Capacity
	}
	if fa.cfg.MaxTenants <= 0 {
		fa.cfg.MaxTenants = DefaultFairMaxTenants
	}
	return fa
}

// FairTicket proves one admitted in-flight slot. Release is idempotent and
// nil-safe so defer sites never need their own guards.
type FairTicket struct {
	fa     *FairAdmission
	tenant string
	once   sync.Once
}

// Release returns the slot to the controller and grants it to the next
// eligible waiter (FIFO scan order across tenants, skipping tenants already
// at their own bound).
func (t *FairTicket) Release() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		if t.fa != nil {
			t.fa.release(t.tenant)
		}
	})
}

// Admit admits one request for the tenant identified by orgID and
// workloadID (the identity pair admission already resolved). Outcomes:
//
//   - a slot under both the global and the tenant bound: admitted ticket;
//   - saturation with queue headroom and queueing enabled: the request
//     parks in the tenant's bounded queue until a slot is granted, the
//     context ends, or WaitTimeout elapses;
//   - otherwise: *FairShedError (shed immediately, no added latency).
//
// A nil controller or Capacity <= 0 admits unconditionally (fail open).
// ctx must be non-nil; cancellation while queued returns ctx.Err() and
// frees the queue place without consuming a slot. With the controller
// enabled, an already-ended context (canceled or past its deadline) is
// refused up front — a request that can never run must not consume a slot
// or a queue place even for an instant.
//
// Deadline coordination (N09-P02-T04): a queued wait is bounded by the
// first of the caller's context deadline and WaitTimeout, and a grant is
// never delivered to a waiter whose context has already ended — dead
// waiters are retired from the queue at grant time so the freed slot goes
// to the first live waiter (a noisy tenant's canceled queue storm cannot
// displace other tenants' grants, not even transiently).
func (fa *FairAdmission) Admit(ctx context.Context, orgID, workloadID string) (*FairTicket, error) {
	if fa == nil || fa.cfg.Capacity <= 0 {
		return &FairTicket{}, nil
	}
	if err := ctx.Err(); err != nil {
		// Dead on arrival: refuse before any accounting so the decision
		// ledger and slot counters only ever describe runnable requests.
		fairDecisions.WithLabelValues("canceled").Inc()
		return nil, err
	}

	key := FairTenantKey(orgID, workloadID)

	fa.mu.Lock()
	t := fa.tenantLocked(key)
	if fa.free > 0 && t.inFlight < fa.perTenant {
		fa.acquireLocked(t)
		fa.mu.Unlock()
		fairDecisions.WithLabelValues("admitted").Inc()
		return &FairTicket{fa: fa, tenant: key}, nil
	}

	shed := func(reason FairShedReason) (*FairTicket, error) {
		fa.mu.Unlock()
		fairDecisions.WithLabelValues("shed_" + string(reason)).Inc()
		return nil, &FairShedError{Tenant: key, Reason: reason, RetryAfter: fa.shedHint()}
	}
	if fa.cfg.QueueLimit <= 0 {
		if t.inFlight >= fa.perTenant {
			return shed(ShedTenantLimit)
		}
		return shed(ShedCapacity)
	}
	if t.queuedWaiters >= fa.cfg.QueueLimit {
		return shed(ShedQueueFull)
	}

	w := &fairWaiter{tenant: t, ready: make(chan struct{}), ctx: ctx}
	t.queuedWaiters++
	fa.queue = append(fa.queue, w)
	fa.queued.Set(float64(len(fa.queue)))
	fa.mu.Unlock()

	// waitDone is nil (blocks forever) unless a wait deadline is set, so a
	// single select covers the no-timeout and timeout cases.
	var waitDone <-chan struct{}
	if fa.cfg.WaitTimeout > 0 {
		tctx, cancel := context.WithTimeout(ctx, fa.cfg.WaitTimeout)
		defer cancel()
		waitDone = tctx.Done()
	}

	select {
	case <-w.ready:
		// Granted. A cancellation racing the grant must not leak the
		// slot: hand it straight back.
		if err := ctx.Err(); err != nil {
			fa.release(key)
			fairDecisions.WithLabelValues("canceled").Inc()
			return nil, err
		}
		fairDecisions.WithLabelValues("admitted").Inc()
		return &FairTicket{fa: fa, tenant: key}, nil

	case <-ctx.Done():
		return nil, fa.abandon(w, ctx.Err(), false)

	case <-waitDone:
		// A parent cancellation racing the internal deadline is reported
		// as the cancellation, not as a queue timeout.
		if err := ctx.Err(); err != nil {
			return nil, fa.abandon(w, err, false)
		}
		return nil, fa.abandon(w, nil, true)
	}
}

// abandon finalizes a queued request whose context ended or whose wait
// deadline elapsed. It returns the error to report: a FairShedError with
// ShedQueueWait when the controller's own deadline fired (with the
// backpressure hint), otherwise nil and the caller reports cause. If a grant
// raced the abandonment, the just-granted slot is released again so
// accounting stays exact. A waiter already retired by the grant scan (its
// context was dead when a slot freed) is left untouched: the scan settled
// the queue place and counters.
func (fa *FairAdmission) abandon(w *fairWaiter, cause error, timedOut bool) error {
	fa.mu.Lock()
	if w.dropped {
		fa.mu.Unlock()
		return cause
	}
	if w.granted {
		// The grant landed before we could leave the queue: we owned a
		// slot for an instant; return it.
		fa.mu.Unlock()
		fa.release(w.tenant.key)
		if timedOut {
			fairDecisions.WithLabelValues("shed_" + string(ShedQueueWait)).Inc()
			return &FairShedError{Tenant: w.tenant.key, Reason: ShedQueueWait, RetryAfter: fa.shedHint()}
		}
		fairDecisions.WithLabelValues("canceled").Inc()
		return cause
	}
	fa.removeWaiterLocked(w)
	fa.mu.Unlock()

	if timedOut {
		fairDecisions.WithLabelValues("shed_" + string(ShedQueueWait)).Inc()
		return &FairShedError{Tenant: w.tenant.key, Reason: ShedQueueWait, RetryAfter: fa.shedHint()}
	}
	fairDecisions.WithLabelValues("canceled").Inc()
	return cause
}

// shedHint returns the backpressure hint for one shed decision, widened by
// ShedJitter so simultaneous sheds spread their retries over
// [ShedRetryAfter, ShedRetryAfter×(1+ShedJitter)) instead of re-striking the
// saturated upstream in lockstep. Each shed draws independently.
func (fa *FairAdmission) shedHint() time.Duration {
	return jitterHint(fa.cfg.ShedRetryAfter, fa.cfg.ShedJitter, fairShedRandom)
}

// jitterHint widens a retry hint upward by a random fraction of itself so
// simultaneous refusals spread their retries over [base, base×(1+fraction))
// instead of striking at the same instant. fraction is clamped to [0, 1];
// base ≤ 0, fraction ≤ 0 or a missing draw leave the hint unchanged. The
// widening is upward-only by design: no caller may be sent earlier than the
// base backpressure guarantee.
func jitterHint(base time.Duration, fraction float64, draw func() float64) time.Duration {
	if base <= 0 || fraction <= 0 || draw == nil {
		return base
	}
	if fraction > 1 {
		fraction = 1
	}
	return base + time.Duration(draw()*fraction*float64(base))
}

// release returns one slot and grants it to the next eligible waiter.
func (fa *FairAdmission) release(tenant string) {
	fa.mu.Lock()
	fa.free++
	if t, ok := fa.tenants[tenant]; ok && t.inFlight > 0 {
		// The entry is present by construction (in-flight load pins it),
		// but never let a defensive miss corrupt global accounting.
		t.inFlight--
	}
	fa.inFlight.Set(float64(fa.cfg.Capacity - fa.free))
	fa.grantReadyLocked()
	fa.mu.Unlock()
}

// grantReadyLocked hands free slots to queued waiters. The scan walks the
// queue in arrival order but skips waiters whose own tenant is at its
// bound, so a noisy tenant's queued requests cannot starve other tenants:
// the slot goes past them to the first eligible waiter. Waiters whose
// context has already ended are retired in place instead of being granted:
// a dead request can never use the slot, and granting it would hand the
// slot to the dead waiter and give it back only after that waiter wakes —
// a canceled queue storm could then displace every other tenant's grant by
// one full wake cycle each.
func (fa *FairAdmission) grantReadyLocked() {
	for fa.free > 0 {
		advanced := false
		for i, w := range fa.queue {
			// Deadline/cancellation coordination: retire the dead waiter —
			// removed from the queue, its place and counters settled, one
			// canceled decision counted — then keep scanning for a live
			// grantee without consuming the slot.
			if w.ctx.Err() != nil {
				fa.queue = append(fa.queue[:i], fa.queue[i+1:]...)
				w.tenant.queuedWaiters--
				w.dropped = true
				fairDecisions.WithLabelValues("canceled").Inc()
				advanced = true
				break
			}
			if w.tenant.inFlight >= fa.perTenant {
				continue
			}
			fa.queue = append(fa.queue[:i], fa.queue[i+1:]...)
			w.granted = true
			w.tenant.queuedWaiters--
			w.tenant.inFlight++
			fa.free--
			close(w.ready)
			advanced = true
			break
		}
		if !advanced {
			break
		}
	}
	fa.queued.Set(float64(len(fa.queue)))
}

func (fa *FairAdmission) acquireLocked(t *fairTenantLoad) {
	t.inFlight++
	fa.free--
	fa.inFlight.Set(float64(fa.cfg.Capacity - fa.free))
	fa.touchLocked(t)
}

// tenantLocked returns the tenant's load entry, creating it if needed. New
// entries first evict idle tenants least-recently-used until the table is
// under MaxTenants; tenants holding live load are never evicted, so the
// table overshoots the bound only by the number of concurrently active
// tenants.
func (fa *FairAdmission) tenantLocked(key string) *fairTenantLoad {
	if t, ok := fa.tenants[key]; ok {
		return t
	}
	for len(fa.tenants) >= fa.cfg.MaxTenants {
		if !fa.evictIdleLocked() {
			break
		}
	}
	t := &fairTenantLoad{key: key}
	fa.tenants[key] = t
	t.elem = fa.order.PushFront(t)
	return t
}

// evictIdleLocked removes the least recently used tenant that holds no live
// load. It reports whether such a tenant was found.
func (fa *FairAdmission) evictIdleLocked() bool {
	for e := fa.order.Back(); e != nil; e = e.Prev() {
		t := e.Value.(*fairTenantLoad)
		if t.inFlight > 0 || t.queuedWaiters > 0 {
			continue
		}
		fa.order.Remove(e)
		delete(fa.tenants, t.key)
		return true
	}
	return false
}

func (fa *FairAdmission) touchLocked(t *fairTenantLoad) {
	if t.elem != nil {
		fa.order.MoveToFront(t.elem)
	}
}

func (fa *FairAdmission) removeWaiterLocked(w *fairWaiter) {
	for i, q := range fa.queue {
		if q == w {
			fa.queue = append(fa.queue[:i], fa.queue[i+1:]...)
			w.tenant.queuedWaiters--
			fa.queued.Set(float64(len(fa.queue)))
			return
		}
	}
}

// FairTenantKey composes the tenant identity from the authenticated org and
// the derived workload key. The org is length-prefixed so distinct
// (org, workload) pairs can never concatenate into the same key.
func FairTenantKey(orgID, workloadID string) string {
	return strconv.Itoa(len(orgID)) + ":" + orgID + workloadID
}

// fairStats is a point-in-time snapshot of controller counters (health
// endpoints and tests).
type fairStats struct {
	Free     int
	InFlight int
	Queued   int
	Tenants  int
}

func (fa *FairAdmission) stats() fairStats {
	if fa == nil {
		return fairStats{}
	}
	fa.mu.Lock()
	defer fa.mu.Unlock()
	s := fairStats{Free: fa.free, Queued: len(fa.queue), Tenants: len(fa.tenants)}
	for _, t := range fa.tenants {
		s.InFlight += t.inFlight
	}
	return s
}

// pendingWaiters reports how many of the tenant's requests are currently
// parked in queue (introspection for tests and health endpoints).
func (fa *FairAdmission) pendingWaiters(orgID, workloadID string) int {
	if fa == nil {
		return 0
	}
	fa.mu.Lock()
	defer fa.mu.Unlock()
	if t, ok := fa.tenants[FairTenantKey(orgID, workloadID)]; ok {
		return t.queuedWaiters
	}
	return 0
}
