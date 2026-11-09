package upstream

// Multi-credential pool engine: the in-process rotation core
// for pools of upstream credentials with the frozen identity triple
// (org, provider, base_url): one pool serves exactly one organization,
// one provider adapter and one upstream base URL; rotation is round-robin
// and 401/429 responses quarantine the credential.
//
// Boundary within the repo:
//
//   - pkg/gateway/credpool.go (package cli) is the production gateway
//     selector: DB-backed snapshots (adminstore OrgCredentialPoolEntry),
//     TTL/version invalidation and quarantine writes (D-5 state in DB/RLS).
//   - THIS engine is the standalone in-process primitive: membership,
//     round-robin (D-2), unavailability state with auto-expiry recovery and
//     manual reset, the upstream 401/429 quarantine/cooldown policy
//     (ReportOutcome) and secret-free credential refs for attribution. It
//     never touches the database and never stores plaintext keys. It can
//     serve non-gateway entry points (e.g. pkg/sovereign) with the same
//     rotation semantics as the gateway selector above.
//
// Recovery-without-race contract: membership is an append/remove list with
// FIXED positions — recovery (cooldown expiry or manual reset) only flips a
// per-member availability field under the pool mutex, it never re-inserts a
// member. A credential therefore exists exactly once in a pool under any
// interleaving of Acquire/MarkUnavailable/MarkRecovered/rotation; the
// round-robin cursor advances under the same mutex, so concurrent acquires
// observe a strict single advance per pick (no double-pick).
//
// Secret hygiene (W-BYOK-DB parity, "plaintext живёт одну попытку"):
// plaintext keys are fetched per acquire through the caller-supplied
// CredentialSource and live for exactly one attempt. The pool stores only
// secret-free metadata (credential id, last-4 mask, key version). Lease
// implements fmt.Stringer/fmt.GoStringer redaction so fmt cannot leak the
// key; reason strings passed to MarkUnavailable are caller-supplied
// classification tags and must never contain key material.
//
// Selection-failure contract (mirrors the gateway pool's fail-closed
// posture): ErrPoolEmpty is a routing miss — the caller may fall through to
// per-model/global keys. PoolExhaustedError means the org HOLDS credentials
// but none is eligible: the caller must NOT silently route the global key to
// an org-registered endpoint (W-PROV leak hazard); it fails or retries
// instead. Acquire never loops internally — an invalid credential is skipped
// only through explicit unavailability, never retried inside the pool.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// CredentialPoolKey is the frozen identity of one credential pool
// Credentials of one pool belong to exactly one organization,
// one provider adapter and one upstream base URL. The triple is a property
// of the POOL, never of an individual credential, so key rotation and RR
// turns cannot drift a credential onto another org/provider/endpoint.
//
// Matching/normalization (e.g. /v1-suffix folding) is the caller's concern —
// the engine treats the triple as opaque.
type CredentialPoolKey struct {
	OrgID    string
	Provider string
	BaseURL  string
}

// String renders the pool identity for logs and errors. All three fields are
// configuration metadata, never secret material.
func (k CredentialPoolKey) String() string {
	return fmt.Sprintf("org=%s provider=%s base_url=%s", k.OrgID, k.Provider, k.BaseURL)
}

// CredentialRef is the secret-free identity of one pooled credential:
// the store credential id (safe for logs and attribution), the store-provided
// last-4 display mask and the key version (bumped on rotation). It never
// carries the plaintext key.
type CredentialRef struct {
	ID         string
	Last4      string
	KeyVersion int
}

// String renders the reference for logs and errors. Only masked fields are
// included; AttributionRef is the attribution shape.
func (r CredentialRef) String() string {
	return fmt.Sprintf("cred=%s last4=%s v=%d", r.ID, r.Last4, r.KeyVersion)
}

// AttributionRef returns the masked attribution reference: the first 8
// characters of the credential id plus the last-4 mask ("3f2ac1b2:9c11") —
// byte-compatible with the gateway's org-credential attribution format. ""
// when the reference carries no id; the (truncated) id alone when no last-4
// mask is known. Never plaintext or the full id.
func (r CredentialRef) AttributionRef() string {
	if r.ID == "" {
		return ""
	}
	id := r.ID
	if len(id) > 8 {
		id = id[:8]
	}
	if r.Last4 != "" {
		return id + ":" + r.Last4
	}
	return id
}

// CredentialSource resolves the plaintext key of one credential at acquire
// time (per-attempt decrypt, DB/KMS fetch — never cached by the pool).
// Implementations must not log or embed the key in returned errors; the
// pool only ever surfaces the CredentialRef alongside a source failure.
type CredentialSource func(ctx context.Context) (string, error)

// CredentialSpec registers one credential into a pool.
type CredentialSpec struct {
	ID         string
	Last4      string
	KeyVersion int
	// Source resolves the plaintext for one acquire. Required.
	Source CredentialSource
}

// Errors returned by the credential pool. They never contain credential
// values.
var (
	// ErrPoolEmpty is returned by Acquire when the pool holds no
	// credentials. It is a routing miss (gateway parity: ok=false) — the
	// caller may fall through to per-model/global keys.
	ErrPoolEmpty = errors.New("credential pool: no credentials registered")
	// ErrUnknownCredential is returned when an operation names a credential
	// id the pool does not hold.
	ErrUnknownCredential = errors.New("credential pool: unknown credential")
	// ErrDuplicateCredential is returned by Add when the credential id is
	// already registered (rotation must use UpsertCredential).
	ErrDuplicateCredential = errors.New("credential pool: credential already registered")
	// ErrInvalidCredential is returned for a spec without an id or without
	// a plaintext source.
	ErrInvalidCredential = errors.New("credential pool: credential needs an id and a source")
)

// PoolExhaustedError reports that the pool HOLDS credentials but none is
// eligible for new attempts right now (all unavailable; e.g. quarantined by
// the upstream outcome policy). Fail-closed parity with the gateway pool:
// callers must not
// fall through to a non-org key while the org plausibly holds credentials
// for this endpoint. EarliestRecovery (zero when unknown) is when the first
// member becomes eligible again.
type PoolExhaustedError struct {
	Pool             CredentialPoolKey
	EarliestRecovery time.Time
}

// Error implements the error interface; the message is secret-free.
func (e *PoolExhaustedError) Error() string {
	if e.EarliestRecovery.IsZero() {
		return fmt.Sprintf("credential pool %s: all credentials are out of rotation", e.Pool)
	}
	return fmt.Sprintf("credential pool %s: all credentials are out of rotation; earliest recovery %s",
		e.Pool, e.EarliestRecovery.UTC().Format(time.RFC3339))
}

// Quarantine reason tags recorded in Snapshot diagnostics when an upstream
// outcome quarantines a credential. Secret-free by contract — they name the
// upstream classification, never key material.
const (
	QuarantineReasonUnauthorized = "upstream_401" // invalid, revoked or misrotated key
	QuarantineReasonThrottled    = "upstream_429" // per-key rate limit / quota exhaustion
)

// QuarantinableStatus reports whether an upstream HTTP status must take the
// credential that authenticated the attempt out of rotation: 401 (the key
// does not authenticate) and 429 (the key is throttled) quarantine; every
// other status — including other 4xx and 5xx — must not (a malformed-request
// 400 or an infrastructure 502 is not a property of the key).
func QuarantinableStatus(statusCode int) bool {
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusTooManyRequests
}

// QuarantineReason maps a quarantinable upstream status to its secret-free
// Snapshot reason tag. "" for statuses that do not quarantine.
func QuarantineReason(statusCode int) string {
	switch statusCode {
	case http.StatusUnauthorized:
		return QuarantineReasonUnauthorized
	case http.StatusTooManyRequests:
		return QuarantineReasonThrottled
	default:
		return ""
	}
}

// QuarantineDeadline is the cooldown horizon for a quarantinable outcome:
// the start of the next UTC day — "until the end of the current day", at
// most 24h away. Parity with the gateway store policy: the DB row carries
// the same horizon and the same expiry boundary (a deadline exactly equal
// to now is already lifted — the key returns to rotation at that instant).
func QuarantineDeadline(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}

// poolMember is one registered credential with its availability state.
// Members keep a fixed position for their whole lifetime; recovery flips
// fields, it never re-inserts the member.
type poolMember struct {
	ref    CredentialRef
	source CredentialSource
	// unavailableUntil is the zero time when the member is in rotation.
	// Boundary parity with the gateway/store SQL: a deadline exactly equal
	// to now is expired (the key returns to rotation at that instant).
	unavailableUntil time.Time
	// unavailableReason is a caller-supplied secret-free classification tag
	// for the quarantine/cooldown policy. Exposed only via Snapshot.
	unavailableReason string
	// acquires counts completed picks of this member (attribution counter).
	acquires uint64
}

// inRotationAt reports whether the member may serve NEW attempts at now.
// Caller holds the pool mutex.
func (m *poolMember) inRotationAt(now time.Time) bool {
	return m.unavailableUntil.IsZero() || !m.unavailableUntil.After(now)
}

// Lease is one acquired credential for exactly one upstream attempt.
// The plaintext is handed to the caller once; it must be used for the
// attempt's Authorization and never logged, cached or attributed in
// unmasked form (attribution uses the masked Ref/AttributionRef). Multiple
// concurrent leases on the same credential are allowed (upstream keys are
// shareable); the round-robin cursor still advances per pick.
type Lease struct {
	pool CredentialPoolKey
	ref  CredentialRef
	key  string
}

// Pool returns the identity of the pool the lease came from. The triple is
// copied from the pool — it stays bound across rotation and recovery.
func (l *Lease) Pool() CredentialPoolKey { return l.pool }

// Ref returns the secret-free credential reference.
func (l *Lease) Ref() CredentialRef { return l.ref }

// AttributionRef returns the masked attribution reference of the lease's
// credential (see CredentialRef.AttributionRef). Nil-safe: a nil lease
// yields "".
func (l *Lease) AttributionRef() string {
	if l == nil {
		return ""
	}
	return l.ref.AttributionRef()
}

// Plaintext returns the per-attempt upstream key. Callers must treat it as
// single-use secret material: never log, cache or serialize it.
func (l *Lease) Plaintext() string { return l.key }

// String implements fmt.Stringer with redacted output (no plaintext).
func (l *Lease) String() string {
	if l == nil {
		return "<nil upstream lease>"
	}
	return fmt.Sprintf("lease(pool=%s, %s)", l.pool, l.ref)
}

// GoString implements fmt.GoStringer with redacted output (no plaintext),
// so %#v formatting cannot leak the key either.
func (l *Lease) GoString() string {
	if l == nil {
		return "<nil upstream lease>"
	}
	return fmt.Sprintf("upstream.Lease{pool:%q ref:%q}", l.pool.String(), l.ref.String())
}

// CredentialPool is the per-endpoint rotation engine for one identity
// triple. All methods are safe for concurrent use.
type CredentialPool struct {
	key CredentialPoolKey

	mu      sync.Mutex
	members []*poolMember
	cursor  int
	now     func() time.Time

	// acquires counts all completed picks (attribution counter).
	acquires uint64
}

// NewCredentialPool builds an empty pool bound to the given identity triple.
func NewCredentialPool(key CredentialPoolKey) *CredentialPool {
	return &CredentialPool{
		key: key,
		now: time.Now,
	}
}

// Key returns the pool's frozen identity triple.
func (p *CredentialPool) Key() CredentialPoolKey { return p.key }

// Add registers a new credential. It fails when the id is already present
// (rotation goes through UpsertCredential) or when the spec is incomplete.
func (p *CredentialPool) Add(spec CredentialSpec) error {
	if err := validateSpec(spec); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.members {
		if m.ref.ID == spec.ID {
			return fmt.Errorf("%w: %s", ErrDuplicateCredential, CredentialRef{ID: spec.ID, Last4: spec.Last4, KeyVersion: spec.KeyVersion})
		}
	}
	p.members = append(p.members, &poolMember{
		ref:    CredentialRef{ID: spec.ID, Last4: spec.Last4, KeyVersion: spec.KeyVersion},
		source: spec.Source,
	})
	return nil
}

// UpsertCredential registers a credential or rotates it in place: an
// existing id keeps its membership position and acquire counter while its
// key version and plaintext source are replaced. A key-version change lifts
// any quarantine/cooldown — the stored unavailability belongs to the OLD
// key and a rotated key is a new key (store parity: quarantine rows are
// version-scoped to key_version). The same version preserves current
// unavailability (re-registering a source is not a rotation). This is the
// seam the adminstore rotation path (Update + newPlaintextKey,
// key_version++) feeds — the pool identity triple never changes.
func (p *CredentialPool) UpsertCredential(spec CredentialSpec) error {
	if err := validateSpec(spec); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.members {
		if m.ref.ID != spec.ID {
			continue
		}
		if m.ref.KeyVersion != spec.KeyVersion {
			m.unavailableUntil = time.Time{}
			m.unavailableReason = ""
		}
		m.ref.Last4 = spec.Last4
		m.ref.KeyVersion = spec.KeyVersion
		m.source = spec.Source
		return nil
	}
	p.members = append(p.members, &poolMember{
		ref:    CredentialRef{ID: spec.ID, Last4: spec.Last4, KeyVersion: spec.KeyVersion},
		source: spec.Source,
	})
	return nil
}

// Remove drops a credential from the pool: it stops receiving new picks
// immediately (disabled/deleted exclusion). In-flight leases keep their
// already-resolved plaintext ("активные доживают"). Returns false when the
// id was not registered.
func (p *CredentialPool) Remove(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, m := range p.members {
		if m.ref.ID != id {
			continue
		}
		p.members = append(p.members[:i], p.members[i+1:]...)
		if p.cursor > i {
			p.cursor--
		}
		if p.cursor >= len(p.members) {
			p.cursor = 0
		}
		return true
	}
	return false
}

// MarkUnavailable takes a credential out of rotation until the given
// deadline (cooldown expiry restores it automatically — see Acquire).
// Callers that only know the upstream HTTP status use ReportOutcome: it
// classifies 401/429 into concrete deadlines and reason tags. This method
// is the raw state primitive for custom cooldowns and admin flows.
// reason is a secret-free classification tag for Snapshot diagnostics — it
// must never contain key material. Overwrites any previous unavailability.
// Returns false when the id is not registered.
func (p *CredentialPool) MarkUnavailable(id string, until time.Time, reason string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.members {
		if m.ref.ID != id {
			continue
		}
		m.unavailableUntil = until
		m.unavailableReason = reason
		return true
	}
	return false
}

// MarkRecovered returns a credential to rotation immediately (manual
// reset). Idempotent and race-free by construction: it only clears the
// availability fields under the pool mutex — a credential is never
// re-inserted, so it can never appear twice in the rotation. A concurrent
// cooldown expiry converges to the same single member. Returns false when
// the id is not registered.
func (p *CredentialPool) MarkRecovered(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.members {
		if m.ref.ID != id {
			continue
		}
		m.unavailableUntil = time.Time{}
		m.unavailableReason = ""
		return true
	}
	return false
}

// ReportOutcome classifies one attempt's upstream HTTP status and applies
// the quarantine policy to the lease's credential: 401 and 429 take the
// credential out of rotation until QuarantineDeadline(p.now()) with the
// matching reason tag; every other status leaves pool state unchanged.
// The manual counterpart is MarkRecovered; UpsertCredential with a new key
// version also lifts a quarantine (a rotated key is a new key).
//
// The lease binds the report to its pool: a lease acquired from another
// pool, a nil lease or a nil pool reports false and mutates nothing, so
// same-id credentials of different pools (orgs/endpoints) stay isolated.
// Returns true when the outcome was accepted for this pool (quarantine
// applied, or a recognized no-op for a non-quarantining status), false when
// the underlying credential id is not registered.
func (p *CredentialPool) ReportOutcome(l *Lease, statusCode int) bool {
	if p == nil || l == nil || l.pool != p.key {
		return false
	}
	if !QuarantinableStatus(statusCode) {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, m := range p.members {
			if m.ref.ID == l.ref.ID {
				return true
			}
		}
		return false
	}
	return p.MarkUnavailable(l.ref.ID, QuarantineDeadline(p.now()), QuarantineReason(statusCode))
}

// Acquire returns the next credential by round-robin (D-2) among members in
// rotation at the current instant. Members whose unavailability deadline
// has passed are recovered by this check itself — expiry is evaluated under
// the pool mutex at pick time, so a recovered key returns to rotation
// without a background goroutine and without a double-pick: the cursor
// advances exactly once per successful pick.
//
// When every member is out of rotation, a secret-free PoolExhaustedError is
// returned (fail-closed parity — see the package boundary comment); an
// empty pool yields ErrPoolEmpty. The plaintext is resolved after the
// selection lock is released; a source failure surfaces the CredentialRef
// (never key material) and leaves pool state unchanged.
func (p *CredentialPool) Acquire(ctx context.Context) (*Lease, error) { //nolint:contextcheck // the nil-guard backfills Background only when a caller omits ctx; the acquire path is ctx-propagating
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	n := len(p.members)
	if n == 0 {
		p.mu.Unlock()
		return nil, ErrPoolEmpty
	}
	now := p.now()
	var picked *poolMember
	for i := 0; i < n; i++ {
		idx := (p.cursor + i) % n
		m := p.members[idx]
		if m.inRotationAt(now) {
			picked = m
			p.cursor = (idx + 1) % n
			m.acquires++
			p.acquires++
			break
		}
	}
	if picked == nil {
		earliest := earliestRecoveryLocked(p.members, now)
		p.mu.Unlock()
		return nil, &PoolExhaustedError{Pool: p.key, EarliestRecovery: earliest}
	}
	// Copy what the lease needs while still under the mutex; the member may
	// be rotated or removed right after, and the lease keeps its picked
	// identity (rotation preserves pool identity by construction).
	ref := picked.ref
	source := picked.source
	p.mu.Unlock()

	plain, err := source(ctx)
	if err != nil {
		return nil, fmt.Errorf("credential pool %s: resolve plaintext for %s: %w", p.key, ref, err)
	}
	if plain == "" {
		return nil, fmt.Errorf("credential pool %s: credential %s resolved an empty key", p.key, ref)
	}
	return &Lease{pool: p.key, ref: ref, key: plain}, nil
}

// Len returns the number of registered credentials (in rotation or not).
// Recovery never changes this number — a regression guard against
// double-insert races.
func (p *CredentialPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.members)
}

// CredentialSnapshot is the secret-free view of one member (usage
// attribution reads Acquires and Ref; operators read availability
// diagnostics).
type CredentialSnapshot struct {
	Ref               CredentialRef
	InRotation        bool
	UnavailableReason string // caller-supplied classification tag, secret-free
	RecoversAt        time.Time
	Acquires          uint64
}

// PoolSnapshot is the secret-free view of a pool at one instant.
type PoolSnapshot struct {
	Key      CredentialPoolKey
	Acquires uint64
	Members  []CredentialSnapshot
}

// Snapshot returns the current secret-free state of the pool.
func (p *CredentialPool) Snapshot() PoolSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	snap := PoolSnapshot{Key: p.key, Acquires: p.acquires, Members: make([]CredentialSnapshot, 0, len(p.members))}
	for _, m := range p.members {
		snap.Members = append(snap.Members, CredentialSnapshot{
			Ref:               m.ref,
			InRotation:        m.inRotationAt(now),
			UnavailableReason: m.unavailableReason,
			RecoversAt:        m.unavailableUntil,
			Acquires:          m.acquires,
		})
	}
	return snap
}

// earliestRecoveryLocked returns the smallest live unavailability deadline
// across the members (zero when none is out of rotation). Caller holds the
// pool mutex.
func earliestRecoveryLocked(members []*poolMember, now time.Time) time.Time {
	var earliest time.Time
	for _, m := range members {
		if m.unavailableUntil.IsZero() || !m.unavailableUntil.After(now) {
			continue
		}
		if earliest.IsZero() || m.unavailableUntil.Before(earliest) {
			earliest = m.unavailableUntil
		}
	}
	return earliest
}

func validateSpec(spec CredentialSpec) error {
	if spec.ID == "" || spec.Source == nil {
		return fmt.Errorf("%w: id=%q", ErrInvalidCredential, spec.ID)
	}
	return nil
}

// CredentialPools is a registry of credential pools keyed by the frozen
// identity triple. It gives independent entry points (gateway, sovereign,
// admin tooling) one shared home per (org, provider, base_url) so a
// credential registered for one org is structurally invisible to another
// pool key.
type CredentialPools struct {
	mu    sync.Mutex
	pools map[CredentialPoolKey]*CredentialPool
}

// NewCredentialPools builds an empty registry.
func NewCredentialPools() *CredentialPools {
	return &CredentialPools{pools: make(map[CredentialPoolKey]*CredentialPool)}
}

// GetOrCreate returns the pool for the key, creating it on first use. The
// same key always yields the same *CredentialPool for the registry's
// lifetime; Remove(key) detaches it — the detached object keeps serving its
// existing leases while a later GetOrCreate builds a fresh pool.
func (r *CredentialPools) GetOrCreate(key CredentialPoolKey) *CredentialPool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pools[key]
	if !ok {
		p = NewCredentialPool(key)
		r.pools[key] = p
	}
	return p
}

// Get returns the pool for the key if it exists.
func (r *CredentialPools) Get(key CredentialPoolKey) (*CredentialPool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pools[key]
	return p, ok
}

// Remove detaches the pool for the key. Returns false when absent.
func (r *CredentialPools) Remove(key CredentialPoolKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.pools[key]; !ok {
		return false
	}
	delete(r.pools, key)
	return true
}

// Len returns the number of registered pools.
func (r *CredentialPools) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pools)
}
