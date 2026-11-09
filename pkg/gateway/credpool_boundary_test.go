package cli

// boundary matrix (unit level): the failure and edge horizons of
// the multi-credential pool — the all-quarantined fail-closed verdict, the
// quarantine expiry boundary at the next UTC midnight, the single-credential
// pool (no sibling to rotate to), the store-round-trip bound while
// all-quarantined, and the log-record redaction guard (mutation anchor for

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// quarantineAll pins a live version-scoped quarantine row on every enabled
// credential of the stub (direct store mutation — the same state three 401
// hops would leave behind).
func quarantineAll(s *stubCredPoolStore, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.creds {
		if c.enabled {
			s.quarantine[c.id] = stubQuarantine{version: c.version, until: until}
		}
	}
}

// TestCredPoolBoundary_AllQuarantinedFailsClosed: when every held credential
// of the endpoint is quarantined, the pool refuses to serve — a wrapped
// errOrgCredsAllQuarantined naming the earliest return, never a silent
// fall-through candidate — and the refusal carries no key material.
func TestCredPoolBoundary_AllQuarantinedFailsClosed(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	pool := newTestCredPool(store, nil, now)
	ctx := context.Background()

	until := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	quarantineAll(store, until)

	_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.Error(t, err, "all credentials quarantined must fail closed, not fall through")
	assert.False(t, ok)
	require.ErrorIs(t, err, errOrgCredsAllQuarantined, "the sentinel must stay wrapped for callers")
	assert.Contains(t, err.Error(), "earliest return 2026-10-17T00:00:00Z", "the refusal names when traffic can return")
	assert.NotContains(t, err.Error(), "sk-pool-key", "no key material in the refusal")

	// Contrast: an org with NO credentials for the endpoint is a normal
	// routing miss (ok=false, nil error) — the two states stay
	// distinguishable per path.
	empty := newStubCredPoolStore()
	emptyPool := newTestCredPool(empty, nil, now)
	_, _, ok, err = emptyPool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestCredPoolBoundary_AllQuarantinedStoreRoundTripBound: while the pool
// holds an all-quarantined snapshot, repeated refusals are served from the
// cached snapshot — the fail-closed error is not a per-request store
// hammer.
func TestCredPoolBoundary_AllQuarantineStoreRoundTripBound(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	store := newStubCredPoolStore(
		stubPoolCred{id: "11111111-aaaa-4aaa-8aaa-000000000001", last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	pool := newTestCredPool(store, nil, now)
	ctx := context.Background()

	quarantineAll(store, time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC))
	for i := 0; i < 10; i++ {
		_, _, _, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.Error(t, err)
	}
	assert.Equal(t, 1, store.lists(), "the held snapshot serves the whole TTL window, refusals included")
}

// TestCredPoolBoundary_QuarantineExpiryEdge: the eligibility boundary
// mirrors the store SQL (quarantined_until <= now()). A deadline exactly at
// now — and therefore exactly at the next UTC midnight — is EXPIRED: the
// key serves again without a store round trip; one nanosecond later than
// now it is still quarantined.
func TestCredPoolBoundary_QuarantineExpiryEdge(t *testing.T) {
	midnight := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
	)

	// One nanosecond before the deadline: still quarantined, fail closed.
	quarantineAll(store, midnight)
	before := midnight.Add(-time.Nanosecond)
	store.nowFn = func() time.Time { return before }
	pool := newTestCredPool(store, nil, before)
	_, _, _, err := pool.pickAndResolve(context.Background(), "org-a", "openai-compat", "https://ep.test/v1")
	require.Error(t, err, "a deadline strictly after now keeps the credential quarantined")
	require.ErrorIs(t, err, errOrgCredsAllQuarantined)

	// Exactly at the deadline (the midnight tick): expired, serves again —
	// from the SAME cached snapshot, no store round trip. The store clock
	// follows the pool's (one timeline, the stub's documented contract).
	store.nowFn = func() time.Time { return midnight }
	atEdge := &orgCredsPool{store: store, ttl: orgCredsPoolTTL, now: func() time.Time { return midnight }, log: testLogger(), states: pool.states}
	use, plain, ok, err := atEdge.pickAndResolve(context.Background(), "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k1, use.credID)
	assert.Equal(t, "sk-pool-key-00000001", plain)
	assert.Equal(t, 1, store.lists(), "expiry is evaluated per pick: no reload needed at the boundary")

	// Store-level predicate parity (the SQL arm the gateway mirrors).
	assert.True(t, eligibleAt(adminstore.OrgCredentialPoolEntry{QuarantinedUntil: midnight}, midnight), "until == now is expired (<= now())")
	assert.False(t, eligibleAt(adminstore.OrgCredentialPoolEntry{QuarantinedUntil: midnight.Add(time.Nanosecond)}, midnight))
	assert.True(t, eligibleAt(adminstore.OrgCredentialPoolEntry{}, midnight), "no quarantine row is always eligible")
}

// TestCredPoolBoundary_SingleCredentialPool: one credential means no
// rotation sibling — every pick serves it; a 401 quarantines it into the
// fail-closed verdict (no global-key fall-through); expiry or a rotation
// (key_version++) brings it back.
func TestCredPoolBoundary_SingleCredentialPool(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	pool := newTestCredPool(store, nil, now)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, k1, use.credID, "a single-credential pool has no sibling to rotate to")
		assert.Equal(t, "sk-pool-key-00000001", plain)
	}

	// The one key is rejected upstream: quarantine → fail closed (there is
	// no second key, and the pool must not silently hand the endpoint to
	// the global key).
	use, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	pool.recordOutcome(ctx, "org-a", "openai-compat", use, http.StatusUnauthorized)
	calls := store.quarantineLog()
	require.Len(t, calls, 1)
	assert.Equal(t, k1, calls[0].credID)
	assert.Equal(t, time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), calls[0].until)

	_, _, ok, err = pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.Error(t, err, "the quarantined sole credential fails closed")
	assert.False(t, ok)
	require.ErrorIs(t, err, errOrgCredsAllQuarantined)

	// Rotation (Update + newPlaintextKey, key_version++): the credential
	// returns with the NEW key.
	store.rotate(k1, "sk-pool-key-ROTATED-0011")
	pool.invalidate("org-a", "openai-compat", "https://ep.test/v1")
	use2, plain2, ok2, err2 := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err2)
	require.True(t, ok2)
	assert.Equal(t, k1, use2.credID)
	assert.Equal(t, "sk-pool-key-ROTATED-0011", plain2, "a rotation returns the sole credential with its new key")

	// A DISABLED sole credential is a routing miss (ok=false), not the
	// quarantine refusal — disable and delete are "not held", quarantine is
	// "held but rejected".
	store.setEnabled(k1, false)
	pool.invalidate("org-a", "openai-compat", "https://ep.test/v1")
	_, _, ok3, err3 := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err3)
	assert.False(t, ok3, "a disabled credential leaves the pool as a plain miss")
}

// capturingHandler is an slog handler that keeps every record's message and
// log records must never carry key material).
type capturingHandler struct {
	mu      sync.Mutex
	records []string
}

func (h *capturingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, b.String())
	h.mu.Unlock()
	return nil
}

func (h *capturingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(_ string) slog.Handler      { return h }

// TestCredPoolBoundary_NoSecretsInLogRecords: every log record the pool
// emits on the serving path (pin + quarantine refusal + quarantine write)
// carries only the credential id and the last-4 mask — never the resolved
// break.
func TestCredPoolBoundary_NoSecretsInLogRecords(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-SECRET-aa01", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	h := &capturingHandler{}
	pool := &orgCredsPool{store: store, ttl: orgCredsPoolTTL, now: func() time.Time { return now }, log: slog.New(h), states: map[string]*orgCredsPoolState{}}
	ctx := context.Background()

	// Serving pin (Debug record), then the quarantine write records.
	use, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	pool.recordOutcome(ctx, "org-a", "openai-compat", use, http.StatusUnauthorized)

	// All-quarantined refusal error (log-free) and its error text.
	_, _, _, err = pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sk-pool-SECRET-aa01")

	require.NotEmpty(t, h.records, "the serving path must have produced log records to inspect")
	for _, rec := range h.records {
		assert.NotContains(t, rec, "sk-pool-SECRET-aa01", "log records must never carry the plaintext key")
	}
}
