package cli

// fairness (D-2), version-scoped quarantine on 401/429 until the end of the
// current UTC day (D-3), per-request pinning so active attempts survive a
// rotation-out, stale-pin recovery, fail-closed store errors, the negative
// load guard, version-based invalidation, and the masked D-4 ref.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubPoolCred is one in-memory pool credential.
type stubPoolCred struct {
	id      string
	last4   string
	key     string // synthetic fixture value, never a real credential
	enabled bool
	version int
	// org is the owning org of the credential row (the store's RLS scoping
	// stand-in). newStubCredPoolStore defaults an empty org to "org-a", so
	// single-org fixtures keep working unchanged.
	org string
}

// stubQuarantine is the persisted version-scoped quarantine row.
type stubQuarantine struct {
	version int
	until   time.Time
}

// stubQuarantineCall records one QuarantineOrgCredential invocation.
type stubQuarantineCall struct {
	org     string
	credID  string
	version int
	until   time.Time
}

// stubCredPoolStore is an in-memory OrgCredsPoolStore that mirrors the SQL
// eligibility semantics: enabled rows whose version-scoped quarantine has
// not expired. It also implements the frozen ResolveKey surface (newest
// first) so gateway wiring keeps its historical shape.
type stubCredPoolStore struct {
	mu              sync.Mutex
	creds           []stubPoolCred
	quarantine      map[string]stubQuarantine
	listCalls       int
	resolveCalls    int
	quarantineCalls []stubQuarantineCall
	listErr         error
	// quarantineErr, when set, fails every quarantine write with a
	// non-NotFound infrastructure error (write-failure injection).
	quarantineErr error
	// resolveErr, when set, fails every ResolveKeyEntry with an
	// infrastructure error (resolve-failure injection).
	resolveErr error
	// resolveEmpty makes ResolveKeyEntry return ("", true, nil) for the
	// listed ids: the resolved-but-empty plaintext injection (the stale-key
	// signal) — persistent until cleared, so both pickAndResolve attempts
	// observe it.
	resolveEmpty map[string]bool
	// nowFn is the eligibility clock (the DB's now() stand-in). Fixed-clock
	// tests pin it to the pool's clock so quarantine expiry is evaluated in
	// the same timeline as quarantineDeadline.
	nowFn func() time.Time
	// resolveMissOnce makes the NEXT ResolveKeyEntry of the given id return
	// ok=false once (stale-pin simulation), then clears itself.
	resolveMissOnce map[string]bool
}

func newStubCredPoolStore(creds ...stubPoolCred) *stubCredPoolStore {
	normalized := make([]stubPoolCred, 0, len(creds))
	for _, c := range creds {
		if c.org == "" {
			c.org = "org-a"
		}
		normalized = append(normalized, c)
	}
	return &stubCredPoolStore{
		creds:           normalized,
		quarantine:      map[string]stubQuarantine{},
		nowFn:           time.Now,
		resolveMissOnce: map[string]bool{},
		resolveEmpty:    map[string]bool{},
	}
}

func (s *stubCredPoolStore) eligibleLocked(c stubPoolCred, now time.Time) bool {
	if !c.enabled {
		return false
	}
	if q, ok := s.quarantine[c.id]; ok && q.version == c.version && q.until.After(now) {
		return false
	}
	return true
}

func (s *stubCredPoolStore) ListActiveOrgCredentials(_ context.Context, orgID, provider, baseURL string) ([]adminstore.OrgCredentialPoolEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCalls++
	if s.listErr != nil {
		return nil, s.listErr
	}
	if orgID == "" || provider == "" {
		return nil, nil
	}
	_ = baseURL
	var out []adminstore.OrgCredentialPoolEntry
	for _, c := range s.creds {
		if !c.enabled {
			continue
		}
		// The org field is the RLS scoping stand-in: a tenant never lists
		// another tenant's rows (parity with the real store query).
		if c.org != orgID {
			continue
		}
		// version-scoped quarantine snapshot; eligibility (expiry) is the
		// caller's decision.
		e := adminstore.OrgCredentialPoolEntry{
			OrgCredential: adminstore.OrgCredential{
				ID: c.id, OrgID: orgID, Provider: provider, BaseURL: baseURL,
				KeyLast4: c.last4, Enabled: true, KeyVersion: c.version,
			},
		}
		if q, ok := s.quarantine[c.id]; ok && q.version == c.version {
			e.QuarantinedUntil = q.until
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *stubCredPoolStore) ResolveKeyEntry(_ context.Context, orgID, provider, baseURL, credentialID string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolveCalls++
	if s.resolveErr != nil {
		return "", false, s.resolveErr
	}
	if s.resolveMissOnce[credentialID] {
		delete(s.resolveMissOnce, credentialID)
		return "", false, nil
	}
	if s.resolveEmpty[credentialID] {
		return "", true, nil
	}
	now := s.nowFn()
	for _, c := range s.creds {
		if c.id != credentialID {
			continue
		}
		if !s.eligibleLocked(c, now) {
			return "", false, nil
		}
		return c.key, true, nil
	}
	return "", false, nil
}

func (s *stubCredPoolStore) QuarantineOrgCredential(_ context.Context, orgID, credentialID string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quarantineErr != nil {
		return s.quarantineErr
	}
	for _, c := range s.creds {
		if c.id == credentialID && c.org == orgID {
			s.quarantine[credentialID] = stubQuarantine{version: c.version, until: until}
			s.quarantineCalls = append(s.quarantineCalls, stubQuarantineCall{org: orgID, credID: credentialID, version: c.version, until: until})
			return nil
		}
	}
	return adminstore.ErrNotFound
}

// rotate mirrors the frozen Update + newPlaintextKey semantics: the key is
// replaced and key_version increments — which must lift the quarantine.
func (s *stubCredPoolStore) rotate(credID, newKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.creds {
		if s.creds[i].id == credID {
			s.creds[i].key = newKey
			s.creds[i].version++
			return
		}
	}
}

func (s *stubCredPoolStore) setEnabled(credID string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.creds {
		if s.creds[i].id == credID {
			s.creds[i].enabled = enabled
			return
		}
	}
}

func (s *stubCredPoolStore) lists() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listCalls
}

func (s *stubCredPoolStore) resolves() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolveCalls
}

func (s *stubCredPoolStore) quarantineLog() []stubQuarantineCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubQuarantineCall(nil), s.quarantineCalls...)
}

// newTestCredPool builds a pool with a fixed clock for deadline math.
func newTestCredPool(store OrgCredsPoolStore, versions OrgCredsVersionStore, now time.Time) *orgCredsPool {
	return &orgCredsPool{
		store:    store,
		versions: versions,
		ttl:      orgCredsPoolTTL,
		now:      func() time.Time { return now },
		log:      testLogger(),
		states:   make(map[string]*orgCredsPoolState),
	}
}

// TestCredPool_RoundRobinFairness: with 3 eligible credentials, 30 picks
// distribute exactly 10/10/10 (D-2; the card's fairness acceptance as a
// deterministic selector property — no key monopolizes the traffic).
func TestCredPool_RoundRobinFairness(t *testing.T) {
	store := newStubCredPoolStore(
		stubPoolCred{id: "11111111-aaaa-4aaa-8aaa-000000000001", last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: "11111111-aaaa-4aaa-8aaa-000000000002", last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
		stubPoolCred{id: "11111111-aaaa-4aaa-8aaa-000000000003", last4: "0003", key: "sk-pool-key-00000003", enabled: true, version: 1},
	)
	pool := newTestCredPool(store, nil, time.Now())
	ctx := context.Background()

	counts := map[string]int{}
	keys := map[string]string{
		"11111111-aaaa-4aaa-8aaa-000000000001": "sk-pool-key-00000001",
		"11111111-aaaa-4aaa-8aaa-000000000002": "sk-pool-key-00000002",
		"11111111-aaaa-4aaa-8aaa-000000000003": "sk-pool-key-00000003",
	}
	for i := 0; i < 30; i++ {
		use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, keys[use.credID], plain)
		counts[use.credID]++
	}
	for _, id := range []string{
		"11111111-aaaa-4aaa-8aaa-000000000001",
		"11111111-aaaa-4aaa-8aaa-000000000002",
		"11111111-aaaa-4aaa-8aaa-000000000003",
	} {
		assert.Equal(t, 10, counts[id], "round-robin must split 30 picks evenly across 3 keys")
	}
	assert.Equal(t, 1, store.lists(), "the snapshot serves all picks within the TTL")
}

// TestCredPool_QuarantineOn401: a 401 outcome quarantines the credential
// that authenticated the attempt until the START of the next UTC day (D-3:
// "до конца суток", at most 24h), bumps the org version, and every later
// pick moves to the siblings.
func TestCredPool_QuarantineOn401(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 3},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := newTestCredPool(store, versions, now)
	ctx := context.Background()

	use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k1, use.credID)
	assert.Equal(t, "sk-pool-key-00000001", plain)

	// The upstream rejected the key with 401.
	pool.recordOutcome(ctx, "org-a", "openai-compat", use, http.StatusUnauthorized)

	calls := store.quarantineLog()
	require.Len(t, calls, 1)
	assert.Equal(t, k1, calls[0].credID)
	assert.Equal(t, 3, calls[0].version, "the quarantine row must pin the credential's current key_version")
	assert.Equal(t, time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), calls[0].until,
		"quarantine must run until the end of the current UTC day")
	assert.Positive(t, versions.versions["org-a"], "the org version must be bumped for cross-instance invalidation")

	// New attempts never see k1 while quarantined.
	for i := 0; i < 5; i++ {
		use2, plain2, ok2, err2 := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err2)
		require.True(t, ok2)
		assert.Equal(t, k2, use2.credID, "a quarantined credential must not serve new attempts")
		assert.Equal(t, "sk-pool-key-00000002", plain2)
	}
}

// TestCredPool_QuarantineOn429AndIgnoredStatuses: 429 quarantines the
// credential (per-key cooldown); 200/500/404 leave the pool untouched.
func TestCredPool_QuarantineOn429AndIgnoredStatuses(t *testing.T) {
	now := time.Date(2026, 10, 16, 23, 30, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	pool := newTestCredPool(store, nil, now)
	ctx := context.Background()

	use1, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)

	for _, status := range []int{http.StatusOK, http.StatusInternalServerError, http.StatusNotFound} {
		pool.recordOutcome(ctx, "org-a", "openai-compat", use1, status)
	}
	assert.Empty(t, store.quarantineLog(), "non-401/429 statuses must not quarantine")

	pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusTooManyRequests)
	calls := store.quarantineLog()
	require.Len(t, calls, 1)
	// 23:30 UTC → 30 minutes to the day boundary (still "до конца суток").
	assert.Equal(t, time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), calls[0].until)
}

// TestCredPool_QuarantineExpiryAndRotationReturn: an EXPIRED quarantine row
// leaves the credential eligible again; a rotation (key_version++) lifts a
// still-active quarantine implicitly (D-3 version scoping) and serves the
// rotated key.
func TestCredPool_QuarantineExpiryAndRotationReturn(t *testing.T) {
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

	use1, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, k1, use1.credID)
	pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusUnauthorized)

	// Quarantine expired (yesterday's row): k1 is eligible again with the
	// SAME key (no rotation happened).
	store.mu.Lock()
	store.quarantine[k1] = stubQuarantine{version: 1, until: now.Add(-time.Hour)}
	store.mu.Unlock()
	use1b, plain1b, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k1, use1b.credID, "an expired quarantine must return the credential to rotation")
	assert.Equal(t, "sk-pool-key-00000001", plain1b)

	// Fresh quarantine + rotation: the version bump must lift it and serve
	// the NEW key (the card's rotation acceptance).
	pool.recordOutcome(ctx, "org-a", "openai-compat", use1b, http.StatusUnauthorized)
	store.rotate(k1, "sk-pool-key-ROTATED-0011")
	pool.invalidate("org-a", "openai-compat", "https://ep.test/v1")
	for i := 0; i < 4; i++ {
		useR, plainR, okR, errR := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, errR)
		require.True(t, okR)
		if useR.credID == k1 {
			assert.Equal(t, "sk-pool-key-ROTATED-0011", plainR, "after rotation the credential serves its new key")
			return
		}
	}
	t.Fatal("rotated credential never returned to rotation")
}

// TestCredPool_ActiveSurvivesRotationOut: per-request pinning — an attempt
// that already resolved its plaintext keeps it verbatim across a quarantine
// AND a rotation of the same credential; only NEW attempts move away.
func TestCredPool_ActiveSurvivesRotationOut(t *testing.T) {
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

	use1, inFlight, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, k1, use1.credID)

	// Mid-flight: the key is quarantined (another request's 401) and even
	// rotated underneath. The in-flight attempt's resolved plaintext is a
	// plain string nobody can revoke — it must still be exactly what was
	// resolved (активные доживают).
	pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusUnauthorized)
	store.rotate(k1, "sk-pool-key-ROTATED-0011")
	assert.Equal(t, "sk-pool-key-00000001", inFlight,
		"an in-flight attempt keeps its already-resolved key: taking a credential out of rotation must not break active requests")

	// New attempts: k1 with the rotated key and k2 — never the old k1 key.
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		_, plainN, okN, errN := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, errN)
		require.True(t, okN)
		assert.NotEqual(t, "sk-pool-key-00000001", plainN)
		seen[plainN] = true
	}
	assert.Contains(t, seen, "sk-pool-key-ROTATED-0011")
	assert.Contains(t, seen, "sk-pool-key-00000002")
}

// TestCredPool_DisabledCredentialExcluded: a mid-flight disable leaves the
// pool through the same eligibility arm (new picks exclude it in the
// version-bump/TTL bound).
func TestCredPool_DisabledCredentialExcluded(t *testing.T) {
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	pool := newTestCredPool(store, nil, time.Now())
	ctx := context.Background()

	_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)

	store.setEnabled(k1, false)
	pool.invalidate("org-a", "openai-compat", "https://ep.test/v1")
	for i := 0; i < 4; i++ {
		use, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, k2, use.credID, "a disabled credential must not be selected")
	}
}

// TestCredPool_StalePinRetriesSibling: when the pinned entry leaves rotation
// between selection and resolution, the pool refreshes and serves ANOTHER
// org credential — it must not fall through to a per-model/global key while
// eligible org credentials remain.
func TestCredPool_StalePinRetriesSibling(t *testing.T) {
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	pool := newTestCredPool(store, nil, time.Now())
	ctx := context.Background()

	// Prime the snapshot so the pick cursor lands on k1.
	_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)

	store.mu.Lock()
	store.resolveMissOnce[k1] = true // k1 vanishes between pick and resolve
	store.mu.Unlock()
	use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok, "a stale pin must fall back to a sibling credential, not to the global key")
	assert.Equal(t, k2, use.credID)
	assert.Equal(t, "sk-pool-key-00000002", plain)
}

// TestCredPool_FailClosedOnStoreError: an infrastructure failure of the pool
// read is an error (never a silent global-key fallback) — the same W-PROV
// leak-hazard refusal the legacy ResolveKey path has.
func TestCredPool_FailClosedOnStoreError(t *testing.T) {
	store := newStubCredPoolStore(
		stubPoolCred{id: "11111111-aaaa-4aaa-8aaa-000000000001", last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
	)
	pool := newTestCredPool(store, nil, time.Now())
	ctx := context.Background()

	_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)

	store.mu.Lock()
	store.listErr = errors.New("credential store unavailable")
	store.mu.Unlock()
	pool.invalidate("org-a", "openai-compat", "https://ep.test/v1")

	_, _, ok, err = pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.Error(t, err, "a pool outage must fail closed")
	assert.False(t, ok)
}

// TestCredPool_NegativeLoadGuard: an endpoint with no eligible credentials
// is cached as a negative for the TTL — the non-BYOK traffic stays at one
// store hit per TTL window, exactly like the boolean probe it replaces.
func TestCredPool_NegativeLoadGuard(t *testing.T) {
	store := newStubCredPoolStore()
	pool := newTestCredPool(store, nil, time.Now())
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err)
		assert.False(t, ok)
	}
	assert.Equal(t, 1, store.lists(), "the negative snapshot serves the whole TTL window")
}

// TestCredPool_VersionInvalidation: positives reuse the snapshot while the
// org version is unchanged (no store round trip at TTL expiry); a version
// bump forces a re-list.
func TestCredPool_VersionInvalidation(t *testing.T) {
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
	)
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := newTestCredPool(store, versions, time.Now())
	ctx := context.Background()
	entryKey := "org-a\x00openai-compat\x00https://ep.test/v1"

	_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, store.lists())

	// TTL expiry + unchanged version → snapshot kept, no store round trip.
	pool.states[entryKey].loadedAt = pool.now().Add(-2 * orgCredsPoolTTL)
	_, _, ok, err = pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 1, store.lists(), "unchanged version must keep the snapshot")

	// Version bump (admin CRUD contract) → re-list.
	require.NoError(t, versions.SetOrgCredsVersion(ctx, "org-a", 42))
	pool.states[entryKey].loadedAt = pool.now().Add(-2 * orgCredsPoolTTL)
	_, _, ok, err = pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 2, store.lists(), "a version bump must re-list the snapshot")
}

// TestCredPool_RefMasking: the D-4 attribution ref carries only the first 8
// id characters and the last-4 mask — never key material — and serializes
// away when unused.
func TestCredPool_RefMasking(t *testing.T) {
	assert.Empty(t, orgCredentialUse{}.ref())
	assert.Empty(t, orgCredentialUse{used: true}.ref())
	assert.Equal(t, "abcd1234", orgCredentialUse{used: true, credID: "abcd1234"}.ref())
	assert.Equal(t, "abcd1234:9f11", orgCredentialUse{used: true, credID: "abcd1234-5678-4cab-99ab-0123456789ab", last4: "9f11"}.ref())
	assert.NotContains(t, orgCredentialUse{used: true, credID: "abcd1234-5678-4cab-99ab-0123456789ab", last4: "9f11"}.ref(), "sk-")

	raw, err := json.Marshal(struct {
		OrgCredentialRef string `json:"org_credential_ref,omitempty"`
	}{})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "org_credential_ref", "empty ref must stay off the wire")
}

// TestCredPool_QuarantineDeadlineBound: the D-3 horizon is the next UTC
// midnight — at most 24h from any moment of the day.
func TestCredPool_QuarantineDeadlineBound(t *testing.T) {
	for _, tc := range []struct {
		now   time.Time
		until time.Time
	}{
		{time.Date(2026, 10, 16, 0, 0, 1, 0, time.UTC), time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 10, 16, 23, 59, 59, 0, time.UTC), time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 12, 31, 18, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		until := quarantineDeadline(tc.now)
		assert.Equal(t, tc.until, until)
		assert.LessOrEqual(t, until.Sub(tc.now), 24*time.Hour, "quarantine must never exceed one day")
	}
	// Non-UTC input normalizes to the UTC day boundary.
	local := time.Date(2026, 10, 16, 23, 0, 0, 0, time.FixedZone("X", 5*3600))
	assert.Equal(t, time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1), quarantineDeadline(local))
}

// TestCredPool_NoSecretsInLogsAndErrors: quarantine/write failures surface
// only the credential id and mask — the synthetic key never appears in any
// error or log string produced by the pool.
func TestCredPool_NoSecretsInLogsAndErrors(t *testing.T) {
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-SECRET-value-0001", enabled: true, version: 1},
	)
	store.mu.Lock()
	store.listErr = fmt.Errorf("boom")
	store.mu.Unlock()
	pool := newTestCredPool(store, nil, time.Now())
	ctx := context.Background()

	_, _, _, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sk-pool-SECRET-value-0001")

	store.mu.Lock()
	store.listErr = nil
	store.mu.Unlock()
	pool.invalidate("org-a", "openai-compat", "https://ep.test/v1")
	use, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.NotContains(t, use.ref(), "sk-pool")
}

// TestCredPool_ResetOrgCredential_ReturnsToRotation: the operator reset
// writes a past-dated quarantine row through the existing store verb
// (expired by the eligibility boundary), bumps the org version for
// cross-instance invalidation, and the credential serves new attempts again
// ahead of its original deadline.
func TestCredPool_ResetOrgCredential_ReturnsToRotation(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 3},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	// Mutable clock shared by the pool and the store eligibility check
	// (newTestCredPool pins a constant, which would hide a stale version
	// bump): the reset's fresh version and past-dated row are only
	// observable on an advancing timeline.
	clock := now
	advance := func(d time.Duration) time.Time { clock = clock.Add(d); return clock }
	store.nowFn = func() time.Time { return clock }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := &orgCredsPool{
		store:    store,
		versions: versions,
		ttl:      orgCredsPoolTTL,
		now:      func() time.Time { return clock },
		log:      testLogger(),
		states:   make(map[string]*orgCredsPoolState),
	}
	ctx := context.Background()

	use, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, k1, use.credID)
	pool.recordOutcome(ctx, "org-a", "openai-compat", use, http.StatusUnauthorized)

	// k1 is quarantined until the next UTC midnight: only k2 serves.
	for i := 0; i < 3; i++ {
		use2, _, ok2, err2 := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err2)
		require.True(t, ok2)
		assert.Equal(t, k2, use2.credID, "the quarantined credential must not serve new attempts")
	}
	verAfterQuarantine := versions.versions["org-a"]
	require.Positive(t, verAfterQuarantine)

	// The timeline moves on before the operator resets (the quarantine is
	// still live: until = next UTC midnight > clock).
	clockNow := advance(time.Minute)
	require.NoError(t, pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", k1))

	calls := store.quarantineLog()
	require.Len(t, calls, 2)
	assert.Equal(t, k1, calls[1].credID)
	assert.Equal(t, 3, calls[1].version, "the reset row pins the credential's current key_version like any quarantine write")
	assert.Equal(t, clockNow.Add(-time.Second), calls[1].until, "the reset writes a past-dated (expired) deadline")
	store.mu.Lock()
	row := store.quarantine[k1]
	store.mu.Unlock()
	assert.False(t, row.until.After(clock), "the stored row must read as expired to the eligibility check")
	assert.Greater(t, versions.versions["org-a"], verAfterQuarantine, "the reset must bump the org version")

	// The credential serves new attempts again, ahead of its old deadline.
	useBack, plainBack, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k1, useBack.credID, "a reset credential returns to rotation before its original deadline")
	assert.Equal(t, "sk-pool-key-00000001", plainBack)

	// Idempotent: resetting again stays a no-op success.
	require.NoError(t, pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", k1))
}

func TestCredPool_ResetOrgCredential_Errors(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := newTestCredPool(store, versions, now)
	ctx := context.Background()

	// Empty id: rejected before any store write.
	require.Error(t, pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", ""))
	assert.Empty(t, store.quarantineLog())
	assert.Equal(t, int64(0), versions.versions["org-a"])

	// Unknown credential: surfaces as adminstore.ErrNotFound (wrapped), no
	// version bump, no local state change.
	err := pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", "ghost")
	require.ErrorIs(t, err, adminstore.ErrNotFound)
	assert.Empty(t, store.quarantineLog())
	assert.Equal(t, int64(0), versions.versions["org-a"])

	// Nil pool: a wiring error, not a panic.
	var nilPool *orgCredsPool
	err = nilPool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", k1)
	require.Error(t, err)
	assert.ErrorContains(t, err, "not wired")
}

// TestCredPool_ResetOrgCredential_Concurrent races operator resets against
// the 401 quarantine feedback path: bounded in-memory loops, then a
// deterministic tail — resetting every credential must put the pool back in
// serving state.
func TestCredPool_ResetOrgCredential_Concurrent(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	pool := newTestCredPool(store, &stubOrgVersions{versions: map[string]int64{}}, now)
	ctx := context.Background()

	var wg sync.WaitGroup
	// Churner: hammers 401s on whatever the pool pins (quarantine feedback).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			use, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
			if err != nil || !ok {
				continue // all quarantined: legal while the reset loop runs
			}
			pool.recordOutcome(ctx, "org-a", "openai-compat", use, http.StatusUnauthorized)
		}
	}()
	// Churner: operator resets lift k1's quarantine while the 401s land.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			if err := pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", k1); err != nil {
				t.Errorf("reset failed: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	// Deterministic tail: with every credential reset the pool serves again.
	require.NoError(t, pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", k1))
	require.NoError(t, pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", k2))
	use, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok, "after resetting every credential the pool must serve again")
	assert.Contains(t, []string{k1, k2}, use.credID)
}

// TestCredPool_AllQuarantined_FailsClosedNoKeyFetchNoNegativeCache: when the
// org holds credentials for the endpoint but every one is quarantined, the
// pool fails closed — the attempt errors with the typed all-quarantined
// cause plus the earliest-return horizon, and the caller never falls
// through to a global key. While every pick stays exhausted, no plaintext
// is fetched and the store is not re-listed per pick; an operator reset
// returns traffic without restarting anything.
func TestCredPool_AllQuarantined_FailsClosedNoKeyFetchNoNegativeCache(t *testing.T) {
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

	use1, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusUnauthorized)

	use2, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEqual(t, k1, use2.credID)
	pool.recordOutcome(ctx, "org-a", "openai-compat", use2, http.StatusUnauthorized)

	resolvesBefore := store.resolves()
	listsBefore := store.lists()
	for i := 0; i < 3; i++ {
		_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.ErrorIs(t, err, errOrgCredsAllQuarantined, "with every credential quarantined the pick must fail closed")
		require.False(t, ok)
		require.ErrorContains(t, err, "earliest return 2026-10-17T00:00:00Z",
			"the surfaced failure must carry the diagnosability horizon")
		assert.NotContains(t, err.Error(), "sk-pool-key", "no key material may surface through the failure")
	}
	assert.Equal(t, resolvesBefore, store.resolves(),
		"exhausted picks must not resolve any plaintext")
	assert.Equal(t, listsBefore+1, store.lists(),
		"the whole exhausted episode lists the store exactly once: the outcome invalidation re-arms the held snapshot, and every exhausted pick after it reuses the cache")

	require.NoError(t, pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", k2))
	use3, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok, "an operator reset must return traffic without restarting anything")
	assert.Equal(t, k2, use3.credID)
	assert.Equal(t, "sk-pool-key-00000002", plain)
}

// TestCredPool_RecordOutcome_CannotBypassQuarantine: outcome feedback can
// only ever widen a quarantine, never lift or shrink it. Ignored statuses
// (200/500/404) are no-ops even for an already-quarantined credential; a
// repeated 401/429 rewrites the same horizon; a late 401 for a credential
// deleted mid-flight is a silent no-op (no write, no version bump, no
// panic) and the pool keeps serving.
func TestCredPool_RecordOutcome_CannotBypassQuarantine(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := newTestCredPool(store, versions, now)
	ctx := context.Background()

	use1, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusUnauthorized)
	require.Len(t, store.quarantineLog(), 1)
	bumped := versions.versions["org-a"]
	require.Positive(t, bumped)

	// Ignored outcomes replayed against the already-quarantined credential:
	// no store write, no version change, the quarantine holds.
	for _, status := range []int{http.StatusOK, http.StatusInternalServerError, http.StatusNotFound} {
		pool.recordOutcome(ctx, "org-a", "openai-compat", use1, status)
		require.Len(t, store.quarantineLog(), 1, "status %d must not touch the quarantine", status)
		assert.Equal(t, bumped, versions.versions["org-a"], "status %d must not bump the org version", status)
	}
	use2, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k2, use2.credID, "k1 must stay out of rotation")
	assert.Equal(t, "sk-pool-key-00000002", plain)

	// A late 429 for the same in-flight attempt re-writes the same horizon
	// (fixed clock): still out, never shortened.
	pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusTooManyRequests)
	calls := store.quarantineLog()
	require.Len(t, calls, 2)
	assert.Equal(t, calls[0].until, calls[1].until, "repeated feedback must not shorten the quarantine")
	assert.Equal(t, k1, calls[1].credID)

	// A late 401 for a credential deleted mid-flight: silent no-op.
	ghost := orgCredentialUse{used: true, credID: "22222222-aaaa-4aaa-8aaa-000000000009", last4: "0009", baseURL: "https://ep.test/v1"}
	require.NotPanics(t, func() { pool.recordOutcome(ctx, "org-a", "openai-compat", ghost, http.StatusUnauthorized) })
	require.Len(t, store.quarantineLog(), 2, "a deleted credential must not land a quarantine row")
	assert.Equal(t, bumped, versions.versions["org-a"], "a no-op feedback must not bump the org version")
	use3, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok, "the pool keeps serving after a ghost feedback")
	assert.Equal(t, k2, use3.credID)
}

// TestCredPool_RecordOutcome_WriteFailure_NeverFailsRequestNoBump: a
// quarantine write failure is bookkeeping-only — the request path never
// sees it, no row and no version bump lands, the pool keeps serving from
// the intact snapshot, and once the store recovers the same feedback lands
// and the credential exits rotation.
func TestCredPool_RecordOutcome_WriteFailure_NeverFailsRequestNoBump(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := newTestCredPool(store, versions, now)
	ctx := context.Background()

	store.quarantineErr = errors.New("quarantine write backend down")
	use1, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok, "the pool must serve before any quarantine write")
	require.Equal(t, k1, use1.credID)

	// The 401 feedback hits the failing store: never fails the request path.
	require.NotPanics(t, func() { pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusUnauthorized) })
	require.Empty(t, store.quarantineLog(), "a failed write must not land a quarantine row")
	assert.Equal(t, int64(0), versions.versions["org-a"], "a failed write must not bump the org version")

	// The snapshot survived untouched (no invalidation on the failure path):
	// round-robin keeps serving both credentials, k1 included.
	use2, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, k2, use2.credID)
	use3, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, k1, use3.credID, "until a write lands, k1 stays in rotation")

	// Recovery: the same feedback against the same attempt now lands and k1
	// exits rotation.
	store.quarantineErr = nil
	pool.recordOutcome(ctx, "org-a", "openai-compat", use3, http.StatusUnauthorized)
	require.Len(t, store.quarantineLog(), 1)
	assert.Positive(t, versions.versions["org-a"])
	for i := 0; i < 4; i++ {
		useN, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, k2, useN.credID, "once the quarantine lands, k1 must not serve again")
	}
}

// TestCredPool_ResetOrgCredential_CrossOrgRejected: the reset is org-scoped
// end to end. A reset attempt from another org is rejected by the store's
// scoping with ErrNotFound — no write, no version bump, the quarantined
// credential stays out — while the owning org's identical reset flips the
// credential back into rotation.
func TestCredPool_ResetOrgCredential_CrossOrgRejected(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := newTestCredPool(store, versions, now)
	ctx := context.Background()

	use1, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusUnauthorized)
	calls := store.quarantineLog()
	require.Len(t, calls, 1)
	assert.Equal(t, "org-a", calls[0].org, "the quarantine write must carry the scoping org")
	bumped := versions.versions["org-a"]
	require.Positive(t, bumped)

	// A different org's reset finds no such credential: rejected, no write,
	// no bump, the quarantine holds.
	err = pool.ResetOrgCredential(ctx, "org-b", "openai-compat", "https://ep.test/v1", k1)
	require.ErrorIs(t, err, adminstore.ErrNotFound, "a cross-org reset must be rejected by the store scoping")
	require.Len(t, store.quarantineLog(), 1)
	assert.Equal(t, bumped, versions.versions["org-a"], "a rejected reset must not bump the org version")
	use2, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k2, use2.credID, "k1 must stay out after a rejected reset")
	assert.Equal(t, "sk-pool-key-00000002", plain)

	// The owning org's identical reset flips k1 back into rotation.
	require.NoError(t, pool.ResetOrgCredential(ctx, "org-a", "openai-compat", "https://ep.test/v1", k1))
	calls = store.quarantineLog()
	require.Len(t, calls, 2)
	assert.Equal(t, now.Add(-time.Second), calls[1].until,
		"the reset lands the past-dated deadline: the lift needs no new store verb")
	assert.Equal(t, now.UnixNano(), versions.versions["org-a"],
		"the reset bumps the org version (the frozen clock writes the same instant as the quarantine bump; the past-dated row above proves the reset path ran)")
	use3, plain3, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k1, use3.credID)
	assert.Equal(t, "sk-pool-key-00000001", plain3)
}
