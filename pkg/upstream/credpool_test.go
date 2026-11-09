package upstream

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newClockedPool builds a pool with a deterministic clock starting at base.
// The returned pointer rewrites p.now (same-package test hook); it must only
// be reassigned from the test goroutine while no acquires are in flight.
func newClockedPool(t *testing.T, key CredentialPoolKey, base time.Time) (*CredentialPool, *time.Time) {
	t.Helper()
	p := NewCredentialPool(key)
	now := base
	clock := &now
	p.now = func() time.Time { return *clock }
	return p, clock
}

func credKey(org, provider, url string) CredentialPoolKey {
	return CredentialPoolKey{OrgID: org, Provider: provider, BaseURL: url}
}

func sourceFor(secret string) CredentialSource {
	return func(context.Context) (string, error) { return secret, nil }
}

func TestCredentialPool_KeyString_HasNoSecretMaterial(t *testing.T) {
	key := credKey("org-1", "openai-compat", "https://api.example.com/v1")
	assert.Equal(t, "org=org-1 provider=openai-compat base_url=https://api.example.com/v1", key.String())
}

func TestCredentialPool_Add_Validation(t *testing.T) {
	p := NewCredentialPool(credKey("o", "openai-compat", "https://u.local"))
	require.ErrorIs(t, p.Add(CredentialSpec{ID: "", Source: sourceFor("k")}), ErrInvalidCredential)
	require.ErrorIs(t, p.Add(CredentialSpec{ID: "c1"}), ErrInvalidCredential)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "1234", KeyVersion: 1, Source: sourceFor("k1")}))
	// Duplicate id must not silently register a second member (a credential
	// exists exactly once in a pool — the no-double-pick foundation).
	require.ErrorIs(t, p.Add(CredentialSpec{ID: "c1", Source: sourceFor("k1b")}), ErrDuplicateCredential)
	assert.Equal(t, 1, p.Len())
}

func TestCredentialPool_RR_DistributesInOrder(t *testing.T) {
	p := NewCredentialPool(credKey("org-1", "openai-compat", "https://u.local"))
	for _, id := range []string{"c1", "c2", "c3"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Last4: "0000", Source: sourceFor("key-" + id)}))
	}
	got := make([]string, 0, 9)
	for range 9 {
		lease, err := p.Acquire(context.Background())
		require.NoError(t, err)
		got = append(got, lease.Ref().ID)
		assert.Equal(t, "key-"+lease.Ref().ID, lease.Plaintext(), "plaintext must be bound to the picked credential")
		assert.Equal(t, credKey("org-1", "openai-compat", "https://u.local"), lease.Pool())
	}
	assert.Equal(t, []string{"c1", "c2", "c3", "c1", "c2", "c3", "c1", "c2", "c3"}, got)
}

func TestCredentialPool_EmptyPool_RoutingMiss(t *testing.T) {
	p := NewCredentialPool(credKey("org-1", "openai-compat", "https://u.local"))
	_, err := p.Acquire(context.Background())
	require.ErrorIs(t, err, ErrPoolEmpty)
}

func TestCredentialPool_PoolIdentityIsolation(t *testing.T) {
	// Registry: a credential registered under (orgA, provider, url/v1) is
	// structurally invisible to every other pool key — including the same
	// org with a different base URL and another org with the same endpoint.
	reg := NewCredentialPools()
	keyA := credKey("org-a", "openai-compat", "https://api.example.com/v1")
	poolA := reg.GetOrCreate(keyA)
	require.NoError(t, poolA.Add(CredentialSpec{ID: "a1", Source: sourceFor("key-a1")}))

	same, ok := reg.Get(keyA)
	require.True(t, ok)
	assert.Same(t, poolA, same)

	for _, other := range []CredentialPoolKey{
		credKey("org-b", "openai-compat", "https://api.example.com/v1"),
		credKey("org-a", "anthropic", "https://api.example.com/v1"),
		credKey("org-a", "openai-compat", "https://api.example.com"),
	} {
		p := reg.GetOrCreate(other)
		_, err := p.Acquire(context.Background())
		assert.ErrorIs(t, err, ErrPoolEmpty, "pool %s must not see org-a credentials", other)
	}
}

func TestCredentialPool_MarkUnavailable_SkipsAndPoolContinues(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, clock := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	for _, id := range []string{"c1", "c2", "c3"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Source: sourceFor("key-" + id)}))
	}
	require.True(t, p.MarkUnavailable("c1", base.Add(time.Hour), "cooldown_test"))

	// Pool keeps working: RR over the remaining two, c1 never picked.
	for range 6 {
		lease, err := p.Acquire(context.Background())
		require.NoError(t, err)
		assert.NotEqual(t, "c1", lease.Ref().ID)
	}
	snap := p.Snapshot()
	require.Len(t, snap.Members, 3)
	for _, m := range snap.Members {
		switch m.Ref.ID {
		case "c1":
			assert.False(t, m.InRotation)
			assert.Equal(t, "cooldown_test", m.UnavailableReason)
			assert.Equal(t, base.Add(time.Hour), m.RecoversAt)
		default:
			assert.True(t, m.InRotation)
			assert.Equal(t, uint64(3), m.Acquires)
		}
	}

	// Advance past c1's deadline: expiry recovery is evaluated at pick time.
	*clock = base.Add(time.Hour)
	// Take every member out of rotation again with staggered deadlines.
	require.True(t, p.MarkUnavailable("c1", base.Add(3*time.Hour), "cooldown_test"))
	require.True(t, p.MarkUnavailable("c2", base.Add(2*time.Hour), "cooldown_test"))
	require.True(t, p.MarkUnavailable("c3", base.Add(4*time.Hour), "cooldown_test"))

	// Exhausted state is typed and fail-closed, never an internal retry.
	_, err := p.Acquire(context.Background())
	var exhausted *PoolExhaustedError
	require.ErrorAs(t, err, &exhausted)
	assert.Equal(t, base.Add(2*time.Hour), exhausted.EarliestRecovery)
	assert.NotContains(t, exhausted.Error(), "key-", "error must stay secret-free")

	// Manual recovery of one member unblocks the pool again.
	require.True(t, p.MarkRecovered("c2"))
	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c2", lease.Ref().ID)
}

func TestCredentialPool_CooldownExpiry_AutoRecovery(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, clock := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	for _, id := range []string{"c1", "c2"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Source: sourceFor("key-" + id)}))
	}
	require.True(t, p.MarkUnavailable("c1", base.Add(time.Minute), "cooldown_test"))

	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c2", lease.Ref().ID, "c1 is out of rotation")

	// Boundary parity with the store SQL: deadline == now is expired.
	*clock = base.Add(time.Minute)
	recovered, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c1", recovered.Ref().ID, "recovered key returns to rotation at its deadline")
	// Membership did not grow: recovery flips state, never re-inserts.
	assert.Equal(t, 2, p.Len())
	next, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c2", next.Ref().ID, "RR continues after recovery without re-insertion gaps")
}

func TestCredentialPool_ManualRecover_ImmediateReturn(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	for _, id := range []string{"c1", "c2"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Source: sourceFor("key-" + id)}))
	}
	require.True(t, p.MarkUnavailable("c1", base.Add(24*time.Hour), "manual_test"))

	// Manual reset returns the key before its cooldown expires...
	require.True(t, p.MarkRecovered("c1"))
	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c1", lease.Ref().ID)

	// ...idempotently...
	require.True(t, p.MarkRecovered("c1"))
	assert.True(t, p.Snapshot().Members[0].InRotation)

	// ...and unknown ids report false instead of mutating anything.
	assert.False(t, p.MarkRecovered("ghost"))
	assert.False(t, p.MarkUnavailable("ghost", base, "x"))
	assert.False(t, p.Remove("ghost"))
}

func TestCredentialPool_FetchFailure_PropagatesWithoutPoolMutation(t *testing.T) {
	p := NewCredentialPool(credKey("org-1", "openai-compat", "https://u.local"))
	boom := errors.New("decrypt unavailable")
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "9999", Source: func(context.Context) (string, error) {
		return "", boom
	}}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Source: sourceFor("key-c2")}))

	_, err := p.Acquire(context.Background())
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "cred=c1", "ref is included")
	assert.NotContains(t, err.Error(), "key-c2")
	// No internal retry, no state change: the next pick continues RR at c2.
	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c2", lease.Ref().ID)
	assert.Equal(t, 2, p.Len())
}

func TestCredentialPool_Removal_ExcludesNewPicks_ActiveLeaseSurvives(t *testing.T) {
	p := NewCredentialPool(credKey("org-1", "openai-compat", "https://u.local"))
	for _, id := range []string{"c1", "c2"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Source: sourceFor("key-" + id)}))
	}
	lease, err := p.Acquire(context.Background()) // c1 in flight
	require.NoError(t, err)
	require.True(t, p.Remove("c1"))
	// In-flight attempt keeps its resolved plaintext ("активные доживают").
	assert.Equal(t, "key-c1", lease.Plaintext())
	for range 4 {
		next, err := p.Acquire(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "c2", next.Ref().ID)
	}
	assert.Equal(t, 1, p.Len())
}

func TestCredentialPool_Rotation_PreservesPoolIdentity_PositionAndCounters(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "1111", KeyVersion: 1, Source: sourceFor("key-c1-v1")}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "2222", KeyVersion: 1, Source: sourceFor("key-c2-v1")}))

	first, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "c1", first.Ref().ID)

	// Rotate c1 (adminstore Update + newPlaintextKey, key_version++).
	require.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c1", Last4: "1111", KeyVersion: 2, Source: sourceFor("key-c1-v2")}))

	second, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c2", second.Ref().ID, "rotation preserves the RR position")
	third, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c1", third.Ref().ID)
	assert.Equal(t, 2, third.Ref().KeyVersion, "rotated version is served")
	assert.Equal(t, "key-c1-v2", third.Plaintext())
	assert.Equal(t, 2, p.Len(), "rotation does not duplicate membership")
	assert.Equal(t, credKey("org-1", "openai-compat", "https://u.local"), third.Pool(), "pool identity unchanged")
}

func TestCredentialPool_Secrets_NeverInStringOrErrors(t *testing.T) {
	const secret = "sk-live-SUPERSECRETVALUE-42" //nolint:gosec // G101: synthetic leak-probe secret, not a credential
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0042", KeyVersion: 7, Source: sourceFor(secret)}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0043", Source: sourceFor("sk-c2-secret")}))

	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, secret, lease.Plaintext())

	formats := []string{
		fmt.Sprint(lease),
		fmt.Sprintf("%v", lease),
		fmt.Sprintf("%+v", lease),
		fmt.Sprintf("%#v", lease),
		fmt.Sprintf("%s", lease), //nolint:staticcheck // S1025: the Stringer probe must exercise the %s formatting path itself
		fmt.Sprint(lease.Ref()),
		fmt.Sprint(p.Snapshot()),
		fmt.Sprintf("%+v", p.Snapshot()),
		fmt.Sprint(p.Key()),
	}
	for _, f := range formats {
		assert.NotContains(t, f, secret, "formatted output must not leak the plaintext: %s", f)
		assert.NotContains(t, f, "sk-c2-secret", "formatted output must not leak any plaintext: %s", f)
	}

	// Exhausted state stays secret-free too.
	require.True(t, p.MarkUnavailable("c1", base.Add(time.Hour), "cooldown_test"))
	require.True(t, p.MarkUnavailable("c2", base.Add(2*time.Hour), "cooldown_test"))
	_, err = p.Acquire(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.NotContains(t, err.Error(), "sk-c2-secret")
}

// TestCredentialPool_ConcurrentAcquireRecoverRotate is the -race workhorse:
// concurrent acquires over a pool whose members are concurrently cooled
// down, recovered (auto-expiry + manual reset) and rotated. Invariants:
//   - every pick returns a credential of THIS pool with its matching
//     plaintext (identity binding through rotation and recovery);
//   - every pick is accounted exactly once (no lost/double pick);
//   - membership never grows (recovery never re-inserts a member);
//   - the pool identity triple is preserved on every lease.
func TestCredentialPool_ConcurrentAcquireRecoverRotate(t *testing.T) {
	p := NewCredentialPool(credKey("org-1", "openai-compat", "https://u.local"))
	ids := []string{"c1", "c2", "c3", "c4"}
	for _, id := range ids {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Last4: "0000", KeyVersion: 1, Source: sourceFor("key-" + id + "-v1")}))
	}

	const workers = 8
	const perWorker = 300

	var mu sync.Mutex
	picks := make(map[string]int)                // cred id -> pick count
	versionPicks := make(map[string]map[int]int) // cred id -> key version -> count
	var totalPicks int

	stop := make(chan struct{})
	var churners sync.WaitGroup

	// Churner 1: cooldown + auto-expiry cycles on c1 (short real-time
	// deadlines exercise the expiry path under concurrency).
	churners.Add(1)
	go func() {
		defer churners.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			assert.True(t, p.MarkUnavailable("c1", time.Now().Add(time.Microsecond), "churn"))
			time.Sleep(time.Microsecond)
		}
	}()
	// Churner 2: manual reset racing cooldown expiry on c4.
	churners.Add(1)
	go func() {
		defer churners.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			assert.True(t, p.MarkUnavailable("c4", time.Now().Add(time.Hour), "churn"))
			assert.True(t, p.MarkRecovered("c4"))
			time.Sleep(time.Microsecond)
		}
	}()
	// Churner 3: rotation of c3 (key_version 1 <-> 2, same pool identity).
	churners.Add(1)
	go func() {
		defer churners.Done()
		v := 1
		for {
			select {
			case <-stop:
				return
			default:
			}
			next, src := 1, "key-c3-v1"
			if v == 1 {
				next, src = 2, "key-c3-v2"
			}
			if assert.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c3", Last4: "0000", KeyVersion: next, Source: sourceFor(src)})) {
				v = next
			}
			time.Sleep(time.Microsecond)
		}
	}()

	var workersWG sync.WaitGroup
	for range workers {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for range perWorker {
				lease, err := p.Acquire(context.Background())
				if err != nil {
					t.Errorf("acquire failed: %v", err)
					return
				}
				ref := lease.Ref()
				mu.Lock()
				picks[ref.ID]++
				if versionPicks[ref.ID] == nil {
					versionPicks[ref.ID] = make(map[int]int)
				}
				versionPicks[ref.ID][ref.KeyVersion]++
				totalPicks++
				mu.Unlock()
				// Identity binding: the plaintext must match the picked
				// credential AND its observed key version (c3 rotates).
				want, ok := plaintextFor(ref)
				if !ok || lease.Plaintext() != want {
					t.Errorf("identity binding broken: credential %s v%d served %q, want %q", ref.ID, ref.KeyVersion, lease.Plaintext(), want)
					return
				}
				if lease.Pool() != p.Key() {
					t.Errorf("pool identity drifted: %s", lease.Pool())
					return
				}
			}
		}()
	}

	// Workers are bounded (workers × perWorker in-memory ops); wait for them
	// first, then stop the churners so the final accounting is deterministic.
	workersWG.Wait()
	close(stop)
	churners.Wait()

	assert.Equal(t, workers*perWorker, totalPicks)
	sum := 0
	for _, n := range picks {
		sum += n
	}
	assert.Equal(t, workers*perWorker, sum, "every pick is accounted exactly once")

	snap := p.Snapshot()
	assert.Len(t, snap.Members, len(ids), "membership never grows: recovery must not re-insert members")
	assert.Equal(t, uint64(workers*perWorker), snap.Acquires)
	seen := make(map[string]bool, len(ids))
	for _, m := range snap.Members {
		seen[m.Ref.ID] = true
		versionSum := 0
		for _, n := range versionPicks[m.Ref.ID] {
			versionSum += n
		}
		assert.Equal(t, picks[m.Ref.ID], versionSum, "version accounting must sum to pick accounting for %s", m.Ref.ID)
	}
	for _, id := range ids {
		assert.True(t, seen[id], "member %s missing from final snapshot", id)
		assert.Positive(t, picks[id], "every member served traffic")
	}
}

// plaintextFor maps a picked credential reference to the plaintext its
// registered source returns for that version (c3 is rotated between v1/v2,
// all other members stay at v1).
func plaintextFor(ref CredentialRef) (string, bool) {
	switch {
	case ref.ID == "c3" && ref.KeyVersion == 1:
		return "key-c3-v1", true
	case ref.ID == "c3" && ref.KeyVersion == 2:
		return "key-c3-v2", true
	case ref.KeyVersion == 1:
		return "key-" + ref.ID + "-v1", true
	default:
		return "", false
	}
}

func TestCredentialPools_GetOrCreate_Concurrent_SameInstance(t *testing.T) {
	reg := NewCredentialPools()
	key := credKey("org-1", "openai-compat", "https://u.local")
	p0 := reg.GetOrCreate(key)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if reg.GetOrCreate(key) != p0 {
				t.Error("GetOrCreate returned different instances for the same key")
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, reg.Len())

	// Remove detaches; a later GetOrCreate builds a fresh, empty pool while
	// the detached one keeps serving existing leases.
	require.True(t, reg.Remove(key))
	assert.False(t, reg.Remove(key))
	fresh := reg.GetOrCreate(key)
	assert.NotSame(t, p0, fresh)
	_, err := fresh.Acquire(context.Background())
	assert.ErrorIs(t, err, ErrPoolEmpty)
}

func TestCredentialPool_ExhaustedError_Format(t *testing.T) {
	key := credKey("org-1", "openai-compat", "https://u.local")
	e := &PoolExhaustedError{Pool: key}
	assert.True(t, strings.HasPrefix(e.Error(), "credential pool org=org-1"))
	assert.Contains(t, e.Error(), "out of rotation")

	e2 := &PoolExhaustedError{Pool: key, EarliestRecovery: time.Date(2026, 10, 28, 13, 0, 0, 0, time.UTC)}
	assert.Contains(t, e2.Error(), "earliest recovery 2026-10-28T13:00:00Z")
}

// snapshotMemberByID finds one member in the pool's secret-free snapshot.
func snapshotMemberByID(p *CredentialPool, id string) (CredentialSnapshot, bool) {
	for _, m := range p.Snapshot().Members {
		if m.Ref.ID == id {
			return m, true
		}
	}
	return CredentialSnapshot{}, false
}

func TestCredentialPool_ReportOutcome_Classification(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name        string
		status      int
		quarantines bool
		reason      string
	}{
		{"ok", 200, false, ""},
		{"created", 201, false, ""},
		{"bad request is not a key fault", 400, false, ""},
		{"payment required", 402, false, ""},
		{"forbidden may be a scope problem", 403, false, ""},
		{"not found", 404, false, ""},
		{"conflict", 409, false, ""},
		{"unauthorized quarantines", 401, true, QuarantineReasonUnauthorized},
		{"throttled quarantines", 429, true, QuarantineReasonThrottled},
		{"internal error", 500, false, ""},
		{"bad gateway", 502, false, ""},
		{"service unavailable", 503, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
			require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-c1")}))
			require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: sourceFor("key-c2")}))
			lease, err := p.Acquire(context.Background())
			require.NoError(t, err)
			require.Equal(t, "c1", lease.Ref().ID)

			require.True(t, p.ReportOutcome(lease, tc.status))

			m, ok := snapshotMemberByID(p, "c1")
			require.True(t, ok)
			if tc.quarantines {
				assert.False(t, m.InRotation)
				assert.Equal(t, tc.reason, m.UnavailableReason)
				assert.Equal(t, QuarantineDeadline(base), m.RecoversAt)
				// The pool keeps serving: the sibling takes the traffic.
				next, err := p.Acquire(context.Background())
				require.NoError(t, err)
				assert.Equal(t, "c2", next.Ref().ID)
			} else {
				assert.True(t, m.InRotation, "non-quarantining status must not take the key out")
				assert.Empty(t, m.UnavailableReason)
				assert.True(t, m.RecoversAt.IsZero())
			}
		})
	}
}

// TestCredentialPool_ReportOutcome_InvalidKeyNotRetried_PoolContinues is the
// negative acceptance: a key that drew a 401 is never picked again, the pool
// continues serving with the remaining keys (no retry loop, no exhausted
// false positive), and a manual reset returns the recovered key without
// membership growth.
func TestCredentialPool_ReportOutcome_InvalidKeyNotRetried_PoolContinues(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	for _, id := range []string{"c1", "c2", "c3"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Last4: "0000", KeyVersion: 1, Source: sourceFor("key-" + id)}))
	}

	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "c1", lease.Ref().ID)
	require.True(t, p.ReportOutcome(lease, 401))

	for range 10 {
		got, err := p.Acquire(context.Background())
		require.NoError(t, err)
		assert.NotEqual(t, "c1", got.Ref().ID, "a 401-quarantined key must not be retried")
	}
	assert.Equal(t, 3, p.Len(), "quarantine must not change membership")

	require.True(t, p.MarkRecovered("c1"))
	back, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c1", back.Ref().ID, "manual reset returns the recovered key")
}

func TestCredentialPool_ReportOutcome_PoolBindingAndIsolation(t *testing.T) {
	poolA := NewCredentialPool(credKey("org-a", "openai-compat", "https://u.local"))
	poolB := NewCredentialPool(credKey("org-b", "openai-compat", "https://u.local"))
	for _, p := range []*CredentialPool{poolA, poolB} {
		// Same credential id registered for two orgs: pools are isolated by
		// their identity triple, never by credential identity.
		require.NoError(t, p.Add(CredentialSpec{ID: "shared-id", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-shared")}))
		require.NoError(t, p.Add(CredentialSpec{ID: "own-" + p.Key().OrgID, Last4: "0002", KeyVersion: 1, Source: sourceFor("key-" + p.Key().OrgID)}))
	}

	leaseA, err := poolA.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "shared-id", leaseA.Ref().ID)

	// A lease reports only to its own pool: B rejects the report and both of
	// B's credentials stay in rotation.
	assert.False(t, poolB.ReportOutcome(leaseA, 401), "a lease from another pool must be rejected")
	mB, ok := snapshotMemberByID(poolB, "shared-id")
	require.True(t, ok)
	assert.True(t, mB.InRotation, "cross-pool report must not quarantine the same-id credential of another org")

	require.True(t, poolA.ReportOutcome(leaseA, 401))
	mA, ok := snapshotMemberByID(poolA, "shared-id")
	require.True(t, ok)
	assert.False(t, mA.InRotation)

	// Non-quarantining statuses are accepted no-ops for the lease's own pool.
	leaseB, err := poolB.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "shared-id", leaseB.Ref().ID, "pool B's round-robin starts at its own shared-id")
	require.True(t, poolB.ReportOutcome(leaseB, 503))
	mB2, ok := snapshotMemberByID(poolB, leaseB.Ref().ID)
	require.True(t, ok)
	assert.True(t, mB2.InRotation, "no-op report must not change availability")
	// ...and rejected outright for a foreign pool.
	assert.False(t, poolA.ReportOutcome(leaseB, 503))

	// Unknown credential ids report false instead of mutating anything.
	require.True(t, poolB.Remove(leaseB.Ref().ID))
	assert.False(t, poolB.ReportOutcome(leaseB, 429))
	assert.False(t, poolB.ReportOutcome(leaseB, 200))

	// Nil lease and nil pool never panic and never mutate.
	assert.False(t, poolA.ReportOutcome(nil, 401))
	var nilPool *CredentialPool
	assert.False(t, nilPool.ReportOutcome(leaseA, 401))
	assert.Equal(t, 2, poolA.Len(), "nil reports must not change membership")
}

func TestQuarantineDeadline_Boundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		now   time.Time
		until time.Time
	}{
		{"first second of the day", time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)},
		{"mid-day", time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC), time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)},
		{"last nanosecond before midnight", time.Date(2026, 10, 28, 23, 59, 59, 999999999, time.UTC), time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)},
		{"exact midnight rolls to the next day", time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)},
		{"year boundary", time.Date(2026, 12, 31, 18, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"leap day", time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC), time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			until := QuarantineDeadline(tc.now)
			assert.Equal(t, tc.until, until)
			assert.LessOrEqual(t, until.Sub(tc.now), 24*time.Hour, "quarantine must never exceed one day")
			assert.Positive(t, until.Sub(tc.now), "the deadline must lie in the future of now")
		})
	}
	// Non-UTC input normalizes to the UTC day boundary.
	local := time.Date(2026, 10, 28, 20, 0, 0, 0, time.FixedZone("X", 5*3600))
	assert.Equal(t, time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), QuarantineDeadline(local))
}

// TestCredentialPool_ReportOutcome_RecoversAtUTCMidnight pins the full
// deadline story: both keys 429-quarantined late in the day produce the
// fail-closed exhaustion with the midnight horizon, and the keys return to
// rotation exactly at the deadline (pick-time evaluation, no goroutine).
func TestCredentialPool_ReportOutcome_RecoversAtUTCMidnight(t *testing.T) {
	base := time.Date(2026, 10, 28, 23, 59, 59, 0, time.UTC)
	p, clock := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-c1")}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: sourceFor("key-c2")}))

	lease1, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "c1", lease1.Ref().ID)
	require.True(t, p.ReportOutcome(lease1, 429))
	lease2, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "c2", lease2.Ref().ID)
	require.True(t, p.ReportOutcome(lease2, 401))

	_, err = p.Acquire(context.Background())
	var exhausted *PoolExhaustedError
	require.ErrorAs(t, err, &exhausted)
	assert.Equal(t, time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), exhausted.EarliestRecovery)
	assert.NotContains(t, exhausted.Error(), "key-", "exhaustion stays secret-free")

	// deadline == now is the expired boundary: the keys are picked again.
	*clock = base.Add(time.Second)
	back, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c1", back.Ref().ID)
	assert.Equal(t, 2, p.Len(), "recovery flips state, never re-inserts")
}

func TestCredentialPool_UpsertCredential_VersionScopedQuarantineLift(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-c1-v1")}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: sourceFor("key-c2-v1")}))

	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "c1", lease.Ref().ID)
	require.True(t, p.ReportOutcome(lease, 401))
	require.False(t, p.Snapshot().Members[0].InRotation)

	// Same version (a source re-registration): the quarantine persists —
	// the stored state belongs to the stored key version.
	require.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-c1-v1-again")}))
	m, ok := snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.False(t, m.InRotation, "same-version upsert must not lift the quarantine")
	assert.Equal(t, QuarantineReasonUnauthorized, m.UnavailableReason)
	got, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c2", got.Ref().ID)

	// Rotation (key_version++): a new key is a new key — immediate lift.
	require.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 2, Source: sourceFor("key-c1-v2")}))
	rotated, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c1", rotated.Ref().ID, "the rotated key returns to rotation immediately")
	assert.Equal(t, 2, rotated.Ref().KeyVersion)
	assert.Equal(t, "key-c1-v2", rotated.Plaintext())
	m, ok = snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.True(t, m.InRotation)
	assert.Empty(t, m.UnavailableReason)
	assert.True(t, m.RecoversAt.IsZero())
	assert.Equal(t, 2, p.Len(), "rotation never duplicates membership")
}

// TestCredentialPool_ReportOutcome_ConcurrentChurn races the quarantine
// policy against acquires, manual resets and rotation: two keys draw 401s
// while a reset churner frees them, a third key rotates its key version, and
// the same-id twin pool must reject every foreign report. Invariants:
// identity binding, exact pick accounting, stable membership.
func TestCredentialPool_ReportOutcome_ConcurrentChurn(t *testing.T) {
	p := NewCredentialPool(credKey("org-1", "openai-compat", "https://u.local"))
	other := NewCredentialPool(credKey("org-2", "openai-compat", "https://u.local"))
	ids := []string{"c1", "c2", "c3", "c4"}
	for _, id := range ids {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Last4: "0000", KeyVersion: 1, Source: sourceFor("key-" + id + "-v1")}))
		require.NoError(t, other.Add(CredentialSpec{ID: id, Last4: "0000", KeyVersion: 1, Source: sourceFor("key-" + id + "-v1")}))
	}

	const workers = 6
	const perWorker = 200

	var mu sync.Mutex
	picks := make(map[string]uint64)
	var totalPicks uint64

	stop := make(chan struct{})
	var churners sync.WaitGroup

	// Churner: manual resets free the quarantined keys so c1/c2 keep
	// re-entering rotation under the 401 workload.
	churners.Add(1)
	go func() {
		defer churners.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, id := range ids {
				p.MarkRecovered(id)
			}
			time.Sleep(time.Microsecond)
		}
	}()
	// Churner: c3 rotates between v1/v2 — quarantines must lift on version
	// change and the identity binding must hold per version.
	churners.Add(1)
	go func() {
		defer churners.Done()
		v := 1
		for {
			select {
			case <-stop:
				return
			default:
			}
			next, src := 2, "key-c3-v2"
			if v == 2 {
				next, src = 1, "key-c3-v1"
			}
			if p.UpsertCredential(CredentialSpec{ID: "c3", Last4: "0000", KeyVersion: next, Source: sourceFor(src)}) == nil {
				v = next
			}
			time.Sleep(time.Microsecond)
		}
	}()

	var workersWG sync.WaitGroup
	for range workers {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for range perWorker {
				lease, err := p.Acquire(context.Background())
				if err != nil {
					var exhausted *PoolExhaustedError
					if errors.As(err, &exhausted) {
						continue // legal transient: every member momentarily out
					}
					t.Errorf("acquire failed: %v", err)
					return
				}
				ref := lease.Ref()
				if lease.Pool() != p.Key() {
					t.Errorf("pool identity drifted: %s", lease.Pool())
					return
				}
				// Same-id credentials of the other pool must reject the
				// foreign lease under any interleaving.
				if other.ReportOutcome(lease, 401) {
					t.Errorf("cross-pool quarantine accepted for %s", ref.ID)
					return
				}
				// c1/c2 draw quarantining outcomes, c3/c4 no-ops.
				status := 401
				if ref.ID == "c3" || ref.ID == "c4" {
					status = 200
				}
				if !p.ReportOutcome(lease, status) {
					t.Errorf("own-pool report rejected for %s", ref.ID)
					return
				}
				mu.Lock()
				picks[ref.ID]++
				totalPicks++
				mu.Unlock()
			}
		}()
	}

	workersWG.Wait()
	close(stop)
	churners.Wait()

	assert.Equal(t, uint64(workers*perWorker), totalPicks, "every successful pick is accounted exactly once")
	snap := p.Snapshot()
	assert.Len(t, snap.Members, len(ids), "membership never grows")
	var memberAcquires uint64
	seen := make(map[string]bool, len(ids))
	for _, m := range snap.Members {
		seen[m.Ref.ID] = true
		memberAcquires += m.Acquires
	}
	assert.Equal(t, uint64(totalPicks), snap.Acquires)
	assert.Equal(t, uint64(totalPicks), memberAcquires, "pool and per-member counters agree")
	for _, id := range ids {
		assert.True(t, seen[id], "member %s missing from the final snapshot", id)
	}
}

func TestCredentialRef_AttributionRef(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  CredentialRef
		want string
	}{
		{"long id with last4 mask", CredentialRef{ID: "3f2ac1b2-9c11-4e5f-8a1b-2c3d4e5f6a7b", Last4: "9c11", KeyVersion: 3}, "3f2ac1b2:9c11"},
		{"id exactly eight characters", CredentialRef{ID: "12345678", Last4: "0001", KeyVersion: 1}, "12345678:0001"},
		{"short id keeps its length", CredentialRef{ID: "abc", Last4: "1234", KeyVersion: 1}, "abc:1234"},
		{"long id without a mask is truncated", CredentialRef{ID: "3f2ac1b2-9c11", KeyVersion: 1}, "3f2ac1b2"},
		{"empty mask leaves the truncated id alone", CredentialRef{ID: "abcdefgh", KeyVersion: 1}, "abcdefgh"},
		{"empty id attributes nothing", CredentialRef{ID: "", Last4: "1234", KeyVersion: 1}, ""},
		{"zero ref is empty", CredentialRef{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.ref.AttributionRef()
			assert.Equal(t, tc.want, got)
			if len(tc.ref.ID) > 8 {
				assert.NotEqual(t, tc.ref.ID, got, "the full id must never be attributed")
				assert.NotContains(t, got, tc.ref.ID[8:], "the id tail must never leak past the mask")
			}
		})
	}
	// The key version is configuration metadata, not part of the attribution
	// identity: one credential attributes identically across its rotations.
	assert.Equal(t, "3f2ac1b2:9c11",
		CredentialRef{ID: "3f2ac1b2-9c11-4e5f-8a1b-2c3d4e5f6a7b", Last4: "9c11", KeyVersion: 7}.AttributionRef())
}

// TestLease_AttributionRef_MaskedStableAcrossRotation: a lease attributes the
// masked pick-time identity — never the plaintext, never a sibling's key,
// and frozen against a concurrent rotation (a usage event must describe the
// attempt that happened, not the store's current state). A nil lease
// attributes nothing (the no-org-credential event shape) instead of panicking.
func TestLease_AttributionRef_MaskedStableAcrossRotation(t *testing.T) {
	const secret = "sk-live-ATTRIBUTION-PROBE-VALUE" //nolint:gosec // G101: synthetic leak-probe secret, not a credential
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{
		ID:         "3f2ac1b2-9c11-4e5f-8a1b-2c3d4e5f6a7b",
		Last4:      "9c11",
		KeyVersion: 1,
		Source:     sourceFor(secret),
	}))
	require.NoError(t, p.Add(CredentialSpec{
		ID:         "aaaaaaaa-bbbb-cccc-dddd-000000000002",
		Last4:      "0002",
		KeyVersion: 1,
		Source:     sourceFor("sk-c2-plain"),
	}))

	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "3f2ac1b2-9c11-4e5f-8a1b-2c3d4e5f6a7b", lease.Ref().ID)
	assert.Equal(t, "3f2ac1b2:9c11", lease.AttributionRef())
	assert.NotContains(t, lease.AttributionRef(), secret, "attribution must never carry the plaintext")
	assert.NotContains(t, lease.AttributionRef(), "sk-c2-plain", "attribution must never carry any plaintext")

	// Rotate the served credential under the in-flight lease: the attribution
	// stays the picked one (last4 and version of the attempt, not the store).
	require.NoError(t, p.UpsertCredential(CredentialSpec{
		ID:         "3f2ac1b2-9c11-4e5f-8a1b-2c3d4e5f6a7b",
		Last4:      "7777",
		KeyVersion: 2,
		Source:     sourceFor("sk-rotated-plain"),
	}))
	assert.Equal(t, "3f2ac1b2:9c11", lease.AttributionRef(), "in-flight attribution must not follow the rotation")

	// Fresh picks attribute with the rotated mask and version.
	sibling, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "aaaaaaaa:0002", sibling.AttributionRef())
	rotated, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "3f2ac1b2:7777", rotated.AttributionRef())
	assert.Equal(t, 2, rotated.Ref().KeyVersion)
	assert.NotContains(t, rotated.AttributionRef(), "sk-rotated-plain")

	var nilLease *Lease
	assert.Empty(t, nilLease.AttributionRef())
}

// TestCredentialPool_Attribution_PoolContinuesRecoversNoDisclosure is the
// attribution acceptance over the quarantine lifecycle: while the pool keeps
// serving (401 quarantine, sibling failover, manual reset of the recovered
// key) every pick yields exactly one masked attribution, no attribution ever
// carries key material, and the per-member counters account every pick.
func TestCredentialPool_Attribution_PoolContinuesRecoversNoDisclosure(t *testing.T) {
	const secret1 = "sk-live-POOL-PROBE-VALUE" //nolint:gosec // G101: synthetic leak-probe secret, not a credential
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	specs := []CredentialSpec{
		{ID: "aaaaaaaa-1111-4111-8111-111111111111", Last4: "0001", KeyVersion: 1, Source: sourceFor(secret1)},
		{ID: "bbbbbbbb-2222-4222-8222-222222222222", Last4: "0002", KeyVersion: 1, Source: sourceFor("sk-c2-plain")},
		{ID: "cccccccc-3333-4333-8333-333333333333", Last4: "0003", KeyVersion: 1, Source: sourceFor("sk-c3-plain")},
	}
	for _, spec := range specs {
		require.NoError(t, p.Add(spec))
	}
	attributed := make([]string, 0, 16)
	record := func(l *Lease) string {
		ref := l.AttributionRef()
		attributed = append(attributed, ref)
		return ref
	}

	lease1, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, specs[0].ID, lease1.Ref().ID)
	assert.Equal(t, "aaaaaaaa:0001", record(lease1))
	require.True(t, p.ReportOutcome(lease1, 401))

	// The pool continues on the siblings; the quarantined credential is
	// attributed exactly zero times while it is out.
	for range 10 {
		got, err := p.Acquire(context.Background())
		require.NoError(t, err)
		ref := record(got)
		assert.Contains(t, []string{"bbbbbbbb:0002", "cccccccc:0003"}, ref, "only in-rotation credentials are attributed")
		assert.NotEqual(t, "aaaaaaaa:0001", ref, "the quarantined credential must not be attributed")
	}

	// The operator reset returns the recovered key and its attribution.
	require.True(t, p.MarkRecovered(specs[0].ID))
	back, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "aaaaaaaa:0001", record(back), "the recovered key is attributed again")
	assert.Equal(t, secret1, back.Plaintext(), "attribution masking must not disturb plaintext binding")

	for _, ref := range attributed {
		assert.NotContains(t, ref, secret1, "no attribution carries key material")
		assert.NotContains(t, ref, "sk-c2-plain", "no attribution carries key material")
		assert.NotContains(t, ref, "sk-c3-plain", "no attribution carries key material")
	}
	assert.Equal(t, 3, p.Len(), "attribution never changes membership")

	snap := p.Snapshot()
	assert.Len(t, snap.Members, 3)
	assert.Equal(t, uint64(len(attributed)), snap.Acquires, "every pick is attributed exactly once")
	for _, m := range snap.Members {
		switch m.Ref.ID {
		case specs[0].ID:
			assert.Equal(t, uint64(2), m.Acquires)
		case specs[1].ID, specs[2].ID:
			assert.Positive(t, m.Acquires)
			assert.Equal(t, m.Ref.ID[:8]+":"+m.Ref.Last4, m.Ref.AttributionRef(), "masked shape holds in the snapshot too")
		}
	}
}

// TestCredentialPool_Attribution_ConcurrentChurn races attribution
// collection against quarantine feedback and operator resets: under any
// interleaving every pick's attribution keeps the masked id8:last4 shape,
// stays bound to the picked credential's plaintext, rejects cross-pool
// reports, and the final counters agree exactly. A bounded reset-all tail
// proves the recovered keys attribute again without membership growth.
func TestCredentialPool_Attribution_ConcurrentChurn(t *testing.T) {
	p := NewCredentialPool(credKey("org-1", "openai-compat", "https://u.local"))
	other := NewCredentialPool(credKey("org-2", "openai-compat", "https://u.local"))
	type member struct {
		id, last4, secret, ref string
	}
	members := []member{
		{"aaaaaaaa-1111-4111-8111-111111111111", "0001", "sk-pool-attr-one", "aaaaaaaa:0001"},
		{"bbbbbbbb-2222-4222-8222-222222222222", "0002", "sk-pool-attr-two", "bbbbbbbb:0002"},
		{"cccccccc-3333-4333-8333-333333333333", "0003", "sk-pool-attr-three", "cccccccc:0003"},
		{"dddddddd-4444-4444-8444-444444444444", "0004", "sk-pool-attr-four", "dddddddd:0004"},
	}
	byRef := make(map[string]member, len(members))
	for _, m := range members {
		spec := CredentialSpec{ID: m.id, Last4: m.last4, KeyVersion: 1, Source: sourceFor(m.secret)}
		require.NoError(t, p.Add(spec))
		require.NoError(t, other.Add(spec))
		byRef[m.ref] = m
	}

	const workers = 4
	const perWorker = 200

	var mu sync.Mutex
	refCounts := make(map[string]uint64)
	var totalPicks uint64

	stop := make(chan struct{})
	var churners sync.WaitGroup
	// Churner: operator resets lift the 401 quarantines of the first two
	// credentials while the workers keep drawing unauthorized outcomes.
	churners.Add(1)
	go func() {
		defer churners.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.MarkRecovered(members[0].id)
			p.MarkRecovered(members[1].id)
			time.Sleep(time.Microsecond)
		}
	}()

	var workersWG sync.WaitGroup
	for range workers {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for range perWorker {
				lease, err := p.Acquire(context.Background())
				if err != nil {
					t.Errorf("acquire failed (the no-op members must keep the pool serving): %v", err)
					return
				}
				ref := lease.AttributionRef()
				m, ok := byRef[ref]
				if !ok {
					t.Errorf("unattributable or malformed reference %q", ref)
					return
				}
				if lease.Plaintext() != m.secret {
					t.Errorf("attribution %q is not bound to its credential's plaintext", ref)
					return
				}
				// Same-id credentials of the other org stay isolated.
				if other.ReportOutcome(lease, 401) {
					t.Errorf("cross-pool report accepted for %q", ref)
					return
				}
				// aaaa/bbbb churn 401s; the no-op members keep serving.
				status := 200
				if ref == members[0].ref || ref == members[1].ref {
					status = 401
				}
				if !p.ReportOutcome(lease, status) {
					t.Errorf("own-pool report rejected for %q", ref)
					return
				}
				mu.Lock()
				refCounts[ref]++
				totalPicks++
				mu.Unlock()
			}
		}()
	}

	// Bounded workers first, then stop the churners for a deterministic tail.
	workersWG.Wait()
	close(stop)
	churners.Wait()

	for _, m := range members {
		require.True(t, p.MarkRecovered(m.id), "reset %s", m.id)
	}
	snap := p.Snapshot()
	assert.Len(t, snap.Members, len(members), "membership never grows")
	assert.Equal(t, totalPicks, snap.Acquires, "every pick is accounted exactly once")
	for _, m := range snap.Members {
		assert.Equal(t, refCounts[m.Ref.AttributionRef()], m.Acquires,
			"per-reference attribution must equal the member's pick count for %s", m.Ref.ID)
	}
	for _, m := range members {
		assert.Positive(t, refCounts[m.ref], "every credential served and was attributed")
		got, err := p.Acquire(context.Background())
		require.NoError(t, err)
		assert.NotContains(t, got.AttributionRef(), m.secret, "attribution stays secret-free after recovery")
	}
}

// countingSource wraps a plaintext source with a pick-time invocation
// counter: a credential that is out of rotation must never even reach its
// resolver (zero plaintext fetches while quarantined).
type countingSource struct {
	calls int
	key   string
}

func (s *countingSource) source(context.Context) (string, error) {
	s.calls++
	return s.key, nil
}

// TestQuarantinableStatus_AdversarialStatuses: only 401 and 429 quarantine —
// non-standard, malformed and adjacent statuses must never take a key out of
// rotation and must never produce a reason tag.
func TestQuarantinableStatus_AdversarialStatuses(t *testing.T) {
	for _, status := range []int{
		-1, 0, 99, 100, 199, 226, 301, 400, 402, 403, 404, 405, 407, 408, 409,
		410, 418, 422, 425, 431, 451, 499, 500, 502, 503, 504, 511, 529, 999,
	} {
		assert.False(t, QuarantinableStatus(status), "status %d must not quarantine", status)
		assert.Empty(t, QuarantineReason(status), "status %d must not produce a reason tag", status)
	}
}

// TestCredentialPool_ReportOutcome_NoOutcomeLiftsQuarantine is the cooldown
// bypass battery: once a key is 401-quarantined, no stream of later outcomes
// (in-flight attempts completing with 200, infra 5xx, or even repeated 401
// re-reports) may resurrect it. Only the authorized lifts exist: manual
// reset, key-version rotation and deadline expiry.
func TestCredentialPool_ReportOutcome_NoOutcomeLiftsQuarantine(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	c1 := &countingSource{key: "key-c1"}
	c2 := &countingSource{key: "key-c2"}
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: c1.source}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: c2.source}))

	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "c1", lease.Ref().ID)
	require.True(t, p.ReportOutcome(lease, 401))
	deadline := QuarantineDeadline(base)
	assert.Equal(t, 1, c1.calls, "the pick resolved plaintext exactly once")

	// Bypass attempts: every non-quarantining outcome of the in-flight lease
	// is accepted as a no-op report (the attempt happened) but mutates
	// nothing — the key stays out with its reason and deadline intact.
	for _, status := range []int{200, 201, 204, 301, 400, 402, 403, 404, 409, 418, 499, 500, 502, 503} {
		assert.True(t, p.ReportOutcome(lease, status), "status %d: a registered in-flight outcome is a recognized no-op", status)
		m, ok := snapshotMemberByID(p, "c1")
		require.True(t, ok)
		assert.False(t, m.InRotation, "status %d must not lift the quarantine", status)
		assert.Equal(t, QuarantineReasonUnauthorized, m.UnavailableReason)
		assert.Equal(t, deadline, m.RecoversAt, "status %d must not move the deadline", status)
		assert.Equal(t, 2, p.Len(), "status %d must not change membership", status)
	}

	// Repeating the quarantining outcome re-writes the same state: still out,
	// still one member, deadline pinned to the same day boundary.
	for range 3 {
		assert.True(t, p.ReportOutcome(lease, 401))
		m, ok := snapshotMemberByID(p, "c1")
		require.True(t, ok)
		assert.False(t, m.InRotation)
		assert.Equal(t, deadline, m.RecoversAt, "re-reports must not extend quarantine beyond the policy horizon")
	}

	// The bypass stream never fetched the invalid key's plaintext again:
	// while out of rotation the credential is not even consulted.
	for range 10 {
		got, err := p.Acquire(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "c2", got.Ref().ID)
	}
	assert.Equal(t, 1, c1.calls, "a quarantined credential must not reach its plaintext resolver")
	assert.Equal(t, 2, p.Len())
}

// TestCredentialPool_QuarantinedCredential_SourceNeverConsulted pins the
// no-infinite-retry contract at the resolver boundary: after a 401 the
// invalid key's plaintext source sees zero further calls while it is out,
// an operator reset re-enables exactly one fetch, and a renewed 401 freezes
// the fetches again.
func TestCredentialPool_QuarantinedCredential_SourceNeverConsulted(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	c1 := &countingSource{key: "key-c1"}
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: c1.source}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: sourceFor("key-c2")}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c3", Last4: "0003", KeyVersion: 1, Source: sourceFor("key-c3")}))

	pick := func(want string) *Lease {
		t.Helper()
		for range 4 {
			lease, err := p.Acquire(context.Background())
			require.NoError(t, err)
			if lease.Ref().ID == want {
				return lease
			}
		}
		t.Fatalf("credential %s was never picked", want)
		return nil
	}

	require.NotNil(t, pick("c1"))
	require.Equal(t, 1, c1.calls)
	require.True(t, p.ReportOutcome(pick("c1"), 401), "c1 must be quarantined by its 401")

	// While out: the pool keeps serving and the invalid key is never
	// fetched again (no silent retry, no resolver bypass).
	before := c1.calls
	for range 12 {
		got, err := p.Acquire(context.Background())
		require.NoError(t, err)
		assert.NotEqual(t, "c1", got.Ref().ID)
	}
	assert.Equal(t, before, c1.calls)

	// Operator reset: the recovered key serves again — exactly one fetch.
	require.True(t, p.MarkRecovered("c1"))
	lease := pick("c1")
	assert.Equal(t, before+1, c1.calls, "the reset key is fetched exactly once for its first attempt")

	// The key is still invalid upstream: the renewed 401 takes it out again
	// and the fetch counter freezes once more.
	require.True(t, p.ReportOutcome(lease, 401))
	for range 8 {
		got, err := p.Acquire(context.Background())
		require.NoError(t, err)
		assert.NotEqual(t, "c1", got.Ref().ID)
	}
	assert.Equal(t, before+1, c1.calls, "the re-quarantined key must not be fetched again")
	assert.Equal(t, 3, p.Len())
}

// TestCredentialPool_ResetOfStillInvalidKey_ReQuarantinesEachCycle is the
// hostile reset loop: an operator resets a key that is still invalid, and
// every cycle must re-quarantine it observably — the reset buys one attempt,
// never a standing exemption. The pool keeps serving on the siblings
// throughout, full exhaustion stays typed and secret-free, and the final
// reset tail returns every recovered key to rotation.
func TestCredentialPool_ResetOfStillInvalidKey_ReQuarantinesEachCycle(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	for _, id := range []string{"c1", "c2", "c3"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Last4: "0000", KeyVersion: 1, Source: sourceFor("key-" + id)}))
	}

	pick := func(want string) *Lease {
		t.Helper()
		for range 4 {
			lease, err := p.Acquire(context.Background())
			require.NoError(t, err)
			if lease.Ref().ID == want {
				return lease
			}
		}
		t.Fatalf("credential %s was never picked", want)
		return nil
	}

	for cycle := range 3 {
		// The operator bets on a transient upstream failure and resets (the
		// first cycle resets an already-eligible key: an idempotent no-op).
		require.True(t, p.MarkRecovered("c1"))
		lease := pick("c1")
		require.True(t, p.ReportOutcome(lease, 401), "cycle %d: the 401 must quarantine c1", cycle)
		for range 4 {
			got, aerr := p.Acquire(context.Background())
			require.NoError(t, aerr)
			assert.NotEqual(t, "c1", got.Ref().ID, "cycle %d: the invalid key must not be retried", cycle)
		}
		assert.Equal(t, 3, p.Len(), "cycle %d: no cycle may change membership", cycle)
	}

	// All three keys draw their 401s: full exhaustion is the typed,
	// fail-closed, secret-free state — never a silent fall-through.
	for _, id := range []string{"c2", "c3"} {
		require.True(t, p.ReportOutcome(pick(id), 401))
	}
	_, err := p.Acquire(context.Background())
	var exhausted *PoolExhaustedError
	require.ErrorAs(t, err, &exhausted)
	assert.Equal(t, QuarantineDeadline(base), exhausted.EarliestRecovery)
	assert.NotContains(t, exhausted.Error(), "key-", "exhaustion stays secret-free")

	// Reset tail: every recovered key returns without membership growth and
	// the round-robin serves each of them.
	for _, id := range []string{"c1", "c2", "c3"} {
		require.True(t, p.MarkRecovered(id))
	}
	served := make(map[string]bool, 3)
	for range 3 {
		got, aerr := p.Acquire(context.Background())
		require.NoError(t, aerr)
		served[got.Ref().ID] = true
		assert.Equal(t, "key-"+got.Ref().ID, got.Plaintext(), "recovered keys keep their plaintext binding")
	}
	assert.Len(t, served, 3, "every recovered key is served after the reset tail")
	assert.Equal(t, 3, p.Len())
}

// TestCredentialPool_UnauthorizedReset_IsolationBetweenPools: reset-like
// verbs are pool-scoped — a foreign pool (another org holding a credential
// with the same id, or holding none) cannot lift, move or clone another
// pool's quarantine state through any mutation surface.
func TestCredentialPool_UnauthorizedReset_IsolationBetweenPools(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	poolA, _ := newClockedPool(t, credKey("org-a", "openai-compat", "https://u.local"), base)
	poolB, _ := newClockedPool(t, credKey("org-b", "openai-compat", "https://u.local"), base)
	// Both orgs registered the same credential id; only A additionally holds
	// "only-a", and only B holds "only-b".
	for _, p := range []*CredentialPool{poolA, poolB} {
		require.NoError(t, p.Add(CredentialSpec{ID: "shared", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-shared-" + p.Key().OrgID)}))
	}
	require.NoError(t, poolA.Add(CredentialSpec{ID: "only-a", Last4: "0002", KeyVersion: 1, Source: sourceFor("key-only-a")}))
	require.NoError(t, poolB.Add(CredentialSpec{ID: "only-b", Last4: "0003", KeyVersion: 1, Source: sourceFor("key-only-b")}))

	leaseA, err := poolA.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "shared", leaseA.Ref().ID)
	require.True(t, poolA.ReportOutcome(leaseA, 401))
	mA, ok := snapshotMemberByID(poolA, "shared")
	require.True(t, ok)
	require.False(t, mA.InRotation)

	// org B's reset attempt on org A's state must not touch it — neither
	// through a same-id member of its own nor through an id only A holds.
	assert.True(t, poolB.MarkRecovered("shared"), "B resets its own same-id member: A's state is untouched")
	assert.False(t, poolB.MarkRecovered("only-a"), "an id foreign to B must report false")
	assert.False(t, poolB.MarkUnavailable("only-a", base.Add(-time.Second), "bypass"), "an id foreign to B must not take a cooldown")
	assert.False(t, poolB.Remove("only-a"), "an id foreign to B must not be removable")

	mA, ok = snapshotMemberByID(poolA, "shared")
	require.True(t, ok)
	assert.False(t, mA.InRotation, "org B must not be able to lift org A's quarantine")
	assert.Equal(t, QuarantineReasonUnauthorized, mA.UnavailableReason)

	mOnlyA, ok := snapshotMemberByID(poolA, "only-a")
	require.True(t, ok)
	assert.True(t, mOnlyA.InRotation, "org B must not take org A's credential out of rotation")

	mB, ok := snapshotMemberByID(poolB, "shared")
	require.True(t, ok)
	assert.True(t, mB.InRotation, "B's own reset must still work on B's member")

	// The snapshot of each pool carries only its own org's state.
	assert.Equal(t, credKey("org-a", "openai-compat", "https://u.local"), poolA.Snapshot().Key)
	assert.Equal(t, credKey("org-b", "openai-compat", "https://u.local"), poolB.Snapshot().Key)
}

// TestCredentialPool_QuarantineTransition_RaceSingleMember is the degenerate
// transition race: one member flipped between quarantined and recovered by
// two churners (cooldown write with expiry, manual reset) while workers
// hammer Acquire. Invariants under any interleaving: no outcome other than a
// pick or the typed exhaustion, membership never grows or duplicates, the
// member's counter accounts every successful pick exactly, and the final
// reset tail serves the member again.
func TestCredentialPool_QuarantineTransition_RaceSingleMember(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "solo", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-solo")}))

	const workers = 4
	const perWorker = 250

	var successes atomic.Uint64
	stop := make(chan struct{})
	var churners sync.WaitGroup

	// Churner 1: short cooldowns that expire within microseconds (auto
	// recovery evaluated at pick time).
	churners.Add(1)
	go func() {
		defer churners.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				p.MarkUnavailable("solo", time.Now().Add(2*time.Microsecond), "churn")
			} else {
				p.MarkUnavailable("solo", time.Now().Add(-time.Second), "already expired")
			}
			time.Sleep(time.Microsecond)
		}
	}()
	// Churner 2: manual resets racing the cooldown writes.
	churners.Add(1)
	go func() {
		defer churners.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.MarkRecovered("solo")
			time.Sleep(time.Microsecond)
		}
	}()

	var workersWG sync.WaitGroup
	for range workers {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for range perWorker {
				lease, err := p.Acquire(context.Background())
				if err != nil {
					var exhausted *PoolExhaustedError
					if errors.As(err, &exhausted) {
						continue // legal transient: the member is momentarily out
					}
					t.Errorf("acquire failed with an unexpected error: %v", err)
					return
				}
				if lease.Ref().ID != "solo" || lease.Plaintext() != "key-solo" {
					t.Errorf("identity binding broken: %s served %q", lease.Ref().ID, lease.Plaintext())
					return
				}
				if lease.Pool() != p.Key() {
					t.Errorf("pool identity drifted: %s", lease.Pool())
					return
				}
				successes.Add(1)
			}
		}()
	}

	workersWG.Wait()
	close(stop)
	churners.Wait()

	// Deterministic tail: with churn stopped and the member reset the pool
	// serves exactly the one member; the tail pick is accounted like any
	// other.
	require.True(t, p.MarkRecovered("solo"))
	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "solo", lease.Ref().ID)
	assert.Equal(t, "key-solo", lease.Plaintext())
	successes.Add(1)

	snap := p.Snapshot()
	require.Len(t, snap.Members, 1, "membership never grows: transitions must never re-insert")
	assert.Equal(t, "solo", snap.Members[0].Ref.ID)
	assert.Equal(t, successes.Load(), snap.Members[0].Acquires, "the member's counter accounts every successful pick exactly")
	assert.Equal(t, successes.Load(), snap.Acquires)
}

// TestCredentialPool_SecretLeakProbes_FailedResolveAndEmbeddedId probes the
// masked-ref leak paths with hostile inputs: a plaintext that embeds its own
// credential id (so any id-tail over-disclosure would carry the key), and a
// misbehaving source that returns a secret value alongside its error (the
// pool must drop the value and surface only the cause and the masked ref).
func TestCredentialPool_SecretLeakProbes_FailedResolveAndEmbeddedId(t *testing.T) {
	const embeddedSecret = "sk-live-HOSTILE-aaaaaaaa-1111-TAIL-VALUE" //nolint:gosec // G101: synthetic leak-probe secret, not a credential
	const failedResolveSecret = "sk-live-RESOLVE-FAILURE-VALUE"       //nolint:gosec // G101: synthetic leak-probe secret, not a credential
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{
		ID:         "aaaaaaaa-1111-4111-8111-111111111111",
		Last4:      "0001",
		KeyVersion: 1,
		Source:     sourceFor(embeddedSecret),
	}))
	require.NoError(t, p.Add(CredentialSpec{
		ID:         "bbbbbbbb-2222-4222-8222-222222222222",
		Last4:      "0002",
		KeyVersion: 1,
		Source: func(context.Context) (string, error) {
			// Misbehaving resolver: a value AND an error at once. The pool
			// must treat the attempt as failed and never surface the value.
			return failedResolveSecret, errors.New("resolve backend down")
		},
	}))

	// The first pick serves the embedded-id key (round-robin starts at the
	// first registered member).
	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "aaaaaaaa-1111-4111-8111-111111111111", lease.Ref().ID)
	assert.Equal(t, embeddedSecret, lease.Plaintext(), "masking must not disturb plaintext binding")
	assert.Equal(t, "aaaaaaaa:0001", lease.AttributionRef())

	// The next pick hits the misbehaving resolver: the surfaced error names
	// the cause and the masked ref, never the value the source returned.
	_, err = p.Acquire(context.Background())
	require.Error(t, err)
	require.ErrorContains(t, err, "resolve backend down")
	require.ErrorContains(t, err, "cred=bbbbbbbb-2222", "the ref identifies the failed credential")
	assert.NotContains(t, err.Error(), failedResolveSecret, "a failed resolve must never surface the returned value")
	assert.NotContains(t, err.Error(), embeddedSecret, "no sibling secret may surface through the failure")

	// Both credentials out of rotation: exhaustion is typed and secret-free.
	require.True(t, p.ReportOutcome(lease, 401))
	require.True(t, p.MarkUnavailable("bbbbbbbb-2222-4222-8222-222222222222", base.Add(time.Hour), "cooldown_test"))
	_, exhaustedErr := p.Acquire(context.Background())
	var exhausted *PoolExhaustedError
	require.ErrorAs(t, exhaustedErr, &exhausted)

	snap := p.Snapshot()
	formats := []string{
		lease.AttributionRef(),
		lease.String(),
		lease.GoString(),
		fmt.Sprint(snap),
		fmt.Sprintf("%+v", snap),
		exhausted.Error(),
	}
	for _, f := range formats {
		assert.NotContains(t, f, embeddedSecret, "no surface may leak the embedded-id key: %s", f)
		assert.NotContains(t, f, failedResolveSecret, "no surface may leak the failed-resolve value: %s", f)
		assert.NotContains(t, f, "sk-live", "no surface may leak any key material: %s", f)
	}
	// The quarantine tag names the classification, never the key, and the
	// attribution mask stays byte-identical to the gateway shape.
	m, ok := snapshotMemberByID(p, "aaaaaaaa-1111-4111-8111-111111111111")
	require.True(t, ok)
	assert.False(t, m.InRotation)
	assert.Equal(t, "upstream_401", m.UnavailableReason)
	assert.Equal(t, "aaaaaaaa:0001", m.Ref.AttributionRef())
}
