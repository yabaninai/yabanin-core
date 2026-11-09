package upstream

// N08-P05-T06 — the packet's joint user scenario on the credential-pool
// engine: one continuous organization journey across the T03 (pool),
// T04 (attribution) and T05 (negative battery) semantics. Deterministic and
// hermetic: fixed test clocks, in-memory plaintext sources, no DB, no
// network — the REAL-store leg is the integration-tagged RealPostgres suite
// (pkg/gateway/credpool_integration_test.go, build tag `integration`); the
// two environments are explicitly distinct per the card's stage acceptance.

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

// Joint-journey fixtures. The four synthetic keys are test-only plaintexts
// (leak probes, not credentials — no nolint needed: inline literals only).
const (
	jointKeyA1   = "sk-joint-key-00000001"
	jointKeyB1   = "sk-joint-key-00000002"
	jointKeyC1   = "sk-joint-key-00000003"
	jointKeyD1   = "sk-joint-key-00000004"
	jointMaskA1  = "aaaaaaaa:0001"
	jointMaskB1  = "bbbbbbbb:0002"
	jointMaskC1  = "cccccccc:0003"
	jointIDB1    = "bbbbbbbb-2222-4222-8222-000000000002"
	jointIDC1    = "cccccccc-3333-4333-8333-000000000003"
	jointIDD1    = "dddddddd-4444-4444-4444-000000000004"
	jointIDB1rot = "sk-joint-key-00000002-v2"
)

// TestCredentialPool_JointScenario_PacketUserJourney walks one organization
// through the full acceptance arc on a fixed clock: fair round-robin serve
// with masked attribution → the invalid key quarantined by its 401 and never
// retried → the throttled key quarantined by its 429 → the last sibling
// falls → typed fail-closed exhaustion with the exact recovery instant →
// cross-pool isolation → the recovered key returns with its ORIGINAL
// plaintext → a key-version rotation lifts the sibling's quarantine without
// touching pool identity. Exact round-robin and pick accounting asserted at
// every act; no surface ever carries plaintext.
func TestCredentialPool_JointScenario_PacketUserJourney(t *testing.T) {
	base := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	midnight := QuarantineDeadline(base) // 2026-10-30T00:00:00Z
	keyA := credKey("org-a", "openai-compat", "https://u.local")
	keyB := credKey("org-b", "openai-compat", "https://u.local")

	reg := NewCredentialPools()
	poolA := reg.GetOrCreate(keyA)
	poolB := reg.GetOrCreate(keyB)
	require.Same(t, poolA, reg.GetOrCreate(keyA), "the registry must hand out the same pool per identity triple")
	require.Same(t, poolB, reg.GetOrCreate(keyB))
	// Fixed-clock hooks (same-package test hook, newClockedPool's pattern);
	// the journey never moves them — all deadlines derive from `base`, which
	// makes the recovery instant exactly assertable.
	now := base
	clock := &now
	poolA.now = func() time.Time { return *clock }
	poolB.now = func() time.Time { return *clock }

	require.NoError(t, poolA.Add(CredentialSpec{ID: "aaaaaaaa-1111-4111-8111-000000000001", Last4: "0001", KeyVersion: 1, Source: sourceFor(jointKeyA1)}))
	require.NoError(t, poolA.Add(CredentialSpec{ID: jointIDB1, Last4: "0002", KeyVersion: 1, Source: sourceFor(jointKeyB1)}))
	require.NoError(t, poolA.Add(CredentialSpec{ID: jointIDC1, Last4: "0003", KeyVersion: 1, Source: sourceFor(jointKeyC1)}))
	require.NoError(t, poolB.Add(CredentialSpec{ID: jointIDD1, Last4: "0004", KeyVersion: 1, Source: sourceFor(jointKeyD1)}))

	// Act 1 — fair serve: six acquires rotate 2/2/2 with masked attribution
	// and per-lease plaintext binding.
	for i, wantID := range []string{"aaaaaaaa-1111-4111-8111-000000000001", jointIDB1, jointIDC1, "aaaaaaaa-1111-4111-8111-000000000001", jointIDB1, jointIDC1} {
		lease, err := poolA.Acquire(context.Background())
		require.NoError(t, err, "pick %d", i+1)
		assert.Equal(t, wantID, lease.Ref().ID, "pick %d", i+1)
		assert.Equal(t, 1, lease.Ref().KeyVersion, "pick %d", i+1)
		assert.Equal(t, keyA, lease.Pool(), "pick %d", i+1)
		switch lease.Ref().ID {
		case "aaaaaaaa-1111-4111-8111-000000000001":
			assert.Equal(t, jointKeyA1, lease.Plaintext(), "pick %d", i+1)
			assert.Equal(t, jointMaskA1, lease.AttributionRef(), "pick %d", i+1)
		case jointIDB1:
			assert.Equal(t, jointKeyB1, lease.Plaintext(), "pick %d", i+1)
			assert.Equal(t, jointMaskB1, lease.AttributionRef(), "pick %d", i+1)
		case jointIDC1:
			assert.Equal(t, jointKeyC1, lease.Plaintext(), "pick %d", i+1)
			assert.Equal(t, jointMaskC1, lease.AttributionRef(), "pick %d", i+1)
		}
	}
	snap := poolA.Snapshot()
	require.Len(t, snap.Members, 3)
	for _, m := range snap.Members {
		assert.Equal(t, uint64(2), m.Acquires, "member %s", m.Ref.ID)
		assert.True(t, m.InRotation, "member %s", m.Ref.ID)
	}
	assert.Equal(t, uint64(6), snap.Acquires)

	// Act 2 — the invalid key: its 401 quarantines it until the packet
	// deadline, and it is never picked again.
	leaseA1, err := poolA.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "aaaaaaaa-1111-4111-8111-000000000001", leaseA1.Ref().ID)
	require.True(t, poolA.ReportOutcome(leaseA1, 401))
	mA1, ok := snapshotMemberByID(poolA, "aaaaaaaa-1111-4111-8111-000000000001")
	require.True(t, ok)
	assert.False(t, mA1.InRotation)
	assert.Equal(t, QuarantineReasonUnauthorized, mA1.UnavailableReason)
	assert.Equal(t, midnight, mA1.RecoversAt)
	// Negative replay on the same lease: a non-quarantining status must not
	// lift or mutate the recorded quarantine.
	assert.True(t, poolA.ReportOutcome(leaseA1, 404), "the lease id is still registered")
	mA1, _ = snapshotMemberByID(poolA, "aaaaaaaa-1111-4111-8111-000000000001")
	assert.False(t, mA1.InRotation, "a 404 replay must not lift the 401 quarantine")
	assert.Equal(t, QuarantineReasonUnauthorized, mA1.UnavailableReason)
	assert.Equal(t, midnight, mA1.RecoversAt)

	a1PlaintextSeen := false
	for i := 0; i < 10; i++ {
		lease, err := poolA.Acquire(context.Background())
		require.NoError(t, err)
		assert.NotEqual(t, "aaaaaaaa-1111-4111-8111-000000000001", lease.Ref().ID, "the 401-quarantined key must never be retried")
		a1PlaintextSeen = a1PlaintextSeen || lease.Plaintext() == jointKeyA1
		assert.NotEqual(t, jointMaskA1, lease.AttributionRef())
	}
	assert.False(t, a1PlaintextSeen, "the invalid key's plaintext must never be served again before recovery")
	mA1, _ = snapshotMemberByID(poolA, "aaaaaaaa-1111-4111-8111-000000000001")
	assert.Equal(t, uint64(3), mA1.Acquires, "the quarantine must not inflate or erase pick accounting")

	// Act 3 — the throttled key: its 429 quarantines it with the throttle tag.
	leaseB1, err := poolA.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, jointIDB1, leaseB1.Ref().ID)
	require.True(t, poolA.ReportOutcome(leaseB1, 429))
	mB1, ok := snapshotMemberByID(poolA, jointIDB1)
	require.True(t, ok)
	assert.False(t, mB1.InRotation)
	assert.Equal(t, QuarantineReasonThrottled, mB1.UnavailableReason)
	assert.Equal(t, midnight, mB1.RecoversAt)

	// Act 4 — the last sibling serves once, falls too, and the pool fails
	// closed with the typed, secret-free exhaustion error.
	leaseC1, err := poolA.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, jointIDC1, leaseC1.Ref().ID)
	require.Equal(t, jointKeyC1, leaseC1.Plaintext())
	require.True(t, poolA.ReportOutcome(leaseC1, 401))
	_, err = poolA.Acquire(context.Background())
	require.Error(t, err)
	var exhausted *PoolExhaustedError
	require.ErrorAs(t, err, &exhausted)
	assert.Equal(t, keyA, exhausted.Pool)
	assert.Equal(t, midnight, exhausted.EarliestRecovery)
	assert.Contains(t, err.Error(), "earliest recovery 2026-10-30T00:00:00Z")
	assert.NotContains(t, err.Error(), "sk-joint", "the exhaustion error must stay secret-free")
	assert.Equal(t, 3, poolA.Len(), "exhaustion must not evict members")

	// Act 5 — cross-pool isolation: pool B keeps serving while pool A is
	// exhausted, and A cannot quarantine B's same-shaped credential.
	leaseB, err := poolB.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, jointIDD1, leaseB.Ref().ID)
	assert.Equal(t, jointKeyD1, leaseB.Plaintext())
	assert.False(t, poolA.ReportOutcome(leaseB, 401), "a lease from another pool must be rejected")
	mD1, ok := snapshotMemberByID(poolB, jointIDD1)
	require.True(t, ok)
	assert.True(t, mD1.InRotation, "org B must keep working while org A is exhausted")
	_, err = poolA.Acquire(context.Background())
	require.ErrorAs(t, err, &exhausted, "org A stays exhausted on its own")

	// Act 6 — recovery: the manual reset returns the recovered key with its
	// ORIGINAL plaintext, and the pool continues.
	require.True(t, poolA.MarkRecovered("aaaaaaaa-1111-4111-8111-000000000001"))
	for i := 0; i < 3; i++ {
		lease, err := poolA.Acquire(context.Background())
		require.NoError(t, err, "recovered pick %d", i+1)
		assert.Equal(t, "aaaaaaaa-1111-4111-8111-000000000001", lease.Ref().ID, "recovered pick %d: the other members are still quarantined", i+1)
		assert.Equal(t, jointKeyA1, lease.Plaintext(), "recovery must return the original key")
		assert.Equal(t, jointMaskA1, lease.AttributionRef())
	}

	// Act 7 — rotation lifts the sibling's quarantine: a key-version bump on
	// b1 returns it to rotation serving the NEW plaintext, the attribution
	// mask is stable across the rotation, and c1 stays quarantined.
	require.NoError(t, poolA.UpsertCredential(CredentialSpec{ID: jointIDB1, Last4: "0002", KeyVersion: 2, Source: sourceFor(jointIDB1rot)}))
	pick23, err := poolA.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, jointIDB1, pick23.Ref().ID)
	assert.Equal(t, 2, pick23.Ref().KeyVersion)
	assert.Equal(t, jointIDB1rot, pick23.Plaintext(), "the rotated sibling must serve the new plaintext")
	assert.Equal(t, jointMaskB1, pick23.AttributionRef(), "the attribution mask survives rotation")
	pick24, err := poolA.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "aaaaaaaa-1111-4111-8111-000000000001", pick24.Ref().ID, "a1 keeps rotating (c1 still out)")
	pick25, err := poolA.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, jointIDB1, pick25.Ref().ID, "the rotated sibling alternates back in")
	mC1, ok := snapshotMemberByID(poolA, jointIDC1)
	require.True(t, ok)
	assert.False(t, mC1.InRotation, "rotation of one member must not lift a sibling's quarantine")
	assert.Equal(t, QuarantineReasonUnauthorized, mC1.UnavailableReason)

	// Final exact accounting: 25 successful picks total, 7/10/8 per member,
	// membership intact, pool total equal to the member sum.
	snap = poolA.Snapshot()
	require.Len(t, snap.Members, 3)
	var sum uint64
	for _, m := range snap.Members {
		sum += m.Acquires
		switch m.Ref.ID {
		case "aaaaaaaa-1111-4111-8111-000000000001":
			assert.Equal(t, uint64(7), m.Acquires)
		case jointIDB1:
			assert.Equal(t, uint64(10), m.Acquires)
			assert.Equal(t, 2, m.Ref.KeyVersion)
		case jointIDC1:
			assert.Equal(t, uint64(8), m.Acquires)
		}
	}
	assert.Equal(t, uint64(25), snap.Acquires)
	assert.Equal(t, snap.Acquires, sum, "per-member counters must sum to the pool total")
}

// TestCredentialPool_JointScenario_ConcurrentServeRecover is the acceptance's
// no-race leg: the serve/quarantine/reset/rotation churn of the joint
// scenario hammered concurrently under -race. Workers pick, verify plaintext
// binding and masked attribution, 401-out the a1 key and 200-report the
// rest; one churner resets a1 back into rotation, another rotates c1's key
// version. Invariants under any interleaving: every served plaintext matches
// the picked (id, key-version) pair, every attribution keeps the masked
// shape, exhaustion is the only alternative outcome, membership never grows,
// and the final accounting is exact.
func TestCredentialPool_JointScenario_ConcurrentServeRecover(t *testing.T) {
	p, _ := newClockedPool(t, credKey("org-joint", "openai-compat", "https://u.local"), time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC))
	require.NoError(t, p.Add(CredentialSpec{ID: "aaaaaaaa-1111-4111-8111-000000000001", Last4: "0001", KeyVersion: 1, Source: sourceFor(jointKeyA1)}))
	require.NoError(t, p.Add(CredentialSpec{ID: jointIDB1, Last4: "0002", KeyVersion: 1, Source: sourceFor(jointKeyB1)}))
	require.NoError(t, p.Add(CredentialSpec{ID: jointIDC1, Last4: "0003", KeyVersion: 1, Source: sourceFor(jointKeyC1)}))

	// jointC1Plaintext is the deterministic plaintext of c1 at a key version:
	// v1 is the original, vN (N >= 2) comes from the rotation churner.
	jointC1Plaintext := func(version int) string {
		if version == 1 {
			return jointKeyC1
		}
		return fmt.Sprintf("sk-joint-c1-v%03d", version)
	}
	expectedPlaintext := func(ref CredentialRef) string {
		switch ref.ID {
		case "aaaaaaaa-1111-4111-8111-000000000001":
			return jointKeyA1
		case jointIDB1:
			return jointKeyB1
		case jointIDC1:
			return jointC1Plaintext(ref.KeyVersion)
		}
		return ""
	}
	expectedMask := func(ref CredentialRef) string {
		switch ref.ID {
		case "aaaaaaaa-1111-4111-8111-000000000001":
			return jointMaskA1
		case jointIDB1:
			return jointMaskB1
		case jointIDC1:
			return jointMaskC1
		}
		return ""
	}

	const workers = 4
	const perWorker = 100

	var (
		picks      sync.Map // credential id → *atomic.Uint64
		exhausted  atomic.Uint64
		mu         sync.Mutex
		mismatches []string
	)
	record := func(id string) *atomic.Uint64 {
		v, _ := picks.LoadOrStore(id, &atomic.Uint64{})
		return v.(*atomic.Uint64)
	}
	note := func(format string, args ...any) {
		mu.Lock()
		mismatches = append(mismatches, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	// Churner 1: bounded reset churn on a1 (the worker-quarantined key).
	var resetChurner sync.WaitGroup
	resetChurner.Add(1)
	go func() {
		defer resetChurner.Done()
		for range 150 {
			p.MarkRecovered("aaaaaaaa-1111-4111-8111-000000000001")
		}
	}()
	// Churner 2: bounded rotation churn on c1 (key versions 2..151, each
	// lifting any unavailability and swapping the plaintext source).
	var rotationChurner sync.WaitGroup
	rotationChurner.Add(1)
	go func() {
		defer rotationChurner.Done()
		for i := range 150 {
			version := i + 2
			err := p.UpsertCredential(CredentialSpec{
				ID:         jointIDC1,
				Last4:      "0003",
				KeyVersion: version,
				Source:     sourceFor(jointC1Plaintext(version)),
			})
			if err != nil {
				note("rotation churn v%d: %v", version, err)
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				lease, err := p.Acquire(context.Background())
				if err != nil {
					var exhaustedErr *PoolExhaustedError
					if errors.As(err, &exhaustedErr) {
						exhausted.Add(1)
						continue // legal transient: all members momentarily out
					}
					note("acquire: unexpected error %v", err)
					return
				}
				ref := lease.Ref()
				if want := expectedPlaintext(ref); lease.Plaintext() != want {
					note("plaintext binding broken: %s v%d served the wrong key", ref.ID, ref.KeyVersion)
					return
				}
				if got := lease.AttributionRef(); got != expectedMask(ref) || strings.Contains(got, "sk-joint") {
					note("attribution broken: %q", got)
					return
				}
				if lease.Pool() != p.Key() {
					note("pool identity drifted: %s", lease.Pool())
					return
				}
				if ref.ID == "aaaaaaaa-1111-4111-8111-000000000001" {
					p.ReportOutcome(lease, 401)
				} else {
					p.ReportOutcome(lease, 200) // recognized no-op
				}
				record(ref.ID).Add(1)
			}
		}()
	}

	wg.Wait()
	resetChurner.Wait()
	rotationChurner.Wait()
	require.Empty(t, mismatches, "joint invariants must hold under every interleaving")

	// Deterministic tail: reset the (possibly quarantined) a1 key and serve
	// exactly the three members once each, with exact plaintexts — c1 at its
	// final churned version.
	require.True(t, p.MarkRecovered("aaaaaaaa-1111-4111-8111-000000000001"))
	tail := map[string]string{}
	for range 3 {
		lease, err := p.Acquire(context.Background())
		require.NoError(t, err)
		_, dup := tail[lease.Ref().ID]
		require.False(t, dup, "the tail must serve each member exactly once")
		tail[lease.Ref().ID] = lease.Plaintext()
	}
	assert.Equal(t, map[string]string{
		"aaaaaaaa-1111-4111-8111-000000000001": jointKeyA1,
		jointIDB1:                              jointKeyB1,
		jointIDC1:                              jointC1Plaintext(151),
	}, tail)

	// Exact accounting: every successful pick counted once; per-member sums
	// equal the pool total; every member served at least once; membership
	// never grew.
	snap := p.Snapshot()
	require.Len(t, snap.Members, 3)
	var servedTotal uint64
	picks.Range(func(_, v any) bool {
		servedTotal += v.(*atomic.Uint64).Load()
		return true
	})
	servedTotal += 3 // the deterministic tail
	var memberSum uint64
	for _, m := range snap.Members {
		memberSum += m.Acquires
		assert.Positive(t, m.Acquires, "member %s", m.Ref.ID)
	}
	assert.Equal(t, servedTotal, snap.Acquires)
	assert.Equal(t, snap.Acquires, memberSum)
	t.Logf("joint concurrent scenario: %d picks, %d transient exhaustions, counters exact", servedTotal, exhausted.Load())
}
