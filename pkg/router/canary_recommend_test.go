package router

// N09-P04-T03 tests — evidence-only automatic rollback recommendation.
//
// Table-driven and deterministic: thresholds are set to binary-exact values
// where a boundary is asserted (counts chosen so the rates are exact
// powers-of-two fractions), and the clock is injected.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCanaryRolloutAdvisor_Defaults(t *testing.T) {
	a := NewCanaryRolloutAdvisor(0, 0, 0, 0, 0)
	require.NotNil(t, a)
	assert.Equal(t, int64(30), a.MinCanaryRequests)
	assert.Equal(t, int64(30), a.MinBaseRequests)
	assert.InDelta(t, 0.05, a.MaxFailureRateDelta, 0)
	assert.InDelta(t, 0.02, a.MinFailureRate, 0)
	assert.InDelta(t, 1.5, a.MaxLatencyRatio, 0)
	assert.NotNil(t, a.now)
}

func TestCanaryRolloutAdvisor_Recommend(t *testing.T) {
	// Binary-exact thresholds: delta 0.0625 (1/16), floor 0.03125 (1/32),
	// so the >= boundary cases are exact float comparisons, not luck.
	a := NewCanaryRolloutAdvisor(10, 10, 0.0625, 0.03125, 1.5)
	fixed := time.Unix(1700000000, 0)
	a.now = func() time.Time { return fixed }

	tests := []struct {
		name string
		in   CanaryAdviceInput
		// expectations
		action       string
		recommended  bool
		insufficient bool
		wantReason   string // substring that must appear in Reasons
	}{
		{
			name: "insufficient canary samples hold, never a verdict",
			in: CanaryAdviceInput{
				RolloutID: "r1", Version: 2,
				Canary: CanaryArmOutcome{Requests: 5, Failures: 5}, // 100% failures, but 5 < 10 samples
				Base:   CanaryArmOutcome{Requests: 100, Failures: 1},
			},
			action: CanaryAdviceHold, insufficient: true,
			wantReason: "insufficient samples: canary 5/10 requests",
		},
		{
			name: "insufficient base samples hold",
			in: CanaryAdviceInput{
				RolloutID: "r1", Version: 2,
				Canary: CanaryArmOutcome{Requests: 100, Failures: 20},
				Base:   CanaryArmOutcome{Requests: 3},
			},
			action: CanaryAdviceHold, insufficient: true,
			wantReason: "base 3/10 requests",
		},
		{
			name: "failure-rate gap at the exact boundary recommends rollback",
			in: CanaryAdviceInput{
				RolloutID: "r1", Version: 2,
				Canary: CanaryArmOutcome{Requests: 32, Failures: 4}, // 0.125
				Base:   CanaryArmOutcome{Requests: 32, Failures: 2}, // 0.0625 → delta exactly 0.0625
			},
			action: CanaryAdviceManualRollback, recommended: true,
			wantReason: "failure rate: canary 0.1250 vs base 0.0625 (delta 0.0625 >= 0.0625",
		},
		{
			name: "failure-rate gap just below the boundary holds",
			in: CanaryAdviceInput{
				RolloutID: "r1", Version: 2,
				Canary: CanaryArmOutcome{Requests: 32, Failures: 4}, // 0.125
				Base:   CanaryArmOutcome{Requests: 32, Failures: 3}, // 0.09375 → delta 0.03125 < 0.0625
			},
			action:     CanaryAdviceHold,
			wantReason: "within thresholds",
		},
		{
			name: "latency ratio at the exact boundary recommends rollback",
			in: CanaryAdviceInput{
				RolloutID: "r1", Version: 2,
				Canary: CanaryArmOutcome{Requests: 32, LatencySum: 96 * time.Millisecond}, // mean 3ms
				Base:   CanaryArmOutcome{Requests: 32, LatencySum: 64 * time.Millisecond}, // mean 2ms → ratio exactly 1.5
			},
			action: CanaryAdviceManualRollback, recommended: true,
			wantReason: "latency: canary mean 3ms vs base mean 2ms (ratio 1.500 >= 1.500)",
		},
		{
			name: "latency ratio below the boundary holds",
			in: CanaryAdviceInput{
				RolloutID: "r1", Version: 2,
				Canary: CanaryArmOutcome{Requests: 32, LatencySum: 95 * time.Millisecond}, // mean 2.96875ms
				Base:   CanaryArmOutcome{Requests: 32, LatencySum: 64 * time.Millisecond},
			},
			action:     CanaryAdviceHold,
			wantReason: "within thresholds",
		},
		{
			name: "healthy canary holds with evidence",
			in: CanaryAdviceInput{
				RolloutID: "r1", Version: 2,
				Canary: CanaryArmOutcome{Requests: 100, Failures: 2, LatencySum: 200 * time.Millisecond},
				Base:   CanaryArmOutcome{Requests: 100, Failures: 2, LatencySum: 200 * time.Millisecond},
			},
			action:     CanaryAdviceHold,
			wantReason: "within thresholds",
		},
		{
			name:   "zero traffic on both arms is insufficient, not healthy",
			in:     CanaryAdviceInput{RolloutID: "r1", Version: 2},
			action: CanaryAdviceHold, insufficient: true,
			wantReason: "insufficient samples",
		},
		{
			name: "negative counters are invalid evidence, never a verdict",
			in: CanaryAdviceInput{
				RolloutID: "r1", Version: 2,
				Canary: CanaryArmOutcome{Requests: -5, Failures: 0},
				Base:   CanaryArmOutcome{Requests: 100, Failures: 1},
			},
			action: CanaryAdviceHold, insufficient: true,
			wantReason: "invalid evidence: negative counters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv := a.Recommend(tt.in)
			assert.Equal(t, tt.action, adv.Action)
			assert.Equal(t, tt.recommended, adv.Recommended)
			assert.Equal(t, tt.insufficient, adv.Insufficient)
			assert.Equal(t, tt.in.RolloutID, adv.RolloutID)
			assert.Equal(t, tt.in.Version, adv.Version)
			assert.Equal(t, fixed, adv.EvaluatedAt)
			require.NotEmpty(t, adv.Reasons)
			found := false
			for _, r := range adv.Reasons {
				if strings.Contains(r, tt.wantReason) {
					found = true
				}
			}
			assert.True(t, found, "reasons %v must contain %q", adv.Reasons, tt.wantReason)
			if tt.recommended {
				require.Contains(t, adv.Reasons[len(adv.Reasons)-1], "manual rollback",
					"a recommendation must always name the manual rollback path (D3: never automatic)")
			}
		})
	}
}

func TestCanaryRolloutAdvisor_FloorBlocksTinyGap(t *testing.T) {
	// A dedicated config where the floor (not the delta) is what blocks:
	// delta 0.015 exceeds the 0.01 gap threshold, but the canary rate is
	// under the 0.02 absolute floor — a noisy near-zero baseline must not
	// recommend a rollback.
	a := NewCanaryRolloutAdvisor(10, 10, 0.01, 0.02, 1.5)
	a.now = func() time.Time { return time.Unix(1700000000, 0) }

	adv := a.Recommend(CanaryAdviceInput{
		RolloutID: "r1", Version: 2,
		Canary: CanaryArmOutcome{Requests: 1000, Failures: 15}, // 0.015
		Base:   CanaryArmOutcome{Requests: 1000},
	})
	assert.Equal(t, CanaryAdviceHold, adv.Action)
	assert.False(t, adv.Recommended)
	assert.InDelta(t, 0.015, adv.CanaryFailureRate, 0)
	assert.Contains(t, adv.Reasons, "within thresholds: failure delta 0.0150 < 0.0100 (or below floor 0.0200), latency ratio within 1.500")

	// Same gap above the floor: the recommendation fires (the floor is a
	// guard, not a gag).
	adv = a.Recommend(CanaryAdviceInput{
		RolloutID: "r1", Version: 2,
		Canary: CanaryArmOutcome{Requests: 1000, Failures: 30}, // 0.030
		Base:   CanaryArmOutcome{Requests: 1000},
	})
	assert.Equal(t, CanaryAdviceManualRollback, adv.Action)
}

func TestCanaryRolloutAdvisor_BothSignalsRecommendOnce(t *testing.T) {
	// Failure gap AND latency ratio both fire: one recommendation, both
	// reasons, and the manual-rollback note — never two actions, never an
	// automatic execution path.
	a := NewCanaryRolloutAdvisor(10, 10, 0.0625, 0.03125, 1.5)
	a.now = func() time.Time { return time.Unix(1700000000, 0) }

	adv := a.Recommend(CanaryAdviceInput{
		RolloutID: "r1", Name: "both", Version: 7,
		Canary: CanaryArmOutcome{Requests: 32, Failures: 8, LatencySum: 128 * time.Millisecond}, // 0.25, mean 4ms
		Base:   CanaryArmOutcome{Requests: 32, Failures: 2, LatencySum: 64 * time.Millisecond},  // 0.0625, mean 2ms
	})
	assert.Equal(t, CanaryAdviceManualRollback, adv.Action)
	assert.True(t, adv.Recommended)
	assert.False(t, adv.Insufficient)
	require.Len(t, adv.Reasons, 3, "failure reason + latency reason + manual note")
	assert.Contains(t, adv.Reasons[0], "failure rate")
	assert.Contains(t, adv.Reasons[1], "latency")
	assert.Contains(t, adv.Reasons[2], "manual rollback")
	assert.InDelta(t, 0.0625, adv.BaseFailureRate, 0)
	assert.InDelta(t, 0.25, adv.CanaryFailureRate, 0)
	assert.Equal(t, 2*time.Millisecond, adv.BaseLatencyMean)
	assert.Equal(t, 4*time.Millisecond, adv.CanaryLatencyMean)
}

func TestCanaryRolloutAdvisor_Deterministic(t *testing.T) {
	// Same counters + same clock → byte-identical advice (the evaluator is
	// pure; nothing else may leak in).
	a := NewCanaryRolloutAdvisor(10, 10, 0.0625, 0.03125, 1.5)
	a.now = func() time.Time { return time.Unix(1700000000, 0) }
	in := CanaryAdviceInput{
		RolloutID: "r1", Name: "det", Version: 3,
		Canary: CanaryArmOutcome{Requests: 32, Failures: 4, LatencySum: 96 * time.Millisecond},
		Base:   CanaryArmOutcome{Requests: 32, Failures: 2, LatencySum: 64 * time.Millisecond},
	}
	first, second := a.Recommend(in), a.Recommend(in)
	assert.Equal(t, first, second)
	assert.Equal(t, []string{
		"failure rate: canary 0.1250 vs base 0.0625 (delta 0.0625 >= 0.0625, floor 0.0312)",
		"latency: canary mean 3ms vs base mean 2ms (ratio 1.500 >= 1.500)",
		"recommendation only: run the manual rollback (PUT enabled=false — atomic, bumps the version key); the system never rolls back by itself",
	}, first.Reasons)
}

func TestCanaryRolloutAdvisor_ConcurrentUse(t *testing.T) {
	// The advisor is immutable after construction: concurrent evaluations
	// must be race-free and identical.
	a := NewCanaryRolloutAdvisor(10, 10, 0.0625, 0.03125, 1.5)
	a.now = func() time.Time { return time.Unix(1700000000, 0) }
	in := CanaryAdviceInput{
		RolloutID: "r1", Version: 1,
		Canary: CanaryArmOutcome{Requests: 32, Failures: 4},
		Base:   CanaryArmOutcome{Requests: 32, Failures: 2},
	}
	want := a.Recommend(in)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.Equal(t, want, a.Recommend(in))
		}()
	}
	wg.Wait()
}
