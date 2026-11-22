package cli

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/stretchr/testify/require"
)

// Critical-go wave 3 facts: the admission/rate-limit surface facts — fair
// shed hints, budget event attribution, the workload cap knob, and the
// OpenAI-style rate-limit header rendering.
func TestAdmissionLimitFacts(t *testing.T) {
	for i := range uint8(9) {
		if i < 5 {
			admissionEarlyCase(t, int(i))
			continue
		}
		admissionLateCase(t, int(i))
	}
}

// admissionEarlyCase covers cases 0-4.
func admissionEarlyCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 0:
		// fairShedRetryAfterSeconds: 0/negative omit the header, positive
		// hints round up and cap at the 60s client ceiling.
		require.Equal(t, 0, fairShedRetryAfterSeconds(0))
		require.Equal(t, 0, fairShedRetryAfterSeconds(-time.Second))
		require.Equal(t, 1, fairShedRetryAfterSeconds(500*time.Millisecond))
		require.Equal(t, 2, fairShedRetryAfterSeconds(1500*time.Millisecond))
		require.Equal(t, 60, fairShedRetryAfterSeconds(60*time.Second))
		require.Equal(t, 60, fairShedRetryAfterSeconds(61*time.Second))
	case 1:
		// fairShedMessage mirrors the key rate-limit wording.
		require.Equal(t, "gateway capacity reached (capacity), retry in 3s",
			fairShedMessage(3, router.ShedCapacity))
		require.Equal(t, "gateway capacity reached (tenant_limit)",
			fairShedMessage(0, router.ShedTenantLimit))
	case 2:
		// budgetEventUser: chat-shaped events carry the user, non-chat omit.
		core := admissionCore{UserID: "u1"}
		require.Equal(t, "u1", core.budgetEventUser(true))
		require.Empty(t, core.budgetEventUser(false))
	case 3:
		// workloadCapFromEnv: unset, unparsable or non-positive values keep
		// the ledger disabled; a positive value converts USD to micros.
		t.Setenv(WorkloadBudgetEnvUSD, "")
		require.Equal(t, money.MicroUSD(0), workloadCapFromEnv())
		t.Setenv(WorkloadBudgetEnvUSD, "abc")
		require.Equal(t, money.MicroUSD(0), workloadCapFromEnv())
		t.Setenv(WorkloadBudgetEnvUSD, "-1")
		require.Equal(t, money.MicroUSD(0), workloadCapFromEnv())
		t.Setenv(WorkloadBudgetEnvUSD, "0")
		require.Equal(t, money.MicroUSD(0), workloadCapFromEnv())
		t.Setenv(WorkloadBudgetEnvUSD, " 2.5 ")
		require.Equal(t, money.MicroUSD(2500000), workloadCapFromEnv())
	case 4:
		// estimateRequestTokens seeds reservations at ~4 bytes/token.
		require.Equal(t, int64(0), estimateRequestTokens(0))
		require.Equal(t, int64(1), estimateRequestTokens(4))
		require.Equal(t, int64(2), estimateRequestTokens(5))
	default:
		t.Fatalf("unknown early admission case %d", index)
	}
}

// admissionLateCase covers cases 5-8.
func admissionLateCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 5:
		// rateLimitDimensionText names the binding dimension; anything
		// outside the token dimensions reads as RPM.
		require.Equal(t, "tokens per minute (TPM) limit exceeded", rateLimitDimensionText("tpm"))
		require.Equal(t, "input tokens per minute (ITPM) limit exceeded", rateLimitDimensionText("itpm"))
		require.Equal(t, "output tokens per minute (OTPM) limit exceeded", rateLimitDimensionText("otpm"))
		require.Equal(t, "requests per minute (RPM) limit exceeded", rateLimitDimensionText("rpm"))
		require.Equal(t, "requests per minute (RPM) limit exceeded", rateLimitDimensionText(""))
	case 6:
		// setRateLimitHeaders mirrors the decision exactly; a dimension
		// without a limit stays absent; negative remainders clamp to 0.
		w := httptest.NewRecorder()
		setRateLimitHeaders(w, admitDecision{})
		require.Empty(t, w.Header().Get("x-ratelimit-limit-requests"))
		w = httptest.NewRecorder()
		setRateLimitHeaders(w, admitDecision{rpmLimit: 60, rpmRem: -1, rpmReset: 90 * time.Second})
		require.Equal(t, "60", w.Header().Get("x-ratelimit-limit-requests"))
		require.Equal(t, "0", w.Header().Get("x-ratelimit-remaining-requests"))
		require.Equal(t, "1m30s", w.Header().Get("x-ratelimit-reset-requests"))
		require.Empty(t, w.Header().Get("x-ratelimit-limit-tokens"))
		w = httptest.NewRecorder()
		setRateLimitHeaders(w, admitDecision{rpmLimit: 60, rpmRem: 7, rpmReset: time.Second,
			tpmLimit: 1000, tpmRem: 999, tpmReset: 3 * time.Second})
		require.Equal(t, "7", w.Header().Get("x-ratelimit-remaining-requests"))
		require.Equal(t, "1000", w.Header().Get("x-ratelimit-limit-tokens"))
		require.Equal(t, "999", w.Header().Get("x-ratelimit-remaining-tokens"))
		require.Equal(t, "3s", w.Header().Get("x-ratelimit-reset-tokens"))
	case 7:
		// formatResetSeconds rounds up to whole seconds and clamps negatives.
		require.Equal(t, "0s", formatResetSeconds(0))
		require.Equal(t, "0s", formatResetSeconds(-3*time.Second))
		require.Equal(t, "1s", formatResetSeconds(500*time.Millisecond))
		require.Equal(t, "1m30s", formatResetSeconds(90*time.Second))
		require.Equal(t, "1m1s", formatResetSeconds(61*time.Second))
	case 8:
		// max64 is the plain maximum.
		require.Equal(t, int64(5), max64(5, 3))
		require.Equal(t, int64(5), max64(3, 5))
		require.Equal(t, int64(-1), max64(-1, -2))
	default:
		t.Fatalf("unknown late admission case %d", index)
	}
}
