package handlers

// the same bcrypt work as a login with a wrong password, so response time
// does not reveal whether the account exists. The comparison is statistical:
// 20 interleaved samples per group, medians compared with a ±5 ms budget
// plus a 10% noise allowance. No sleeps — the work itself is the signal.

import (
	"net/url"
	"sort"
	"testing"
	"time"
)

func medianDuration(xs []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), xs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func TestLoginTimingParityUnknownEmailVsWrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("timing parity needs the full run (real bcrypt cost)")
	}
	h, email := newLoginTestHandlers(t)
	csrf, token, _ := loginPageGET(t, h, "", "")

	const samples = 20
	wrongPassword := url.Values{
		"email":    {email},
		"password": {"definitely-not-the-password"},
		"_csrf":    {token},
	}
	unknownEmail := url.Values{
		"email":    {"no-such-admin@example.com"},
		"password": {"definitely-not-the-password"},
		"_csrf":    {token},
	}

	// Warm-up: template and allocator paths, one sample per group.
	loginPOST(t, h, wrongPassword, csrf, "")
	loginPOST(t, h, unknownEmail, csrf, "")

	withWrongPassword := make([]time.Duration, 0, samples)
	withUnknownEmail := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		loginPOST(t, h, wrongPassword, csrf, "")
		withWrongPassword = append(withWrongPassword, time.Since(start))

		start = time.Now()
		loginPOST(t, h, unknownEmail, csrf, "")
		withUnknownEmail = append(withUnknownEmail, time.Since(start))
	}

	medianWrong := medianDuration(withWrongPassword)
	medianUnknown := medianDuration(withUnknownEmail)

	// Sanity: both groups must have done real bcrypt work; otherwise the
	// parity claim would be vacuous.
	if medianWrong < 100*time.Millisecond || medianUnknown < 100*time.Millisecond {
		t.Fatalf("bcrypt work not exercised: wrong-password median %v, unknown-email median %v", medianWrong, medianUnknown)
	}

	// Parity budget: ±5 ms plus 10% noise allowance on the slower median.
	budget := 5*time.Millisecond + medianWrong/10
	delta := medianWrong - medianUnknown
	if delta < 0 {
		delta = -delta
	}
	if delta > budget {
		t.Errorf("login timing oracle: unknown-email median %v vs wrong-password median %v (Δ=%v, budget %v) — account existence is distinguishable", medianUnknown, medianWrong, delta, budget)
	}
}
