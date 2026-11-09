package retry

// N09-P01-T10 [risk] — internal probes for the Retry-After bound. Test-only
// card: zero production changes. delayFor is unexported, so the Do-level
// corpus (package retry_test) pins the wall clock; these probes pin the
// computed durations exactly, including one documented observation the
// Do-level test cannot observe: a MaxDelay of zero disables the clamp, so a
// server-controlled far-future HTTP-date is trusted as-is. Flagged in the
// card record for a policy-owner decision (recommended: clamp to the
// package default even when the policy leaves MaxDelay unset).

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func t10Header(v string) http.Header {
	h := http.Header{}
	h.Set("Retry-After", v)
	return h
}

// TestN09P1T10_Risk_DelayForHTTPDateExact: the HTTP-date form resolves to
// time-until and clamps to MaxDelay when a MaxDelay is configured.
func TestN09P1T10_Risk_DelayForHTTPDateExact(t *testing.T) {
	t.Parallel()

	p := Policy{BaseDelay: 5 * time.Millisecond, MaxDelay: 20 * time.Millisecond}

	farFuture := time.Now().Add(73 * 365 * 24 * time.Hour)
	d := p.delayFor(0, Result{Headers: t10Header(farFuture.Format(http.TimeFormat))})
	assert.Equal(t, 20*time.Millisecond, d,
		"far-future date must clamp to MaxDelay")

	nearFuture := time.Now().Add(5 * time.Second)
	d = p.delayFor(0, Result{Headers: t10Header(nearFuture.Format(http.TimeFormat))})
	assert.Greater(t, d, time.Duration(0))
	assert.LessOrEqual(t, d, 20*time.Millisecond,
		"a below-max date passes through, an above-max one clamps")

	past := time.Now().Add(-time.Hour)
	d = p.delayFor(2, Result{Headers: t10Header(past.Format(http.TimeFormat))})
	assert.Greater(t, d, time.Duration(0), "past dates fall through to the backoff path")
	assert.LessOrEqual(t, d, p.MaxDelay)
}

// TestN09P1T10_Risk_DelayForUnclampedWhenMaxDelayUnset: the documented
// observation. With MaxDelay=0 the clamp condition (p.MaxDelay > 0) is false,
// so the raw server-controlled value is returned. Pinned as current behavior;
// see the card record for the recommended follow-up.
func TestN09P1T10_Risk_DelayForUnclampedWhenMaxDelayUnset(t *testing.T) {
	t.Parallel()

	p := Policy{BaseDelay: 5 * time.Millisecond, MaxDelay: 0} // MaxDelay unset

	farFuture := time.Now().Add(73 * 365 * 24 * time.Hour)
	d := p.delayFor(0, Result{Headers: t10Header(farFuture.Format(http.TimeFormat))})
	assert.Greater(t, d, 365*24*time.Hour,
		"observation: with MaxDelay unset the server-controlled date is unclamped")

	d = p.delayFor(0, Result{Headers: t10Header("3600")})
	assert.Equal(t, time.Hour, d,
		"observation: with MaxDelay unset the seconds form is unclamped too")
}
