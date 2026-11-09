package retry

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestAfter_ExportedParser pins the canonical retry.After parse contract
// at the capture boundary (RATELIMIT-FALLBACK P1): the gateway decision layer
// and the client-facing render path consume hints through this exported
// function, so the same forms that the Do-loop boundary corpus pins must
// behave identically when called directly on captured attempt headers.
func TestAfter_ExportedParser(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
		want    time.Duration
	}{
		{name: "nil headers", headers: nil, want: 0},
		{name: "absent hint", headers: http.Header{}, want: 0},
		{name: "seconds form", headers: headerWith("Retry-After", "12"), want: 12 * time.Second},
		{name: "garbage form", headers: headerWith("Retry-After", "soon"), want: 0},
		{name: "negative form", headers: headerWith("Retry-After", "-5"), want: 0},
		{name: "zero seconds", headers: headerWith("Retry-After", "0"), want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := After(tc.headers)
			if tc.want == 0 {
				assert.Zero(t, got, "unusable hints must collapse to 0 (never fabricate)")
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("future http-date honored", func(t *testing.T) {
		future := time.Now().Add(2 * time.Minute).UTC().Format(http.TimeFormat)
		got := After(headerWith("Retry-After", future))
		assert.Greater(t, got, time.Minute, "a future date yields the remaining delta")
		assert.LessOrEqual(t, got, 2*time.Minute)
	})
}

func headerWith(k, v string) http.Header {
	h := http.Header{}
	h.Set(k, v)
	return h
}
