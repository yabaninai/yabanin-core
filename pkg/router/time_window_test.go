package router

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTimeWindow(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    TimeWindow
		wantErr bool
	}{
		{"normal", "22:00-07:00", TimeWindow{Start: 22 * time.Hour, End: 7 * time.Hour}, false},
		{"same-day", "08:00-18:00", TimeWindow{Start: 8 * time.Hour, End: 18 * time.Hour}, false},
		{"whitespace", " 22:00 - 07:00 ", TimeWindow{Start: 22 * time.Hour, End: 7 * time.Hour}, false},
		{"missing dash", "22:00", TimeWindow{}, true},
		{"three parts", "22:00-07:00-01:00", TimeWindow{}, true},
		{"bad hour", "25:00-07:00", TimeWindow{}, true},
		{"bad minute", "22:60-07:00", TimeWindow{}, true},
		{"no colon", "2200-0700", TimeWindow{}, true},
		{"negative", "-2:00-07:00", TimeWindow{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTimeWindow(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTimeWindow_Contains(t *testing.T) {
	// Wrapping window 22:00–07:00.
	w, err := ParseTimeWindow("22:00-07:00")
	require.NoError(t, err)
	utc := time.UTC

	cases := []struct {
		tod string
		in  bool
	}{
		{"2026-09-06T23:30:00Z", true},  // 23:30 in window
		{"2026-09-07T00:00:00Z", true},  // 00:00 (midnight) in window
		{"2026-09-07T06:59:00Z", true},  // 06:59 in window
		{"2026-09-07T07:00:00Z", false}, // 07:00 is the end (exclusive)
		{"2026-09-07T12:00:00Z", false}, // noon, out
		{"2026-09-06T21:59:00Z", false}, // 21:59, just before start
		{"2026-09-06T22:00:00Z", true},  // 22:00 is the start (inclusive)
	}
	for _, c := range cases {
		tm, err := time.Parse(time.RFC3339, c.tod)
		require.NoError(t, err)
		assert.Equalf(t, c.in, w.Contains(tm, utc), "Contains(%s)", c.tod)
	}
}

func TestTimeWindow_ContainsSameDay(t *testing.T) {
	w, err := ParseTimeWindow("08:00-18:00")
	require.NoError(t, err)
	// Build a UTC time-of-day directly (no string parsing / local-time drift).
	at := func(h, m int) time.Time {
		return time.Date(2026, 9, 6, h, m, 0, 0, time.UTC)
	}
	assert.True(t, w.Contains(at(9, 0), time.UTC))
	assert.True(t, w.Contains(at(17, 59), time.UTC))
	assert.False(t, w.Contains(at(18, 0), time.UTC)) // exclusive end
	assert.False(t, w.Contains(at(7, 59), time.UTC)) // before start
	assert.True(t, w.Contains(at(8, 0), time.UTC))   // inclusive start
}

func TestTimeWindow_EmptyWindowMatchesNothing(t *testing.T) {
	w := TimeWindow{Start: 5 * time.Hour, End: 5 * time.Hour}
	tm := time.Date(2026, 9, 6, 5, 0, 0, 0, time.UTC)
	assert.False(t, w.Contains(tm, time.UTC))
}

func TestTimeWindow_DefaultsToUTCWhenNilLoc(t *testing.T) {
	w, _ := ParseTimeWindow("22:00-07:00")
	// A time at 23:00 UTC. loc=nil must be treated as UTC.
	tm := time.Date(2026, 9, 6, 23, 0, 0, 0, time.UTC)
	assert.True(t, w.Contains(tm, nil))
}

func TestDowngradeClass(t *testing.T) {
	assert.Equal(t, "hard", DowngradeClass("hard")) // hard never moves
	assert.Equal(t, "easy", DowngradeClass("medium"))
	assert.Equal(t, "easy", DowngradeClass("easy"))
	assert.Equal(t, "easy", DowngradeClass("")) // default medium → easy
}

func TestShouldDowngrade(t *testing.T) {
	tests := []struct {
		name     string
		inWindow bool
		batch    bool
		highPri  bool
		want     bool
	}{
		{"off, no window, not batch", false, false, false, false},
		{"in window, not high, not batch", true, false, false, true},
		{"in window, high priority", true, false, true, false},
		{"not in window, batch", false, true, false, true},
		{"in window, batch, high", true, true, true, true}, // batch overrides
		{"not in window, high, no batch", false, false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ShouldDowngrade(tc.inWindow, tc.batch, tc.highPri))
		})
	}
}
