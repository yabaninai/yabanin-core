package router

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// R2: opt-in time-window / batch tier downgrade. During cheap hours (e.g.
// 22:00–07:00 across midnight) a request is routed to a cheaper tier unless the
// client marked it high-priority; an explicit X-Yabanin-Batch:true always
// downgrades. Pure function + small types so it is trivially table-testable.
//
// The downgrade is a ceiling, not a floor: a Hard request stays Hard (it needs
// the top tier), while Medium→easy and Easy→easy are applied. The actual model
// for the target class is resolved by the TierRouter at the call site.

// TimeWindow is a [start, end) 24h clock window. It wraps across midnight when
// start > end (e.g. 22:00–07:00).
type TimeWindow struct {
	Start time.Duration
	End   time.Duration
}

// ParseTimeWindow parses "HH:MM-HH:MM" (24h clock, minutes precision) into a
// TimeWindow. Both endpoints must be valid HH:MM (00–23 / 00–59).
func ParseTimeWindow(s string) (TimeWindow, error) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) != 2 {
		return TimeWindow{}, fmt.Errorf("time window must be 'HH:MM-HH:MM' (got %q)", s)
	}
	start, err := parseHM(parts[0])
	if err != nil {
		return TimeWindow{}, fmt.Errorf("start: %w", err)
	}
	end, err := parseHM(parts[1])
	if err != nil {
		return TimeWindow{}, fmt.Errorf("end: %w", err)
	}
	return TimeWindow{Start: start, End: end}, nil
}

func parseHM(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("must be HH:MM (got %q)", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("hour out of range (got %q)", parts[0])
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("minute out of range (got %q)", parts[1])
	}
	return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute, nil
}

// Contains reports whether t's time-of-day (in the given location, defaulting
// to UTC when loc is nil) falls inside the [start, end) window. A non-wrapping
// window is start <= t < end; a wrapping window (start > end) is t >= start ||
// t < end. An empty window (start == end) matches nothing.
func (w TimeWindow) Contains(t time.Time, loc *time.Location) bool {
	if w.Start == w.End {
		return false
	}
	if loc == nil {
		loc = time.UTC
	}
	tod := time.Duration(t.In(loc).Hour())*time.Hour + time.Duration(t.In(loc).Minute())*time.Minute
	if w.Start < w.End {
		return tod >= w.Start && tod < w.End
	}
	return tod >= w.Start || tod < w.End
}

// TierDowngradeStep is the number of tiers a non-hard request moves down in one
// application (1 = medium→easy, easy→easy). A hard request is never moved.
const TierDowngradeStep = 1

// DowngradeClass returns the class to route to after applying a cheap-hours /
// batch downgrade. Hard is returned unchanged (it must keep the top tier);
// Medium → Easy; Easy → Easy.
func DowngradeClass(cls string) string {
	switch cls {
	case "hard":
		return "hard"
	default:
		return "easy"
	}
}

// ShouldDowngrade reports whether a request should be downgraded given the
// active cheap-hours window, the request time, the client priority header, and
// the batch header.
//
//   - batch true            → downgrade (regardless of window/priority).
//   - in window AND NOT high → downgrade.
//   - otherwise              → no downgrade.
func ShouldDowngrade(inWindow, batch, highPriority bool) bool {
	if batch {
		return true
	}
	return inWindow && !highPriority
}
