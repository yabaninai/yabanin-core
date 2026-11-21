// SPDX-License-Identifier: Apache-2.0

// Package retryclock carries the between-attempts sleeper for pkg/retry
// through a context. Tests use it to observe retry scheduling
// deterministically (recorded delays, cancellation from inside a pending
// wait) without exporting a sleeping seam on the public retry.Policy.
// Production code never wraps a context, so retry.Do keeps its
// context-aware real-time waiting by default.
package retryclock

import (
	"context"
	"time"
)

// Sleeper suspends the caller for d or until ctx ends, mirroring the
// context-aware real-time wait it replaces.
type Sleeper func(ctx context.Context, d time.Duration)

type sleeperKey struct{}

// With returns a context whose retry waits are driven by sleep instead of
// real time.
func With(ctx context.Context, sleep Sleeper) context.Context {
	return context.WithValue(ctx, sleeperKey{}, sleep)
}

// From returns the sleeper ctx carries; ok reports whether a usable one is
// present. A nil sleeper reports false so the caller keeps the real-time
// wait.
func From(ctx context.Context) (sleep Sleeper, ok bool) {
	sleep, ok = ctx.Value(sleeperKey{}).(Sleeper)
	return sleep, ok && sleep != nil
}
