//go:build race

package expr

// raceEnabled reports race-instrumented builds. The detector multiplies the
// cost of allocation-heavy VM execution severalfold and shared self-hosted
// runners add GC pauses and CPU contention, so the wall-clock ceiling is
// scaled by raceWallScale on these builds only. There is no deterministic
// step budget to leave unscaled: expr-lang exposes no per-instruction hook
// in production builds.
const raceEnabled = true
