//go:build race

package starlark

// raceEnabled reports race-instrumented builds. The detector multiplies the
// cost of allocation-heavy interpreter execution severalfold and shared
// self-hosted runners add GC pauses and CPU contention, so the wall-clock
// watchdog is scaled by raceWallScale on these builds only. The step budget
// needs no scaling: step counts do not depend on machine speed.
const raceEnabled = true
