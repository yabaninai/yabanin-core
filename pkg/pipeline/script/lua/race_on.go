//go:build race

package lua

// raceEnabled reports race-instrumented builds. The detector multiplies the
// cost of allocation- and copy-heavy VM execution severalfold and shared
// self-hosted runners add GC pauses and CPU contention, so wall-clock
// ceilings are scaled by raceWallScale on these builds only. The step budget
// needs no scaling: dispatch counts do not depend on machine speed.
const raceEnabled = true
