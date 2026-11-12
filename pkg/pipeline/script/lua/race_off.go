//go:build !race

package lua

// raceEnabled is false on production builds; wall ceilings are unscaled.
const raceEnabled = false
