//go:build !race

package expr

// raceEnabled is false on production builds; the wall ceiling is unscaled.
const raceEnabled = false
