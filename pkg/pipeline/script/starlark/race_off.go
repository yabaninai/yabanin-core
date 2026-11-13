//go:build !race

package starlark

// raceEnabled is false on production builds; the wall watchdog is unscaled.
const raceEnabled = false
