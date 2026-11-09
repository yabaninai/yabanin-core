package script

// DefaultMaxWorkers is the per-engine concurrent VM execution limit. Script
// engines default to 16 workers, matching the Expr VM cap.
const DefaultMaxWorkers = 16
