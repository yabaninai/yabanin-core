package cli

import (
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/circuit"
)

// CircuitScopeWiring resolves YABANIN_CIRCUIT_SCOPE in services/run (pkg/config stays untouched —
// the PolicyWiring/JWTWiring pattern).
//
//	YABANIN_CIRCUIT_SCOPE = per-endpoint | global
//
//	per-endpoint (default): every upstream endpoint (normalized scheme://host)
//	gets an independent breaker — a flapping provider opens only its own
//	circuit and the fallback chain can still reach candidates on other
//	endpoints (W-VER defect fix).
//	an open circuit rejects requests before the fallback chain runs.
type CircuitScopeWiring struct {
	// Scope is the resolved granularity. The zero value (ScopePerEndpoint)
	// is the W-VER default, so unwired callers get the new default without
	// extra ceremony.
	Scope circuit.Scope
}

// ResolvedScope returns the wiring scope, mapping the zero value onto the
// per-endpoint default.
func (w CircuitScopeWiring) ResolvedScope() circuit.Scope {
	if w.Scope == circuit.ScopePerEndpoint || w.Scope == circuit.ScopeGlobal {
		return w.Scope
	}
	return circuit.ScopePerEndpoint
}

// ResolveCircuitScope parses the YABANIN_CIRCUIT_SCOPE env value. Empty and
// unknown values resolve to per-endpoint (the second return is a non-empty
// warning note for unknown values only — an unset knob must not log).
func ResolveCircuitScope(v string) (circuit.Scope, string) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return circuit.ScopePerEndpoint, ""
	case "per-endpoint", "per_endpoint":
		return circuit.ScopePerEndpoint, ""
	case "global":
		return circuit.ScopeGlobal, ""
	default:
		return circuit.ScopePerEndpoint, fmt.Sprintf("YABANIN_CIRCUIT_SCOPE %q is not per-endpoint|global — using per-endpoint", v)
	}
}
