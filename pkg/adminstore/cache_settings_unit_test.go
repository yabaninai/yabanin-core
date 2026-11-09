package adminstore

// P5.5 unit tests: the pure routing-mode helpers behind the per-org cache/
// routing settings (no DB — the SQL paths carry their own integration
// coverage). Table-driven so every mode branch is pinned explicitly.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultRoutingThreshold(t *testing.T) {
	tests := []struct {
		name string
		mode string
		set  float64
		want float64
	}{
		{"aggressive cost pins the low cutoff", RoutingModeAggressiveCost, 0.95, 0.4},
		{"classifier only pins the high cutoff", RoutingModeClassifierOnly, 0.1, 0.9},
		{"auto uses the stored threshold", RoutingModeAuto, 0.75, 0.75},
		{"auto without a stored value falls back to 0.6", RoutingModeAuto, 0, 0.6},
		{"always premium falls back to the stored value", RoutingModeAlwaysPremium, 0.8, 0.8},
		{"always premium without a value falls back to 0.6", RoutingModeAlwaysPremium, 0, 0.6},
		{"unknown mode falls back to the stored value", "mystery", 0.55, 0.55},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := OrgRoutingSettings{RoutingMode: tt.mode, RoutingThresholdConfidence: tt.set}
			require.InDelta(t, tt.want, rs.DefaultRoutingThreshold(), 1e-9)
		})
	}
}

func TestEffectiveRoutingMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{"always premium", RoutingModeAlwaysPremium, "always_premium"},
		{"always cheap", RoutingModeAlwaysCheap, "always_cheap"},
		{"aggressive cost routes by class", RoutingModeAggressiveCost, "route_by_class"},
		{"classifier only routes by class", RoutingModeClassifierOnly, "route_by_class"},
		{"auto routes by class", RoutingModeAuto, "route_by_class"},
		{"disabled", "disabled", "disabled"},
		{"unknown treated as disabled", "mystery", "disabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, (&OrgRoutingSettings{RoutingMode: tt.mode}).EffectiveRoutingMode())
		})
	}
}
