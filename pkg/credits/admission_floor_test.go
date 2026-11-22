package credits

// Per-org grace floor resolution (ADR-0001 §8) at unit level. The floor
// resolver is pure, so the override precedence — explicit 0 wins over a
// negative platform floor (AF-01 zero preserved), NULL falls back to the
// store-level floor — is pinned without a database. The admission decision
// itself is authoritative (fresh snapshot per decision): its behavior is
// covered DB-backed in admission_floor_int_test.go and
// admission_config_test.go; seeding the display cache cannot gate admission
// by contract, so the former cache-fed audit fixtures were converted.

import "testing"

func floorPtr(v int64) *int64 { return &v }

// TestEffectiveFloorCents pins the resolver: the persisted override wins
// verbatim (0 included — AF-01 zero preserved), NULL falls back to the
// store-level platform floor.
func TestEffectiveFloorCents(t *testing.T) {
	cases := []struct {
		name       string
		storeFloor int64
		override   *int64
		want       int64
	}{
		{"nil override falls back to the store floor", -100, nil, -100},
		{"explicit zero wins over a negative store floor", -100, floorPtr(0), 0},
		{"negative override wins verbatim", -100, floorPtr(-1), -1},
		{"minimum bounded override wins verbatim", -100, floorPtr(-100000), -100000},
		{"zero store floor with nil override stays zero", 0, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveFloorCents(tc.storeFloor, tc.override); got != tc.want {
				t.Fatalf("effectiveFloorCents(%d, %v) = %d, want %d", tc.storeFloor, tc.override, got, tc.want)
			}
		})
	}
}
