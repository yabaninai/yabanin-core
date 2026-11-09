package run

// E01-P05 W04-C02: the pure State→snapshot mapper, pinned with literal
// license.State values. In chain-only contours *license.Server can only
// ever yield the zero State (no activation document), so the non-zero arms
// are pinned HERE rather than through a live server; the mapper itself is
// 1:1 with no derivation, and this file is where a future drift (a field
// added to State but not surfaced, or a value rewritten in transit) turns
// red.

import (
	"reflect"
	"testing"

	"github.com/reireirei/yabanin/pkg/license"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

func TestMapLicenseState_LiteralArms(t *testing.T) {
	active := license.State{
		Active:    true,
		OrgID:     "ex-org",
		Seats:     7,
		Features:  []string{"protection-pack", "media-persistence"},
		ExpiresAt: "2027-05-01T00:00:00Z",
	}
	grace := active
	grace.Expired = true
	hard := license.State{OrgID: "ex-org", HardExpired: true, ExpiresAt: "2026-04-01T00:00:00Z"}

	cases := []struct {
		label      string
		configured bool
		st         license.State
		want       handlers.EntitlementDiagnosticsSnapshot
	}{
		{
			label: "unconfigured contour (no license file): all dark, configured false",
			st:    license.State{},
			want:  handlers.EntitlementDiagnosticsSnapshot{},
		},
		{
			label:      "chain-only contour: configured but activation plane dark (honest dark)",
			configured: true,
			st:         license.State{},
			want:       handlers.EntitlementDiagnosticsSnapshot{Configured: true},
		},
		{
			label:      "active state is copied 1:1",
			configured: true,
			st:         active,
			want: handlers.EntitlementDiagnosticsSnapshot{
				Configured: true, Active: true, OrgID: "ex-org", Seats: 7,
				Features:  []string{"protection-pack", "media-persistence"},
				ExpiresAt: "2027-05-01T00:00:00Z",
			},
		},
		{
			label:      "grace state keeps Active (the served grace semantics)",
			configured: true,
			st:         grace,
			want: handlers.EntitlementDiagnosticsSnapshot{
				Configured: true, Active: true, OrgID: "ex-org", Seats: 7,
				Features: []string{"protection-pack", "media-persistence"}, Expired: true,
				ExpiresAt: "2027-05-01T00:00:00Z",
			},
		},
		{
			label:      "hard-expired state",
			configured: true,
			st:         hard,
			want: handlers.EntitlementDiagnosticsSnapshot{
				Configured: true, OrgID: "ex-org", HardExpired: true,
				ExpiresAt: "2026-04-01T00:00:00Z",
			},
		},
	}
	for _, tc := range cases {
		got := mapLicenseState(tc.configured, tc.st)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: mapper drifted:\n got %+v\nwant %+v", tc.label, got, tc.want)
		}
	}
}

// TestMapLicenseState_NoDerivation pins the no-derivation law: the mapper
// may not synthesize or rewrite anything — the snapshot's verdict fields
// equal the State's verdict fields for arbitrary shapes, including the
// contradictory shape the state machine never serves.
func TestMapLicenseState_NoDerivation(t *testing.T) {
	weird := license.State{Active: true, Expired: true, HardExpired: true, OrgID: "w", Seats: 1}
	got := mapLicenseState(true, weird)
	if !got.Active || !got.Expired || !got.HardExpired || got.OrgID != "w" || got.Seats != 1 {
		t.Errorf("mapper rewrote the state: %+v", got)
	}
}
