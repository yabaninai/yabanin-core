package adminstore

// Lockstep guard for the mirrored §14 default grace floor. The product edge
// adminstore → pkg/budget is forbidden (pkg/budget's integration tests import
// adminstore; a product-level edge is an import cycle), so the default lives
// here as a constant. This test keeps the mirror honest: if the budget
// package's §14 default ever moves, this fails and the constant must be
// updated consciously (or the dependency restructured at a lower layer).
import (
	"testing"

	"github.com/reireirei/yabanin/pkg/budget"
)

func TestBudgetsDefaultGraceFloorMirrorLockstep(t *testing.T) {
	if defaultGraceFloorCents != budget.DefaultReservationConfig().DefaultGraceFloorCents {
		t.Fatalf("mirrored default grace floor drifted: adminstore=%d budget=%d — update defaultGraceFloorCents consciously",
			defaultGraceFloorCents, budget.DefaultReservationConfig().DefaultGraceFloorCents)
	}
}
