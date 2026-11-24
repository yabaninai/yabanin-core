package dimensions

// Correction tests: lineage binds by value, the original is never mutated,
// and events stay dedupable while corrections stay distinct.

import (
	"strings"
	"testing"
)

func TestBindCorrection_BindsLineage(t *testing.T) {
	got, err := BindCorrection(usdFixture(), correctionSuccessorFixture())
	if err != nil {
		t.Fatalf("bind correction: %v", err)
	}
	pairs := []struct{ name, want string }{
		{"lifecycle", string(LifecycleCorrected)},
		{"corrects_component_id", "comp-req-0001-usd"},
		{"tenant_id", "tenant-acme"},
		{"meter", "money.usd"},
		{"unit", "USD"},
	}
	for _, p := range pairs {
		if gotValue(got, p.name) != p.want {
			t.Errorf("%s = %s, want %s", p.name, gotValue(got, p.name), p.want)
		}
	}
	if len(got.CoverageMeters) != 1 || got.CoverageMeters[0] != "money.usd" {
		t.Errorf("coverage_meters = %v, want [money.usd]", got.CoverageMeters)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("bound correction should validate: %v", err)
	}
}

// gotValue reads a handful of string fields by name for table-driven checks.
func gotValue(c Component, name string) string {
	switch name {
	case "lifecycle":
		return string(c.Lifecycle)
	case "corrects_component_id":
		return c.CorrectsComponentID
	case "tenant_id":
		return c.TenantID
	case "meter":
		return c.Meter
	case "unit":
		return c.Unit
	}
	return ""
}

func TestBindCorrection_DoesNotMutateOriginal(t *testing.T) {
	original := usdFixture()
	before := string(mustMarshal(t, original))
	got, err := BindCorrection(original, correctionSuccessorFixture())
	if err != nil {
		t.Fatalf("bind correction: %v", err)
	}
	after := string(mustMarshal(t, original))
	if before != after {
		t.Errorf("original mutated by BindCorrection:\nbefore %s\nafter  %s", before, after)
	}
	if got.ComponentID == original.ComponentID {
		t.Error("successor must keep its own component_id")
	}
}

func TestBindCorrection_SupersedesNotRewrites(t *testing.T) {
	original := usdFixture()
	original.Lifecycle = LifecycleFinal
	got, err := BindCorrection(original, correctionSuccessorFixture())
	if err != nil {
		t.Fatalf("bind correction: %v", err)
	}
	if got.Quantity == nil || got.Quantity.String() != "0.03" {
		t.Errorf("successor quantity = %v, want 0.03", got.Quantity)
	}
	if original.Quantity == nil || original.Quantity.String() != "0.02" {
		t.Errorf("original quantity = %v, must stay 0.02", original.Quantity)
	}
	if original.Lifecycle != LifecycleFinal {
		t.Errorf("original lifecycle = %s, must stay final", original.Lifecycle)
	}
	if got.CorrectsComponentID != original.ComponentID {
		t.Errorf("successor must point at %s, got %s", original.ComponentID, got.CorrectsComponentID)
	}
}

func TestCorrection_DeliveryKeysDistinctPerEvent(t *testing.T) {
	original := usdFixture()
	corrected, err := BindCorrection(original, correctionSuccessorFixture())
	if err != nil {
		t.Fatalf("bind correction: %v", err)
	}
	if original.DeliveryKey() == corrected.DeliveryKey() {
		t.Error("successor event must have a distinct delivery key")
	}
	want := "tenant-acme\x00evt-2026-06-01-0002"
	if corrected.DeliveryKey() != want {
		t.Errorf("corrected DeliveryKey() = %q, want %q", corrected.DeliveryKey(), want)
	}
	if !strings.Contains(corrected.DeliveryKey(), corrected.EventID) {
		t.Error("delivery key must contain the successor event id")
	}
}

func TestManualCorrectionWithoutLineageIsInvalid(t *testing.T) {
	manual := correctionSuccessorFixture()
	manual.Lifecycle = LifecycleCorrected
	assertProblem(t, manual, nil, "corrects_component_id is required when lifecycle is corrected")
	bound, err := BindCorrection(usdFixture(), correctionSuccessorFixture())
	if err != nil {
		t.Fatalf("bind correction: %v", err)
	}
	if err := bound.Validate(); err != nil {
		t.Errorf("bound correction should validate: %v", err)
	}
}

func TestBindCorrection_CrossMeterSuccessorInheritsOriginalDimension(t *testing.T) {
	original := energyFixture()
	successor := correctionSuccessorFixture()
	got, err := BindCorrection(original, successor)
	if err != nil {
		t.Fatalf("bind correction: %v", err)
	}
	if got.Meter != "energy.it" || got.Unit != "Wh" {
		t.Errorf("successor dimension = %s/%s, want energy.it/Wh", got.Meter, got.Unit)
	}
	if got.Quantity == nil || got.Quantity.String() != "0.03" {
		t.Errorf("successor keeps its own quantity, got %v", got.Quantity)
	}
	if got.CoverageMeters[0] != "energy.it" {
		t.Errorf("coverage follows the original meter, got %v", got.CoverageMeters)
	}
}

// A correction is a new event: reusing the original's event ID would replay
// its delivery key and silently merge two deliveries in future dedup, so
// the pairing is rejected and no partially bound component escapes.
func TestBindCorrection_RejectsOriginalEventID(t *testing.T) {
	original := usdFixture()
	replay := correctionSuccessorFixture()
	replay.EventID = original.EventID
	got, err := BindCorrection(original, replay)
	if err == nil || !strings.Contains(err.Error(), "must differ from the corrected event") {
		t.Fatalf("err = %v, want rejection naming the reused event id", err)
	}
	if got.EventID != "" || got.TenantID != "" {
		t.Errorf("rejected pairing must return a zero component, got %+v", got)
	}
	selfCopy := original
	if got, err := BindCorrection(original, selfCopy); err == nil || got.EventID != "" {
		t.Errorf("binding a component as its own correction: err = %v, got %+v", err, got)
	}
}
