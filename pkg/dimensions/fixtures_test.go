package dimensions

// Frozen CM-00-01 fixtures: one request with USD, credit, estimated-energy and
// unknown-emissions components; expected decimals are hand-written constants.

import (
	"encoding/json"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)

func mustParseDecimal(s string) Decimal {
	d, err := ParseDecimal(s)
	if err != nil {
		panic(err)
	}
	return d
}

func decPtr(s string) *Decimal {
	d := mustParseDecimal(s)
	return &d
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func usdFixture() Component {
	q := mustParseDecimal("0.02")
	return Component{
		ComponentID:   "comp-req-0001-usd",
		EventID:       "evt-2026-06-01-0001",
		RequestID:     "req-2026-06-01-0001",
		TenantID:      "tenant-acme",
		Meter:         "money.usd",
		Unit:          "USD",
		Quantity:      &q,
		SourceKind:    "request_log",
		SourceRef:     "req-2026-06-01-0001-usd",
		Method:        "token-pricing@v1",
		FactorVersion: "pricefile-2026-06",
		EventTime:     fixtureTime,
		EffectiveTime: fixtureTime,
		Boundary:      BoundaryMeasurement,
		Precision:     PrecisionExact,
		Lifecycle:     LifecycleProvisional,
	}
}

func creditsFixture() Component {
	q := mustParseDecimal("3")
	return Component{
		ComponentID:   "comp-req-0001-credits",
		EventID:       "evt-2026-06-01-0001",
		RequestID:     "req-2026-06-01-0001",
		TenantID:      "tenant-acme",
		Meter:         "credits.internal",
		Unit:          "credit",
		Quantity:      &q,
		SourceKind:    "request_log",
		SourceRef:     "req-2026-06-01-0001-credits",
		Method:        "credit-ledger@v1",
		FactorVersion: "credit-policy-2026-06",
		EventTime:     fixtureTime,
		EffectiveTime: fixtureTime,
		Boundary:      BoundaryMeasurement,
		Precision:     PrecisionExact,
		Lifecycle:     LifecycleProvisional,
	}
}

func energyFixture() Component {
	return Component{
		ComponentID:   "comp-req-0001-energy",
		EventID:       "evt-2026-06-01-0001",
		RequestID:     "req-2026-06-01-0001",
		TenantID:      "tenant-acme",
		Meter:         "energy.it",
		Unit:          "Wh",
		SourceKind:    "telemetry",
		SourceRef:     "node-42:cpu-meter:2026-06-01",
		Method:        "shared-node-meter@v2",
		FactorVersion: "node-meter-calibration-2026-05",
		EventTime:     fixtureTime,
		EffectiveTime: fixtureTime,
		Boundary:      BoundaryMeasurement,
		Precision:     PrecisionEstimated,
		Bounds:        &Bounds{Lower: decPtr("0.4"), Upper: decPtr("0.6")},
		Lifecycle:     LifecycleFinal,
	}
}

func emissionsFixture() Component {
	return Component{
		ComponentID:   "comp-req-0001-co2",
		EventID:       "evt-2026-06-01-0001",
		RequestID:     "req-2026-06-01-0001",
		TenantID:      "tenant-acme",
		Meter:         "emissions.operational",
		Unit:          "gCO2e",
		SourceKind:    "regional-grid",
		SourceRef:     "grid-region-eu-north-1",
		Method:        "regional-factor-lookup@v1",
		EventTime:     fixtureTime,
		EffectiveTime: fixtureTime,
		Boundary:      BoundaryAllocation,
		Precision:     PrecisionUnknown,
		Lifecycle:     LifecycleProvisional,
	}
}

// correctionSuccessorFixture is a later USD measurement for the same request,
// carrying its own component and event identity.
func correctionSuccessorFixture() Component {
	c := usdFixture()
	q := mustParseDecimal("0.03")
	c.ComponentID = "comp-req-0002-usd"
	c.EventID = "evt-2026-06-01-0002"
	c.SourceRef = "req-2026-06-01-0002-usd"
	c.Quantity = &q
	return c
}

func requestFixtures() []Component {
	return []Component{usdFixture(), creditsFixture(), energyFixture(), emissionsFixture()}
}

// fixtureWant is the hand-written oracle: expected strings as literals, never
// computed by the package.
type fixtureWant struct {
	ComponentID, EventID, RequestID, TenantID    string
	Meter, Unit, Quantity                        string
	Lower, Upper                                 string
	SourceKind, SourceRef, Method, FactorVersion string
	Precision                                    Precision
	Lifecycle                                    Lifecycle
	Boundary                                     Boundary
}

func fixtureWants() []fixtureWant {
	return []fixtureWant{
		{
			ComponentID: "comp-req-0001-usd", EventID: "evt-2026-06-01-0001",
			RequestID: "req-2026-06-01-0001", TenantID: "tenant-acme",
			Meter: "money.usd", Unit: "USD", Quantity: "0.02",
			SourceKind: "request_log", SourceRef: "req-2026-06-01-0001-usd",
			Method: "token-pricing@v1", FactorVersion: "pricefile-2026-06",
			Precision: PrecisionExact, Lifecycle: LifecycleProvisional, Boundary: BoundaryMeasurement,
		},
		{
			ComponentID: "comp-req-0001-credits", EventID: "evt-2026-06-01-0001",
			RequestID: "req-2026-06-01-0001", TenantID: "tenant-acme",
			Meter: "credits.internal", Unit: "credit", Quantity: "3",
			SourceKind: "request_log", SourceRef: "req-2026-06-01-0001-credits",
			Method: "credit-ledger@v1", FactorVersion: "credit-policy-2026-06",
			Precision: PrecisionExact, Lifecycle: LifecycleProvisional, Boundary: BoundaryMeasurement,
		},
		{
			ComponentID: "comp-req-0001-energy", EventID: "evt-2026-06-01-0001",
			RequestID: "req-2026-06-01-0001", TenantID: "tenant-acme",
			Meter: "energy.it", Unit: "Wh", Quantity: "", Lower: "0.4", Upper: "0.6",
			SourceKind: "telemetry", SourceRef: "node-42:cpu-meter:2026-06-01",
			Method: "shared-node-meter@v2", FactorVersion: "node-meter-calibration-2026-05",
			Precision: PrecisionEstimated, Lifecycle: LifecycleFinal, Boundary: BoundaryMeasurement,
		},
		{
			ComponentID: "comp-req-0001-co2", EventID: "evt-2026-06-01-0001",
			RequestID: "req-2026-06-01-0001", TenantID: "tenant-acme",
			Meter: "emissions.operational", Unit: "gCO2e", Quantity: "",
			SourceKind: "regional-grid", SourceRef: "grid-region-eu-north-1",
			Method: "regional-factor-lookup@v1", FactorVersion: "",
			Precision: PrecisionUnknown, Lifecycle: LifecycleProvisional, Boundary: BoundaryAllocation,
		},
	}
}

const requestFixtureJSON = `[
  {
    "component_id": "comp-req-0001-usd",
    "event_id": "evt-2026-06-01-0001",
    "request_id": "req-2026-06-01-0001",
    "tenant_id": "tenant-acme",
    "meter": "money.usd",
    "unit": "USD",
    "quantity": "0.02",
    "source_kind": "request_log",
    "source_ref": "req-2026-06-01-0001-usd",
    "method": "token-pricing@v1",
    "factor_version": "pricefile-2026-06",
    "event_time": "2026-06-01T12:00:00Z",
    "effective_time": "2026-06-01T12:00:00Z",
    "boundary": "measurement",
    "precision": "exact",
    "lifecycle": "provisional"
  },
  {
    "component_id": "comp-req-0001-credits",
    "event_id": "evt-2026-06-01-0001",
    "request_id": "req-2026-06-01-0001",
    "tenant_id": "tenant-acme",
    "meter": "credits.internal",
    "unit": "credit",
    "quantity": "3",
    "source_kind": "request_log",
    "source_ref": "req-2026-06-01-0001-credits",
    "method": "credit-ledger@v1",
    "factor_version": "credit-policy-2026-06",
    "event_time": "2026-06-01T12:00:00Z",
    "effective_time": "2026-06-01T12:00:00Z",
    "boundary": "measurement",
    "precision": "exact",
    "lifecycle": "provisional"
  },
  {
    "component_id": "comp-req-0001-energy",
    "event_id": "evt-2026-06-01-0001",
    "request_id": "req-2026-06-01-0001",
    "tenant_id": "tenant-acme",
    "meter": "energy.it",
    "unit": "Wh",
    "source_kind": "telemetry",
    "source_ref": "node-42:cpu-meter:2026-06-01",
    "method": "shared-node-meter@v2",
    "factor_version": "node-meter-calibration-2026-05",
    "event_time": "2026-06-01T12:00:00Z",
    "effective_time": "2026-06-01T12:00:00Z",
    "boundary": "measurement",
    "precision": "estimated",
    "bounds": {"lower": "0.4", "upper": "0.6"},
    "lifecycle": "final"
  },
  {
    "component_id": "comp-req-0001-co2",
    "event_id": "evt-2026-06-01-0001",
    "request_id": "req-2026-06-01-0001",
    "tenant_id": "tenant-acme",
    "meter": "emissions.operational",
    "unit": "gCO2e",
    "source_kind": "regional-grid",
    "source_ref": "grid-region-eu-north-1",
    "method": "regional-factor-lookup@v1",
    "event_time": "2026-06-01T12:00:00Z",
    "effective_time": "2026-06-01T12:00:00Z",
    "boundary": "allocation",
    "precision": "unknown",
    "lifecycle": "provisional"
  }
]`

// assertFixtureComponent checks one component against the hand-written oracle.
func assertFixtureComponent(t *testing.T, c Component, w fixtureWant) {
	t.Helper()
	fields := []struct{ name, got, want string }{
		{"component_id", c.ComponentID, w.ComponentID},
		{"event_id", c.EventID, w.EventID},
		{"request_id", c.RequestID, w.RequestID},
		{"tenant_id", c.TenantID, w.TenantID},
		{"meter", c.Meter, w.Meter},
		{"unit", c.Unit, w.Unit},
		{"precision", string(c.Precision), string(w.Precision)},
		{"lifecycle", string(c.Lifecycle), string(w.Lifecycle)},
		{"boundary", string(c.Boundary), string(w.Boundary)},
		{"source_kind", c.SourceKind, w.SourceKind},
		{"source_ref", c.SourceRef, w.SourceRef},
		{"method", c.Method, w.Method},
		{"factor_version", c.FactorVersion, w.FactorVersion},
	}
	for _, f := range fields {
		if f.got != f.want {
			t.Errorf("%s = %q, want %q", f.name, f.got, f.want)
		}
	}
	assertFixtureQuantity(t, c, w)
	assertFixtureBounds(t, c, w)
	assertFixtureTimes(t, c)
}

func assertFixtureQuantity(t *testing.T, c Component, w fixtureWant) {
	t.Helper()
	if w.Quantity == "" {
		if c.Quantity != nil {
			t.Errorf("quantity = %s, want absent", c.Quantity)
		}
	} else if c.Quantity == nil || c.Quantity.String() != w.Quantity {
		t.Errorf("quantity = %v, want %q", c.Quantity, w.Quantity)
	}
}

// assertFixtureBounds checks the estimated-range half of the oracle: an
// absent bound stays a nil pointer, distinct from an explicit "0".
func assertFixtureBounds(t *testing.T, c Component, w fixtureWant) {
	t.Helper()
	if w.Lower == "" {
		if c.Bounds != nil {
			t.Errorf("bounds = %v, want absent", c.Bounds)
		}
		return
	}
	if c.Bounds == nil || c.Bounds.Lower == nil || c.Bounds.Upper == nil {
		t.Errorf("bounds = %v, want %s..%s", c.Bounds, w.Lower, w.Upper)
		return
	}
	if c.Bounds.Lower.String() != w.Lower || c.Bounds.Upper.String() != w.Upper {
		t.Errorf("bounds = %s..%s, want %s..%s", c.Bounds.Lower, c.Bounds.Upper, w.Lower, w.Upper)
	}
}

func assertFixtureTimes(t *testing.T, c Component) {
	t.Helper()
	if !c.EventTime.Equal(fixtureTime) {
		t.Errorf("event_time = %s, want %s", c.EventTime, fixtureTime)
	}
	if !c.EffectiveTime.Equal(fixtureTime) {
		t.Errorf("effective_time = %s, want %s", c.EffectiveTime, fixtureTime)
	}
}

// TestFixtures_GoLiteralsMatchHandWrittenOracle: the shared constructors are
// the single source of truth for every scenario; they are pinned here
// against literals the package never computed.
func TestFixtures_GoLiteralsMatchHandWrittenOracle(t *testing.T) {
	got := requestFixtures()
	want := fixtureWants()
	if len(got) != len(want) {
		t.Fatalf("fixture count = %d, want %d", len(got), len(want))
	}
	for i := range got {
		assertFixtureComponent(t, got[i], want[i])
		if err := got[i].Validate(); err != nil {
			t.Errorf("fixture %s: %v", got[i].ComponentID, err)
		}
	}
}

// TestFixtureJSON_DecodesToHandWrittenOracle: the same four components,
// hand-written as JSON, decode to the same literal facts — quantities as
// quoted strings, energy bounds-only, emissions without a factor.
func TestFixtureJSON_DecodesToHandWrittenOracle(t *testing.T) {
	var got []Component
	if err := json.Unmarshal([]byte(requestFixtureJSON), &got); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	want := fixtureWants()
	if len(got) != len(want) {
		t.Fatalf("fixture JSON decoded %d components, want %d", len(got), len(want))
	}
	for i := range got {
		assertFixtureComponent(t, got[i], want[i])
		if err := got[i].Validate(); err != nil {
			t.Errorf("decoded fixture %s: %v", got[i].ComponentID, err)
		}
	}
}
