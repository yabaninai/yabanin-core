package dimensions

// Component validation tests: closed vocabularies, aggregated problems, and a
// negative-control table whose expected problem text is hand-written.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func timeZero() time.Time { return time.Time{} }

func TestPrecision_Validate(t *testing.T) {
	for _, p := range []Precision{PrecisionExact, PrecisionEstimated, PrecisionUnknown} {
		if !p.InClosedSet() {
			t.Errorf("precision %q should be in the closed set", p)
		}
		if err := p.Validate(); err != nil {
			t.Errorf("precision %q: %v", p, err)
		}
	}
	bad := Precision("approximate")
	if bad.InClosedSet() {
		t.Error("approximate should not be in the closed set")
	}
	err := bad.Validate()
	if err == nil || !strings.Contains(err.Error(), `precision must be exact, estimated or unknown, got "approximate"`) {
		t.Errorf("precision error = %v, want closed-set message", err)
	}
}

func TestLifecycle_Validate(t *testing.T) {
	for _, l := range []Lifecycle{LifecycleProvisional, LifecycleFinal, LifecycleCorrected} {
		if !l.InClosedSet() || l.Validate() != nil {
			t.Errorf("lifecycle %q should validate", l)
		}
	}
	err := Lifecycle("revoked").Validate()
	if err == nil || !strings.Contains(err.Error(), `lifecycle must be provisional, final or corrected, got "revoked"`) {
		t.Errorf("lifecycle error = %v, want closed-set message", err)
	}
}

func TestBoundary_Validate(t *testing.T) {
	for _, b := range []Boundary{BoundaryMeasurement, BoundaryAllocation} {
		if !b.InClosedSet() || b.Validate() != nil {
			t.Errorf("boundary %q should validate", b)
		}
	}
	err := Boundary("guess").Validate()
	if err == nil || !strings.Contains(err.Error(), `boundary must be measurement or allocation, got "guess"`) {
		t.Errorf("boundary error = %v, want closed-set message", err)
	}
}

func TestValidate_AggregatesProblems(t *testing.T) {
	err := Component{}.Validate()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("empty component err = %v, want ValidationError", err)
	}
	if len(ve.Problems) < 10 {
		t.Errorf("problem count = %d, want at least 10", len(ve.Problems))
	}
	for _, want := range []string{
		"component_id is required",
		"meter is required",
		"event_time is required",
		"effective_time is required",
		"precision must be exact",
	} {
		if !strings.Contains(ve.Error(), want) {
			t.Errorf("aggregated error %q missing %q", ve.Error(), want)
		}
	}
}

// assertProblem validates c (after mutate) and fails unless some aggregated
// problem contains want.
func assertProblem(t *testing.T, c Component, mutate func(*Component), want string) {
	t.Helper()
	if mutate != nil {
		mutate(&c)
	}
	var ve *ValidationError
	if !errors.As(c.Validate(), &ve) {
		t.Fatalf("expected a validation problem %q, got none", want)
	}
	for _, p := range ve.Problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("validation problems %v lack %q", ve.Problems, want)
}

// assertNoProblem validates c (after mutate) and fails if any aggregated
// problem contains unwanted.
func assertNoProblem(t *testing.T, c Component, mutate func(*Component), unwanted string) {
	t.Helper()
	if mutate != nil {
		mutate(&c)
	}
	var ve *ValidationError
	if !errors.As(c.Validate(), &ve) {
		return
	}
	for _, p := range ve.Problems {
		if strings.Contains(p, unwanted) {
			t.Fatalf("validation problems %v should not contain %q", ve.Problems, unwanted)
		}
	}
}

// Each row proves the rule fires (mutate) and that the problem really comes
// from that rule: negate repairs exactly the condition mutate broke, on the
// same record, so the named problem disappears while everything else stays.
func TestValidate_NegativeControls(t *testing.T) {
	tests := []struct {
		name   string
		base   func() Component
		mutate func(*Component)
		negate func(*Component)
		want   string
	}{
		{
			name:   "exact without quantity",
			base:   usdFixture,
			mutate: func(c *Component) { c.Quantity = nil },
			negate: func(c *Component) {
				q := mustParseDecimal("0.02")
				c.Quantity = &q
			},
			want: "quantity is required when precision is exact",
		},
		{
			name: "estimated with neither quantity nor bounds",
			base: energyFixture,
			mutate: func(c *Component) {
				c.Quantity = nil
				c.Bounds = nil
			},
			negate: func(c *Component) { c.Bounds = &Bounds{Lower: decPtr("0.4"), Upper: decPtr("0.6")} },
			want:   "quantity or bounds is required when precision is estimated",
		},
		{
			name: "unknown with quantity",
			base: emissionsFixture,
			mutate: func(c *Component) {
				q := mustParseDecimal("0.5")
				c.Quantity = &q
			},
			negate: func(c *Component) { c.Quantity = nil },
			want:   "quantity must be absent when precision is unknown",
		},
		{
			name: "exact with bounds",
			base: usdFixture,
			mutate: func(c *Component) {
				c.Bounds = &Bounds{Lower: decPtr("0.01"), Upper: decPtr("0.03")}
			},
			negate: func(c *Component) { c.Bounds = nil },
			want:   "bounds are only valid when precision is estimated",
		},
		{
			name: "one-sided bounds lower only",
			base: energyFixture,
			mutate: func(c *Component) {
				c.Bounds = &Bounds{Lower: decPtr("0.4")}
			},
			negate: func(c *Component) { c.Bounds.Upper = decPtr("0.6") },
			want:   "bounds require both lower and upper",
		},
		{
			name: "one-sided bounds upper only",
			base: energyFixture,
			mutate: func(c *Component) {
				c.Bounds = &Bounds{Upper: decPtr("0.6")}
			},
			negate: func(c *Component) { c.Bounds.Lower = decPtr("0.4") },
			want:   "bounds require both lower and upper",
		},
		{
			name: "lower above upper",
			base: energyFixture,
			mutate: func(c *Component) {
				c.Bounds = &Bounds{Lower: decPtr("0.6"), Upper: decPtr("0.4")}
			},
			negate: func(c *Component) { c.Bounds = &Bounds{Lower: decPtr("0.4"), Upper: decPtr("0.6")} },
			want:   "bounds lower must not exceed upper",
		},
		{
			name:   "estimated quantity outside its own bounds",
			base:   energyFixture,
			mutate: func(c *Component) { c.Quantity = decPtr("3") },
			negate: func(c *Component) { c.Quantity = nil },
			want:   "estimated quantity must lie within bounds",
		},
		{
			name:   "missing factor version for exact",
			base:   usdFixture,
			mutate: func(c *Component) { c.FactorVersion = "" },
			negate: func(c *Component) { c.FactorVersion = "pricefile-2026-06" },
			want:   "factor_version is required",
		},
		{
			name:   "missing factor version for estimated",
			base:   energyFixture,
			mutate: func(c *Component) { c.FactorVersion = "" },
			negate: func(c *Component) { c.FactorVersion = "node-meter-calibration-2026-05" },
			want:   "factor_version is required",
		},
		{
			name:   "corrected without lineage",
			base:   usdFixture,
			mutate: func(c *Component) { c.Lifecycle = LifecycleCorrected },
			negate: func(c *Component) {
				c.CorrectsComponentID = "comp-req-0001-x"
				c.CoverageMeters = []string{"money.usd"}
			},
			want: "corrects_component_id is required when lifecycle is corrected",
		},
		{
			name: "corrected self-reference",
			base: usdFixture,
			mutate: func(c *Component) {
				c.Lifecycle = LifecycleCorrected
				c.CorrectsComponentID = c.ComponentID
				c.CoverageMeters = []string{"money.usd"}
			},
			negate: func(c *Component) { c.CorrectsComponentID = "comp-req-0001-x" },
			want:   "corrects_component_id must not equal component_id",
		},
		{
			name: "corrected without coverage meters",
			base: usdFixture,
			mutate: func(c *Component) {
				c.Lifecycle = LifecycleCorrected
				c.CorrectsComponentID = "comp-req-0001-x"
			},
			negate: func(c *Component) { c.CoverageMeters = []string{"money.usd"} },
			want:   "coverage_meters is required when lifecycle is corrected",
		},
		{
			name: "corrected with invalid coverage entry",
			base: usdFixture,
			mutate: func(c *Component) {
				c.Lifecycle = LifecycleCorrected
				c.CorrectsComponentID = "comp-req-0001-x"
				c.CoverageMeters = []string{"money.usd", ""}
			},
			negate: func(c *Component) { c.CoverageMeters = []string{"money.usd"} },
			want:   "coverage_meters[1] is required",
		},
		{
			name: "corrected coverage omits the corrected meter",
			base: usdFixture,
			mutate: func(c *Component) {
				c.Lifecycle = LifecycleCorrected
				c.CorrectsComponentID = "comp-req-0001-x"
				c.CoverageMeters = []string{"energy.it"}
			},
			negate: func(c *Component) { c.CoverageMeters = []string{"money.usd"} },
			want:   "coverage_meters must include the corrected meter",
		},
		{
			name:   "provisional with corrects_component_id",
			base:   usdFixture,
			mutate: func(c *Component) { c.CorrectsComponentID = "comp-req-0001-x" },
			negate: func(c *Component) { c.CorrectsComponentID = "" },
			want:   "corrects_component_id is only valid when lifecycle is corrected",
		},
		{
			name: "final with corrects_component_id",
			base: energyFixture,
			mutate: func(c *Component) {
				c.CorrectsComponentID = "comp-req-0001-x"
			},
			negate: func(c *Component) { c.CorrectsComponentID = "" },
			want:   "corrects_component_id is only valid when lifecycle is corrected",
		},
		{
			name:   "provisional with coverage meters",
			base:   usdFixture,
			mutate: func(c *Component) { c.CoverageMeters = []string{"money.usd"} },
			negate: func(c *Component) { c.CoverageMeters = nil },
			want:   "coverage_meters is only valid when lifecycle is corrected",
		},
		{
			name:   "zero event time",
			base:   usdFixture,
			mutate: func(c *Component) { c.EventTime = timeZero() },
			negate: func(c *Component) { c.EventTime = fixtureTime },
			want:   "event_time is required",
		},
		{
			name:   "zero effective time",
			base:   usdFixture,
			mutate: func(c *Component) { c.EffectiveTime = timeZero() },
			negate: func(c *Component) { c.EffectiveTime = fixtureTime },
			want:   "effective_time is required",
		},
		{
			name:   "identifier over 128 bytes",
			base:   usdFixture,
			mutate: func(c *Component) { c.SourceRef = strings.Repeat("a", 129) },
			negate: func(c *Component) { c.SourceRef = "req-2026-06-01-0001-usd" },
			want:   "source_ref exceeds 128 bytes",
		},
		{
			name:   "identifier not valid UTF-8",
			base:   usdFixture,
			mutate: func(c *Component) { c.SourceRef = "\xff\xfe" },
			negate: func(c *Component) { c.SourceRef = "req-2026-06-01-0001-usd" },
			want:   "source_ref is not valid UTF-8",
		},
		{
			name:   "identifier with control byte",
			base:   usdFixture,
			mutate: func(c *Component) { c.SourceRef = "req\x0001" },
			negate: func(c *Component) { c.SourceRef = "req-2026-06-01-0001-usd" },
			want:   "source_ref must not contain control bytes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// One record: corrupt it, observe the named problem, repair
			// exactly that condition, observe the problem gone.
			c := tc.base()
			tc.mutate(&c)
			assertProblem(t, c, nil, tc.want)
			tc.negate(&c)
			assertNoProblem(t, c, nil, tc.want)
		})
	}
}

func TestValidate_EstimatedAllowsQuantityAndBoundsTogether(t *testing.T) {
	c := energyFixture()
	q := mustParseDecimal("0.5")
	c.Quantity = &q
	if err := c.Validate(); err != nil {
		t.Errorf("estimated with quantity and bounds should validate: %v", err)
	}
}

// A point quantity outside the record's own stated range contradicts the
// estimate; values at either boundary are the range's edge, not outside it.
func TestValidate_EstimatedQuantityMustLieWithinBounds(t *testing.T) {
	for _, outside := range []string{"0.3", "3", "0.7"} {
		c := energyFixture()
		c.Quantity = decPtr(outside)
		assertProblem(t, c, nil, "estimated quantity must lie within bounds")
	}
	for _, inside := range []string{"0.4", "0.5", "0.6"} {
		c := energyFixture()
		c.Quantity = decPtr(inside)
		if err := c.Validate(); err != nil {
			t.Errorf("quantity %s at or between the bounds should validate: %v", inside, err)
		}
	}
}

func TestValidate_AggregatesUnrelatedProblems(t *testing.T) {
	c := usdFixture()
	c.Quantity = nil
	c.EventTime = timeZero()
	var ve *ValidationError
	if !errors.As(c.Validate(), &ve) {
		t.Fatal("expected ValidationError")
	}
	joined := ve.Error()
	for _, want := range []string{"quantity is required when precision is exact", "event_time is required"} {
		if !strings.Contains(joined, want) {
			t.Errorf("aggregated error %q missing %q", joined, want)
		}
	}
	if len(ve.Problems) != 2 {
		t.Errorf("problem count = %d, want 2", len(ve.Problems))
	}
}

func TestUnmarshal_RejectsJSONNumberQuantity(t *testing.T) {
	var c Component
	err := json.Unmarshal([]byte(`{"quantity": 0.02}`), &c)
	if !errors.Is(err, ErrJSONNumber) {
		t.Errorf("quantity as JSON number err = %v, want ErrJSONNumber", err)
	}
}

func TestUnmarshal_MalformedTimestampFailsAtDecode(t *testing.T) {
	var c Component
	doc := `{"event_id":"evt","event_time":"June 1, 2026 at noon"}`
	err := json.Unmarshal([]byte(doc), &c)
	if err == nil {
		t.Error("malformed RFC3339 timestamp must fail at decode, not validation")
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		t.Errorf("decode error should not be a ValidationError: %v", err)
	}
}

func TestUnmarshal_OneSidedBoundsJSON(t *testing.T) {
	var c Component
	doc := `{"bounds": {"lower": "0.4"}, "precision": "estimated"}`
	if err := json.Unmarshal([]byte(doc), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Bounds == nil || c.Bounds.Upper != nil {
		t.Fatal("missing upper bound must stay a nil pointer")
	}
	assertProblem(t, c, nil, "bounds require both lower and upper")
}

// A missing bound side must survive a marshal/decode roundtrip as absence:
// serializing the zero Decimal would fabricate a measured zero ("0" reads
// back as a real bound) and the re-decoded record would wrongly validate.
func TestBoundsRoundtrip_PreservesMissingSide(t *testing.T) {
	var c Component
	doc := `{"bounds": {"upper": "0.6"}, "precision": "estimated"}`
	if err := json.Unmarshal([]byte(doc), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Bounds == nil || c.Bounds.Lower != nil {
		t.Fatalf("missing lower bound must stay a nil pointer, got %v", c.Bounds)
	}
	assertProblem(t, c, nil, "bounds require both lower and upper")

	blob := mustMarshal(t, c)
	if strings.Contains(string(blob), `"lower":"0"`) {
		t.Errorf("roundtrip fabricated a measured zero lower bound: %s", blob)
	}
	var rt Component
	if err := json.Unmarshal(blob, &rt); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if rt.Bounds == nil || rt.Bounds.Lower != nil {
		t.Errorf("lower bound must still be nil after the roundtrip, got %v", rt.Bounds)
	}
	assertProblem(t, rt, nil, "bounds require both lower and upper")
}

// An explicit zero lower bound is a meaningful measured value and must stay
// a real zero through a roundtrip, not decay into a nil "absent" side.
func TestBoundsRoundtrip_ExplicitZeroStaysZero(t *testing.T) {
	var c Component
	doc := `{"bounds": {"lower": "0", "upper": "0.6"}, "precision": "estimated"}`
	if err := json.Unmarshal([]byte(doc), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertNoProblem(t, c, nil, "bounds")
	assertZeroLower(t, c)
	var rt Component
	if err := json.Unmarshal(mustMarshal(t, c), &rt); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	assertZeroLower(t, rt)
}

func assertZeroLower(t *testing.T, c Component) {
	t.Helper()
	if c.Bounds == nil || c.Bounds.Lower == nil {
		t.Fatalf("bounds = %v, want an explicit zero lower bound", c.Bounds)
	}
	if got := c.Bounds.Lower.String(); got != "0" {
		t.Errorf("lower bound = %s, want explicit 0", got)
	}
}

func TestDeliveryKey(t *testing.T) {
	got := usdFixture().DeliveryKey()
	want := "tenant-acme\x00evt-2026-06-01-0001"
	if got != want {
		t.Errorf("DeliveryKey() = %q, want %q", got, want)
	}
	if credits := creditsFixture().DeliveryKey(); credits != got {
		t.Errorf("credits key = %q; same tenant+event must dedup across meters", credits)
	}
}

func TestSumExact(t *testing.T) {
	tests := []struct {
		name      string
		component func() Component
		meter     string
		unit      string
		want      string
		wantErr   string
	}{
		{
			name:      "single exact usd component",
			component: usdFixture,
			meter:     "money.usd", unit: "USD",
			want: "0.02",
		},
		{
			name:      "second exact usd component",
			component: correctionSuccessorFixture,
			meter:     "money.usd", unit: "USD",
			want: "0.03",
		},
		{
			name: "estimated component is not summed silently",
			component: func() Component {
				c := energyFixture()
				c.Meter, c.Unit = "money.usd", "USD"
				return c
			},
			meter: "money.usd", unit: "USD",
			wantErr: `precision "estimated" is not exact`,
		},
		{
			name:      "foreign unit is not summed",
			component: usdFixture,
			meter:     "money.usd", unit: "EUR",
			wantErr: "does not match",
		},
		{
			name: "exact component without quantity is not summed as zero",
			component: func() Component {
				c := usdFixture()
				c.Quantity = nil
				return c
			},
			meter: "money.usd", unit: "USD",
			wantErr: "has no quantity",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SumExact([]Component{tc.component()}, tc.meter, tc.unit)
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %v, want containing %q", err, tc.wantErr)
				}
			case err != nil:
				t.Errorf("unexpected error: %v", err)
			case got.String() != tc.want:
				t.Errorf("sum = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSumExact_MultipleComponentsAndEmpty(t *testing.T) {
	total, err := SumExact([]Component{usdFixture(), correctionSuccessorFixture()}, "money.usd", "USD")
	if err != nil {
		t.Fatalf("sum of two exact usd components: %v", err)
	}
	if total.String() != "0.05" {
		t.Errorf("total = %s, want 0.05", total)
	}
	empty, err := SumExact(nil, "money.usd", "USD")
	if err != nil || empty.String() != "0" {
		t.Errorf("empty sum = %s, %v; want 0, nil", empty, err)
	}
}

func TestSumExact_OverflowPropagates(t *testing.T) {
	nines := mustParseDecimal(strings.Repeat("9", 38))
	c := usdFixture()
	c.Quantity = &nines
	_, err := SumExact([]Component{c, c}, "money.usd", "USD")
	if !errors.Is(err, ErrOverflow) {
		t.Errorf("overflow err = %v, want ErrOverflow", err)
	}
}
