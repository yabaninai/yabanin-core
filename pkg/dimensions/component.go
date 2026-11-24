package dimensions

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// maxIDBytes bounds every identifier carried by a component.
const maxIDBytes = 128

// Precision declares how exact a component's quantity is. The set is
// closed: an unknown value is a validation error, never silently dropped —
// a silently ignored value would price a billable dimension at zero
// (parity with the pkg/pricing axis vocabulary).
type Precision string

const (
	// PrecisionExact is an exact decimal under the declared inputs. This
	// does not make a physical estimate physically exact.
	PrecisionExact Precision = "exact"
	// PrecisionEstimated is approximate; a nil quantity is allowed only
	// with meaningful bounds.
	PrecisionEstimated Precision = "estimated"
	// PrecisionUnknown means the quantity is unknown and can never become
	// zero.
	PrecisionUnknown Precision = "unknown"
)

// Lifecycle is the publication state of a component. The set is closed.
type Lifecycle string

const (
	// LifecycleProvisional means recorded, not yet settled.
	LifecycleProvisional Lifecycle = "provisional"
	// LifecycleFinal means settled; a mistake requires an explicit
	// correction, never an in-place rewrite.
	LifecycleFinal Lifecycle = "final"
	// LifecycleCorrected supersedes an earlier component by reference.
	LifecycleCorrected Lifecycle = "corrected"
)

// Boundary separates measured observation from allocated attribution. The
// set is closed.
type Boundary string

const (
	// BoundaryMeasurement means directly observed at the source boundary.
	BoundaryMeasurement Boundary = "measurement"
	// BoundaryAllocation means attributed by a declared allocation method.
	BoundaryAllocation Boundary = "allocation"
)

var (
	precisionKinds = map[Precision]struct{}{
		PrecisionExact: {}, PrecisionEstimated: {}, PrecisionUnknown: {},
	}
	lifecycleKinds = map[Lifecycle]struct{}{
		LifecycleProvisional: {}, LifecycleFinal: {}, LifecycleCorrected: {},
	}
	boundaryKinds = map[Boundary]struct{}{
		BoundaryMeasurement: {}, BoundaryAllocation: {},
	}
)

func inClosedSet[T ~string](set map[T]struct{}, v T) bool {
	_, ok := set[v]
	return ok
}

// InClosedSet reports whether p is one of the defined precision kinds.
func (p Precision) InClosedSet() bool { return inClosedSet(precisionKinds, p) }

// Validate returns an error naming the closed set when p is unknown.
func (p Precision) Validate() error {
	if !p.InClosedSet() {
		return fmt.Errorf("precision must be exact, estimated or unknown, got %q", string(p))
	}
	return nil
}

// InClosedSet reports whether l is one of the defined lifecycle kinds.
func (l Lifecycle) InClosedSet() bool { return inClosedSet(lifecycleKinds, l) }

// Validate returns an error naming the closed set when l is unknown.
func (l Lifecycle) Validate() error {
	if !l.InClosedSet() {
		return fmt.Errorf("lifecycle must be provisional, final or corrected, got %q", string(l))
	}
	return nil
}

// InClosedSet reports whether b is one of the defined boundary kinds.
func (b Boundary) InClosedSet() bool { return inClosedSet(boundaryKinds, b) }

// Validate returns an error naming the closed set when b is unknown.
func (b Boundary) Validate() error {
	if !b.InClosedSet() {
		return fmt.Errorf("boundary must be measurement or allocation, got %q", string(b))
	}
	return nil
}

// Bounds is a meaningful estimated range. Each side is a pointer so an
// absent bound stays nil after decode — distinct from an explicit "0" (a
// meaningful measured value); a marshal/decode roundtrip preserves absence
// instead of fabricating a measured zero that would read back as a real
// bound.
type Bounds struct {
	Lower *Decimal `json:"lower,omitempty"`
	Upper *Decimal `json:"upper,omitempty"`
}

// boundsComplete reports whether both sides of b were explicitly set: an
// absent side is a nil pointer, distinct from an explicit "0".
func boundsComplete(b *Bounds) bool {
	return b != nil && b.Lower != nil && b.Upper != nil
}

// Component is one dimensional cost observation of a request: money,
// internal credits, energy, emissions or another configured unit. The
// snake_case names are a contract proposal, not an existing stored schema;
// this leaf validates only and persists nothing.
type Component struct {
	// ComponentID stably identifies this component within the event.
	ComponentID string `json:"component_id"`
	EventID     string `json:"event_id"`
	RequestID   string `json:"request_id"`
	// TaskID, Formula and AllocationBasis are optional: validated only when
	// non-empty (schema assumption — absence is not an error).
	TaskID   string `json:"task_id,omitempty"`
	TenantID string `json:"tenant_id"`
	Meter    string `json:"meter"`
	Unit     string `json:"unit"`
	// Quantity is the exact decimal amount. nil means absent/unknown —
	// never an implicit zero; an explicit zero must be parsed from "0" and
	// sums as zero.
	Quantity        *Decimal  `json:"quantity,omitempty"`
	SourceKind      string    `json:"source_kind"`
	SourceRef       string    `json:"source_ref"`
	Method          string    `json:"method"`
	Formula         string    `json:"formula,omitempty"`
	FactorVersion   string    `json:"factor_version,omitempty"`
	EventTime       time.Time `json:"event_time"`
	EffectiveTime   time.Time `json:"effective_time"`
	Boundary        Boundary  `json:"boundary"`
	AllocationBasis string    `json:"allocation_basis,omitempty"`
	Precision       Precision `json:"precision"`
	Bounds          *Bounds   `json:"bounds,omitempty"`
	Lifecycle       Lifecycle `json:"lifecycle"`
	// CorrectsComponentID names the component this one corrects; required
	// exactly when lifecycle is corrected.
	CorrectsComponentID string   `json:"corrects_component_id,omitempty"`
	CoverageMeters      []string `json:"coverage_meters,omitempty"`
}

// ValidationError aggregates every validation problem of one component so a
// caller fixes the whole record at once (UnitFileError pattern). The
// component is rejected if any problem is present.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "invalid component: " + strings.Join(e.Problems, "; ")
}

type problemCollector struct{ problems []string }

func (c *problemCollector) add(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
}

func (c *problemCollector) err() error {
	if len(c.problems) == 0 {
		return nil
	}
	return &ValidationError{Problems: c.problems}
}

// validateID checks one identifier: 1..128 bytes, valid UTF-8, no control
// bytes. It returns the full problem text, or "" when the value is valid.
func validateID(kind, s string) string {
	if s == "" {
		return fmt.Sprintf("%s is required", kind)
	}
	if len(s) > maxIDBytes {
		return fmt.Sprintf("%s exceeds %d bytes", kind, maxIDBytes)
	}
	if !utf8.ValidString(s) {
		return fmt.Sprintf("%s is not valid UTF-8", kind)
	}
	if hasControlByte(s) {
		return fmt.Sprintf("%s must not contain control bytes", kind)
	}
	return ""
}

// hasControlByte rejects bytes below 0x20 and 0x7f; multibyte UTF-8
// continuation bytes are all >= 0x80, so a byte scan is safe.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func validateFieldID(pc *problemCollector, kind, value string) {
	if msg := validateID(kind, value); msg != "" {
		pc.add("%s", msg)
	}
}

func validateOptionalID(pc *problemCollector, kind, value string) {
	if value == "" {
		return
	}
	validateFieldID(pc, kind, value)
}

// Validate checks the component against the contract rules and reports every
// problem at once. It returns nil only when the component is complete.
func (c Component) Validate() error {
	var pc problemCollector
	validateIdentities(&pc, c)
	validateEnums(&pc, c)
	validateTimes(&pc, c)
	validateQuantity(&pc, c)
	validateBounds(&pc, c)
	validateFactorVersion(&pc, c)
	validateLifecycle(&pc, c)
	return pc.err()
}

func validateIdentities(pc *problemCollector, c Component) {
	required := []struct{ kind, value string }{
		{"component_id", c.ComponentID},
		{"event_id", c.EventID},
		{"request_id", c.RequestID},
		{"tenant_id", c.TenantID},
		{"meter", c.Meter},
		{"unit", c.Unit},
		{"source_kind", c.SourceKind},
		{"source_ref", c.SourceRef},
		{"method", c.Method},
	}
	for _, f := range required {
		validateFieldID(pc, f.kind, f.value)
	}
	validateOptionalID(pc, "task_id", c.TaskID)
	validateOptionalID(pc, "formula", c.Formula)
	validateOptionalID(pc, "allocation_basis", c.AllocationBasis)
}

func validateEnums(pc *problemCollector, c Component) {
	if err := c.Precision.Validate(); err != nil {
		pc.add("%v", err)
	}
	if err := c.Lifecycle.Validate(); err != nil {
		pc.add("%v", err)
	}
	if err := c.Boundary.Validate(); err != nil {
		pc.add("%v", err)
	}
}

// validateTimes fails loudly on the zero time: a malformed RFC3339 string
// already fails at decode, so a zero here means the field was never set.
func validateTimes(pc *problemCollector, c Component) {
	if c.EventTime.IsZero() {
		pc.add("event_time is required")
	}
	if c.EffectiveTime.IsZero() {
		pc.add("effective_time is required")
	}
}

func validateQuantity(pc *problemCollector, c Component) {
	switch c.Precision {
	case PrecisionExact:
		if c.Quantity == nil {
			pc.add("quantity is required when precision is exact")
		}
	case PrecisionEstimated:
		validateEstimatedQuantity(pc, c)
	case PrecisionUnknown:
		if c.Quantity != nil {
			pc.add("quantity must be absent when precision is unknown")
		}
	}
}

// validateEstimatedQuantity: an estimated record carries a point quantity, a
// meaningful range, or both; when both are present the point must lie inside
// its own stated range — a point outside its bounds contradicts the estimate.
func validateEstimatedQuantity(pc *problemCollector, c Component) {
	if c.Quantity == nil && c.Bounds == nil {
		pc.add("quantity or bounds is required when precision is estimated")
		return
	}
	if c.Quantity == nil || !boundsComplete(c.Bounds) {
		return
	}
	if Compare(*c.Bounds.Lower, *c.Quantity) > 0 || Compare(*c.Quantity, *c.Bounds.Upper) > 0 {
		pc.add("estimated quantity must lie within bounds")
	}
}

func validateBounds(pc *problemCollector, c Component) {
	if c.Bounds == nil {
		return
	}
	if c.Precision != PrecisionEstimated {
		pc.add("bounds are only valid when precision is estimated")
	}
	validateBoundsPair(pc, c.Bounds)
}

func validateBoundsPair(pc *problemCollector, b *Bounds) {
	// An absent side is a nil pointer, distinct from an explicit "0" bound:
	// a one-sided range must be rejected, never read as a zero bound.
	if !boundsComplete(b) {
		pc.add("bounds require both lower and upper")
		return
	}
	if Compare(*b.Lower, *b.Upper) > 0 {
		pc.add("bounds lower must not exceed upper")
	}
}

// validateFactorVersion: a missing factor can never become zero, so every
// citable precision needs one — except unknown, which has no factor to cite
// (schema assumption).
func validateFactorVersion(pc *problemCollector, c Component) {
	if c.Precision == PrecisionUnknown {
		validateOptionalID(pc, "factor_version", c.FactorVersion)
		return
	}
	validateFieldID(pc, "factor_version", c.FactorVersion)
}

func validateLifecycle(pc *problemCollector, c Component) {
	switch c.Lifecycle {
	case LifecycleCorrected:
		validateCorrection(pc, c)
	case LifecycleProvisional, LifecycleFinal:
		if c.CorrectsComponentID != "" {
			pc.add("corrects_component_id is only valid when lifecycle is corrected")
		}
		if len(c.CoverageMeters) > 0 {
			pc.add("coverage_meters is only valid when lifecycle is corrected")
		}
	}
}

func validateCorrection(pc *problemCollector, c Component) {
	if c.CorrectsComponentID == "" {
		pc.add("corrects_component_id is required when lifecycle is corrected")
	} else {
		validateFieldID(pc, "corrects_component_id", c.CorrectsComponentID)
	}
	if c.CorrectsComponentID == c.ComponentID && c.ComponentID != "" {
		pc.add("corrects_component_id must not equal component_id")
	}
	if len(c.CoverageMeters) == 0 {
		pc.add("coverage_meters is required when lifecycle is corrected")
	}
	for i, m := range c.CoverageMeters {
		validateFieldID(pc, fmt.Sprintf("coverage_meters[%d]", i), m)
	}
	// A correction that stops covering its own meter would leave a billable
	// dimension unmeasured, so a non-empty coverage list must name it.
	if len(c.CoverageMeters) > 0 && !coversMeter(c.CoverageMeters, c.Meter) {
		pc.add("coverage_meters must include the corrected meter %q", c.Meter)
	}
}

// coversMeter reports whether coverage names the corrected record's own
// meter: a correction that silently stops covering its meter would turn a
// billable dimension unmeasured.
func coversMeter(coverage []string, meter string) bool {
	for _, m := range coverage {
		if m == meter {
			return true
		}
	}
	return false
}

// BindCorrection binds lineage by value: the successor receives the
// original's tenant, meter, unit and correction identity, and the original
// is never mutated. The caller supplies the successor's own component and
// event IDs and its quantity; Validate still applies to the result.
// A correction is a new event — reusing the original's event ID would replay
// its delivery key (tenant plus event) and silently merge two deliveries in
// future dedup, so the pairing is rejected here where both events are
// visible.
func BindCorrection(original, successor Component) (Component, error) {
	if successor.EventID == original.EventID {
		return Component{}, fmt.Errorf("dimensions: correction event_id %q must differ from the corrected event %q", successor.EventID, original.EventID)
	}
	successor.Lifecycle = LifecycleCorrected
	successor.CorrectsComponentID = original.ComponentID
	successor.TenantID = original.TenantID
	successor.Meter = original.Meter
	successor.Unit = original.Unit
	successor.CoverageMeters = []string{original.Meter}
	return successor, nil
}

// DeliveryKey is the replay identity for future ingestion dedup: tenant plus
// event, parity with the pkg/inventory org+RequestID keying. Pure identity —
// this package has no store.
func (c Component) DeliveryKey() string {
	return c.TenantID + "\x00" + c.EventID
}

// SumExact sums the quantities of exactly the components matching meter and
// unit with precision exact. A foreign dimension, an estimated or unknown
// component, or an exact component without a quantity is an error — never
// silently skipped, never treated as zero. Add overflow propagates.
func SumExact(components []Component, meter, unit string) (Decimal, error) {
	total := Decimal{digits: "0"}
	for i := range components {
		if err := checkSummable(components[i], meter, unit, i); err != nil {
			return Decimal{}, err
		}
		sum, err := Add(total, *components[i].Quantity)
		if err != nil {
			return Decimal{}, err
		}
		total = sum
	}
	return total, nil
}

func checkSummable(c Component, meter, unit string, i int) error {
	where := fmt.Sprintf("components[%d]", i)
	if c.Meter != meter || c.Unit != unit {
		return fmt.Errorf("dimensions: %s: meter/unit %q/%q does not match %q/%q; incompatible dimensions are never summed", where, c.Meter, c.Unit, meter, unit)
	}
	if c.Precision != PrecisionExact {
		return fmt.Errorf("dimensions: %s: precision %q is not exact", where, string(c.Precision))
	}
	if c.Quantity == nil {
		return fmt.Errorf("dimensions: %s: exact component has no quantity", where)
	}
	return nil
}
