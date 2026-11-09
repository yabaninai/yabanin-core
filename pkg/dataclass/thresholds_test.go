package dataclass

// E04-P01-W04-C03 battery: threshold overrides — validation grammar,
// the single-default resolver, the storage seam (fake reader; the core
// ships none) and the fail-closed load path.

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

type fakeThresholdReader struct {
	calls     int
	overrides Thresholds
	found     bool
	err       error
}

func (r *fakeThresholdReader) ThresholdOverrides(_ context.Context, _ string) (Thresholds, bool, error) {
	r.calls++
	return r.overrides, r.found, r.err
}

const thresholdTestOrg = "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f"

func TestThresholdsValidateHappy(t *testing.T) {
	th := Thresholds{Min: map[string]float64{
		"pii.pan":                 0.8,
		"pii.innsnils":            0,
		"secrets.credential_keys": 1,
	}}
	if err := th.Validate(); err != nil {
		t.Fatalf("valid overrides refused: %v", err)
	}
	if err := (Thresholds{}).Validate(); err != nil {
		t.Fatalf("nil map must be valid (defaults for everything): %v", err)
	}
	if err := (Thresholds{Min: map[string]float64{}}).Validate(); err != nil {
		t.Fatalf("empty map must be valid: %v", err)
	}
}

func TestThresholdsValidateRefusesBadKeysAndValues(t *testing.T) {
	th := Thresholds{Min: map[string]float64{
		"PII.PAN":        0.8, // not canonical
		"bad key!":       0.8, // invalid grammar
		"yabanin.system": 0.5, // reserved prefix
		"pii.pan":        math.NaN(),
		"pii.phone":      -0.1,
		"pii.email":      1.1,
		"pii.inn":        math.Inf(1),
	}}
	err := th.Validate()
	if err == nil {
		t.Fatalf("every bad override must be refused")
	}
	var verr *ThresholdValidationError
	if !errors.As(err, &verr) || len(verr.Errors) != 7 {
		t.Fatalf("all seven problems must be listed, got %v", err)
	}
	joined := strings.Join(verr.Errors, "; ")
	for _, want := range []string{"PII.PAN", "bad key!", "yabanin.system", "pii.pan", "pii.phone", "pii.email", "pii.inn"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("error must name %q: %v", want, verr.Errors)
		}
	}
	for i := 1; i < len(verr.Errors); i++ {
		if verr.Errors[i-1] > verr.Errors[i] {
			t.Fatalf("error list must be sorted: %v", verr.Errors)
		}
	}
	again := th.Validate()
	if !reflect.DeepEqual(verr, again.(*ThresholdValidationError)) {
		t.Fatalf("validation output must be deterministic")
	}
}

func TestThresholdsResolver(t *testing.T) {
	th := Thresholds{Min: map[string]float64{"pii.phone": 0.8}}
	minFor := th.Resolver()
	if got := minFor("pii.phone"); got != 0.8 {
		t.Fatalf("override must win, got %v", got)
	}
	if got := minFor("anything.else"); got != DefaultMinConfidence || DefaultMinConfidence != 0.9 {
		t.Fatalf("everything else falls back to the single default 0.9, got %v (default %v)", got, DefaultMinConfidence)
	}
	if got := (Thresholds{}).Resolver()("pii.pan"); got != DefaultMinConfidence {
		t.Fatalf("nil overrides resolve to the default, got %v", got)
	}
}

func TestThresholdsResolverNaNFailsClosed(t *testing.T) {
	// An unvalidated NaN override must not become an admit-everything
	// switch: NaN compares below every confidence, so the key passes
	// nothing — the fail-closed direction.
	minFor := Thresholds{Min: map[string]float64{"pii.pan": math.NaN()}}.Resolver()
	if LabelPassesThreshold(1, minFor("pii.pan")) {
		t.Fatalf("NaN minimum must pass nothing, not even confidence 1.0")
	}
	if !LabelPassesThreshold(1, minFor("other.key")) {
		t.Fatalf("other keys keep the default")
	}
}

func TestResolveThresholdsDefaults(t *testing.T) {
	minFor, err := ResolveThresholds(context.Background(), nil, thresholdTestOrg)
	if err != nil {
		t.Fatalf("nil reader must resolve to defaults: %v", err)
	}
	if minFor("pii.pan") != DefaultMinConfidence {
		t.Fatalf("nil reader must default every key")
	}

	reader := &fakeThresholdReader{found: false} // org never wrote overrides
	minFor, err = ResolveThresholds(context.Background(), reader, thresholdTestOrg)
	if err != nil || reader.calls != 1 {
		t.Fatalf("not-found must be defaults after one read: err=%v calls=%d", err, reader.calls)
	}
	if minFor("pii.pan") != DefaultMinConfidence {
		t.Fatalf("not-found must default every key")
	}
}

func TestResolveThresholdsHonorsValidOverrides(t *testing.T) {
	reader := &fakeThresholdReader{
		found:     true,
		overrides: Thresholds{Min: map[string]float64{"pii.email": 0.8}},
	}
	minFor, err := ResolveThresholds(context.Background(), reader, thresholdTestOrg)
	if err != nil {
		t.Fatalf("valid overrides must resolve: %v", err)
	}
	if minFor("pii.email") != 0.8 || minFor("pii.pan") != DefaultMinConfidence {
		t.Fatalf("override must apply to its key only")
	}
}

func TestResolveThresholdsFailClosedOnReaderError(t *testing.T) {
	boom := errors.New("storage down")
	reader := &fakeThresholdReader{err: boom}
	minFor, err := ResolveThresholds(context.Background(), reader, thresholdTestOrg)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("reader error must fail resolution (fail-closed), got %v", err)
	}
	if minFor != nil {
		t.Fatalf("no resolver may be returned alongside an error")
	}
}

func TestResolveThresholdsNeverTrustsStorage(t *testing.T) {
	for name, stored := range map[string]Thresholds{
		"NaN value":    {Min: map[string]float64{"pii.pan": math.NaN()}},
		"bad key":      {Min: map[string]float64{"PII.PAN": 0.5}},
		"out of range": {Min: map[string]float64{"pii.pan": 1.5}},
		"reserved key": {Min: map[string]float64{"yabanin.x": 0.5}},
	} {
		reader := &fakeThresholdReader{found: true, overrides: stored}
		if _, err := ResolveThresholds(context.Background(), reader, thresholdTestOrg); err == nil {
			t.Fatalf("%s: stored overrides must be re-validated, not trusted", name)
		}
	}
}

func TestResolveThresholdsInvalidOrgStopsBeforeReader(t *testing.T) {
	reader := &fakeThresholdReader{found: true}
	for _, org := range []string{"", "garbage"} {
		if _, err := ResolveThresholds(context.Background(), reader, org); !errors.Is(err, ErrInvalidOrgID) && !errors.Is(err, ErrEmptyOrgID) {
			t.Fatalf("org %q must be a typed refusal, got %v", org, err)
		}
	}
	if reader.calls != 0 {
		t.Fatalf("garbage org ids must stop before the reader is touched, got %d calls", reader.calls)
	}
}

// TestThresholdsEndToEndWithBuiltin wires the whole W04 chain: builtin
// evidence → org-resolved minFor → ApplyThreshold. The org admitting
// 0.8 keeps the email label that the default threshold drops.
func TestThresholdsEndToEndWithBuiltin(t *testing.T) {
	const version = 31
	tax := builtinTaxonomy(t, version, "pii.email", "pii.phone")
	b := mustBuiltin(t, tax)
	res := classify(t, b, version, TextTypePlain, "тел. +7 912 345 67 89, почта user@example.com")

	defaults, err := ResolveThresholds(context.Background(), nil, thresholdTestOrg)
	if err != nil {
		t.Fatalf("defaults resolve: %v", err)
	}
	if got := ApplyThreshold(res, defaults); !got.Unknown || len(got.Labels) != 0 {
		t.Fatalf("default threshold drops the 0.8 contact labels: %+v", got.Labels)
	}

	reader := &fakeThresholdReader{
		found:     true,
		overrides: Thresholds{Min: map[string]float64{"pii.email": 0.8, "pii.phone": 0.8}},
	}
	orgMinFor, err := ResolveThresholds(context.Background(), reader, thresholdTestOrg)
	if err != nil {
		t.Fatalf("org resolve: %v", err)
	}
	got := ApplyThreshold(res, orgMinFor)
	if got.Unknown || len(got.Labels) != 2 || len(got.Spans) != 2 {
		t.Fatalf("org overrides must admit both contact labels at 0.8: %+v", got)
	}
}
