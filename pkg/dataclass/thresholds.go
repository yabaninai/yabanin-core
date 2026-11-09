// Package dataclass — per-org confidence threshold overrides
// (E04-P01-W04-C03).
//
// The default per-label minimum is DefaultMinConfidence (confidence.go);
// an org can override individual label keys. Three rules hold:
//
//   - single source of truth: DefaultMinConfidence is defined once and
//     every resolver falls back to it — no copy of the default lives
//     here;
//   - stored overrides are never trusted: ThresholdReader output is
//     re-validated before use, because the writer-of-record and the
//     reader-of-record are different code paths;
//   - fail-closed loads: a reader error fails threshold resolution
//     instead of silently downgrading to defaults — defaults are
//     stricter than typical overrides, and silently re-tightening an
//     org's labels after the org explicitly relaxed them is a decision
//     the caller must see, not one this package makes.
//
// Persistence is deliberately out of scope: ThresholdReader is the
// storage seam, and the write path (admin surface + table) belongs to
// the wiring card — this packet's migrations stop at 0025.
package dataclass

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/labels"
)

// ThresholdValidationError lists every threshold problem, mirroring the
// taxonomy ValidationError convention: one deterministic, sorted error
// list; empty means valid.
type ThresholdValidationError struct {
	Errors []string `json:"errors"`
}

func (e *ThresholdValidationError) Error() string {
	return "dataclass: threshold overrides invalid: " + strings.Join(e.Errors, "; ")
}

// Thresholds is a set of per-label-key minimum-confidence overrides. A
// nil or empty Min map means "defaults for everything" and is valid.
type Thresholds struct {
	Min map[string]float64 `json:"min"`
}

// Validate checks every override: the key must be a canonical,
// non-reserved label key (the pkg/labels grammar — same as taxonomy
// label keys), the value must be within [0, 1] inclusive, and NaN is
// refused outright (a NaN minimum would pass nothing silently). The
// error list is sorted, so identical input yields identical output.
func (t Thresholds) Validate() error {
	var errs []string
	for key, value := range t.Min {
		canonical, ok := labels.NormalizeKey(key)
		if !ok {
			errs = append(errs, fmt.Sprintf("label key %q: invalid grammar (lowercase, <=%d bytes, dots/digits/underscores/hyphens)", key, labels.MaxKeyLen))
			continue
		}
		if canonical != key {
			errs = append(errs, fmt.Sprintf("label key %q: not canonical (want %q)", key, canonical))
			continue
		}
		if strings.HasPrefix(key, labels.ReservedPrefix) {
			errs = append(errs, fmt.Sprintf("label key %q: reserved prefix %q", key, labels.ReservedPrefix))
			continue
		}
		if math.IsNaN(value) {
			errs = append(errs, fmt.Sprintf("label %q: NaN minimum", key))
			continue
		}
		if value < 0 || value > 1 {
			errs = append(errs, fmt.Sprintf("label %q: minimum %v outside [0, 1]", key, value))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return &ThresholdValidationError{Errors: errs}
}

// Resolver returns the per-label minimum function for these overrides:
// an override wins for its key, every other key falls back to
// DefaultMinConfidence. Thresholds that skipped Validate with a NaN
// value fail closed here — NaN is below every comparison, so the
// affected key passes nothing.
func (t Thresholds) Resolver() func(label string) float64 {
	return func(label string) float64 {
		if v, ok := t.Min[label]; ok {
			return v
		}
		return DefaultMinConfidence
	}
}

// defaultThresholdResolver is the defaults-only resolver (nil reader,
// org without overrides).
func defaultThresholdResolver() func(string) float64 {
	return Thresholds{}.Resolver()
}

// ThresholdReader loads an org's stored threshold overrides. found is
// false when the org never wrote any — that is the defaults case, not
// an error. The core ships no implementation: the read side lands with
// the wiring card (the write side with the admin surface).
type ThresholdReader interface {
	ThresholdOverrides(ctx context.Context, orgID string) (overrides Thresholds, found bool, err error)
}

// ResolveThresholds resolves the effective per-label minimum function
// for one org: org id checked up front, then nil reader / not-found →
// defaults; reader error → the error (fail-closed load); stored
// overrides re-validated, then applied. The returned function is
// ApplyThreshold's minFor.
func ResolveThresholds(ctx context.Context, reader ThresholdReader, orgID string) (func(label string) float64, error) {
	if err := requireOrgID(orgID); err != nil {
		return nil, err
	}
	if reader == nil {
		return defaultThresholdResolver(), nil
	}
	overrides, found, err := reader.ThresholdOverrides(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("dataclass: load threshold overrides for org %s: %w", orgID, err)
	}
	if !found {
		return defaultThresholdResolver(), nil
	}
	if err := overrides.Validate(); err != nil {
		return nil, fmt.Errorf("dataclass: stored threshold overrides for org %s: %w", orgID, err)
	}
	return overrides.Resolver(), nil
}
