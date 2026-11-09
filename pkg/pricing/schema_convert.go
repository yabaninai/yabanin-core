package pricing

import (
	"fmt"
	"sort"
)

// Conversion adapters from the current legacy snapshots (PriceFile /
// UnitFile) to the Yabanin reference catalog (CORE-REF-01). Conversion is
// additive: nothing in the legacy files is rewritten, and no converted
// entry is ever auto-serveable.
//
// Lossy-mapping contract (documented gap, see SCHEMA.md §Conversion):
//
//   - The legacy format has no "explicitly unpriced" state — a plain float.
//     A zero input/output price is converted to Amount=nil (explicitly
//     unpriced), NEVER to free: a silent zero would bill the axis as free
//     once a consumer reads Amount directly. Whether the source meant free
//     must be re-verified against the primary provider during review.
//   - Cache axes are present only when the legacy rate is non-zero: in the
//     legacy format a zero cache rate uniformly means "not offered", so the
//     axis is absent rather than nil-noise on every entry.
//   - The legacy files carry no per-source evidence; converted rates have
//     none. Provenance is entry-level (one internal source record naming the
//     legacy snapshot).
//   - Converted entries are Status=draft with the legacy snapshot date as
//     VerifiedAt: conversion output must pass review before serving.

// CatalogFromPriceFile converts a validated legacy token snapshot
// (PriceFile shape) into a draft reference catalog. The input must have
// passed ValidatePriceFile; currency and unit labels are carried over and
// re-checked by ValidateCatalog. A legacy snapshot whose date is "unknown"
// converts with open windows and no verification instant (the entries stay
// draft until reviewed with a real date).
func CatalogFromPriceFile(pf PriceFile) (Catalog, error) {
	asOf := refDateOrEmpty(pf.Date)
	c := Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "legacy-" + pf.Date,
		GeneratedAt:   asOf,
		Source:        "converted:pricefile:" + pf.Source,
		Models:        make([]RefModel, 0, len(pf.Models)),
	}
	for _, m := range pf.Models {
		entry := RefModel{
			Provider:      m.Provider,
			Model:         m.Model,
			Currency:      pf.Currency,
			EffectiveFrom: asOf,
			VerifiedAt:    asOf,
			Status:        RefStatusDraft,
			Sources: []RefSource{{
				Kind:       RefSourceInternalEvidence,
				Ref:        pf.Source,
				VerifiedAt: asOf,
				Note:       "converted from legacy PriceFile snapshot",
			}},
		}
		entry.Rates = append(entry.Rates, refRateFromLegacy(AxisInput, m.Input))
		entry.Rates = append(entry.Rates, refRateFromLegacy(AxisOutput, m.Output))
		if m.CacheW != 0 {
			entry.Rates = append(entry.Rates, refRateFromLegacy(AxisCacheWrite, m.CacheW))
		}
		if m.CacheR != 0 {
			entry.Rates = append(entry.Rates, refRateFromLegacy(AxisCacheRead, m.CacheR))
		}
		c.Models = append(c.Models, entry)
	}
	return c, nil
}

// refDateOrEmpty passes through a well-formed schema date and maps anything
// else (e.g. the legacy "unknown") to the empty string: an open bound / no
// verification instant instead of an invalid timestamp.
func refDateOrEmpty(d string) string {
	if err := ValidateRefTime(d); err != nil {
		return ""
	}
	return d
}

// refRateFromLegacy maps one legacy scalar to a rate: zero becomes an
// explicitly-unpriced axis (Amount=nil), a non-zero becomes the amount.
func refRateFromLegacy(axis string, v float64) RefRate {
	r := RefRate{Axis: axis, Unit: axisUnits[axis]}
	if v != 0 {
		amount := v
		r.Amount = &amount
	}
	return r
}

// unitFileAxis maps a legacy unit denominator to its schema axis.
func unitFileAxis(unit string) (string, bool) {
	switch unit {
	case UnitPerAudioSecond:
		return AxisAudioSecond, true
	case UnitPerCharacter:
		return AxisCharacter, true
	case UnitPerImage:
		return AxisImage, true
	}
	return "", false
}

// CatalogFromUnitFile converts a validated legacy unit snapshot
// (UnitFile shape) into a draft reference catalog with one entry
// per (provider, model), all of the entry's unit axes merged into its rate
// set.
func CatalogFromUnitFile(uf UnitFile) (Catalog, error) {
	asOf := refDateOrEmpty(uf.Date)
	c := Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "legacy-units-" + uf.Date,
		GeneratedAt:   asOf,
		Source:        "converted:unitfile:" + uf.Source,
		Models:        make([]RefModel, 0),
	}
	byIdentity := make(map[string]*RefModel)
	var order []string
	for _, u := range uf.Units {
		axis, ok := unitFileAxis(u.Unit)
		if !ok {
			return Catalog{}, fmt.Errorf("unit file entry %s:%s has unknown unit %q", u.Provider, u.Model, u.Unit)
		}
		key := u.Provider + "\x00" + u.Model
		entry, seen := byIdentity[key]
		if !seen {
			entry = &RefModel{
				Provider:      u.Provider,
				Model:         u.Model,
				Currency:      uf.Currency,
				EffectiveFrom: asOf,
				VerifiedAt:    asOf,
				Status:        RefStatusDraft,
				Sources: []RefSource{{
					Kind:       RefSourceInternalEvidence,
					Ref:        uf.Source,
					VerifiedAt: asOf,
					Note:       "converted from legacy UnitFile snapshot",
				}},
			}
			byIdentity[key] = entry
			order = append(order, key)
		}
		entry.Rates = append(entry.Rates, refRateFromLegacy(axis, u.Rate))
	}
	sort.Strings(order)
	for _, key := range order {
		c.Models = append(c.Models, *byIdentity[key])
	}
	return c, nil
}

// MergeCatalogs unions src into dst. Metadata (version, source, generated
// instant, supersedes chain, reviewer, review SLA) is taken from dst; the
// caller assigns a new version and seals the result. Entries are keyed by
// full identity (provider, model, region, tier, context band):
//
//   - identical identity: aliases and primary sources are unioned, per-axis
//     rates are merged (an axis present on only one side is copied;
//     nil-vs-number resolves to the number — an unknown axis does not
//     contradict a verified one; two different numbers are an error the
//     operator resolves in the source data, never silently here);
//   - identity only in src: appended as-is.
//
// Neither input is modified.
func MergeCatalogs(dst, src Catalog) (Catalog, error) {
	out := dst
	out.Models = append([]RefModel(nil), dst.Models...)

	index := make(map[string]int, len(out.Models))
	for i := range out.Models {
		index[refIdentityKey(out.Models[i])] = i
	}
	for _, s := range src.Models {
		key := refIdentityKey(s)
		i, exists := index[key]
		if !exists {
			index[key] = len(out.Models)
			out.Models = append(out.Models, s)
			continue
		}
		merged, err := mergeRefModels(out.Models[i], s)
		if err != nil {
			return Catalog{}, fmt.Errorf("merge %s:%s: %w", s.Provider, s.Model, err)
		}
		out.Models[i] = merged
	}
	return out, nil
}

// refIdentityKey is the full identity of an entry: provider and model plus
// the scoping dimensions (region, tier, context band).
func refIdentityKey(m RefModel) string {
	return m.Provider + "\x00" + m.Model + "\x00" + m.Region + "\x00" + m.Tier + "\x00" + m.ContextBand
}

func mergeRefModels(base, add RefModel) (RefModel, error) {
	out := base

	// Aliases: union, sorted, deduped.
	seen := make(map[string]struct{}, len(base.Aliases)+len(add.Aliases))
	for _, a := range append(append([]string(nil), base.Aliases...), add.Aliases...) {
		seen[a] = struct{}{}
	}
	out.Aliases = make([]string, 0, len(seen))
	for a := range seen {
		out.Aliases = append(out.Aliases, a)
	}
	sort.Strings(out.Aliases)

	// Currency must agree across an identity.
	if base.Currency != add.Currency {
		return RefModel{}, fmt.Errorf("currency mismatch (%s vs %s)", base.Currency, add.Currency)
	}

	// Rates: per-axis merge with agreement check.
	byAxis := make(map[string]RefRate, len(base.Rates)+len(add.Rates))
	var order []string
	for _, r := range base.Rates {
		byAxis[r.Axis] = r
		order = append(order, r.Axis)
	}
	for _, r := range add.Rates {
		prev, exists := byAxis[r.Axis]
		if !exists {
			byAxis[r.Axis] = r
			order = append(order, r.Axis)
			continue
		}
		merged, err := mergeRefRates(prev, r)
		if err != nil {
			return RefModel{}, fmt.Errorf("axis %q: %w", r.Axis, err)
		}
		byAxis[r.Axis] = merged
	}
	out.Rates = make([]RefRate, 0, len(order))
	for _, axis := range order {
		out.Rates = append(out.Rates, byAxis[axis])
	}

	// Sources: union by ref, base record wins on duplicate refs.
	seenSrc := make(map[string]struct{}, len(base.Sources)+len(add.Sources))
	out.Sources = make([]RefSource, 0, len(seenSrc))
	for _, s := range append(append([]RefSource(nil), base.Sources...), add.Sources...) {
		if _, dup := seenSrc[s.Ref]; dup {
			continue
		}
		seenSrc[s.Ref] = struct{}{}
		out.Sources = append(out.Sources, s)
	}

	// Conflicts: append, deduped by (axis, ref).
	seenCf := make(map[string]struct{}, len(base.Conflicts)+len(add.Conflicts))
	for _, cf := range append(append([]RefConflict(nil), base.Conflicts...), add.Conflicts...) {
		k := cf.Axis + "\x00" + cf.Ref
		if _, dup := seenCf[k]; dup {
			continue
		}
		seenCf[k] = struct{}{}
		out.Conflicts = append(out.Conflicts, cf)
	}
	return out, nil
}

func mergeRefRates(base, add RefRate) (RefRate, error) {
	out := base
	switch {
	case base.Amount == nil && add.Amount == nil:
		// both unpriced: keep nil
	case base.Amount == nil:
		// unknown vs verified: the verified number wins. This is the one
		// documented resolution (SCHEMA.md §Conversion), not a silent
		// disagreement pick.
		v := *add.Amount
		out.Amount = &v
	case add.Amount == nil:
		// verified vs unknown: keep the verified base amount
	case !sameRefAmount(*base.Amount, *add.Amount):
		return RefRate{}, fmt.Errorf("amounts disagree (%v vs %v)", *base.Amount, *add.Amount)
	}
	// Evidence union by ref; the first record for a ref wins.
	seenEv := make(map[string]struct{}, len(base.Evidence)+len(add.Evidence))
	for _, ev := range append(append([]RefEvidence(nil), base.Evidence...), add.Evidence...) {
		if _, dup := seenEv[ev.Ref]; dup {
			continue
		}
		seenEv[ev.Ref] = struct{}{}
		out.Evidence = append(out.Evidence, ev)
	}
	return out, nil
}
