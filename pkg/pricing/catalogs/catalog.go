// Package catalogs assembles a deterministic reference catalog from independently
// verified primary records and optional operator-supplied token/unit snapshots.
// The shipped catalog contains only the verified Nebius record; no third-party
// price corpus is distributed. Imported entries retain their original source
// and draft status until separately reviewed.
package catalogs

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// Historical format attribution and independently verified primary provenance.
// These are labels, not fetch targets; no third-party price dataset ships.
const (
	// LiteLLMCorpusRef and LiteLLMCorpusDate retain the historical import-format
	// reference for API compatibility. The referenced dataset is not distributed.
	LiteLLMCorpusRef  = "github.com/BerriAI/litellm@61a73c59b049a8cd6c559168d7f3a2557a1a8cf7/model_prices_and_context_window.json"
	LiteLLMCorpusDate = "2026-09-30"
	// NebiusEvidencePrefix is the opaque internal-evidence ref prefix for the
	// verified Nebius console record (COREREF-03 prep R2 default: internal
	// refs are opaque IDs; the evidence archive itself stays outside the
	// public export). The committed in-repo record it summarizes is
	// scripts/stand-agenteval/nebius-catalog.json.
	NebiusEvidencePrefix = "ev-nebius-console-"
	// NebiusRecordPath is the in-repo location of the verified record, for
	// notes and tests.
	NebiusRecordPath = "scripts/stand-agenteval/nebius-catalog.json"
	// ReviewSLADays is the review SLA encoded in the catalog header: a
	// verified_at age past 90 days is reported stale (day 90 is the last
	// fresh day, day 91 is stale — StaleModels semantics).
	ReviewSLADays = 90
	// derivedEntryNote is the per-entry provenance note stamped on every
	// litellm-derived entry (honest labeling at the entry level).
	derivedEntryNote = "provenance: litellm-derived draft converted from third-party snapshot; NOT verified by Yabanin; pending primary-source review (notice: pkg/pricing/NOTICE-litellm.txt)"
	// verifiedEntryNotePrefix labels owner-verified primary entries.
	verifiedEntryNotePrefix = "provenance: verified-primary (owner console verification"
)

// BuildInput is the raw corpus: committed file bytes, read offline. The
// builder consumes bytes only (no paths, no network, no environment).
type BuildInput struct {
	// TokenSnapshot is an optional operator-supplied per_1m_tokens file.
	TokenSnapshot []byte
	// UnitSnapshot is an optional operator-supplied non-token price file.
	UnitSnapshot []byte
	// NebiusRecord is the nebius-catalog.json byte content (verified primary
	// price record evidence).
	NebiusRecord []byte
}

// BuildConfig carries the operator inputs of one assembly. Timestamps and
// versions are explicit inputs — computing them inside the build path would
// make the output bytes wall-clock dependent, which the determinism contract
// forbids.
type BuildConfig struct {
	// Version is the operator-assigned catalog revision.
	Version string
	// GeneratedAt is the assembly instant (YYYY-MM-DD or RFC 3339).
	GeneratedAt string
	// Source names how the snapshot was assembled (header provenance).
	Source string
	// Reviewer is the catalog-level approver ("" = catalog-level review
	// pending; per-entry reviewers are independent facts).
	Reviewer string
	// ReviewSLADays is the review SLA (0 = none).
	ReviewSLADays int
}

// V1BuildConfig retains the pre-release catalog version and assembly date.
// The source label identifies the primary-only payload. The changed digest
// prevents the earlier third-party corpus from being mistaken for this content.
// No catalog-level or release approval is implied by the per-entry evidence.
func V1BuildConfig() BuildConfig {
	return BuildConfig{
		Version:       "0.1.0",
		GeneratedAt:   "2026-11-02",
		Source:        "yabanin-catalog-builder (verified: nebius console record 2026-09-08; no third-party price corpus)",
		Reviewer:      "",
		ReviewSLADays: ReviewSLADays,
	}
}

// BuildCatalog assembles the reference catalog v1 draft from the committed
// corpus. Deterministic: identical inputs (in any per-file entry order)
// produce identical output. The result is unsealed; seal it with
// pricing.SealCatalog / MarshalCatalog before pinning bytes.
//
// The header carries Supersedes="" (genesis snapshot): the rollback chain
// starts here.
func BuildCatalog(in BuildInput, cfg BuildConfig) (pricing.Catalog, error) {
	if err := validateConfig(cfg); err != nil {
		return pricing.Catalog{}, err
	}

	merged := pricing.Catalog{}
	if len(in.TokenSnapshot) != 0 {
		pf, _, err := pricing.ParsePriceFile(bytes.NewReader(in.TokenSnapshot))
		if err != nil {
			return pricing.Catalog{}, fmt.Errorf("corpus token snapshot: %w", err)
		}
		merged, err = pricing.CatalogFromPriceFile(pf)
		if err != nil {
			return pricing.Catalog{}, fmt.Errorf("convert token snapshot: %w", err)
		}
	}
	if len(in.UnitSnapshot) != 0 {
		uf, _, err := pricing.ParseUnitFile(bytes.NewReader(in.UnitSnapshot))
		if err != nil {
			return pricing.Catalog{}, fmt.Errorf("corpus unit snapshot: %w", err)
		}
		unitCat, err := pricing.CatalogFromUnitFile(uf)
		if err != nil {
			return pricing.Catalog{}, fmt.Errorf("convert unit snapshot: %w", err)
		}
		if len(merged.Models) == 0 {
			merged = unitCat
		} else {
			merged, err = pricing.MergeCatalogs(merged, unitCat)
			if err != nil {
				return pricing.Catalog{}, fmt.Errorf("merge corpus snapshots: %w", err)
			}
		}
	}

	// Header: the assembly identity replaces the conversion-adapter defaults
	// (adapters stamp legacy- versions; this is a Yabanin assembly).
	merged.SchemaVersion = pricing.RefSchemaVersion
	merged.Version = cfg.Version
	merged.GeneratedAt = cfg.GeneratedAt
	merged.Source = cfg.Source
	merged.Reviewer = cfg.Reviewer
	merged.ReviewSLADays = cfg.ReviewSLADays
	merged.Supersedes = "" // genesis
	merged.Digest = ""     // sealed by the caller

	relabelDerivedEntries(merged.Models)

	if err := enforceNeverFree(merged); err != nil {
		return pricing.Catalog{}, err
	}

	nebius, err := NebiusEntries(in.NebiusRecord)
	if err != nil {
		return pricing.Catalog{}, err
	}
	merged.Models, err = appendDistinct(merged.Models, nebius)
	if err != nil {
		return pricing.Catalog{}, err
	}

	sortCatalogModels(merged.Models)
	return merged, nil
}

// validateConfig refuses an assembly identity that would not validate as
// catalog header content; fail before any corpus work.
func validateConfig(cfg BuildConfig) error {
	if strings.TrimSpace(cfg.Version) == "" {
		return fmt.Errorf("build config: version is required")
	}
	if err := pricing.ValidateRefTime(cfg.GeneratedAt); err != nil {
		return fmt.Errorf("build config generated_at: %w", err)
	}
	if strings.TrimSpace(cfg.Source) == "" {
		return fmt.Errorf("build config: source is required")
	}
	if cfg.ReviewSLADays < 0 {
		return fmt.Errorf("build config: review_sla_days must not be negative (%d)", cfg.ReviewSLADays)
	}
	return nil
}

// relabelDerivedEntries stamps the honest provenance note on every
// litellm-derived entry. The conversion adapters set a generic note; the
// catalog's contract is stronger: derived entries must say so, per entry,
// where every consumer can see it.
func relabelDerivedEntries(models []pricing.RefModel) {
	for i := range models {
		m := &models[i]
		if ClassifyEntry(*m) != ClassLiteLLMDerived {
			continue
		}
		for j := range m.Sources {
			if strings.Contains(m.Sources[j].Ref, "github.com/BerriAI/litellm") {
				m.Sources[j].Note = derivedEntryNote
			}
		}
	}
}

// enforceNeverFree is the builder-side guard of the "unpriced ≠ free"
// contract: no zero rate may leave the builder. A zero amount in the output
// would read as a verified free price; genuine frees must be re-verified
// from a primary source and land here only through a future reviewed
// release with explicit evidence (none exists in this corpus). Non-finite
// amounts are refused at the same boundary (validation rejects them too;
// failing here keeps the builder itself trustworthy for tests that inspect
// pre-validation intermediates).
func enforceNeverFree(c pricing.Catalog) error {
	for i := range c.Models {
		for j := range c.Models[i].Rates {
			r := &c.Models[i].Rates[j]
			if r.Amount == nil {
				continue
			}
			v := *r.Amount
			switch {
			case math.IsNaN(v) || math.IsInf(v, 0):
				return fmt.Errorf("never-free: %s:%s axis %q carries a non-finite amount (%v)", c.Models[i].Provider, c.Models[i].Model, r.Axis, v)
			case v == 0:
				return fmt.Errorf("never-free: %s:%s axis %q carries amount 0; "+
					"unpriced must be null and free must come from verified evidence", c.Models[i].Provider, c.Models[i].Model, r.Axis)
			}
		}
	}
	return nil
}

// appendDistinct appends entries, refusing identity collisions with the
// corpus (never overwrite a converted entry) and internal duplicates. The
// identity key matches ValidateCatalog's uniqueness semantics —
// (provider, model); region/tier/context-band variants are outside the v1
// corpus and would be rejected by validation anyway.
func appendDistinct(models []pricing.RefModel, entries []pricing.RefModel) ([]pricing.RefModel, error) {
	seen := make(map[string]struct{}, len(models)+len(entries))
	for i := range models {
		seen[identityKey(models[i])] = struct{}{}
	}
	for _, e := range entries {
		key := identityKey(e)
		if _, dup := seen[key]; dup {
			return models, fmt.Errorf("nebius overlay: identity %s:%s already exists in corpus", e.Provider, e.Model)
		}
		seen[key] = struct{}{}
		models = append(models, e)
	}
	return models, nil
}

func identityKey(m pricing.RefModel) string {
	return m.Provider + "\x00" + m.Model
}

// sortCatalogModels applies the schema's canonical order in place: models by
// (provider, model, region, tier, context_band), then per entry the sorted
// aliases / canonical-axis-ordered rates / ref-sorted evidence and sources /
// (axis, ref)-sorted conflicts. MarshalCatalog output is byte-stable because
// this ordering matches the canonical form the digest fingerprints.
func sortCatalogModels(models []pricing.RefModel) {
	for i := range models {
		m := &models[i]
		sort.Strings(m.Aliases)
		rs := append([]pricing.RefRate(nil), m.Rates...)
		sort.SliceStable(rs, func(a, b int) bool {
			return axisRank(rs[a].Axis) < axisRank(rs[b].Axis)
		})
		for k := range rs {
			ev := append([]pricing.RefEvidence(nil), rs[k].Evidence...)
			sort.SliceStable(ev, func(x, y int) bool { return ev[x].Ref < ev[y].Ref })
			rs[k].Evidence = ev
		}
		m.Rates = rs
		src := append([]pricing.RefSource(nil), m.Sources...)
		sort.SliceStable(src, func(a, b int) bool { return src[a].Ref < src[b].Ref })
		m.Sources = src
		cf := append([]pricing.RefConflict(nil), m.Conflicts...)
		sort.SliceStable(cf, func(a, b int) bool {
			if cf[a].Axis != cf[b].Axis {
				return cf[a].Axis < cf[b].Axis
			}
			return cf[a].Ref < cf[b].Ref
		})
		m.Conflicts = cf
	}
	sort.SliceStable(models, func(a, b int) bool {
		x, y := models[a], models[b]
		if x.Provider != y.Provider {
			return x.Provider < y.Provider
		}
		if x.Model != y.Model {
			return x.Model < y.Model
		}
		if x.Region != y.Region {
			return x.Region < y.Region
		}
		if x.Tier != y.Tier {
			return x.Tier < y.Tier
		}
		return x.ContextBand < y.ContextBand
	})
}

// axisRank mirrors pricing.CanonicalAxes order (token axes first, then
// non-token axes); unknown axes sort last (validation rejects them anyway).
func axisRank(axis string) int {
	for i, a := range pricing.CanonicalAxes {
		if a == axis {
			return i
		}
	}
	return len(pricing.CanonicalAxes)
}
