package pricing

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// CORE-REF-04 serving flip: the process default pricer serves the reference
// catalog projection, not the legacy bundled.json corpus.
//
// The projection is deliberately narrow — PRECEDENCE §5 (serveability):
//   - only ACTIVE entries project (draft and retired entries never serve);
//   - the entry must carry at least one source with a verification date and
//     a non-stale entry-level verification date (mirrors StaleModels);
//   - the entry must be inside its effective window;
//   - an active serveable entry must price input AND output — an unknown
//     price must never project as a free one (fail closed).
//
// The pricer cites the catalog label (`yabanin-catalog@<version> <date>
// sha256:<catalog-digest>`) and carries the structured CatalogProvenance
// citation for the admin metadata payload. Preview quotes computed after the
// flip reproduce the exact cents of the committed RefRate amounts; historical
// quotes, usage, invoices and ledger entries are never re-evaluated — their
// stored costs and provenance are immutable, and tenant overrides seated via
// SetDefaultPricer / SetDefaultFilePricer keep precedence above this default.
//
// LoadBundled is a compatibility alias for this primary-only projection.
// No third-party token or unit snapshot is embedded.

//go:embed snapshots/reference-pack-v1.json
var bundledRefPackBytes []byte

// Catalog refusal identities protect the explicitly maintained historical
// fallback if a future reference snapshot retires or drafts one of those keys.
// Unknown entries do not expand the independent fallback allowlist.
var (
	catalogRefusalOnce sync.Once
	catalogRefusalKeys map[string]struct{}
)

// catalogRefusalSet derives draft/retired identities from the primary pack.
// The fallback allowlist is independent of the removed third-party corpus.
func catalogRefusalSet() map[string]struct{} {
	catalogRefusalOnce.Do(func() {
		_, cat, err := LoadRefPack(bundledRefPackBytes)
		if err != nil {
			return
		}
		refused := make(map[string]struct{})
		for i := range cat.Models {
			m := &cat.Models[i]
			if m.Status != RefStatusDraft && m.Status != RefStatusRetired {
				continue
			}
			refused[m.Provider+"\x00"+m.Model] = struct{}{}
			for _, a := range m.Aliases {
				refused[m.Provider+"\x00"+a] = struct{}{}
			}
		}
		catalogRefusalKeys = refused
	})
	return catalogRefusalKeys
}

// catalogRefused reports whether the reference catalog marks (provider,
// model) draft or retired — checked for the exact name and for the
// canonical provider namespace variant (azure-openai → azure).
func catalogRefused(provider, model string) bool {
	ref := catalogRefusalSet()
	if len(ref) == 0 {
		return false
	}
	if _, ok := ref[provider+"\x00"+model]; ok {
		return true
	}
	if c := CanonicalProvider(provider); c != provider {
		_, ok := ref[c+"\x00"+model]
		return ok
	}
	return false
}

// RefCatalogInfo is the structured citation of the served reference catalog:
// the catalog version, its generation date, and the sealed catalog digest.
type RefCatalogInfo struct {
	Version     string `json:"version"`
	GeneratedAt string `json:"generated_at"`
	Digest      string `json:"digest"`
}

// CatalogProvenance returns the structured reference-catalog citation when
// the pricer serves the catalog projection; ok is false for pricers backed
// by legacy snapshots or external files.
func (p *FilePricer) CatalogProvenance() (RefCatalogInfo, bool) {
	if p == nil || p.catalog == nil {
		return RefCatalogInfo{}, false
	}
	return *p.catalog, true
}

// LoadBundledRefServe loads the embedded reference pack, projects the
// serveable entries at process time, and wraps them in a FilePricer that
// cites the catalog label. Time-dependent gates (effective window, review
// SLA) are evaluated once, at load — the embedded pack bytes themselves stay
// deterministic.
func LoadBundledRefServe() (*FilePricer, error) {
	return loadBundledRefServeAt(time.Now().UTC())
}

// loadBundledRefServeAt is LoadBundledRefServe at an explicit instant —
// the test seam that pins the projection, SLA boundary and provenance facts
// deterministically (AUD-PRICE-02); production always delegates with the
// wall clock.
func loadBundledRefServeAt(now time.Time) (*FilePricer, error) {
	_, cat, err := LoadRefPack(bundledRefPackBytes)
	if err != nil {
		return nil, fmt.Errorf("embedded reference pack: %w", err)
	}
	source, date, err := catalogServeSource(cat)
	if err != nil {
		return nil, fmt.Errorf("reference catalog %s: %w", cat.Version, err)
	}
	pf, err := projectServeable(cat, now)
	if err != nil {
		return nil, fmt.Errorf("reference catalog %s: %w", cat.Version, err)
	}
	pf.Source = source
	pf.Date = date
	p, err := NewFilePricer(pf, "sha256:"+cat.Digest)
	if err != nil {
		return nil, err
	}
	p.catalog = &RefCatalogInfo{
		Version:     cat.Version,
		GeneratedAt: cat.GeneratedAt,
		Digest:      cat.Digest,
	}
	return p, nil
}

// catalogServeSource validates the served catalog and renders its source
// identifier and date the way reports cite it: Source carries the version
// identifier, Date the generation date, and Provenance.SHA256 the sealed
// digest — so the composed PricingAsOf line is the full label
// (`yabanin-catalog@<version> <date> sha256:<digest>`), matching the
// release-side catalogs.ProvenanceLabel contract (reimplemented here:
// pkg/pricing must not import pkg/pricing/catalogs).
func catalogServeSource(cat Catalog) (string, string, error) {
	if cat.Version == "" {
		return "", "", fmt.Errorf("catalog version is empty")
	}
	if len(cat.Digest) != 64 {
		return "", "", fmt.Errorf("catalog digest is not sealed (%d hex chars, want 64)", len(cat.Digest))
	}
	if _, err := hex.DecodeString(cat.Digest); err != nil {
		return "", "", fmt.Errorf("catalog digest is not hex: %w", err)
	}
	t, err := parseRefTime(cat.GeneratedAt)
	if err != nil {
		return "", "", fmt.Errorf("generated_at %q: %w", cat.GeneratedAt, err)
	}
	return "yabanin-catalog@" + cat.Version, t.Format("2006-01-02"), nil
}

// projectServeable projects the serveable catalog entries into the legacy
// PriceFile shape (token axes only; per-1M-token amounts). The caller fills
// Source/Date — projection itself is time-gated but label-free so tests can
// drive the serveability rules on synthetic catalogs.
//
// AUD-PRICE-02: every serveable entry also projects under each of its
// aliases with the exact same rates — an alias lookup resolves to the
// target entry's identity, never to a different price (schema.go
// RefModel.Aliases). The canonical name keeps exact-key precedence: an
// alias never shadows another entry's canonical name, duplicate aliases
// collapse, and an alias equal to its own canonical name is skipped.
func projectServeable(cat Catalog, now time.Time) (PriceFile, error) {
	pf := PriceFile{
		Units:  "per_1m_tokens",
		Models: []PriceFileModel{},
	}
	currency := ""
	claimed := make(map[string]struct{})
	projected := make(map[string]PriceFileModel)
	type aliasSpec struct{ provider, target, alias string }
	var aliases []aliasSpec
	for i := range cat.Models {
		m := cat.Models[i]
		if !serveableRefEntry(m, cat, now) {
			continue
		}
		pm, err := projectRefModel(m)
		if err != nil {
			return PriceFile{}, err
		}
		if currency == "" {
			currency = m.Currency
		} else if m.Currency != currency {
			return PriceFile{}, fmt.Errorf("%s/%s: mixed serveable currency %q, want %q",
				m.Provider, m.Model, m.Currency, currency)
		}
		key := m.Provider + "\x00" + m.Model
		claimed[key] = struct{}{}
		projected[key] = pm
		pf.Models = append(pf.Models, pm)
		for _, a := range normalizeNotices(m.Aliases) {
			if a == m.Model {
				continue
			}
			aliases = append(aliases, aliasSpec{provider: m.Provider, target: m.Model, alias: a})
		}
	}
	// Alias pass, canonical rows first: a name already claimed (by any
	// canonical entry or an earlier alias) stays with its first claimant in
	// catalog order — deterministic under any input permutation.
	for _, a := range aliases {
		key := a.provider + "\x00" + a.alias
		if _, dup := claimed[key]; dup {
			continue
		}
		target, ok := projected[a.provider+"\x00"+a.target]
		if !ok {
			continue // unreachable: alias specs come from projected entries
		}
		row := target
		row.Model = a.alias
		claimed[key] = struct{}{}
		pf.Models = append(pf.Models, row)
	}
	pf.Currency = currency
	return pf, nil
}

// serveableRefEntry applies the PRECEDENCE §5 gate to one entry:
// active, verified-source, in-window, non-stale.
func serveableRefEntry(m RefModel, cat Catalog, now time.Time) bool {
	if m.Status != RefStatusActive {
		return false
	}
	if m.EffectiveFrom != "" {
		from, err := parseRefTime(m.EffectiveFrom)
		if err != nil || from.After(now) {
			return false
		}
	}
	if m.EffectiveTo != "" {
		to, err := parseRefTime(m.EffectiveTo)
		if err != nil || !to.After(now) {
			return false
		}
	}
	hasVerified := false
	for _, s := range m.Sources {
		if s.VerifiedAt != "" {
			hasVerified = true
			break
		}
	}
	if !hasVerified {
		return false
	}
	if cat.ReviewSLADays > 0 {
		v, err := parseRefTime(m.VerifiedAt)
		if err != nil {
			return false // an active entry with an unparseable verification date is not serveable
		}
		if v.AddDate(0, 0, cat.ReviewSLADays).Before(now) {
			return false // past the review SLA (same boundary as StaleModels)
		}
	}
	return true
}

// projectRefModel converts one serveable entry to the file shape. Missing
// input or output pricing refuses the entry — never a silent free. Cache
// axes stay absent (0), which the legacy file semantics read as "not
// offered" rather than free.
func projectRefModel(m RefModel) (PriceFileModel, error) {
	rateOf := func(axis string) (float64, bool, error) {
		for _, r := range m.Rates {
			if r.Axis != axis {
				continue
			}
			if r.Amount == nil {
				return 0, false, nil // explicitly unpriced axis
			}
			if r.Unit != RefUnitPer1MTokens {
				return 0, false, fmt.Errorf("axis %s: unit %q is not %s", axis, r.Unit, RefUnitPer1MTokens)
			}
			return *r.Amount, true, nil
		}
		return 0, false, nil
	}
	pm := PriceFileModel{Provider: m.Provider, Model: m.Model}
	var ok bool
	var err error
	if pm.Input, ok, err = rateOf(AxisInput); err != nil {
		return PriceFileModel{}, fmt.Errorf("%s/%s: %w", m.Provider, m.Model, err)
	}
	if !ok {
		return PriceFileModel{}, fmt.Errorf("%s/%s: active entry does not price %s", m.Provider, m.Model, AxisInput)
	}
	if pm.Output, ok, err = rateOf(AxisOutput); err != nil {
		return PriceFileModel{}, fmt.Errorf("%s/%s: %w", m.Provider, m.Model, err)
	}
	if !ok {
		return PriceFileModel{}, fmt.Errorf("%s/%s: active entry does not price %s", m.Provider, m.Model, AxisOutput)
	}
	// Cache axes: absent (or explicitly unpriced) projects as 0 = "not
	// offered"; a present-but-misunit'd rate still refuses the entry.
	if pm.CacheW, _, err = rateOf(AxisCacheWrite); err != nil {
		return PriceFileModel{}, fmt.Errorf("%s/%s: %w", m.Provider, m.Model, err)
	}
	if pm.CacheR, _, err = rateOf(AxisCacheRead); err != nil {
		return PriceFileModel{}, fmt.Errorf("%s/%s: %w", m.Provider, m.Model, err)
	}
	return pm, nil
}
