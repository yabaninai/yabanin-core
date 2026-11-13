package inventory

// E02-P01 W03-C01: import of the model/provider catalog planes into the
// observable asset registry. Three upstream planes feed kind=model and
// kind=provider assets:
//
//   - models_registry (the deployment's own global registry table,
//     migrations/0001_init.up.sql:1089; provider vocabulary pinned by
//     chk_provider — 18 base values + azure-openai (0005) = 19 — read
//     through the NewDBModelLoader pattern of pkg/router/tier_pool.go:328);
//   - the process model catalog (pkg/provider.ModelCatalog — lifecycle
//     statuses incl. deprecation and the provider Withdrawal analog,
//     modelcatalog.go:122/129);
//   - the pricing reference pack (pkg/pricing bundled refpack;
//     refcatalog_meta.go:34 BundledRefPackJSON).
//
// The catalog and pricing planes together form the REFERENCE side; the
// registry is the DEPLOYMENT side. A pair known to only one side is not an
// error: both sides land as separate, verbatim observations on one asset
// and the disagreement is flagged (W03-C02 owns the flag semantics and the
// provenance block; this file builds the two observations without blending
// them — no field of one side is ever derived from the other).
//
// Status vocabulary on assets (lifecycle at import time): pending, active,
// deprecated, withdrawn, unknown. A withdrawn or deprecated model is still
// an asset — catalog delisting is not deletion (the packet invariant
// «отсутствие наблюдений ≠ отсутствие актива» applies to reference planes
// too: statuses persist, assets never disappear from the registry because
// a window closed).
//
// Asset keys are stable and deterministic so the W05-C01 dedup card can
// converge later: model:<provider>/<model> (the canonical model name — an
// alias-named registry row is attributed to its canonical target through
// ModelCatalog.ResolveAlias, modelcatalog.go:463; exact names win over
// aliases) and provider:<provider>. Providers contain no "/" in any of the
// 19 chk_provider values, so the split at the first "/" is injective.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// SourceModelsRegistry marks assets whose existence the deployment's own
// models_registry vouches for.
const SourceModelsRegistry Source = "models_registry"

// SourceModelCatalog marks assets known only through the reference side
// (process model catalog and/or pricing refpack), not registered in
// models_registry.
const SourceModelCatalog Source = "model_catalog"

// RegistryModel is one models_registry row as relevant to inventory. Only
// identity/lifecycle columns are read — upstream_api_key is NEVER selected
// (secrets do not enter the registry).
type RegistryModel struct {
	ModelName   string
	Provider    string
	Tier        string
	UpstreamURL string
	Enabled     bool
}

// ModelRegistrySource lists the GLOBAL models_registry table (deployment
// scope, no org column — cross-org materialization is per-org at the asset
// level, W03-C02). Satisfied by *DBModelRegistrySource; tests use fixtures.
type ModelRegistrySource interface {
	ListRegistryModels(ctx context.Context) ([]RegistryModel, error)
}

// DBModelRegistrySource implements ModelRegistrySource over the inventory
// DB seam with parameterized SQL (the NewDBModelLoader pattern,
// tier_pool.go:328 — no dynamic SQL).
type DBModelRegistrySource struct {
	db DB
}

// NewDBModelRegistrySource wires the registry source to a pool or tx.
func NewDBModelRegistrySource(db DB) *DBModelRegistrySource {
	return &DBModelRegistrySource{db: db}
}

// ListRegistryModels reads every models_registry row in model_name order.
func (s *DBModelRegistrySource) ListRegistryModels(ctx context.Context) ([]RegistryModel, error) {
	rows, err := s.db.Query(ctx, `
		SELECT model_name, provider, tier, COALESCE(upstream_url,''), enabled
		FROM models_registry
		ORDER BY model_name`)
	if err != nil {
		return nil, fmt.Errorf("inventory: list models_registry: %w", err)
	}
	defer rows.Close()
	var out []RegistryModel
	for rows.Next() {
		var m RegistryModel
		if err := rows.Scan(&m.ModelName, &m.Provider, &m.Tier, &m.UpstreamURL, &m.Enabled); err != nil {
			return nil, fmt.Errorf("inventory: scan models_registry row: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CatalogMeta is the reference catalog snapshot metadata (the ModelCatalog
// accessors, modelcatalog.go:374–408).
type CatalogMeta struct {
	Version       string
	SchemaVersion int
	Source        string
	AsOf          time.Time
}

// ModelCatalogSource is the reference catalog seam: snapshot metadata, the
// full entry listing, provider withdrawals and alias resolution.
// ProviderCatalog adapts *provider.ModelCatalog to it; tests use fixtures
// (including deliberately broken entries the builder must skip, W03-C03).
type ModelCatalogSource interface {
	Meta() CatalogMeta
	Entries() []provider.ModelCatalogEntry
	Withdrawals() []provider.Withdrawal
	ResolveAlias(providerName, alias string, at time.Time) (string, provider.ModelStatus)
}

// ProviderCatalog adapts the process *provider.ModelCatalog (nil-safe by
// construction: a nil catalog reports zero metadata and no entries) to the
// ModelCatalogSource seam.
type ProviderCatalog struct{ Cat *provider.ModelCatalog }

// Meta reports the snapshot metadata ("" / 0 without a catalog).
func (p ProviderCatalog) Meta() CatalogMeta {
	return CatalogMeta{
		Version:       p.Cat.Version(),
		SchemaVersion: p.Cat.SchemaVersion(),
		Source:        p.Cat.Source(),
		AsOf:          p.Cat.AsOf(),
	}
}

// Entries lists every catalog row (nil catalog: none).
func (p ProviderCatalog) Entries() []provider.ModelCatalogEntry { return p.Cat.Entries() }

// Withdrawals lists the provider-level delist rows (nil catalog: none).
func (p ProviderCatalog) Withdrawals() []provider.Withdrawal { return p.Cat.Withdrawals() }

// ResolveAlias maps an alias to its canonical model name ("" when unknown).
func (p ProviderCatalog) ResolveAlias(providerName, alias string, at time.Time) (string, provider.ModelStatus) {
	return p.Cat.ResolveAlias(providerName, alias, at)
}

// PricingMeta is the pricing reference pack metadata (the provenance trio
// fixed on assets by W03-C02).
type PricingMeta struct {
	Version     string    // pricing.Catalog.Version
	GeneratedAt string    // pricing.Catalog.GeneratedAt (as_of)
	Digest      string    // pricing.Catalog.Digest — the provenance hash
	AsOfTime    time.Time // parsed GeneratedAt when possible (zero = unparsable)
}

// PricingPack is the pricing reference seam. Satisfied by the bundled pack
// loader (modelprovenance.go) and by test fixtures.
type PricingPack interface {
	Meta() PricingMeta
	Models() []pricing.RefModel
}

// RegistryModelObservation is the deployment-side observation of one pair:
// the models_registry rows seen under the pair's canonical or alias names,
// quoted verbatim (no reference-side field ever enters this section).
type RegistryModelObservation struct {
	ModelName   string `json:"model_name"`
	Tier        string `json:"tier,omitempty"`
	UpstreamURL string `json:"upstream_url,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// CatalogModelObservation is the catalog half of the reference side: the
// ModelCatalogEntry lifecycle at import time.
type CatalogModelObservation struct {
	Aliases       []string  `json:"aliases,omitempty"`
	Status        string    `json:"status"` // pending|active|deprecated|withdrawn
	EffectiveFrom time.Time `json:"effective_from,omitempty"`
	EffectiveTo   time.Time `json:"effective_to,omitempty"`
	DeprecatedAt  time.Time `json:"deprecated_at,omitempty"`
	Custom        bool      `json:"custom,omitempty"`
}

// PricingModelObservation is the pricing half of the reference side: the
// refpack's knowledge of the pair (statuses and scoping axes, deduped).
type PricingModelObservation struct {
	Aliases  []string `json:"aliases,omitempty"`
	Statuses []string `json:"statuses"` // union of RefModel.Status values, sorted
	Regions  []string `json:"regions,omitempty"`
	Tiers    []string `json:"tiers,omitempty"`
}

// ModelPayload is the registry payload of one kind=model asset. Registry is
// the deployment-side observation list, Catalog/Pricing the reference-side
// observations; each section is present only when that plane knows the
// pair. Discrepancy is set (registry_only / reference_only) when exactly
// one side knows the pair — the two observations stay disjoint sections,
// never a blended merge (W03-C02).
type ModelPayload struct {
	Provider     string                     `json:"provider"`
	Model        string                     `json:"model"`
	Status       string                     `json:"status"` // pending|active|deprecated|withdrawn|unknown
	Aliases      []string                   `json:"aliases,omitempty"`
	DeprecatedAt *time.Time                 `json:"deprecated_at,omitempty"`
	WithdrawnAt  *time.Time                 `json:"withdrawn_at,omitempty"` // provider-level withdrawal instant
	Registry     []RegistryModelObservation `json:"registry,omitempty"`
	Catalog      *CatalogModelObservation   `json:"catalog,omitempty"`
	Pricing      *PricingModelObservation   `json:"pricing,omitempty"`
	Discrepancy  string                     `json:"discrepancy,omitempty"` // registry_only|reference_only
	Provenance   *ReferenceProvenance       `json:"provenance,omitempty"`
}

// ProviderPayload is the registry payload of one kind=provider asset.
// A withdrawal-only provider (no models on either side) is still an asset
// with status=withdrawn (W03-C03).
type ProviderPayload struct {
	Provider       string               `json:"provider"`
	Status         string               `json:"status"` // active|withdrawn
	WithdrawnAt    *time.Time           `json:"withdrawn_at,omitempty"`
	RegistryModels int                  `json:"registry_models"`
	CatalogModels  int                  `json:"catalog_models"`
	PricingModels  int                  `json:"pricing_models"`
	Discrepancy    string               `json:"discrepancy,omitempty"` // registry_only|reference_only
	Provenance     *ReferenceProvenance `json:"provenance,omitempty"`
}

// ReferenceProvenance is the source-version block fixed on reference-side
// assets (W03-C02): which catalog and which pack the observations quote.
type ReferenceProvenance struct {
	CatalogVersion string `json:"catalog_version,omitempty"`
	CatalogSource  string `json:"catalog_source,omitempty"`
	PricingVersion string `json:"pricing_version,omitempty"`
	PricingAsOf    string `json:"pricing_as_of,omitempty"`
	PricingDigest  string `json:"pricing_digest,omitempty"`
}

// ModelImportSkip records one upstream entry the builder refused (skipped,
// counted, never silently dropped — the sibling-findings posture of
// pkg/secevents/adapter.go:120: a broken sibling must not abort the import).
type ModelImportSkip struct {
	Plane  string // "catalog" | "registry" | "pricing"
	Ref    string
	Reason string
}

// ModelKey is the deterministic asset key of one model pair.
func ModelKey(providerName, model string) string { return "model:" + providerName + "/" + model }

// ProviderKey is the deterministic asset key of one provider.
func ProviderKey(providerName string) string { return "provider:" + providerName }

// pairKey is the internal map key of one (provider, canonical model).
type pairKey struct {
	provider, model string
}

// BuildModelAssets derives the model/provider asset batch from one upstream
// snapshot. at is the import instant (lifecycle statuses are evaluated
// against at.LastSeen). Nil seams mean "plane absent": the remaining planes
// import alone, and an entirely empty upstream yields zero assets without
// error (the «пустое upstream» rule).
func BuildModelAssets(at Timestamps, orgID string, reg []RegistryModel, catalog ModelCatalogSource, pack PricingPack, prov *ReferenceProvenance) ([]Asset, []ModelImportSkip) {
	now := at.LastSeen

	registryByPair, registryProviders, skips := collectRegistryObservations(reg, catalog, now)
	catalogByPair, catalogProviders, catalogSkips := collectCatalogObservations(catalog, now)
	skips = append(skips, catalogSkips...)
	pricingByPair, pricingProviders, pricingSkips := collectPricingObservations(pack)
	skips = append(skips, pricingSkips...)
	withdrawn := withdrawnProviders(catalog)

	pairs := unionPairs(registryByPair, catalogByPair, pricingByPair)
	modelAssets, marshalSkips := modelAssetsForPairs(pairs, registryByPair, catalogByPair,
		pricingByPair, withdrawn, at, orgID, prov, now)
	skips = append(skips, marshalSkips...)
	providerAssetBatch, providerSkips := providerAssets(registryProviders, catalogProviders,
		pricingProviders, withdrawn, at, orgID, prov, now)
	skips = append(skips, providerSkips...)
	return append(modelAssets, providerAssetBatch...), skips
}

// collectRegistryObservations is the deployment side: registry rows, quoted
// verbatim and attributed through alias resolution to the canonical pair.
// Defective rows are skipped (counted), never fatal for healthy siblings.
func collectRegistryObservations(reg []RegistryModel, catalog ModelCatalogSource, now time.Time) (map[pairKey][]RegistryModelObservation, map[string]int, []ModelImportSkip) {
	byPair := map[pairKey][]RegistryModelObservation{}
	providers := map[string]int{}
	var skips []ModelImportSkip
	for _, m := range reg {
		if m.ModelName == "" || m.Provider == "" {
			skips = append(skips, ModelImportSkip{Plane: "registry", Ref: m.Provider + "/" + m.ModelName,
				Reason: "empty provider or model_name"})
			continue
		}
		if err := validKeyPart("model", m.ModelName); err != nil {
			skips = append(skips, ModelImportSkip{Plane: "registry", Ref: m.Provider + "/" + m.ModelName,
				Reason: "model_name fails key rules"})
			continue
		}
		k := pairKey{m.Provider, canonicalModelName(catalog, m, now)}
		byPair[k] = append(byPair[k], RegistryModelObservation{
			ModelName: m.ModelName, Tier: m.Tier, UpstreamURL: m.UpstreamURL, Enabled: m.Enabled,
		})
		providers[m.Provider]++
	}
	return byPair, providers, skips
}

// canonicalModelName attributes a registry row to its canonical pair: an
// alias that resolves to a non-empty name with a non-unknown status
// redirects the observation (exact names win, the ResolveAlias contract);
// everything else keeps the row's own name.
func canonicalModelName(catalog ModelCatalogSource, m RegistryModel, now time.Time) string {
	if catalog == nil {
		return m.ModelName
	}
	canonical, st := catalog.ResolveAlias(m.Provider, m.ModelName, now)
	if canonical == "" || st == provider.StatusUnknown {
		return m.ModelName
	}
	return canonical
}

// collectCatalogObservations is the reference side, catalog half. Entries
// are re-validated defensively (a constructed *provider.ModelCatalog already
// passed validation; a fixture or a future source may not). A duplicate pair
// keeps the first entry.
func collectCatalogObservations(catalog ModelCatalogSource, now time.Time) (map[pairKey]*CatalogModelObservation, map[string]int, []ModelImportSkip) {
	byPair := map[pairKey]*CatalogModelObservation{}
	providers := map[string]int{}
	var skips []ModelImportSkip
	var entries []provider.ModelCatalogEntry
	if catalog != nil {
		entries = catalog.Entries()
	}
	for _, e := range entries {
		if e.Provider == "" || e.Model == "" {
			skips = append(skips, ModelImportSkip{Plane: "catalog", Ref: e.Provider + "/" + e.Model,
				Reason: "empty provider or model"})
			continue
		}
		if err := validKeyPart("model", e.Model); err != nil {
			skips = append(skips, ModelImportSkip{Plane: "catalog", Ref: e.Provider + "/" + e.Model,
				Reason: "model name fails key rules"})
			continue
		}
		if reason := catalogEntryDefect(e); reason != "" {
			skips = append(skips, ModelImportSkip{Plane: "catalog", Ref: e.Provider + "/" + e.Model, Reason: reason})
			continue
		}
		k := pairKey{e.Provider, e.Model}
		if _, dup := byPair[k]; dup {
			skips = append(skips, ModelImportSkip{Plane: "catalog", Ref: e.Provider + "/" + e.Model,
				Reason: "duplicate entry for pair"})
			continue
		}
		byPair[k] = &CatalogModelObservation{
			Aliases:       append([]string(nil), e.Aliases...),
			Status:        modelStatusAt(e, now),
			EffectiveFrom: e.EffectiveFrom,
			EffectiveTo:   e.EffectiveTo,
			DeprecatedAt:  e.DeprecatedAt,
			Custom:        e.Custom,
		}
		sort.Strings(byPair[k].Aliases)
		providers[e.Provider]++
	}
	return byPair, providers, skips
}

// collectPricingObservations is the reference side, pricing half: many
// refpack rows merge into one observation per pair.
func collectPricingObservations(pack PricingPack) (map[pairKey]*PricingModelObservation, map[string]int, []ModelImportSkip) {
	byPair := map[pairKey]*PricingModelObservation{}
	providers := map[string]int{}
	var skips []ModelImportSkip
	var models []pricing.RefModel
	if pack != nil {
		models = pack.Models()
	}
	for _, rm := range models {
		if rm.Provider == "" || rm.Model == "" {
			skips = append(skips, ModelImportSkip{Plane: "pricing", Ref: rm.Provider + "/" + rm.Model,
				Reason: "empty provider or model"})
			continue
		}
		if err := validKeyPart("model", rm.Model); err != nil {
			skips = append(skips, ModelImportSkip{Plane: "pricing", Ref: rm.Provider + "/" + rm.Model,
				Reason: "model name fails key rules"})
			continue
		}
		k := pairKey{rm.Provider, rm.Model}
		po, seen := byPair[k]
		if !seen {
			po = &PricingModelObservation{}
			byPair[k] = po
			providers[rm.Provider]++ // rollups count pairs, not rows
		}
		mergeRefModel(po, rm)
	}
	return byPair, providers, skips
}

// mergeRefModel folds one refpack row into a pair's pricing observation.
func mergeRefModel(po *PricingModelObservation, rm pricing.RefModel) {
	po.Statuses = appendUniqueSorted(po.Statuses, rm.Status)
	po.Regions = appendUniqueSorted(po.Regions, rm.Region)
	po.Tiers = appendUniqueSorted(po.Tiers, rm.Tier)
	for _, a := range rm.Aliases {
		po.Aliases = appendUniqueSorted(po.Aliases, a)
	}
}

// withdrawnProviders reduces the catalog's provider withdrawals to the
// earliest instant per provider; malformed rows carry no signal and no asset
// noise.
func withdrawnProviders(catalog ModelCatalogSource) map[string]time.Time {
	withdrawn := map[string]time.Time{}
	if catalog == nil {
		return withdrawn
	}
	for _, w := range catalog.Withdrawals() {
		if w.Provider == "" || w.WithdrawnAt.IsZero() {
			continue
		}
		if prev, dup := withdrawn[w.Provider]; !dup || w.WithdrawnAt.Before(prev) {
			withdrawn[w.Provider] = w.WithdrawnAt
		}
	}
	return withdrawn
}

// providerWithdrawalAt reports a provider's withdrawal instant when it is
// already in effect at the import instant (a future withdrawal is not yet a
// fact).
func providerWithdrawalAt(withdrawn map[string]time.Time, name string, now time.Time) (time.Time, bool) {
	wd, ok := withdrawn[name]
	if !ok || now.Before(wd) {
		return time.Time{}, false
	}
	return wd, true
}

// unionPairs lists every pair any plane knows, in deterministic
// (provider, model) order.
func unionPairs(registry map[pairKey][]RegistryModelObservation,
	catalogByPair map[pairKey]*CatalogModelObservation,
	pricingByPair map[pairKey]*PricingModelObservation) []pairKey {
	seen := map[pairKey]bool{}
	pairs := make([]pairKey, 0, len(registry)+len(catalogByPair)+len(pricingByPair))
	for k := range registry {
		seen[k] = true
		pairs = append(pairs, k)
	}
	for k := range catalogByPair {
		if !seen[k] {
			seen[k] = true
			pairs = append(pairs, k)
		}
	}
	for k := range pricingByPair {
		if !seen[k] {
			seen[k] = true
			pairs = append(pairs, k)
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].provider != pairs[j].provider {
			return pairs[i].provider < pairs[j].provider
		}
		return pairs[i].model < pairs[j].model
	})
	return pairs
}

// modelAssetsForPairs builds one kind=model asset per known pair; a pair
// only the marshaler rejects lands as a skip instead of aborting the batch.
func modelAssetsForPairs(pairs []pairKey, registryByPair map[pairKey][]RegistryModelObservation,
	catalogByPair map[pairKey]*CatalogModelObservation, pricingByPair map[pairKey]*PricingModelObservation,
	withdrawn map[string]time.Time, at Timestamps, orgID string, prov *ReferenceProvenance,
	now time.Time) ([]Asset, []ModelImportSkip) {
	var assets []Asset
	var skips []ModelImportSkip
	for _, k := range pairs {
		p, ok := assembleModelPayload(k, registryByPair[k], catalogByPair[k], pricingByPair[k],
			withdrawn, prov, now)
		if !ok {
			continue
		}
		payload, err := json.Marshal(p)
		if err != nil { // unreachable for all-scalar payloads; still never fatal
			skips = append(skips, ModelImportSkip{Plane: "catalog", Ref: k.provider + "/" + k.model,
				Reason: "payload marshal: " + err.Error()})
			continue
		}
		assets = append(assets, Asset{
			OrgID: orgID, AssetKey: ModelKey(k.provider, k.model), Kind: KindModel,
			Payload: payload, Source: modelAssetSource(len(registryByPair[k]) > 0),
			Confidence: ConfidenceHigh, FirstSeen: at.FirstSeen, LastSeen: at.LastSeen,
		})
	}
	return assets, skips
}

// assembleModelPayload merges the three plane observations of one pair into
// its registry payload. The sides stay disjoint sections: no field of one
// side is derived from another (W03-C02).
func assembleModelPayload(k pairKey, regObs []RegistryModelObservation, catObs *CatalogModelObservation,
	priceObs *PricingModelObservation, withdrawn map[string]time.Time, prov *ReferenceProvenance,
	now time.Time) (ModelPayload, bool) {
	registryKnown := len(regObs) > 0
	referenceKnown := catObs != nil || priceObs != nil
	if !registryKnown && !referenceKnown {
		return ModelPayload{}, false // unreachable given the union construction
	}
	p := ModelPayload{Provider: k.provider, Model: k.model}
	p.Status, p.WithdrawnAt, p.DeprecatedAt = modelStatusFields(k.provider, catObs, withdrawn, now)
	if catObs != nil {
		p.Catalog = catObs
		p.Aliases = append(p.Aliases, catObs.Aliases...)
	}
	if priceObs != nil {
		p.Pricing = priceObs
		p.Aliases = append(p.Aliases, priceObs.Aliases...)
	}
	if registryKnown {
		sort.Slice(regObs, func(i, j int) bool { return regObs[i].ModelName < regObs[j].ModelName })
		p.Registry = regObs
	}
	p.Aliases = dedupeSorted(p.Aliases)
	p.Discrepancy = pairDiscrepancy(registryKnown, referenceKnown)
	p.Provenance = prov
	return p, true
}

// modelStatusFields derives the payload lifecycle at import time: the
// catalog's status when the lifecycle plane knows the pair (pricing alone
// leaves "unknown"), overridden by an in-effect provider withdrawal, with
// the in-effect deprecation instant carried even then.
func modelStatusFields(providerName string, catObs *CatalogModelObservation, withdrawn map[string]time.Time, now time.Time) (status string, withdrawnAt, deprecatedAt *time.Time) {
	status = "unknown"
	if catObs != nil {
		status = catObs.Status
	}
	if wd, inEffect := providerWithdrawalAt(withdrawn, providerName, now); inEffect {
		status = "withdrawn"
		t := wd.UTC()
		withdrawnAt = &t
	}
	if catObs != nil && !catObs.DeprecatedAt.IsZero() && !now.Before(catObs.DeprecatedAt) {
		t := catObs.DeprecatedAt.UTC()
		deprecatedAt = &t
	}
	return status, withdrawnAt, deprecatedAt
}

// pairDiscrepancy flags pairs exactly one side knows (registry = deployment,
// catalog+pricing = reference); both or neither means no flag.
func pairDiscrepancy(registryKnown, referenceKnown bool) string {
	switch {
	case registryKnown && !referenceKnown:
		return "registry_only"
	case !registryKnown && referenceKnown:
		return "reference_only"
	}
	return ""
}

// providerAssets builds one kind=provider asset per provider seen on either
// side, plus withdrawal-only providers (no models at all — W03-C03).
func providerAssets(registryProviders, catalogProviders, pricingProviders map[string]int,
	withdrawn map[string]time.Time, at Timestamps, orgID string, prov *ReferenceProvenance,
	now time.Time) ([]Asset, []ModelImportSkip) {
	var assets []Asset
	var skips []ModelImportSkip
	for _, name := range providerNameUnion(registryProviders, catalogProviders, pricingProviders, withdrawn) {
		pp := ProviderPayload{Provider: name, Status: "active",
			RegistryModels: registryProviders[name],
			CatalogModels:  catalogProviders[name],
			PricingModels:  pricingProviders[name],
			Provenance:     prov,
		}
		if wd, inEffect := providerWithdrawalAt(withdrawn, name, now); inEffect {
			pp.Status = "withdrawn"
			t := wd.UTC()
			pp.WithdrawnAt = &t
		}
		pp.Discrepancy = pairDiscrepancy(pp.RegistryModels > 0, pp.CatalogModels > 0 || pp.PricingModels > 0)
		payload, err := json.Marshal(pp)
		if err != nil { // unreachable for all-scalar payloads; still never fatal
			skips = append(skips, ModelImportSkip{Plane: "catalog", Ref: name,
				Reason: "payload marshal: " + err.Error()})
			continue
		}
		assets = append(assets, Asset{
			OrgID: orgID, AssetKey: ProviderKey(name), Kind: KindProvider,
			Payload: payload, Source: modelAssetSource(pp.RegistryModels > 0),
			Confidence: ConfidenceHigh, FirstSeen: at.FirstSeen, LastSeen: at.LastSeen,
		})
	}
	return assets, skips
}

// providerNameUnion is the sorted set of providers any plane (including
// withdrawals) vouches for.
func providerNameUnion(registry, catalogProviders, pricing map[string]int, withdrawn map[string]time.Time) []string {
	names := map[string]bool{}
	for name := range registry {
		names[name] = true
	}
	for name := range catalogProviders {
		names[name] = true
	}
	for name := range pricing {
		names[name] = true
	}
	for name := range withdrawn {
		names[name] = true
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// modelAssetSource picks the provenance source: the deployment registry
// vouches for existence when it knows the identity; otherwise the reference
// side does.
func modelAssetSource(registryKnown bool) Source {
	if registryKnown {
		return SourceModelsRegistry
	}
	return SourceModelCatalog
}

// modelStatusAt classifies one catalog entry at the import instant onto the
// registry's status vocabulary (catalog retired → withdrawn).
func modelStatusAt(e provider.ModelCatalogEntry, at time.Time) string {
	switch {
	case !e.EffectiveFrom.IsZero() && at.Before(e.EffectiveFrom):
		return "pending"
	case !e.EffectiveTo.IsZero() && !at.Before(e.EffectiveTo):
		return "withdrawn" // window closed: still an asset, never deleted
	case !e.DeprecatedAt.IsZero() && !at.Before(e.DeprecatedAt):
		return "deprecated"
	default:
		return "active"
	}
}

// catalogEntryDefect re-validates one raw entry the way the catalog
// constructor would (the validateDeprecation pattern, modelcatalog.go:338):
// a deprecation instant outside the observable sell window is a defect. The
// builder skips defective entries instead of aborting the org import.
func catalogEntryDefect(e provider.ModelCatalogEntry) string {
	if e.DeprecatedAt.IsZero() {
		return ""
	}
	if !e.EffectiveFrom.IsZero() && e.DeprecatedAt.Before(e.EffectiveFrom) {
		return "deprecation instant precedes the sell window opening"
	}
	if !e.EffectiveTo.IsZero() && !e.DeprecatedAt.Before(e.EffectiveTo) {
		return "deprecation instant is not before the sell window closing"
	}
	return ""
}

func appendUniqueSorted(list []string, v string) []string {
	if v == "" {
		return list
	}
	i := sort.SearchStrings(list, v)
	if i < len(list) && list[i] == v {
		return list
	}
	list = append(list, "")
	copy(list[i+1:], list[i:])
	list[i] = v
	return list
}

func dedupeSorted(list []string) []string {
	sort.Strings(list)
	out := list[:0]
	for i, v := range list {
		if i == 0 || v != list[i-1] {
			out = append(out, v)
		}
	}
	return out
}
