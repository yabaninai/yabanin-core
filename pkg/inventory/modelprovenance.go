package inventory

// E02-P01 W03-C02: reference provenance, discrepancy surfacing and the
// org-scoped model import runner.
//
// Provenance: every reference-side observation quotes the exact snapshot it
// came from — the model catalog's Version/Source and the pricing refpack's
// Version/GeneratedAt/Digest (pricing.Catalog.Digest is recomputed by
// LoadRefPack over actual content, never trusted from the envelope). The
// block is fixed on each model/provider asset and repeated in the pass
// report, so any later read can answer "which versions produced this row".
//
// Re-import stability: an import pass over the same upstream snapshot with
// a fixed clock yields Created=0/Updated=0/Unchanged=N — the payload bytes
// are a pure function of (upstream snapshot, versions, clock). A version
// bump (new catalog Version or new pack Version/Digest) changes payloads
// and counts as Updated — the report journal records which versions ran.
//
// Discrepancy trigger: BuildModelAssets flags each pair known to exactly
// one side (registry_only / reference_only, modelimport.go); this file
// carries the flag through to the report so the admin surface can surface
// drift without a second read of the assets. Flags never block the import:
// a disagreement between the deployment registry and the reference side is
// an observation, not an error.
//
// Empty-org refusal (obligation ②, E01-P04 trigger context; binding at the
// wiring/mount card per the batch A review, seams carrying it meanwhile):
// Run refuses an empty org the way Store.ListAssets does (store.go:255) —
// org materialization is explicit, never a global write.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// ErrOrgRequired refuses org-scoped operations without an org (obligation ②:
// readers and importers never silently operate on a missing org scope).
var ErrOrgRequired = errors.New("inventory: org_id is required")

// ErrNilRegistrySource marks a wiring defect (nil models_registry seam).
var ErrNilRegistrySource = errors.New("inventory: nil models registry source")

// loadedPack adapts a validated pricing.Catalog to the PricingPack seam.
type loadedPack struct {
	meta   PricingMeta
	models []pricing.RefModel
}

func (p *loadedPack) Meta() PricingMeta          { return p.meta }
func (p *loadedPack) Models() []pricing.RefModel { return p.models }

var (
	bundledPackOnce sync.Once
	bundledPack     PricingPack
	bundledPackErr  error
)

// BundledPricingPack loads the embedded bundled refpack
// (pricing.BundledRefPackJSON, refcatalog_meta.go:34) exactly once and
// adapts it to the PricingPack seam. The digest is recomputed by
// pricing.LoadRefPack over the actual content; a corrupt bundle is an
// error, never a silent empty pack.
func BundledPricingPack() (PricingPack, error) {
	bundledPackOnce.Do(func() {
		_, cat, err := pricing.LoadRefPack(pricing.BundledRefPackJSON())
		if err != nil {
			bundledPackErr = err
			return
		}
		bundledPack = &loadedPack{meta: PricingMeta{
			Version:     cat.Version,
			GeneratedAt: cat.GeneratedAt,
			Digest:      cat.Digest,
		}, models: cat.Models}
	})
	return bundledPack, bundledPackErr
}

// BuildReferenceProvenance assembles the source-version block from the
// reference seams (nil seams contribute nothing).
func BuildReferenceProvenance(catalog ModelCatalogSource, pack PricingPack) *ReferenceProvenance {
	prov := &ReferenceProvenance{}
	if catalog != nil {
		m := catalog.Meta()
		prov.CatalogVersion = m.Version
		prov.CatalogSource = m.Source
	}
	if pack != nil {
		m := pack.Meta()
		prov.PricingVersion = m.Version
		prov.PricingAsOf = m.GeneratedAt
		prov.PricingDigest = m.Digest
	}
	return prov
}

// ModelImportReport is the outcome of one model import pass: the store
// counts, the skipped entries (never silent), the per-side pair counts and
// the versions journal (which snapshots produced the pass).
type ModelImportReport struct {
	Counts         ImportCounts
	Skips          []ModelImportSkip
	Models         int
	Providers      int
	Discrepancies  int // pairs flagged registry_only or reference_only
	CatalogVersion string
	PricingVersion string
	PricingDigest  string
	PricingAsOf    string
}

// ModelImportRunner drives model/provider import passes for one org.
type ModelImportRunner struct {
	store    *Store
	registry ModelRegistrySource
	catalog  ModelCatalogSource // may be nil: registry-only import
	pack     PricingPack        // may be nil: no pricing plane
	now      func() time.Time
}

// NewModelImportRunner wires the runner. The registry source is required
// (the deployment side is the import's subject); the reference seams are
// optional and default to the process catalog / bundled pack when nil is
// passed as "unset" is expressed by explicit nil at Run configuration
// time — here nil means "no such plane installed".
func NewModelImportRunner(store *Store, registry ModelRegistrySource, catalog ModelCatalogSource, pack PricingPack) (*ModelImportRunner, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	if registry == nil {
		return nil, ErrNilRegistrySource
	}
	return &ModelImportRunner{store: store, registry: registry, catalog: catalog, pack: pack,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// Run executes one import pass for the org: read the three planes, build
// the canonical batch, upsert. The GLOBAL registry read is materialized
// per-org into the org's asset rows (each org gets its own copy of the
// shared reference knowledge); an empty registry snapshot is a no-op pass,
// never a wipe — the registry only grows through imports and shrinks only
// through tombstones (W01 semantics).
func (r *ModelImportRunner) Run(ctx context.Context, orgID string) (*ModelImportReport, error) {
	if orgID == "" {
		return nil, ErrOrgRequired
	}
	reg, err := r.registry.ListRegistryModels(ctx)
	if err != nil {
		return nil, err
	}
	now := r.now()
	at := Timestamps{FirstSeen: now, LastSeen: now}
	prov := BuildReferenceProvenance(r.catalog, r.pack)
	assets, skips := BuildModelAssets(at, orgID, reg, r.catalog, r.pack, prov)

	report := &ModelImportReport{Skips: skips}
	if r.catalog != nil {
		report.CatalogVersion = prov.CatalogVersion
	}
	if r.pack != nil {
		report.PricingVersion = prov.PricingVersion
		report.PricingDigest = prov.PricingDigest
		report.PricingAsOf = prov.PricingAsOf
	}
	for _, a := range assets {
		switch a.Kind {
		case KindModel:
			report.Models++
			var p ModelPayload
			if json.Unmarshal(a.Payload, &p) == nil && p.Discrepancy != "" {
				report.Discrepancies++
			}
		case KindProvider:
			report.Providers++
		}
	}
	if len(assets) > 0 {
		counts, err := r.store.UpsertAssets(ctx, assets)
		if err != nil {
			return nil, err
		}
		report.Counts = counts
	}
	return report, nil
}
