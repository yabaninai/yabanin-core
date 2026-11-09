package pricing

import (
	"bytes"
	"fmt"
	"time"
)

// Process-boundary metadata for the rates
// catalog surfaces (GET /api/rates/catalog, POST /api/rates/promote).
//
// The admin handler layer must not reach into package-private state, and the
// serving-flip machinery (catalogServeSource / projectServeable / the catalog
// citation) lives in refserve.go as unexported functions. This file is the
// same-package shim that exposes exactly two capabilities:
//
//   - BundledRefPackJSON: the committed reference pack bytes — the chain
//     anchor every promotion verifies against;
//   - ServeCatalogFromPack: build a serving pricer from arbitrary pack
//     bytes, with byte-for-byte the same serveability gates as
//     LoadBundledRefServe;
//   - ProjectionFromPack: the serveable PriceFile a pack seats, without
//     building a pricer — the planning input for the durable promotion's
//     models_pricing materialization.
//
// refserve.go stays untouched: LoadBundledRefServe remains the canonical
// entry point for the embedded pack, and this shim mirrors its body instead
// of refactoring it. The lockstep is pinned by
// TestServeCatalogFromPackMatchesBundledServe in refcatalog_meta_test.go.

// BundledRefPackJSON returns a copy of the embedded committed reference pack
// bytes. Callers may treat the result as read-only input: mutations of the
// returned slice cannot reach the embedded original.
func BundledRefPackJSON() []byte {
	return bytes.Clone(bundledRefPackBytes)
}

// ServeCatalogFromPack loads pack bytes, projects the serveable catalog
// entries at process time, and wraps them in a FilePricer citing the catalog
// label — the same gates and the same citation as LoadBundledRefServe. It is
// the supported way to seat a different pack as the process pricer
// (SetDefaultFilePricer callers, e.g. the rates-catalog promotion handler).
func ServeCatalogFromPack(packJSON []byte) (*FilePricer, error) {
	_, cat, err := LoadRefPack(packJSON)
	if err != nil {
		return nil, fmt.Errorf("reference pack: %w", err)
	}
	source, date, err := catalogServeSource(cat)
	if err != nil {
		return nil, fmt.Errorf("reference catalog %s: %w", cat.Version, err)
	}
	pf, err := projectServeable(cat, time.Now().UTC())
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

// ProjectionFromPack returns the serveable PriceFile projection of the pack
// — byte-for-byte the projection ServeCatalogFromPack seats into its
// pricer — without building or seating a pricer. The durable rates
// promotion plans the models_pricing materialization against exactly this
// projection (PlanCatalogFromPack), so the materialized table can never
// diverge from the prices a pack-seated pricer serves. Same load + gates as
// ServeCatalogFromPack: invalid or unservable packs are errors.
func ProjectionFromPack(packJSON []byte) (PriceFile, error) {
	_, cat, err := LoadRefPack(packJSON)
	if err != nil {
		return PriceFile{}, fmt.Errorf("reference pack: %w", err)
	}
	source, date, err := catalogServeSource(cat)
	if err != nil {
		return PriceFile{}, fmt.Errorf("reference catalog %s: %w", cat.Version, err)
	}
	pf, err := projectServeable(cat, time.Now().UTC())
	if err != nil {
		return PriceFile{}, fmt.Errorf("reference catalog %s: %w", cat.Version, err)
	}
	pf.Source = source
	pf.Date = date
	return pf, nil
}
