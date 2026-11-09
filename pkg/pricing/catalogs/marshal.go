package catalogs

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// MarshalCatalog renders the catalog as deterministic sealed JSON: the
// schema's canonical ordering applied to a deep copy, the digest computed
// over that canonical form, compact encoding, one trailing newline.
//
// Determinism contract: identical content produces byte-identical output —
// nothing here reads the clock, the environment or any map iteration order.
// This is the byte format of the committed pin
// (pkg/pricing/catalogs/reference-catalog-v1.json); REF-03's pack envelope
// can lift the body verbatim.
//
// The input catalog is not modified (Catalog is read-only after validation;
// marshaling must not be an exception).
func MarshalCatalog(c pricing.Catalog) ([]byte, error) {
	sealed, err := pricing.SealCatalog(cloneSortedCatalog(c))
	if err != nil {
		return nil, fmt.Errorf("marshal reference catalog: %w", err)
	}
	b, err := json.Marshal(sealed)
	if err != nil {
		return nil, fmt.Errorf("marshal reference catalog: %w", err)
	}
	return append(b, '\n'), nil
}

// LoadCatalog parses sealed catalog bytes and verifies them fail-closed:
// the digest field must be present (digest-stripped or otherwise unsealed
// input is refused outright, before any validation), and the digest is
// recomputed over the actual canonical content and compared, so any
// content tampering — with or without the digest field kept — is refused
// instead of trusted. Validation is the full CORE-REF-01 pass.
func LoadCatalog(b []byte) (pricing.Catalog, error) {
	var c pricing.Catalog
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&c); err != nil {
		return pricing.Catalog{}, fmt.Errorf("parse reference catalog: %w", err)
	}
	// Frozen ValidateCatalog only verifies a digest that is present; a
	// stripped digest would load unverified. The loader contract is
	// fail-closed: no digest field, no catalog.
	if c.Digest == "" {
		return pricing.Catalog{}, fmt.Errorf("reference catalog: digest field missing: bytes without a sealed digest are refused, not trusted")
	}
	if err := pricing.ValidateCatalog(c); err != nil {
		return pricing.Catalog{}, fmt.Errorf("reference catalog: %w", err)
	}
	return c, nil
}

// VerifyChain verifies that next may replace prev: both snapshots must
// validate, and next.Supersedes must equal prev's actual digest. This is
// the rollback-chain check a loader runs when switching snapshots — a chain
// break means the "previous" snapshot is not the one next claims to
// replace, and switching (or rolling back) would silently rewrite history.
func VerifyChain(prev, next pricing.Catalog) error {
	if err := pricing.ValidateCatalog(prev); err != nil {
		return fmt.Errorf("catalog chain: previous snapshot invalid: %w", err)
	}
	if err := pricing.ValidateCatalog(next); err != nil {
		return fmt.Errorf("catalog chain: next snapshot invalid: %w", err)
	}
	return pricing.ValidateCatalogChain(prev, next)
}

// cloneSortedCatalog deep-copies c and applies the canonical ordering.
// The sort helpers reassign per-entry slices on the copy only.
func cloneSortedCatalog(c pricing.Catalog) pricing.Catalog {
	out := c
	out.Models = make([]pricing.RefModel, len(c.Models))
	for i := range c.Models {
		m := c.Models[i]
		m.Aliases = append([]string(nil), m.Aliases...)
		m.Rates = make([]pricing.RefRate, len(c.Models[i].Rates))
		for j := range c.Models[i].Rates {
			r := c.Models[i].Rates[j]
			r.Evidence = append([]pricing.RefEvidence(nil), c.Models[i].Rates[j].Evidence...)
			m.Rates[j] = r
		}
		m.Sources = append([]pricing.RefSource(nil), c.Models[i].Sources...)
		m.Conflicts = append([]pricing.RefConflict(nil), c.Models[i].Conflicts...)
		out.Models[i] = m
	}
	sortCatalogModels(out.Models)
	return out
}
