package pricing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CORE-REF-03: reference pack envelope, deterministic encoder, verifier,
// chain check and review diff (plans/enterprise-beta-next-5000h/
// REFERENCE-MATERIALS-AUDIT.md, card CORE-REF-03; contract
// artifacts/internal-delivery-program/PREP/COREREF-03/prep-20261101.md §2–§4).
//
// The pin is committed bytes (pkg/pricing/snapshots/reference-pack-v1.json);
// the digest is the pin, the Supersedes chain is the history. Loaders
// verify, never trust. The default build/run path never touches the
// network: everything here runs on pure []byte (hermetic by construction).

// RefPackSchemaVersion is the pack envelope version. A change to the
// envelope layout (not the catalog vocabulary) bumps this constant and is
// a breaking loader change by definition.
const RefPackSchemaVersion = 1

// RefPack is the JSON envelope that pins one reference catalog snapshot
// (PREP/COREREF-03 §2.1):
//
//	{
//	  "pack_schema_version": 1,
//	  "catalog": { ...sealed Catalog v1 body, canonical form, verbatim... },
//	  "catalog_digest": "<64-hex, == CatalogDigest == catalog.digest>",
//	  "pack_sha256":    "<64-hex, SHA256 over the envelope bytes with this
//	                     field present and empty>",
//	  "notices":        ["pkg/pricing/NOTICE-litellm.txt", ...]
//	}
//
// Field order is fixed by this struct declaration and is part of the byte
// format; no Go maps are marshaled anywhere in the envelope, so identical
// inputs yield byte-identical envelopes (mutation-pinned by
// TestRefPackDeterministicBytes).
type RefPack struct {
	// PackSchemaVersion guards the envelope layout (independent of the
	// catalog schema version).
	PackSchemaVersion int `json:"pack_schema_version"`
	// Catalog is the sealed catalog body lifted verbatim in canonical
	// form (json.RawMessage so the REF-02 pinned bytes survive untouched).
	Catalog json.RawMessage `json:"catalog"`
	// CatalogDigest must equal both the recomputed CatalogDigest of the
	// body and the body's own digest field.
	CatalogDigest string `json:"catalog_digest"`
	// PackSHA256 is the SHA256 of the envelope bytes with this field
	// marshaled as "". Computed by MarshalRefPack, verified by LoadRefPack.
	PackSHA256 string `json:"pack_sha256"`
	// Notices lists notice-file refs that must keep shipping while
	// converted/vendored content remains (e.g. NOTICE-litellm.txt).
	// Sorted and deduplicated at build time.
	Notices []string `json:"notices,omitempty"`
}

// errUnsealedCatalog is the fail-closed refusal for digest-less input:
// absent verification is not verification (the loader contract in
// pkg/pricing/catalogs refuses it the same way).
var errUnsealedCatalog = errors.New("catalog is not sealed (digest empty); seal with pricing.SealCatalog first")

// BuildRefPack assembles a pack envelope from sealed catalog JSON. The
// input must already carry a digest and pass full validation (fail-closed,
// like the loader); the body is canonicalized before embedding so permuted
// input order cannot change the pack bytes. Notices are sorted and
// deduplicated. Pure bytes-in: no clock, no environment, no I/O.
func BuildRefPack(catalogJSON []byte, notices []string) (*RefPack, error) {
	c, err := parseSealedCatalog(catalogJSON)
	if err != nil {
		return nil, fmt.Errorf("build ref pack: %w", err)
	}
	// Canonical body with the seal preserved: the digest excludes itself
	// (canonicalizeCatalog blanks it), so restore the sealed value before
	// encoding. Canonicalization sorts models/aliases/rates/evidence/
	// sources/conflicts — the same ordering the digest was computed over.
	n := canonicalizeCatalog(c)
	n.Digest = c.Digest
	body, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("build ref pack: canonical body: %w", err)
	}
	normalized := normalizeNotices(notices)
	return &RefPack{
		PackSchemaVersion: RefPackSchemaVersion,
		Catalog:           body,
		CatalogDigest:     c.Digest,
		Notices:           normalized,
	}, nil
}

// MarshalRefPack renders the pack as deterministic envelope bytes: field
// order fixed by the struct, pack_sha256 computed over the envelope with
// the field present and empty, compact encoding. Notices are normalized
// (sorted, deduplicated) into the emitted bytes — the sealed envelope is
// exactly the normalized open form with the digest filled in, so
// MarshalRefPack output round-trips through LoadRefPack for any caller
// input, and notice order cannot leak into the envelope bytes (AUD-PRICE-02).
// On success the input pack's PackSHA256 field is set to the computed
// digest; the returned bytes always carry it.
func MarshalRefPack(p *RefPack) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("marshal ref pack: nil pack")
	}
	if p.PackSchemaVersion != RefPackSchemaVersion {
		return nil, fmt.Errorf("marshal ref pack: pack_schema_version must be %d, got %d", RefPackSchemaVersion, p.PackSchemaVersion)
	}
	if !isDigestHex(p.CatalogDigest) {
		return nil, fmt.Errorf("marshal ref pack: catalog_digest must be a 64-hex digest, got %q", p.CatalogDigest)
	}
	open := *p
	open.PackSHA256 = ""
	open.Notices = normalizeNotices(p.Notices)
	b, err := json.Marshal(open)
	if err != nil {
		return nil, fmt.Errorf("marshal ref pack: %w", err)
	}
	sum := sha256.Sum256(b)
	// Seal the SAME normalized form the digest was computed over — sealing
	// the caller's unnormalized struct here would make the envelope
	// unverifiable by its own pack_sha256 whenever notices arrived unsorted.
	open.PackSHA256 = hex.EncodeToString(sum[:])
	p.PackSHA256 = open.PackSHA256
	sealed, err := json.Marshal(open)
	if err != nil {
		return nil, fmt.Errorf("marshal ref pack: %w", err)
	}
	return sealed, nil
}

// LoadRefPack parses and verifies pack envelope bytes fail-closed, running
// all three independent checks (PREP/COREREF-03 §3): the envelope
// pack_sha256, the catalog digest (recomputed over the actual content, not
// trusted), and the full schema validation pass. Any mismatch is an error
// listing the expected vs actual values — never a warning. Pure bytes-in:
// no files, no network, no environment.
func LoadRefPack(b []byte) (*RefPack, Catalog, error) {
	var p RefPack
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&p); err != nil {
		return nil, Catalog{}, fmt.Errorf("parse ref pack: %w", err)
	}
	if p.PackSchemaVersion != RefPackSchemaVersion {
		return nil, Catalog{}, fmt.Errorf("ref pack: pack_schema_version must be %d, got %d", RefPackSchemaVersion, p.PackSchemaVersion)
	}
	if p.PackSHA256 == "" {
		return nil, Catalog{}, fmt.Errorf("ref pack: pack_sha256 missing: an envelope without its digest is refused, not trusted")
	}
	open := p
	open.PackSHA256 = ""
	openBytes, err := json.Marshal(open)
	if err != nil {
		return nil, Catalog{}, fmt.Errorf("ref pack: envelope digest: %w", err)
	}
	sum := sha256.Sum256(openBytes)
	got := hex.EncodeToString(sum[:])
	if got != p.PackSHA256 {
		return nil, Catalog{}, fmt.Errorf("ref pack: pack_sha256 mismatch: envelope digests to %s but pack_sha256 declares %s", got, p.PackSHA256)
	}
	if p.CatalogDigest == "" {
		return nil, Catalog{}, fmt.Errorf("ref pack: catalog_digest missing: an envelope without the catalog digest is refused, not trusted")
	}
	c, err := parseSealedCatalog(p.Catalog)
	if err != nil {
		return nil, Catalog{}, fmt.Errorf("ref pack: catalog body: %w", err)
	}
	if c.Digest != p.CatalogDigest {
		return nil, Catalog{}, fmt.Errorf("ref pack: catalog_digest mismatch: body digests to %s but catalog_digest declares %s", c.Digest, p.CatalogDigest)
	}
	return &p, c, nil
}

// VerifyRefPackChain verifies that the next pack may replace the previous
// one: both envelopes must pass every LoadRefPack check, and the schema
// chain rule must hold (next.Supersedes == actual digest of prev). Rolling
// back is loading the previous pack again — the chain stays verifiable in
// that direction too, because the link is a fact about the pair, not about
// which snapshot is currently served.
func VerifyRefPackChain(prevPackJSON, nextPackJSON []byte) error {
	_, prev, err := LoadRefPack(prevPackJSON)
	if err != nil {
		return fmt.Errorf("catalog chain: previous pack: %w", err)
	}
	_, next, err := LoadRefPack(nextPackJSON)
	if err != nil {
		return fmt.Errorf("catalog chain: next pack: %w", err)
	}
	return ValidateCatalogChain(prev, next)
}

// parseSealedCatalog parses catalog JSON and refuses unsealed or invalid
// input fail-closed: no digest field, no catalog (mirrors the
// pkg/pricing/catalogs loader contract; kept here because the pack must
// not depend on that package).
func parseSealedCatalog(b []byte) (Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return Catalog{}, fmt.Errorf("parse catalog: %w", err)
	}
	if c.Digest == "" {
		return Catalog{}, errUnsealedCatalog
	}
	if err := ValidateCatalog(c); err != nil {
		return Catalog{}, fmt.Errorf("catalog validation: %w", err)
	}
	return c, nil
}

// normalizeNotices sorts and deduplicates notice refs so operator input
// order cannot leak into the envelope bytes.
func normalizeNotices(in []string) []string {
	clean := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		clean = append(clean, s)
	}
	sort.Strings(clean)
	out := clean[:0]
	var prev string
	for i, s := range clean {
		if i > 0 && s == prev {
			continue
		}
		prev = s
		out = append(out, s)
	}
	return out
}

// packModelIdentity is the canonical identity of one catalog entry
// (provider, model, region, tier, context_band — the merge/identity rule
// from REF-01).
type packModelIdentity struct{ provider, model, region, tier, contextBand string }

func modelIdentity(m *RefModel) packModelIdentity {
	return packModelIdentity{m.Provider, m.Model, m.Region, m.Tier, m.ContextBand}
}

// identityLess is the canonical identity ordering (same key order the
// digest canonicalization uses).
func identityLess(a, b packModelIdentity) bool {
	if a.provider != b.provider {
		return a.provider < b.provider
	}
	if a.model != b.model {
		return a.model < b.model
	}
	if a.region != b.region {
		return a.region < b.region
	}
	if a.tier != b.tier {
		return a.tier < b.tier
	}
	return a.contextBand < b.contextBand
}

// RefDiff renders the deterministic review diff between two sealed catalog
// snapshots: entries in canonical identity order, axes in canonical rank
// order, byte-identical output for identical inputs. It refuses to bless a
// draft→active promotion whose target entry lacks a reviewer or primary
// sources (the review diff is the review gate — it never auto-promotes;
// promotions missing sources are additionally refused by schema validation
// at load time).
func RefDiff(oldJSON, newJSON []byte) (string, error) {
	oldCat, err := parseSealedCatalog(oldJSON)
	if err != nil {
		return "", fmt.Errorf("ref diff: old snapshot: %w", err)
	}
	newCat, err := parseSealedCatalog(newJSON)
	if err != nil {
		return "", fmt.Errorf("ref diff: new snapshot: %w", err)
	}
	if err := refDiffPromotionGate(&oldCat, &newCat); err != nil {
		return "", err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "ref-diff: %s (%s) -> %s (%s)\n", oldCat.Version, shortDigest(oldCat.Digest), newCat.Version, shortDigest(newCat.Digest))

	oldByID := refCatalogByID(&oldCat)
	newByID := refCatalogByID(&newCat)
	ids := refUnionIdentities(&oldCat, &newCat)
	added, removed, changed := refDiffRenderEntries(&sb, ids, oldByID, newByID)
	fmt.Fprintf(&sb, "summary: added=%d removed=%d changed=%d unchanged=%d\n", added, removed, changed, len(ids)-added-removed-changed)
	return sb.String(), nil
}

// refDiffPromotionGate is the review gate RefDiff runs before any
// rendering: a draft→active promotion needs a reviewer and primary sources
// on the promoted entry. Validation already refuses active-without-sources
// at load; the reviewer gate is the diff's own stricter check.
func refDiffPromotionGate(oldCat, newCat *Catalog) error {
	for i := range newCat.Models {
		nm := &newCat.Models[i]
		if nm.Status != RefStatusActive {
			continue
		}
		om := findRefModel(oldCat, modelIdentity(nm))
		if om == nil || om.Status != RefStatusDraft {
			continue
		}
		if strings.TrimSpace(nm.Reviewer) == "" {
			return fmt.Errorf("ref diff: refusing draft→active promotion of %s/%s: no reviewer recorded; the review diff never auto-promotes", nm.Provider, nm.Model)
		}
		if len(nm.Sources) == 0 {
			return fmt.Errorf("ref diff: refusing draft→active promotion of %s/%s: no primary sources recorded", nm.Provider, nm.Model)
		}
	}
	return nil
}

// refCatalogByID indexes a catalog's entries by canonical identity.
func refCatalogByID(c *Catalog) map[packModelIdentity]*RefModel {
	byID := make(map[packModelIdentity]*RefModel, len(c.Models))
	for i := range c.Models {
		byID[modelIdentity(&c.Models[i])] = &c.Models[i]
	}
	return byID
}

// refUnionIdentities returns the sorted union of both catalogs' identities.
// Built from the slices and sorted canonically, so no map iteration order
// can reach the output path.
func refUnionIdentities(oldCat, newCat *Catalog) []packModelIdentity {
	ids := make([]packModelIdentity, 0, len(oldCat.Models)+len(newCat.Models))
	seen := make(map[packModelIdentity]struct{}, cap(ids))
	for _, cat := range []*Catalog{oldCat, newCat} {
		for i := range cat.Models {
			id := modelIdentity(&cat.Models[i])
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool { return identityLess(ids[i], ids[j]) })
	return ids
}

// refDiffRenderEntries writes one line per added, removed or changed
// identity — in the given canonical order — and returns the three summary
// counts. Unchanged identities render nothing.
func refDiffRenderEntries(sb *strings.Builder, ids []packModelIdentity, oldByID, newByID map[packModelIdentity]*RefModel) (added, removed, changed int) {
	for _, id := range ids {
		om, nm := oldByID[id], newByID[id]
		label := id.provider + "/" + id.model
		switch {
		case om == nil:
			added++
			fmt.Fprintf(sb, "ADDED %s\n", label)
		case nm == nil:
			removed++
			fmt.Fprintf(sb, "REMOVED %s\n", label)
		default:
			if line := modelDiffLine(om, nm); line != "" {
				changed++
				fmt.Fprintf(sb, "CHANGED %s\n%s", label, line)
			}
		}
	}
	return added, removed, changed
}

// modelDiffLine renders the field-level changes of one entry in fixed
// order (status, then rates in canonical axis rank), or "" when unchanged.
// AUD-PRICE-02: the operator-visible review facts — entry verified_at, the
// alias set, and the primary-source ref set — are rendered too. A same-count
// source swap is as visible as an added one; the sets are compared and
// rendered in sorted order so input ordering cannot change the diff.
func modelDiffLine(om, nm *RefModel) string {
	var sb strings.Builder
	if om.Status != nm.Status {
		fmt.Fprintf(&sb, "  status: %s -> %s\n", om.Status, nm.Status)
	}
	if om.VerifiedAt != nm.VerifiedAt {
		fmt.Fprintf(&sb, "  verified_at: %s -> %s\n", displayEmpty(om.VerifiedAt), displayEmpty(nm.VerifiedAt))
	}
	if om.Currency != nm.Currency {
		fmt.Fprintf(&sb, "  currency: %s -> %s\n", om.Currency, nm.Currency)
	}
	if om.EffectiveFrom != nm.EffectiveFrom {
		fmt.Fprintf(&sb, "  effective_from: %s -> %s\n", om.EffectiveFrom, nm.EffectiveFrom)
	}
	if om.EffectiveTo != nm.EffectiveTo {
		fmt.Fprintf(&sb, "  effective_to: %s -> %s\n", om.EffectiveTo, nm.EffectiveTo)
	}

	oldRates := rateByAxis(om)
	newRates := rateByAxis(nm)
	for _, axis := range CanonicalAxes {
		o, hasO := oldRates[axis]
		n, hasN := newRates[axis]
		switch {
		case hasO && hasN:
			if (o.Amount == nil) != (n.Amount == nil) || (o.Amount != nil && n.Amount != nil && *o.Amount != *n.Amount) {
				fmt.Fprintf(&sb, "  rates[%s]: %s -> %s\n", axis, amountStr(o.Amount), amountStr(n.Amount))
			}
		case hasN:
			fmt.Fprintf(&sb, "  rates[%s]: (absent) -> %s\n", axis, amountStr(n.Amount))
		case hasO:
			fmt.Fprintf(&sb, "  rates[%s]: %s -> (absent)\n", axis, amountStr(o.Amount))
		}
	}
	if line := nameSetDiffLine("aliases", om.Aliases, nm.Aliases); line != "" {
		sb.WriteString(line)
	}
	if line := sourceRefDiffLine(om.Sources, nm.Sources); line != "" {
		sb.WriteString(line)
	}
	if om.Reviewer != nm.Reviewer {
		fmt.Fprintf(&sb, "  reviewer: %s -> %s\n", displayEmpty(om.Reviewer), displayEmpty(nm.Reviewer))
	}
	return sb.String()
}

// nameSetDiffLine renders a sorted string-set change ("label: old -> new")
// or "" when the sets are equal.
func nameSetDiffLine(label string, oldSet, newSet []string) string {
	o, n := sortedNames(oldSet), sortedNames(newSet)
	if stringSlicesEqual(o, n) {
		return ""
	}
	return fmt.Sprintf("  %s: %s -> %s\n", label, displaySet(o), displaySet(n))
}

// sourceRefDiffLine renders the primary-source ref-set change or "" when
// the ref sets are equal (notes and per-source dates do not gate the diff;
// the ref identity is what reviewers must re-verify).
func sourceRefDiffLine(oldSources, newSources []RefSource) string {
	o := make([]string, 0, len(oldSources))
	for i := range oldSources {
		o = append(o, oldSources[i].Ref)
	}
	n := make([]string, 0, len(newSources))
	for i := range newSources {
		n = append(n, newSources[i].Ref)
	}
	o, n = sortedNames(o), sortedNames(n)
	if stringSlicesEqual(o, n) {
		return ""
	}
	return fmt.Sprintf("  sources: %s -> %s\n", displaySet(o), displaySet(n))
}

func sortedNames(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func displaySet(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ",")
}

// rateByAxis maps rates by axis for fixed-order rendering. The map is
// consumed via CanonicalAxes iteration only — no map iteration reaches the
// output.
func rateByAxis(m *RefModel) map[string]*RefRate {
	out := make(map[string]*RefRate, len(m.Rates))
	for i := range m.Rates {
		out[m.Rates[i].Axis] = &m.Rates[i]
	}
	return out
}

func amountStr(a *float64) string {
	if a == nil {
		return "unpriced"
	}
	return strconv.FormatFloat(*a, 'g', -1, 64)
}

func displayEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func findRefModel(c *Catalog, id packModelIdentity) *RefModel {
	for i := range c.Models {
		if modelIdentity(&c.Models[i]) == id {
			return &c.Models[i]
		}
	}
	return nil
}

// shortDigest renders the first 12 hex chars for diff headers (full digests
// stay in the packs; the header only helps humans tell snapshots apart).
func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
