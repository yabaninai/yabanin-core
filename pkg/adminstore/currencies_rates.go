package adminstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// The rates-catalog surfaces behind
// GET /api/rates/catalog, GET /api/rates/diff and POST /api/rates/promote.
//
// The store owns the cross-package composition: it loads sealed reference
// packs through pkg/pricing's public API, renders the review diff, and — for
// promotions — re-seats the process pricer on the next pack's serveable
// projection. It adds no pricing semantics of its own:
//
//   - the committed pack (pricing.BundledRefPackJSON) is the ONLY allowed
//     predecessor: every promotion verifies the chain against it, so a
//     promotion can never rewrite history relative to the binary;
//   - refusals are data (RatesDiffReport.Refused / *RatesRefusal), not bare
//     errors, so the handler can answer 422 with the structured refusal and
//     journal it;
//   - the review-needed flag (any CHANGED/ADDED active entry recorded
//     without a reviewer) is advisory and never refuses: the upstream
//     RefDiff gate already refuses draft→active without a reviewer, and
//     this flag closes the remaining gap (active→active rate changes on
//     entries whose Reviewer field is empty).
//
// No database is touched: the catalog of record lives in the binary, not in
// Postgres. The pricer swap (pricing.SetDefaultFilePricer) is process-local
// by design — restarts fall back to the committed pack until a promotion is
// re-seated by an operator, which keeps the blast radius of a promotion
// inside the serving process.

// RatesCatalogRef cites one sealed catalog snapshot: the catalog identity,
// the sealed catalog digest, the pack envelope digest, the notice files and
// the composed provenance label — identical to the citation carried by
// PricingMetadata, so the UI renders the same string everywhere.
type RatesCatalogRef struct {
	Version       string   `json:"version"`
	Digest        string   `json:"digest"`
	GeneratedAt   string   `json:"generated_at"`
	ReviewSLADays int      `json:"review_sla_days"`
	PackDigest    string   `json:"pack_digest"`
	Notices       []string `json:"notices"`
	Provenance    string   `json:"provenance"`
}

// RatesCatalog is the GET /api/rates/catalog payload: the citation plus the
// full sealed catalog body (entries, rates, sources, review metadata).
type RatesCatalog struct {
	Ref     RatesCatalogRef `json:"ref"`
	Catalog pricing.Catalog `json:"catalog"`
}

// RatesDiffFlag marks one diff finding that needs human review attention.
type RatesDiffFlag struct {
	// Kind discriminates the finding:
	//   - "active_added_without_reviewer": a new active entry recorded
	//     without a reviewer;
	//   - "active_changed_without_reviewer": an active entry whose content
	//     changed while its Reviewer field is empty.
	Kind string `json:"kind"`
	// Entry is the identity label of the flagged catalog entry.
	Entry string `json:"entry"`
}

// RatesDiffReport is the structured view of the review diff between two
// sealed snapshots: the rendered diff verbatim, the parsed counters, and the
// review-needed flags. A refused diff (draft→active promotion without a
// recorded reviewer) is data, not a Go error, so the UI can render the
// refusal next to the report and the handler can journal it.
type RatesDiffReport struct {
	From          RatesCatalogRef `json:"from"`
	To            RatesCatalogRef `json:"to"`
	Rendered      string          `json:"rendered"`
	Added         int             `json:"added"`
	Removed       int             `json:"removed"`
	Changed       int             `json:"changed"`
	ReviewNeeded  bool            `json:"review_needed"`
	Flags         []RatesDiffFlag `json:"flags"`
	Refused       bool            `json:"refused"`
	RefusalReason string          `json:"refusal_reason,omitempty"`
}

// RatesRefusal is the typed error returned by PromoteRefCatalog when the
// review diff refuses to bless the promotion. errors.As extracts it for the
// 422 response body.
type RatesRefusal struct {
	Report *RatesDiffReport
}

func (r *RatesRefusal) Error() string {
	if r == nil || r.Report == nil {
		return "rates promotion refused"
	}
	return "rates promotion refused: " + r.Report.RefusalReason
}

// RatesPromotion is the POST /api/rates/promote result: the before/after
// citations, the blessed diff, and whether the pricer was re-seated. The
// durable variant (PromoteRefCatalogDurable) additionally reports
// Persisted (the active-of-record row + models_pricing materialization
// landed in one transaction) and the materialization summary.
type RatesPromotion struct {
	Before  RatesCatalogRef  `json:"before"`
	After   RatesCatalogRef  `json:"after"`
	Diff    *RatesDiffReport `json:"diff"`
	Applied bool             `json:"applied"`
	// Persisted is true when the promotion is durable: a restart (or any
	// other process) serves the promoted prices without a re-promotion.
	// False = legacy in-memory re-seat only.
	Persisted bool `json:"persisted"`
	// Materialization summarizes the models_pricing writes that make the
	// table serve the promoted projection (plus operator overrides). nil
	// for legacy in-memory promotions.
	Materialization *RatesMaterializationSummary `json:"materialization,omitempty"`
}

// RatesMaterializationSummary is the operator-facing view of the
// promotion's models_pricing plan: rows added/updated/closed to serve the
// promoted catalog, entries skipped because a manual/local_gpu override
// keeps serving them (RetainedOverrides) or because a price exceeds the
// numeric(10,6) column range (RangeSkipped).
type RatesMaterializationSummary struct {
	Added             int      `json:"added"`
	Updated           int      `json:"updated"`
	Skipped           int      `json:"skipped"`
	Removed           int      `json:"removed"`
	RetainedOverrides []string `json:"retained_overrides,omitempty"`
	RangeSkipped      []string `json:"range_skipped,omitempty"`
}

// ratesCatalogRef builds the citation from a loaded pack.
func ratesCatalogRef(pack *pricing.RefPack, cat pricing.Catalog) RatesCatalogRef {
	return RatesCatalogRef{
		Version:       cat.Version,
		Digest:        cat.Digest,
		GeneratedAt:   cat.GeneratedAt,
		ReviewSLADays: cat.ReviewSLADays,
		PackDigest:    pack.PackSHA256,
		Notices:       append([]string(nil), pack.Notices...),
		Provenance:    CatalogProvenanceLabel(cat.Version, cat.Digest),
	}
}

// CurrentRefRatesCatalog returns the committed reference pack — the chain
// anchor of every promotion — as a catalog response.
func CurrentRefRatesCatalog() (*RatesCatalog, error) {
	return RefRatesCatalogFromPack(pricing.BundledRefPackJSON())
}

// RefRatesCatalogFromPack loads pack bytes (every envelope and seal check
// applies) and returns the citation plus the catalog body.
func RefRatesCatalogFromPack(packJSON []byte) (*RatesCatalog, error) {
	pack, cat, err := pricing.LoadRefPack(packJSON)
	if err != nil {
		return nil, fmt.Errorf("rates catalog: %w", err)
	}
	return &RatesCatalog{Ref: ratesCatalogRef(pack, cat), Catalog: cat}, nil
}

// ratesRefEntryLabel renders an entry's identity for flags and logs.
func ratesRefEntryLabel(m pricing.RefModel) string {
	label := m.Provider + "/" + m.Model
	if m.Region != "" || m.Tier != "" || m.ContextBand != "" {
		label += "@" + m.Region + "/" + m.Tier + "/" + m.ContextBand
	}
	return label
}

// ratesRefIdentityKey is the stable map key of an entry identity (the
// merge/identity rule: provider, model, region, tier, context band).
func ratesRefIdentityKey(m pricing.RefModel) string {
	return strings.Join([]string{m.Provider, m.Model, m.Region, m.Tier, m.ContextBand}, "\x00")
}

// ratesRefEntryEqual reports whether two entries carry identical content.
// Loaded pack catalogs are canonicalized upstream, so struct-level JSON
// equality is a sound content comparison.
func ratesRefEntryEqual(a, b pricing.RefModel) bool {
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

// ratesReviewFlags applies the review-needed rule: every ADDED or CHANGED
// active entry recorded without a reviewer is flagged. Advisory only — it
// never refuses.
func ratesReviewFlags(prev, next pricing.Catalog) []RatesDiffFlag {
	prevByID := make(map[string]pricing.RefModel, len(prev.Models))
	for i := range prev.Models {
		prevByID[ratesRefIdentityKey(prev.Models[i])] = prev.Models[i]
	}
	flags := []RatesDiffFlag{}
	for i := range next.Models {
		nm := next.Models[i]
		if nm.Status != pricing.RefStatusActive {
			continue
		}
		if strings.TrimSpace(nm.Reviewer) != "" {
			continue
		}
		om, existed := prevByID[ratesRefIdentityKey(nm)]
		switch {
		case !existed:
			flags = append(flags, RatesDiffFlag{Kind: "active_added_without_reviewer", Entry: ratesRefEntryLabel(nm)})
		case !ratesRefEntryEqual(om, nm):
			flags = append(flags, RatesDiffFlag{Kind: "active_changed_without_reviewer", Entry: ratesRefEntryLabel(nm)})
		}
	}
	return flags
}

// parseRatesSummary extracts the counters from RefDiff's deterministic
// summary line ("summary: added=N removed=N changed=N unchanged=N") so the
// structured report and the rendered diff can never disagree about what was
// counted.
func parseRatesSummary(rendered string) (added, removed, changed int, err error) {
	const marker = "summary:"
	idx := strings.LastIndex(rendered, marker)
	if idx < 0 {
		return 0, 0, 0, fmt.Errorf("rates diff: rendered output has no summary line")
	}
	line := strings.TrimSpace(rendered[idx+len(marker):])
	n, scanErr := fmt.Sscanf(line, "added=%d removed=%d changed=%d", &added, &removed, &changed)
	if scanErr != nil || n != 3 {
		return 0, 0, 0, fmt.Errorf("rates diff: malformed summary line %q", line)
	}
	return added, removed, changed, nil
}

// DiffRefRatesCatalogs renders the structured review diff between two
// sealed packs. Invalid pack bytes are errors; a refused diff (the upstream
// review gate) comes back as a populated report with Refused set.
func DiffRefRatesCatalogs(prevPackJSON, nextPackJSON []byte) (*RatesDiffReport, error) {
	prevPack, prevCat, err := pricing.LoadRefPack(prevPackJSON)
	if err != nil {
		return nil, fmt.Errorf("rates diff: previous pack: %w", err)
	}
	nextPack, nextCat, err := pricing.LoadRefPack(nextPackJSON)
	if err != nil {
		return nil, fmt.Errorf("rates diff: next pack: %w", err)
	}

	report := &RatesDiffReport{
		From:  ratesCatalogRef(prevPack, prevCat),
		To:    ratesCatalogRef(nextPack, nextCat),
		Flags: []RatesDiffFlag{},
	}
	rendered, err := pricing.RefDiff(prevPack.Catalog, nextPack.Catalog)
	if err != nil {
		// A refusal is report data for the operator (the handler answers
		// 422 with the reason), not a transport error.
		report.Refused = true
		report.RefusalReason = err.Error()
		return report, nil //nolint:nilerr // intentional: refusal-as-data
	}
	report.Rendered = rendered
	added, removed, changed, err := parseRatesSummary(rendered)
	if err != nil {
		return nil, err
	}
	report.Added, report.Removed, report.Changed = added, removed, changed
	report.Flags = ratesReviewFlags(prevCat, nextCat)
	report.ReviewNeeded = len(report.Flags) > 0
	return report, nil
}

// PromoteRefCatalog verifies the next pack against the committed reference
// pack (the only allowed predecessor), renders the review diff, re-seats the
// process pricer on the next pack's serveable projection, and returns the
// promotion record for the audit journal. Refusals come back as a
// *RatesRefusal (carry the structured report for the 422 body); chain or
// load failures as plain errors. On any failure the current pricer is left
// untouched.
func PromoteRefCatalog(nextPackJSON []byte) (*RatesPromotion, error) {
	prevJSON := pricing.BundledRefPackJSON()
	if err := pricing.VerifyRefPackChain(prevJSON, nextPackJSON); err != nil {
		return nil, fmt.Errorf("rates promotion: %w", err)
	}
	diff, err := DiffRefRatesCatalogs(prevJSON, nextPackJSON)
	if err != nil {
		return nil, err
	}
	if diff.Refused {
		return nil, &RatesRefusal{Report: diff}
	}
	pricer, err := pricing.ServeCatalogFromPack(nextPackJSON)
	if err != nil {
		return nil, fmt.Errorf("rates promotion: %w", err)
	}
	pricing.SetDefaultFilePricer(pricer)
	return &RatesPromotion{
		Before:  diff.From,
		After:   diff.To,
		Diff:    diff,
		Applied: true,
	}, nil
}
