package catalogs

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// NebiusEntryReviewer names the verifier of record for entries bridged from
// the committed console record: the record's prices_source is the owner's
// dated console paste (eu-north1 rows, 2026-09-08), so the verifying human
// is the owner. The evidence archive itself stays outside the public
// export; the committed in-repo record is the traceable summary.
const NebiusEntryReviewer = "yabanin-owner"

// NebiusRecordVersion is the only record schema revision this bridge
// understands; anything else must fail loudly rather than guess.
const NebiusRecordVersion = 1

// nebiusVerifiedStatus is the only price status the bridge accepts as
// verified: an arm with any other status must never enter the catalog as
// verified-primary (never present unverified data as verified).
const nebiusVerifiedStatus = "VERIFIED_CONSOLE"

// nebiusRecord mirrors exactly the fields the bridge consumes from
// scripts/stand-agenteval/nebius-catalog.json. Unknown fields are ignored
// by encoding/json (the record carries eval metadata — budgets, flavor
// policy, console capability notes — that is out of the price-catalog
// vocabulary; console capability facts like context windows have no Catalog
// v1 fields and stay out per the ownership split).
type nebiusRecord struct {
	SchemaVersion int                  `json:"schema_version"`
	Provider      string               `json:"provider"`
	AsOf          string               `json:"as_of"`
	PricesSource  string               `json:"prices_source"`
	Arms          map[string]nebiusArm `json:"arms"`
	Avoid         []nebiusAvoid        `json:"avoid"`
}

type nebiusArm struct {
	Model         string        `json:"model"`
	Notes         string        `json:"notes"`
	Prices        *nebiusPrices `json:"prices_usd_per_1m"`
	Status        string        `json:"prices_status"`
	EffectiveFrom string        `json:"prices_effective_from"`
	BillingName   string        `json:"prices_billing_name"`
	AsOf          string        `json:"prices_as_of"`
}

type nebiusPrices struct {
	Input  float64 `json:"input"`
	Output float64 `json:"output"`
}

type nebiusAvoid struct {
	Model  string `json:"model"`
	Reason string `json:"reason"`
}

// nebiusDeprecatedDate extracts the deprecation date the avoid list states
// in prose ("deprecated 2026-08-31; ..."). Best-effort: a miss leaves the
// window open-ended, which is safe because status=retired is never
// serveable regardless of the window.
var nebiusDeprecatedDate = regexp.MustCompile(`deprecated (\d{4}-\d{2}-\d{2})`)

// NebiusEntries bridges the committed verified record into catalog entries:
// one active verified-primary entry per priced arm, one retired entry per
// avoid-list model. Deterministic (arms sorted by model ID). The bridge
// refuses, with an error, anything that would smuggle unverified or
// not-actually-free data into the catalog:
//
//   - unsupported record schema version, missing provider / prices_source;
//   - an arm whose prices_status is not VERIFIED_CONSOLE (never present
//     unverified data as verified);
//   - an arm without prices, or with a missing/zero/negative/non-finite
//     input or output: the record's own pricing notes call provider $0 rows
//     partner exceptions that must not be read as free — a zero rate may
//     only enter through an explicit future owner release, not through this
//     bridge;
//   - an arm without a prices_effective_from / prices_as_of instant.
func NebiusEntries(record []byte) ([]pricing.RefModel, error) {
	var rec nebiusRecord
	if err := json.Unmarshal(record, &rec); err != nil {
		return nil, fmt.Errorf("nebius record: %w", err)
	}
	if rec.SchemaVersion != NebiusRecordVersion {
		return nil, fmt.Errorf("nebius record: unsupported schema_version %d (want %d)", rec.SchemaVersion, NebiusRecordVersion)
	}
	if strings.TrimSpace(rec.Provider) == "" {
		return nil, fmt.Errorf("nebius record: provider is required")
	}
	if strings.TrimSpace(rec.PricesSource) == "" {
		return nil, fmt.Errorf("nebius record: prices_source is required (evidence attribution)")
	}
	if err := pricing.ValidateRefTime(rec.AsOf); err != nil {
		return nil, fmt.Errorf("nebius record as_of: %w", err)
	}

	// Map iteration order is randomized; sort by arm key for a stable
	// assembly (final canonical ordering happens in the builder as well,
	// but the bridge output must be deterministic on its own for direct
	// test use).
	keys := make([]string, 0, len(rec.Arms))
	for k := range rec.Arms {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	models := make([]pricing.RefModel, 0, len(rec.Arms)+len(rec.Avoid))
	for _, key := range keys {
		m, err := nebiusArmEntry(rec, key, rec.Arms[key])
		if err != nil {
			return nil, err
		}
		models = append(models, m)
	}
	for _, av := range rec.Avoid {
		m, err := nebiusAvoidEntry(rec, av)
		if err != nil {
			return nil, err
		}
		models = append(models, m)
	}
	sortCatalogModels(models)
	return models, nil
}

// nebiusArmEntry converts one priced arm into an active verified-primary
// entry: owner-verified console rates, dated evidence per axis, the
// billing-display name kept as an alias (billing names are how the
// provider's own pricing page labels the rows — useful lookup surface,
// clearly attributed to the same verified source).
func nebiusArmEntry(rec nebiusRecord, key string, arm nebiusArm) (pricing.RefModel, error) {
	where := "nebius arm " + key
	if strings.TrimSpace(arm.Model) == "" {
		return pricing.RefModel{}, fmt.Errorf("%s: model is required", where)
	}
	if arm.Status != nebiusVerifiedStatus {
		return pricing.RefModel{}, fmt.Errorf("%s (%s): refusing to bridge as verified: prices_status %q is not %q",
			where, arm.Model, arm.Status, nebiusVerifiedStatus)
	}
	if arm.Prices == nil {
		return pricing.RefModel{}, fmt.Errorf("%s (%s): no prices_usd_per_1m; refusing to bridge an unpriced arm as verified", where, arm.Model)
	}
	in, out := arm.Prices.Input, arm.Prices.Output
	for name, v := range map[string]float64{"input": in, "output": out} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return pricing.RefModel{}, fmt.Errorf("%s (%s): %s price is not a finite number (%v)", where, arm.Model, name, v)
		}
		if v <= 0 {
			return pricing.RefModel{}, fmt.Errorf("%s (%s): %s price %v is not a positive verified amount; "+
				"zero requires an explicit owner release (record pricing note: $0 rows are partner exceptions, not verified frees)",
				where, arm.Model, name, v)
		}
	}
	if strings.TrimSpace(arm.EffectiveFrom) == "" {
		return pricing.RefModel{}, fmt.Errorf("%s (%s): prices_effective_from is required", where, arm.Model)
	}
	asOf := arm.AsOf
	if asOf == "" {
		asOf = rec.AsOf
	}
	if asOf == "" {
		return pricing.RefModel{}, fmt.Errorf("%s (%s): prices_as_of is required (no record-level as_of fallback)", where, arm.Model)
	}
	if err := pricing.ValidateRefTime(arm.EffectiveFrom); err != nil {
		return pricing.RefModel{}, fmt.Errorf("%s (%s) effective_from: %w", where, arm.Model, err)
	}
	if err := pricing.ValidateRefTime(asOf); err != nil {
		return pricing.RefModel{}, fmt.Errorf("%s (%s) prices_as_of: %w", where, arm.Model, err)
	}

	evRef := NebiusEvidencePrefix + asOf
	note := fmt.Sprintf("%s %s); record: %s#arms.%s; evidence archive outside public export",
		verifiedEntryNotePrefix, asOf, NebiusRecordPath, key)
	alias, caveat := nebiusBillingAlias(arm.BillingName, arm.Model)
	if caveat != "" {
		note += "; " + caveat
	}
	if strings.TrimSpace(arm.Notes) != "" {
		note += "; billing note: " + arm.Notes
	}

	amount := func(v float64) *float64 { c := v; return &c }
	return pricing.RefModel{
		Provider:      rec.Provider,
		Model:         arm.Model,
		Aliases:       aliasList(alias),
		Currency:      "USD",
		EffectiveFrom: arm.EffectiveFrom,
		VerifiedAt:    asOf,
		Reviewer:      NebiusEntryReviewer,
		Status:        pricing.RefStatusActive,
		Sources: []pricing.RefSource{{
			Kind:       pricing.RefSourceInternalEvidence,
			Ref:        evRef,
			VerifiedAt: asOf,
			Note:       note,
		}},
		Rates: []pricing.RefRate{
			{
				Axis: pricing.AxisInput, Unit: pricing.RefUnitPer1MTokens, Amount: amount(in),
				Evidence: []pricing.RefEvidence{{Ref: evRef, Amount: in, At: asOf}},
			},
			{
				Axis: pricing.AxisOutput, Unit: pricing.RefUnitPer1MTokens, Amount: amount(out),
				Evidence: []pricing.RefEvidence{{Ref: evRef, Amount: out, At: asOf}},
			},
		},
	}, nil
}

// nebiusBillingAlias extracts the lookup alias from the record's billing
// display name. A parenthetical suffix in the record is a human caveat, not
// part of the billed string (the G2_ALT row: billing line lacks the -0731
// model suffix) — the alias keeps only the clean prefix and the caveat is
// carried verbatim into the source note.
func nebiusBillingAlias(billing, model string) (alias, caveat string) {
	b := strings.TrimSpace(billing)
	if b == "" {
		return "", ""
	}
	if idx := strings.Index(b, " ("); idx > 0 {
		caveat = "billing-name caveat: " + b
		b = strings.TrimSpace(b[:idx])
	}
	if b == "" || b == model {
		return "", caveat
	}
	return b, caveat
}

func aliasList(alias string) []string {
	if alias == "" {
		return nil
	}
	return []string{alias}
}

// nebiusAvoidEntry converts one avoid-list row into a retired entry: the
// deprecation is an owner-verified fact (same evidence record), retired
// status makes it never serveable, and no rates are copied (a deprecated
// model's historical prices are out of scope for a serving catalog; the
// reason text stays in the source note).
func nebiusAvoidEntry(rec nebiusRecord, av nebiusAvoid) (pricing.RefModel, error) {
	if strings.TrimSpace(av.Model) == "" {
		return pricing.RefModel{}, fmt.Errorf("nebius avoid: model is required")
	}
	if strings.TrimSpace(av.Reason) == "" {
		return pricing.RefModel{}, fmt.Errorf("nebius avoid (%s): reason is required (deprecations must be explainable)", av.Model)
	}
	asOf := rec.AsOf
	if err := pricing.ValidateRefTime(asOf); err != nil {
		return pricing.RefModel{}, fmt.Errorf("nebius avoid (%s) as_of: %w", av.Model, err)
	}
	evRef := NebiusEvidencePrefix + asOf
	note := fmt.Sprintf("retired per provider avoid list; record: %s#avoid; evidence archive outside public export; reason: %s",
		NebiusRecordPath, av.Reason)

	m := pricing.RefModel{
		Provider:   rec.Provider,
		Model:      av.Model,
		Currency:   "USD",
		VerifiedAt: asOf,
		Reviewer:   NebiusEntryReviewer,
		Status:     pricing.RefStatusRetired,
		Sources: []pricing.RefSource{{
			Kind:       pricing.RefSourceInternalEvidence,
			Ref:        evRef,
			VerifiedAt: asOf,
			Note:       note,
		}},
	}
	if mt := nebiusDeprecatedDate.FindStringSubmatch(av.Reason); mt != nil {
		if err := pricing.ValidateRefTime(mt[1]); err != nil {
			return pricing.RefModel{}, fmt.Errorf("nebius avoid (%s): %w", av.Model, err)
		}
		m.EffectiveTo = mt[1]
	}
	return m, nil
}
