package adminstore

// The measure vocabulary shared by the currencies
// APIs (Units & Spend + Policies workspace). One rule backs every endpoint:
//
//	Measure = amount × unit × fidelity × provenance
//
// with three hard invariants the UI and the acceptance tests rely on:
//
//  1. unknown ≠ 0 — a measure whose value is not known carries NO amount;
//     collapsing "we don't know" into a numeric zero fabricates data.
//  2. estimate ≠ exact — combining rows of different confidence degrades to
//     the worst mark; an aggregate never inherits "exact" from a subset.
//  3. incompatible units are never summed — USD and tokens describe
//     different dimensions; a cross-unit sum is refused, not coerced.
//
// Fidelity marks: exact (ledger/verified measurement), estimated (computed
// from partial data), simulated (what-if projection), unknown (not
// measurable with the data at hand). Provenance cites the source: REF-04
// catalog citations render as `catalog:<version> digest:<prefix7>`, internal
// ledgers as `internal:<ledger>`, DB tables as `db:<table>`.

import (
	"errors"
	"fmt"
	"strings"
)

// Unit families — the dimension a unit belongs to. Units of different
// families are never summable (rule 3); the family is also the UI's grouping
// key (money / resource / impact).
const (
	UnitFamilyMoney    = "money"
	UnitFamilyResource = "resource"
	UnitFamilyImpact   = "impact"
)

// Units. credits is the wallet currency: 1 credit = 0.01 USD (wallet cents,
// ADR-0001); the scale is stated in every payload that carries the unit so
// no surface has to guess.
const (
	UnitUSD     = "USD"
	UnitCredits = "credits" // 1 credit = 0.01 USD (wallet cents)
	UnitTokens  = "tokens"
	UnitGCO2e   = "gCO2e"
)

// Fidelity marks, ordered from strongest to weakest.
const (
	FidelityExact     = "exact"
	FidelityEstimated = "estimated"
	FidelitySimulated = "simulated"
	FidelityUnknown   = "unknown"
)

// Cap status states for the Policies workspace (slice 2).
const (
	CapStatusOK      = "ok"
	CapStatusNear    = "near"
	CapStatusOver    = "over"
	CapStatusUnknown = "unknown"
)

// Provenance labels for non-catalog sources. Catalog-backed measures cite
// via CatalogProvenanceLabel instead (the label depends on the served
// snapshot).
const (
	ProvenanceCreditsLedger     = "internal:credit-ledger"
	ProvenanceOrgCaps           = "internal:org-caps"
	ProvenanceOrgBudgetSettings = "internal:org-budget-settings"
	ProvenanceCarbonFactors     = "db:carbon_factors"
)

// WalletUnitScale is the wallet-currency definition carried by every payload
// that reports the credits unit.
const WalletUnitScale = "1 credit = 0.01 USD (wallet cents)"

// unitFamilies pins the unit → family mapping Validate enforces.
var unitFamilies = map[string]string{
	UnitUSD:     UnitFamilyMoney,
	UnitCredits: UnitFamilyMoney,
	UnitTokens:  UnitFamilyResource,
	UnitGCO2e:   UnitFamilyImpact,
}

// Measure is one measured quantity in the currencies vocabulary. Amount is
// a pointer BY CONTRACT: nil means unknown — never a fabricated zero.
type Measure struct {
	// Amount is the measured magnitude in Unit. nil = unknown (rule 1).
	Amount *float64 `json:"amount"`
	// Unit is one of the Unit* constants.
	Unit string `json:"unit"`
	// Family groups units by dimension (money / resource / impact).
	Family string `json:"family"`
	// Fidelity is the confidence mark (Fidelity* constants).
	Fidelity string `json:"fidelity"`
	// Provenance cites the measurement source; empty only when the source
	// is the org's own aggregate window (still encouraged to be set).
	Provenance string `json:"provenance,omitempty"`
}

// Validate enforces the vocabulary invariants. Every builder runs it before
// a measure reaches the wire.
func (m Measure) Validate() error {
	switch m.Fidelity {
	case FidelityUnknown:
		if m.Amount != nil {
			return fmt.Errorf("measure %s: unknown fidelity must not carry an amount (unknown ≠ 0)", m.Unit)
		}
	case FidelityExact, FidelityEstimated, FidelitySimulated:
		if m.Amount == nil {
			return fmt.Errorf("measure %s: fidelity %q requires an amount", m.Unit, m.Fidelity)
		}
	default:
		return fmt.Errorf("measure %s: unknown fidelity mark %q", m.Unit, m.Fidelity)
	}
	family, ok := unitFamilies[m.Unit]
	if !ok {
		return fmt.Errorf("measure: unsupported unit %q", m.Unit)
	}
	if m.Family != family {
		return fmt.Errorf("measure %s: family %q, want %q", m.Unit, m.Family, family)
	}
	return nil
}

// fidelityRank orders the marks strongest → weakest for WorstFidelity.
func fidelityRank(f string) int {
	switch f {
	case FidelityExact:
		return 0
	case FidelityEstimated:
		return 1
	case FidelitySimulated:
		return 2
	case FidelityUnknown:
		return 3
	default:
		return 4 // invalid marks rank worst; Validate refuses them anyway
	}
}

// WorstFidelity returns the weaker of two fidelity marks (rule 2).
func WorstFidelity(a, b string) string {
	if fidelityRank(a) >= fidelityRank(b) {
		return a
	}
	return b
}

// KnownMeasure builds a measure that carries a value.
func KnownMeasure(unit string, amount float64, fidelity, provenance string) (Measure, error) {
	family, ok := unitFamilies[unit]
	if !ok {
		return Measure{}, fmt.Errorf("known measure: unsupported unit %q", unit)
	}
	m := Measure{Amount: &amount, Unit: unit, Family: family, Fidelity: fidelity, Provenance: provenance}
	if err := m.Validate(); err != nil {
		return Measure{}, err
	}
	return m, nil
}

// UnknownMeasure builds the honest "we don't know" measure (rule 1).
func UnknownMeasure(unit, provenance string) Measure {
	family := unitFamilies[unit]
	return Measure{Amount: nil, Unit: unit, Family: family, Fidelity: FidelityUnknown, Provenance: provenance}
}

// ZeroMeasure builds an exact zero — ONLY for genuinely-empty inputs (an
// empty window measured zero events); never as a stand-in for unknown.
func ZeroMeasure(unit, provenance string) Measure {
	family := unitFamilies[unit]
	zero := 0.0
	return Measure{Amount: &zero, Unit: unit, Family: family, Fidelity: FidelityExact, Provenance: provenance}
}

// SumCompatible sums same-unit measures under the vocabulary rules: mixed
// units are refused (rule 3), unknown members are refused (unknown is not a
// number), and the result degrades to the worst fidelity (rule 2).
func SumCompatible(ms ...Measure) (Measure, error) {
	if len(ms) == 0 {
		return Measure{}, errors.New("sum compatible: no measures given")
	}
	unit := ms[0].Unit
	family := ms[0].Family
	var total float64
	fidelity := FidelityExact
	provSeen := map[string]struct{}{}
	var provs []string
	for i, m := range ms {
		if err := m.Validate(); err != nil {
			return Measure{}, fmt.Errorf("sum compatible: member %d: %w", i, err)
		}
		if m.Unit != unit || m.Family != family {
			return Measure{}, fmt.Errorf("sum compatible: refusing incompatible units: %s (%s) vs %s (%s)",
				unit, family, m.Unit, m.Family)
		}
		if m.Amount == nil {
			return Measure{}, fmt.Errorf("sum compatible: refusing to sum across an unknown %s member (unknown is not a number)", unit)
		}
		total += *m.Amount
		fidelity = WorstFidelity(fidelity, m.Fidelity)
		if m.Provenance != "" {
			if _, dup := provSeen[m.Provenance]; !dup {
				provSeen[m.Provenance] = struct{}{}
				provs = append(provs, m.Provenance)
			}
		}
	}
	prov := strings.Join(provs, ";")
	amount := total
	return Measure{Amount: &amount, Unit: unit, Family: family, Fidelity: fidelity, Provenance: prov}, nil
}

// CatalogProvenanceLabel renders the REF-04 citation for a served catalog:
// `catalog:<version> digest:<prefix7>`.
func CatalogProvenanceLabel(version, digest string) string {
	if len(digest) > 7 {
		digest = digest[:7]
	}
	return "catalog:" + version + " digest:" + digest
}
