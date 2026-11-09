package adminstore

// Measure vocabulary teeth (design: Units & Spend +
// Policies workspace). The contract under test:
//
//	Measure = amount × unit × fidelity × provenance, with three hard rules:
//	  1. unknown ≠ 0 — an unknown measure never carries an amount, and a
//	     builder that collapses "we don't know" into "zero" is a defect;
//	  2. estimate ≠ exact — combined fidelities degrade to the worst mark;
//	  3. incompatible units are never summed — a cross-unit sum is refused,
//	     not coerced.
//
// These are the mutation teeth for slices 1–5: every rollup builder must go
// through this vocabulary, so the guards here bound what the API can emit.

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// MustKnownMeasure builds a known measure or fails the test.
func MustKnownMeasure(t *testing.T, unit string, amount float64, fidelity, provenance string) Measure {
	t.Helper()
	m, err := KnownMeasure(unit, amount, fidelity, provenance)
	require.NoError(t, err)
	return m
}

func TestMeasureValidate_RefusesUnknownWithAmount(t *testing.T) {
	// unknown ≠ 0: fidelity unknown with a numeric amount is the collapse
	// defect the design names explicitly.
	amt := 0.0
	m := Measure{Amount: &amt, Unit: UnitUSD, Family: UnitFamilyMoney, Fidelity: FidelityUnknown}
	err := m.Validate()
	require.Error(t, err, "unknown fidelity with an amount must be refused")
	require.Contains(t, err.Error(), "unknown")

	// And the honest shape validates: nil amount + unknown fidelity.
	require.NoError(t, UnknownMeasure(UnitUSD, "").Validate())

	// Known fidelities require an amount — an empty exact is a lie too.
	require.Error(t, Measure{Unit: UnitTokens, Family: UnitFamilyResource, Fidelity: FidelityExact}.Validate())
	require.NoError(t, ZeroMeasure(UnitTokens, "").Validate())
}

func TestMeasureValidate_UnitFamilyConsistency(t *testing.T) {
	require.Error(t, Measure{Unit: UnitGCO2e, Family: UnitFamilyMoney, Fidelity: FidelityUnknown}.Validate(),
		"gCO2e is impact, not money")
	require.Error(t, Measure{Unit: "bananas", Family: UnitFamilyResource, Fidelity: FidelityUnknown}.Validate(),
		"unsupported units are refused")
	require.NoError(t, Measure{Unit: UnitGCO2e, Family: UnitFamilyImpact, Fidelity: FidelityUnknown}.Validate())
}

func TestSumCompatible_RefusesCrossUnitSum(t *testing.T) {
	// NEVER sum incompatible units: USD + tokens is the canonical violation.
	usd := MustKnownMeasure(t, UnitUSD, 1.25, FidelityExact, "catalog:x digest:abcdef0")
	tok := MustKnownMeasure(t, UnitTokens, 500, FidelityExact, "internal:ledger")

	_, err := SumCompatible(usd, tok)
	require.Error(t, err, "cross-unit sum must be refused")
	require.Contains(t, err.Error(), "incompatible")

	// Same unit but different family labeling is still a defect.
	usdMislab := usd
	usdMislab.Family = UnitFamilyResource
	_, err = SumCompatible(usd, usdMislab)
	require.Error(t, err, "same unit with mismatched families must be refused")

	// Summing across an unknown member is refused: unknown is not a number.
	unk := UnknownMeasure(UnitUSD, "")
	_, err = SumCompatible(usd, unk)
	require.Error(t, err, "sum across unknown must be refused, not silently narrowed")

	// Compatible members sum with worst-fidelity degradation.
	a := MustKnownMeasure(t, UnitUSD, 1.0, FidelityExact, "p")
	b := MustKnownMeasure(t, UnitUSD, 2.5, FidelityEstimated, "p")
	sum, err := SumCompatible(a, b)
	require.NoError(t, err)
	require.NotNil(t, sum.Amount)
	require.InDelta(t, 3.5, *sum.Amount, 1e-9)
	require.Equal(t, FidelityEstimated, sum.Fidelity, "exact + estimated degrades to estimated")

	// Empty input is a programming error, not zero.
	_, err = SumCompatible()
	require.Error(t, err)
}

func TestWorstFidelity_Ranking(t *testing.T) {
	require.Equal(t, FidelityExact, WorstFidelity(FidelityExact, FidelityExact))
	require.Equal(t, FidelityEstimated, WorstFidelity(FidelityExact, FidelityEstimated))
	require.Equal(t, FidelitySimulated, WorstFidelity(FidelityEstimated, FidelitySimulated))
	require.Equal(t, FidelityUnknown, WorstFidelity(FidelityExact, FidelityUnknown))
	require.Equal(t, FidelityUnknown, WorstFidelity(FidelityUnknown, FidelityUnknown))
}

func TestCatalogProvenanceLabel_Prefix7(t *testing.T) {
	// REF-04 format: catalog:<version> digest:<prefix7>.
	got := CatalogProvenanceLabel("reference-catalog-v1", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.Equal(t, "catalog:reference-catalog-v1 digest:0123456", got)

	require.Equal(t, "catalog:v2 digest:abc", CatalogProvenanceLabel("v2", "abc"),
		"digests shorter than 7 chars render whole")
}

func TestMeasureWireShape_UnknownIsNullAmount(t *testing.T) {
	// The wire contract the UI depends on: an unknown measure serializes
	// amount: null — never amount: 0 with a quiet fidelity.
	m := UnknownMeasure(UnitGCO2e, ProvenanceCarbonFactors)
	require.NoError(t, m.Validate())
	b, err := json.Marshal(m)
	require.NoError(t, err)
	require.Contains(t, string(b), `"amount":null`)
	require.NotContains(t, string(b), `"amount":0`)
}
