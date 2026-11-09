package audit

import "github.com/reireirei/yabanin/pkg/pricing"

// Cost is the USD cost of a single request, split by token direction.
type Cost struct {
	Input  float64 // $ for prompt tokens
	Output float64 // $ for completion tokens
}

// Total returns input + output cost.
func (c Cost) Total() float64 { return c.Input + c.Output }

// priceOf returns the unit price for a record, or the zero Price when the
// (provider, model) pair is unknown. A record whose price is entirely zero is
// "unpriced" and must be excluded from every dollar total (never silently
// priced at $0).
func priceOf(r Record) pricing.Price {
	// Record has no cache-token fields, so the cost stays prompt plus completion.
	// DefaultLookup reads the price file first and the legacy table after it.
	p, ok := pricing.DefaultLookup(r.Provider, r.Model)
	if !ok {
		return pricing.Price{}
	}
	return p
}

// Priced reports whether the record's model has a known non-zero price.
func Priced(r Record) bool {
	p := priceOf(r)
	return p.InputPerM != 0 || p.OutputPerM != 0
}

// CostOf computes the USD cost of a record from its token counts and the model
// unit price. An unpriced model yields a zero Cost (the caller is responsible
// for excluding it from totals via Priced).
func CostOf(r Record) Cost {
	p := priceOf(r)
	return Cost{
		Input:  float64(r.PromptTokens) * p.InputPerM / 1_000_000,
		Output: float64(r.CompletionTokens) * p.OutputPerM / 1_000_000,
	}
}
