// Package dimensions is the first bounded Core Preview3 CM-00-01 contract
// leaf: a typed vocabulary for multidimensional cost components — money,
// internal credits, energy, emissions and other configured units — with an
// exact decimal quantity representation, precision/lifecycle validation and
// correction identity.
//
// This is a contract proposal to bind against existing schemas before
// implementation, not an invented available API: the package provides no
// persistence, ingestion, calculation, analytics or API wiring, and claims
// none of them.
//
// Quantities are exact non-negative decimals carried as normalized digits
// plus a decimal scale, never float64. An absent or unknown quantity is a
// nil quantity, a state distinct from an explicit zero: a missing
// measurement or factor can never become zero. The decimal working limits
// (38 significant digits, 18 fractional digits, 128 input bytes) are
// revisable implementation assumptions, not an owner tariff.
package dimensions
