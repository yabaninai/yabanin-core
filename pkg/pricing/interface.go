package pricing

import "sync/atomic"

// providerAliases maps registry/adapter provider names onto the catalog
// stores Azure OpenAI models under provider "azure" while the registry key
// is "azure-openai"). The alias is a FALLBACK only: lookups always try the
// exact provider first, so operator-entered models_pricing rows under the
// registry name win over the catalog alias.
var providerAliases = map[string]string{
	"azure-openai": "azure",
}

// CanonicalProvider returns the catalog provider name for a registry
// provider name, or the input unchanged when no alias exists.
func CanonicalProvider(provider string) string {
	if c, ok := providerAliases[provider]; ok {
		return c
	}
	return provider
}

// Pricer is the interface for looking up per-model pricing data.
// Both StaticPricer (backed by the verified reference catalog) and DBPricer
// (backed by models_pricing table) implement this interface.
type Pricer interface {
	// Lookup returns the Price for a provider:model pair.
	// Returns false if the combination is unknown.
	Lookup(provider, model string) (Price, bool)
}

// defaultPricer is used by ComputeCost when no custom pricer is set.
// It is stored in an atomic.Value (wrapped so successive stores may carry
// different concrete Pricer types) so SetDefaultPricer at startup never
// data-races the DefaultLookup readers on the compute path.
var defaultPricer atomic.Value // holds pricerHolder

// pricerHolder boxes one Pricer value: a stable storage type keeps
// atomic.Value happy across SetDefaultPricer calls with different
// implementations.
type pricerHolder struct{ p Pricer }

func init() { defaultPricer.Store(pricerHolder{staticPricer{}}) }

// loadDefaultPricer returns the current default pricer; it never returns
// nil (the reference catalog is the built-in default).
func loadDefaultPricer() Pricer {
	if h, ok := defaultPricer.Load().(pricerHolder); ok && h.p != nil {
		return h.p
	}
	return staticPricer{}
}

// SetDefaultPricer overrides the global pricer used by ComputeCost.
// Call this at startup (e.g., from gateway.go) after DB is available.
// Only the explicitly maintained historical primary rates remain a fallback.
// A nil replacement leaves the current pricer unchanged.
func SetDefaultPricer(p Pricer) {
	if p != nil {
		defaultPricer.Store(pricerHolder{p})
	}
}

type staticPricer struct{}

func (staticPricer) Lookup(provider, model string) (Price, bool) {
	if file := DefaultFilePricer(); file != nil {
		if p, ok := file.Lookup(provider, model); ok {
			return p, true
		}
		if c := CanonicalProvider(provider); c != provider {
			if p, ok := file.Lookup(c, model); ok {
				return p, true
			}
		}
	}
	return lookupHistoricalPrimary(provider, model)
}

// lookupHistoricalPrimary preserves only the independently authored Anthropic
// rates that were available before third-party corpus removal. This explicit
// availability policy prevents removed drafts (or newly added table rows) from
// silently becoming serving prices. Operator overrides are handled first.
func lookupHistoricalPrimary(provider, model string) (Price, bool) {
	if provider != "anthropic" || catalogRefused(provider, model) {
		return Price{}, false
	}
	switch model {
	case "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-latest",
		"claude-3-5-haiku-20241022", "claude-3-5-haiku-latest", "claude-3-opus-20240229":
		p, ok := table[provider+":"+model]
		return p, ok
	}
	return Price{}, false
}

// StaticPricer returns the current file/catalog pricer for reseller markup.
// Its fallback is limited to explicitly maintained historical primary rates.
func StaticPricer() Pricer {
	return staticPricer{}
}

// DefaultLookup returns the price from the configured pricer, trying the
// canonical provider alias only after the exact name misses. Unknown prices
// return false unless an explicitly maintained historical primary rate exists.
func DefaultLookup(provider, model string) (Price, bool) {
	if p, ok := loadDefaultPricer().Lookup(provider, model); ok {
		return p, true
	}
	if c := CanonicalProvider(provider); c != provider {
		if p, ok := loadDefaultPricer().Lookup(c, model); ok {
			return p, true
		}
	}
	// Preserve only previously available independently sourced historical rates.
	return lookupHistoricalPrimary(provider, model)
}

// IsKnown reports whether the (provider, model) pair has an entry in the
// default pricer's data source. Useful for distinguishing "free" from
// "unknown" in operator tooling.
func IsKnown(provider, model string) bool {
	_, ok := DefaultLookup(provider, model)
	return ok
}
