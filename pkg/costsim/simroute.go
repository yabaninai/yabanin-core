package audit

import (
	"context"
	"fmt"
	"sort"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// DefaultTierMap is the conservative routing table: hard prompts keep the
// original model (never auto-downgrade the ones most likely to be sensitive),
// medium maps to a mid-tier model, easy to a cheap model. Operators override via
// --tier-map (class=model). Models must be price-known to contribute savings.
var DefaultTierMap = map[string]string{
	"hard":   "", // keep original
	"medium": "gpt-4o-mini",
	"easy":   "gpt-4o-mini",
}

// SimRouteOptions configures the routing simulation.
type SimRouteOptions struct {
	// Classifier produces the easy/medium/hard class for each prompt. Defaults
	// to classifier.NewRuleTier() when nil (in-process, no network). Swap in an
	// ML classifier via the --classifier-url flag; the report records which one
	// produced the numbers.
	Classifier classifier.Classifier
	// TierMap maps a class to the target model. Empty entries mean "keep
	// original." Defaults to DefaultTierMap when nil.
	TierMap map[string]string
}

// SimRouteResult is the routing + combined savings output.
type SimRouteResult struct {
	ClassifierName    string // which classifier produced the classes
	ClassDistribution map[string]int

	// RoutingOnly is the savings if every request were routed (ignoring cache).
	RoutingOnly float64
	// RoutingOnMisses is the savings applied only to requests the cache would
	// have missed (production order: cache first, routing to misses).
	RoutingOnMisses float64
	// Overlap is RoutingOnly - RoutingOnMisses: the savings that double-count
	// when you naively add cache + routing. Stated explicitly so a reader cannot
	// double-count.
	Overlap float64
	// UnpricedDropped counts requests whose source or target model had no known
	// price and so were excluded from the savings.
	UnpricedDropped int
	// RoutedCount counts requests where routing actually changed the model to a
	// cheaper one (the savings are positive for these).
	RoutedCount int
}

// SimulateRouting computes what tier-routing would have saved, in the same
// order the gateway applies it, so the number is comparable to production.
// It reports the routing-only savings and the class distribution. Combined
// savings (cache + routing-on-misses) is computed in CombinedSavings.
func SimulateRouting(records []Record, opts SimRouteOptions) (SimRouteResult, error) {
	if opts.Classifier == nil {
		opts.Classifier = classifier.NewRuleTier()
	}
	if opts.TierMap == nil {
		opts.TierMap = DefaultTierMap
	}
	res := SimRouteResult{
		ClassifierName:    opts.Classifier.Name(),
		ClassDistribution: map[string]int{},
	}
	ctx := context.Background()
	for _, r := range records {
		class, err := classifyPrompt(ctx, opts.Classifier, r)
		if err != nil {
			// A classification failure must not abort the run; count it under a
			// sentinel class so it is visible, not silent.
			class = string(classifier.ClassMedium)
		}
		res.ClassDistribution[class]++
		target := opts.TierMap[class]
		if target == "" {
			continue // keep original: no routing change, no saving, not unpriced
		}
		saving, ok, unpriced := routingSaving(r, target)
		if unpriced {
			res.UnpricedDropped++
			continue
		}
		if ok {
			res.RoutingOnly += saving
			res.RoutedCount++
		}
	}
	return res, nil
}

// SimulateRoutingOnMisses is like SimulateRouting but only counts savings for
// requests NOT in the given cache-hit set (production order: cache first,
// routing to misses). The hitSet is a set of record indices that the cache
// simulation counted as hits.
func SimulateRoutingOnMisses(records []Record, opts SimRouteOptions, hitSet map[int]bool) (SimRouteResult, error) {
	if opts.Classifier == nil {
		opts.Classifier = classifier.NewRuleTier()
	}
	if opts.TierMap == nil {
		opts.TierMap = DefaultTierMap
	}
	res := SimRouteResult{
		ClassifierName:    opts.Classifier.Name(),
		ClassDistribution: map[string]int{},
	}
	ctx := context.Background()
	for i, r := range records {
		class, _ := classifyPrompt(ctx, opts.Classifier, r)
		res.ClassDistribution[class]++
		if hitSet[i] {
			continue // cache already served this; no routing saving in production order
		}
		target := opts.TierMap[class]
		if target == "" {
			continue
		}
		saving, ok, unpriced := routingSaving(r, target)
		if unpriced {
			res.UnpricedDropped++
			continue
		}
		if ok {
			res.RoutingOnMisses += saving
			res.RoutedCount++
		}
	}
	return res, nil
}

// CombinedSavings ties the cache and routing simulations together in
// production order (cache first, routing to misses) and returns the three
// headline numbers with the overlap stated explicitly.
type CombinedSavings struct {
	CacheOnly   float64
	RoutingOnly float64
	Combined    float64 // CacheOnly + RoutingOnMisses (no double-count)
	Overlap     float64 // RoutingOnly - RoutingOnMisses
}

// ComputeCombined computes the three savings figures from a cache result and
// the routing results for all-requests and misses-only.
func ComputeCombined(cacheCache SimCacheResult, routingAll, routingMisses SimRouteResult) CombinedSavings {
	overlap := routingAll.RoutingOnly - routingMisses.RoutingOnMisses
	if overlap < 0 {
		overlap = 0
	}
	return CombinedSavings{
		CacheOnly:   cacheCache.DollarsAvoided,
		RoutingOnly: routingAll.RoutingOnly,
		Combined:    cacheCache.DollarsAvoided + routingMisses.RoutingOnMisses,
		Overlap:     overlap,
	}
}

// --- helpers ---------------------------------------------------------------

// classifyPrompt runs the classifier on a record's prompt and returns the class
// as a string.
func classifyPrompt(ctx context.Context, c classifier.Classifier, r Record) (string, error) {
	res, err := c.Classify(ctx, classifier.Input{
		Prompt:         r.Prompt,
		ContextTokens:  r.PromptTokens,
		ModelRequested: r.Model,
	})
	if err != nil {
		return "", err
	}
	return string(res.Class), nil
}

// routingSaving computes the dollar saving for one request if it were routed to
// the target model. It returns (saving, routed, unpriced):
//   - unpriced is true when the source or target model has no known price; the
//     caller must drop it from savings and count it (never silently price an
//     unknown model at $0).
//   - routed is true when routing changes the model to a strictly cheaper one.
//
// It never claims a saving when the target equals the original model, the target
// is not cheaper, or the target is unpriced.
func routingSaving(r Record, target string) (saving float64, routed, unpriced bool) {
	if target == "" || target == r.Model {
		return 0, false, false
	}
	tgt, targetKnown := costForModel(r, target)
	if !targetKnown {
		// Never bank a saving against an unknown model.
		return 0, false, true
	}
	orig, sourceKnown := costForModel(r, r.Model)
	if !sourceKnown {
		return 0, false, true
	}
	s := orig - tgt
	if s <= 0 {
		return 0, false, false // not cheaper
	}
	return s, true, false
}

// costForModel computes the USD cost of a request's tokens under a specific
// model's price (using the request's real prompt/completion token counts).
func costForModel(r Record, model string) (float64, bool) {
	p, known := pricing.DefaultLookup(r.Provider, model)
	if !known {
		return 0, false
	}
	return float64(r.PromptTokens)*p.InputPerM/1e6 + float64(r.CompletionTokens)*p.OutputPerM/1e6, true
}

// ParseTierMap parses repeatable "class=model" pairs into a tier map. Malformed
// entries (missing '=' or unknown class) are rejected with a clear error so a
// typo does not silently route everything to the default table.
func ParseTierMap(pairs []string) (map[string]string, error) {
	valid := map[string]bool{"easy": true, "medium": true, "hard": true}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		idx := -1
		for i, c := range p {
			if c == '=' {
				idx = i
				break
			}
		}
		if idx <= 0 {
			// No '=' or empty class. ("class=" with empty model is valid: it
			// means "keep original".)
			return nil, fmt.Errorf("invalid tier-map entry %q (want class=model)", p)
		}
		class := p[:idx]
		model := p[idx+1:]
		if !valid[class] {
			return nil, fmt.Errorf("unknown class %q in tier-map entry %q (want easy|medium|hard)", class, p)
		}
		out[class] = model
	}
	return out, nil
}

// SortedClasses returns the class distribution keys in a stable order for
// deterministic rendering.
func (r SimRouteResult) SortedClasses() []string {
	keys := make([]string, 0, len(r.ClassDistribution))
	for k := range r.ClassDistribution {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
