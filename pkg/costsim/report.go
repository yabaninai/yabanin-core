package audit

import (
	"fmt"
	"sort"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// AuditReport is the assembled, render-ready audit output. It holds the inputs,
// the analysis, and the two simulations so the renderer (md/json/html) can lay
// out the six sections without re-running the analysis.
//
// Hard rule: every figure in this struct must be traceable to the input rows or
// the pricing table. No adjectives, no "significant"/"large"/"notable". The
// renderer only formats numbers from these fields.
type AuditReport struct {
	Pricing         pricing.Provenance
	SimulationError string       `json:",omitempty"`
	GeneratedAt     time.Time    // the ONE value that may change between runs; renderers exclude it from the determinism check
	Source          string       // input path(s)
	Mode            SimCacheMode // exact | semantic | off (cache mode)

	S1      Summary
	S2      []Finding
	S3      CacheBlock
	S4      RoutingBlock
	S5      QualityBlock
	S6      Recommendations
	Savings CombinedSavings
}

// Summary is the Section 1 block.
type Summary struct {
	Requests         int
	TotalCost        float64
	InputCost        float64
	OutputCost       float64
	UnpricedRequests int
	Window           string
	HasWindow        bool
	TopModels        []ModelRow
	TopProviders     []NameShare
}

// ModelRow is a per-model cost row.
type ModelRow struct {
	Name     string
	Requests int
	CostUSD  float64
	SharePct float64
	Unpriced bool
}

// NameShare is a name + request-share row.
type NameShare struct {
	Name     string
	Requests int
	SharePct float64
}

// Finding is one rendered finding row for Section 2. Each carries the measured
// number(s) that justify it, so the report can state "what we found" without
// adjectives.
type Finding struct {
	Name   string
	Detail string
	USD    float64
}

// CacheBlock is the Section 3 block.
type CacheBlock struct {
	Mode           SimCacheMode
	HitRatePct     float64
	TokensAvoided  int
	DollarsAvoided float64
	PerModel       []NameShare
	Caveat         string
}

// RoutingBlock is the Section 4 block.
type RoutingBlock struct {
	Classifier        string
	ClassDistribution map[string]int
	RoutingOnly       float64
	RoutingOnMisses   float64
	UnpricedDropped   int
}

// QualityBlock is the Section 5 block.
type QualityBlock struct {
	Parsed  int
	Skipped int
	// Cap is the ingestion cap (effective MaxRecords) that bounds Parsed.
	Cap int
	// Denominator is the total number of lines accounted for: parsed records
	// plus skipped (parse-error) lines. It is the basis for the ingestion
	// regression — a report can always show "X of Y lines produced records".
	Denominator       int
	RealTokenSharePct float64
	TimestampedPct    float64
	UnpricedCount     int
	UnpricedModels    []string
}

// Recommendation is one fired rule, verbatim, anchored to the number that
// triggered it. Section 6 only lists rules that actually fired.
type Recommendation struct {
	Rule   string
	Detail string
	USD    float64
}

// Recommendations is the Section 6 block.
type Recommendations []Recommendation

// InsufficientSample returns true when the report must carry the hard
// "insufficient sample" banner: fewer than 50 requests or a window shorter than
// 24h (or no window at all). This is a fact about the sample, not a suggestion.
func (r AuditReport) InsufficientSample() bool {
	if r.S1.Requests < 50 {
		return true
	}
	if !r.S1.HasWindow {
		return true
	}
	if r.S1.Window == "" {
		return true
	}
	dur, err := parseWindow(r.S1.Window)
	if err != nil {
		return true
	}
	return dur < 24*time.Hour
}

// parseWindow parses the "HH:MM:SS" or "N-D HH:MM:SS" window string.
func parseWindow(s string) (time.Duration, error) {
	return time.ParseDuration(humanDurationToGo(s))
}

// humanDurationToGo converts "72h3m4s" / "1h0m0s" style strings (as produced by
// time.Duration.String) is already Go-parseable; this is a pass-through that
// tolerates the "1d0h0m0s" form we emit for day spans.
func humanDurationToGo(s string) string {
	// time.ParseDuration cannot parse "d"; rewrite "Nd" to hours.
	out := ""
	i := 0
	for i < len(s) {
		c := s[i]
		if c >= '0' && c <= '9' {
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			num := s[i:j]
			if j < len(s) && s[j] == 'd' {
				// N days -> N*24 hours
				var n int
				_, _ = fmt.Sscanf(num, "%d", &n)
				out += fmt.Sprintf("%dh", n*24)
				i = j + 1
				continue
			}
			out += num
			i = j
			continue
		}
		out += string(c)
		i++
	}
	return out
}

// GenerateReport runs the full pipeline for the given records and cache mode and
// returns the assembled report. It performs no I/O or formatting — the A5
// renderers consume the result.
func GenerateReport(records []Record, cacheMode SimCacheMode) AuditReport {
	analysis := Analyze(records, AnalyzeOptions{})
	cacheRes, hitSet, cacheErr := SimulateCacheWithHits(records, SimCacheOptions{Mode: cacheMode})
	routingAll, _ := SimulateRouting(records, SimRouteOptions{})
	var routingMisses SimRouteResult
	if cacheMode == ModeOff {
		routingMisses = routingAll
	} else {
		routingMisses, _ = SimulateRoutingOnMisses(records, SimRouteOptions{}, hitSet)
	}
	savings := ComputeCombined(cacheRes, routingAll, routingMisses)

	simulationError := ""
	if cacheErr != nil {
		simulationError = cacheErr.Error()
	}
	return AuditReport{
		Pricing:         pricing.Snapshot(),
		SimulationError: simulationError,
		GeneratedAt:     time.Now().UTC(),
		Mode:            cacheMode,
		S1:              buildSummary(analysis),
		S2:              buildFindings(analysis),
		S3:              buildCacheBlock(cacheRes),
		S4:              buildRoutingBlock(routingAll, routingMisses),
		S5:              buildQualityBlock(analysis),
		S6:              buildRecommendations(analysis, savings),
		Savings:         savings,
	}
}

// --- section builders --------------------------------------------------------

func buildSummary(a Analysis) Summary {
	// Window string.
	window := ""
	hasWindow := a.HasWindow
	if hasWindow && !a.WindowStart.IsZero() && !a.WindowEnd.IsZero() {
		window = a.WindowEnd.Sub(a.WindowStart).Round(time.Second).String()
	}
	models := make([]ModelRow, 0, len(a.PerModel))
	for _, m := range a.PerModel {
		models = append(models, ModelRow{
			Name:     m.Model,
			Requests: m.Requests,
			CostUSD:  m.CostUSD,
			SharePct: m.Share * 100,
			Unpriced: m.Unpriced,
		})
	}
	// a.PerModel is already sorted by cost desc from Analyze; keep it, cap at 10.
	if len(models) > 10 {
		models = models[:10]
	}
	provs := make([]NameShare, 0, len(a.PerProvider))
	for _, p := range a.PerProvider {
		provs = append(provs, NameShare{
			Name:     p.Provider,
			Requests: p.Requests,
			SharePct: p.Share * 100,
		})
	}
	return Summary{
		Requests:         a.RequestCount,
		TotalCost:        a.SpendTotal,
		InputCost:        a.InputTotal,
		OutputCost:       a.OutputTotal,
		UnpricedRequests: a.Quality.UnpricedCount,
		Window:           window,
		HasWindow:        hasWindow,
		TopModels:        models,
		TopProviders:     provs,
	}
}

func buildFindings(a Analysis) []Finding {
	var fs []Finding
	// Concentration.
	if a.PricedRequests > 0 {
		fs = append(fs, Finding{
			Name: "Spend concentration",
			Detail: fmt.Sprintf("p50=$%.4f p90=$%.4f p99=$%.4f; top 1%% of requests hold %.1f%% of spend, top 10%% hold %.1f%%.",
				a.ConcentrationP50, a.ConcentrationP90, a.ConcentrationP99, a.Top1PctShare*100, a.Top10PctShare*100),
		})
	}
	// Prefix bloat.
	if a.PrefixGroups > 0 {
		fs = append(fs, Finding{
			Name: "Repeated-prefix bloat",
			Detail: fmt.Sprintf("%d prompt prefixes (>= %d repeats) carry %d prompt tokens; %s of spend is repeated context.",
				a.PrefixGroups, a.PrefixMinMembers, a.PrefixBloatTokens, money(a.PrefixBloatCost)),
			USD: a.PrefixBloatCost,
		})
	}
	// Top clusters.
	if len(a.TopClusters) > 0 {
		top := a.TopClusters[0]
		rest := 0.0
		for _, c := range a.TopClusters {
			rest += c.CostUSD
		}
		fs = append(fs, Finding{
			Name: "Top prompt clusters",
			Detail: fmt.Sprintf("top %d repeated prompts hold %s of spend (largest %s across %d requests).",
				len(a.TopClusters), money(rest), money(top.CostUSD), top.Requests),
			USD: rest,
		})
	}
	// Retry storms.
	if a.RetryStormCount > 0 {
		fs = append(fs, Finding{
			Name: "Retry storms",
			Detail: fmt.Sprintf("%d requests re-sent identical prompts within the retry window; %s re-spent.",
				a.RetryStormCount, money(a.RetryStormCost)),
			USD: a.RetryStormCost,
		})
	}
	// Error waste.
	if a.ErrorWasteRequests > 0 {
		fs = append(fs, Finding{
			Name: "Error waste",
			Detail: fmt.Sprintf("%d error responses billed for %s of output tokens.",
				a.ErrorWasteRequests, money(a.ErrorWasteCost)),
			USD: a.ErrorWasteCost,
		})
	}
	// max_tokens over-provision.
	if a.MaxTokensSet > 0 && a.MaxTokensOverProvision > 0 {
		fs = append(fs, Finding{
			Name: "max_tokens over-provision",
			Detail: fmt.Sprintf("%d requests set max_tokens; on %.1f%% of them the model used < 25%% of the cap.",
				a.MaxTokensSet, a.MaxTokensOverProvision*100),
		})
	}
	// Latency.
	if len(a.Latency) > 0 {
		rows := make([]string, 0, len(a.Latency))
		for _, l := range a.Latency {
			rows = append(rows, fmt.Sprintf("%s p95=%dms", l.Model, l.P95))
		}
		fs = append(fs, Finding{
			Name:   "Tail latency",
			Detail: joinRows(rows),
		})
	}
	// Model-mix drift.
	if len(a.ModelMixDrift) > 0 {
		fs = append(fs, Finding{
			Name:   "Model-mix drift",
			Detail: fmt.Sprintf("model share shifted across %d day-model points within the window.", len(a.ModelMixDrift)),
		})
	}
	return fs
}

func buildCacheBlock(c SimCacheResult) CacheBlock {
	per := make([]NameShare, 0, len(c.PerModelRequests))
	for model, reqs := range c.PerModelRequests {
		per = append(per, NameShare{Name: model, Requests: reqs, SharePct: c.PerModelHitRate[model] * 100})
	}
	sort.Slice(per, func(i, j int) bool {
		if per[i].Requests != per[j].Requests {
			return per[i].Requests > per[j].Requests
		}
		return per[i].Name < per[j].Name
	})
	caveat := ""
	if c.Mode == ModeSemantic {
		caveat = "semantic hits are similarity matches, not verified-equivalent answers"
	}
	return CacheBlock{
		Mode:           c.Mode,
		HitRatePct:     c.HitRate * 100,
		TokensAvoided:  c.TokensAvoided,
		DollarsAvoided: c.DollarsAvoided,
		PerModel:       per,
		Caveat:         caveat,
	}
}

func buildRoutingBlock(all, misses SimRouteResult) RoutingBlock {
	return RoutingBlock{
		Classifier:        all.ClassifierName,
		ClassDistribution: all.ClassDistribution,
		RoutingOnly:       all.RoutingOnly,
		RoutingOnMisses:   misses.RoutingOnMisses,
		UnpricedDropped:   all.UnpricedDropped,
	}
}

func buildQualityBlock(a Analysis) QualityBlock {
	return QualityBlock{
		Parsed:            a.Quality.Parsed,
		Skipped:           a.Quality.Skipped,
		Cap:               a.Options.IngestCap,
		Denominator:       a.Quality.Parsed + a.Quality.Skipped,
		RealTokenSharePct: a.Quality.RealTokenShare * 100,
		TimestampedPct:    a.Quality.TimestampedShare * 100,
		UnpricedCount:     a.Quality.UnpricedCount,
		UnpricedModels:    a.Quality.UnpricedModels,
	}
}

// buildRecommendations maps fired findings to concrete, verbatim
// recommendations anchored to their numbers. Only rules that actually fired are
// included.
func buildRecommendations(a Analysis, s CombinedSavings) Recommendations {
	var recs Recommendations
	if a.Top1PctShare > 0 && a.PricedRequests > 0 {
		recs = append(recs, Recommendation{
			Rule:   "Investigate the top spenders",
			Detail: fmt.Sprintf("The top 1%% of requests hold %.1f%% of spend; confirm each is intended before scaling it.", a.Top1PctShare*100),
		})
	}
	if a.PrefixGroups > 0 {
		recs = append(recs, Recommendation{
			Rule:   "Cache the system prefix",
			Detail: fmt.Sprintf("%d repeated prefixes cost %s of prompt tokens; provider prompt caching may discount eligible repeated input; confirm model-specific rates.", a.PrefixGroups, money(a.PrefixBloatCost)),
			USD:    a.PrefixBloatCost,
		})
	}
	if a.RetryStormCount > 0 {
		recs = append(recs, Recommendation{
			Rule:   "Cut retry storms",
			Detail: fmt.Sprintf("%d identical-prompt retries re-sent %s of spend.", a.RetryStormCount, money(a.RetryStormCost)),
			USD:    a.RetryStormCost,
		})
	}
	if a.ErrorWasteRequests > 0 {
		recs = append(recs, Recommendation{
			Rule:   "Stop paying for errors",
			Detail: fmt.Sprintf("%d error responses billed %s of output tokens.", a.ErrorWasteRequests, money(a.ErrorWasteCost)),
			USD:    a.ErrorWasteCost,
		})
	}
	if a.MaxTokensSet > 0 && a.MaxTokensOverProvision > 0 {
		recs = append(recs, Recommendation{
			Rule:   "Right-size max_tokens",
			Detail: fmt.Sprintf("On %.1f%% of capped requests the model used < 25%% of max_tokens; lower the cap to stop reserving unused capacity.", a.MaxTokensOverProvision*100),
		})
	}
	if s.Combined > 0 {
		recs = append(recs, Recommendation{
			Rule: "Enable cache + tier routing",
			Detail: fmt.Sprintf("Simulated combined savings of %s (cache %s + routing on misses %s; overlap %s not double-counted).",
				money(s.Combined), money(s.CacheOnly), money(s.RoutingOnly), money(s.Overlap)),
			USD: s.Combined,
		})
	}
	return recs
}

func joinRows(rows []string) string {
	out := ""
	for i, r := range rows {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	if out == "" {
		out = "no latency data"
	}
	return out
}

// money is the stable data-field formatting used by finding/recommendation
// detail strings (report.go). It is deliberately locale-independent: those
// strings are the JSON contract, not display text. The *render* layers format
// money per-locale via the catalog (see locales.Catalog.Money).
func money(v float64) string {
	return fmt.Sprintf("$%.2f", v)
}
