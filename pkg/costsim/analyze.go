package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"time"
)

// AnalyzeOptions tunes the cost analysis.
type AnalyzeOptions struct {
	// RetryWindow defines how close in time two identical prompts count as a
	// retry/duplicate. Default 60s when zero.
	RetryWindow time.Duration
	// IngestCap is the effective MaxRecords the ingestion used; surfaced in
	// the quality block so a report states its denominator cap.
	IngestCap int
}

// DayPoint is one day's aggregated spend.
type DayPoint struct {
	Day      string // YYYY-MM-DD
	Requests int
	CostUSD  float64
}

// ModelBreakdown is one model's aggregated spend.
type ModelBreakdown struct {
	Model    string
	Requests int
	CostUSD  float64
	Share    float64 // share of total spend
	Unpriced bool
}

// ProviderBreakdown is one provider's aggregated spend.
type ProviderBreakdown struct {
	Provider string
	Requests int
	CostUSD  float64
	Share    float64
	Unpriced bool
}

// Cluster is a group of requests sharing a normalized prompt.
type Cluster struct {
	Hash     string
	Requests int
	CostUSD  float64
	Share    float64
}

// LatencyRow is per-model latency when durations exist.
type LatencyRow struct {
	Model string
	P50   int
	P95   int
	Count int
}

// DayModelShare is one (day, model) mix point for drift detection.
type DayModelShare struct {
	Day   string
	Model string
	Share float64
}

// DataQuality is the always-printed account of input quality.
type DataQuality struct {
	Parsed           int
	Skipped          int
	RealTokenShare   float64 // fraction with real (non-estimated) counts
	TimestampedShare float64
	UnpricedModels   []string // model names with no price, deduped + sorted
	UnpricedCount    int      // requests that were unpriced
}

// Analysis is the result of the cost/spend pass. A5 renders these; A3/A4
// read the per-record data they need from the original slice.
type Analysis struct {
	Options AnalyzeOptions

	SpendTotal     float64
	InputTotal     float64
	OutputTotal    float64
	RequestCount   int // all records
	PricedRequests int // records with a known price (drive dollar totals)
	WindowStart    time.Time
	WindowEnd      time.Time
	HasWindow      bool // false when no timestamps (unordered)

	PerDay      []DayPoint
	PerModel    []ModelBreakdown
	PerProvider []ProviderBreakdown

	ConcentrationP50 float64
	ConcentrationP90 float64
	ConcentrationP99 float64
	Top1PctShare     float64 // share of total spend held by the top 1% of requests
	Top10PctShare    float64

	// Repeated-prefix (system-prompt) bloat.
	PrefixBloatTokens int
	PrefixBloatCost   float64
	PrefixGroups      int // number of prefixes with >= prefixGroupMin members
	PrefixMinMembers  int

	TopClusters []Cluster // top 20 by spend

	RetryStormCount int
	RetryStormCost  float64

	ErrorWasteRequests int
	ErrorWasteCost     float64

	MaxTokensSet           int     // requests with MaxTokens > 0
	MaxTokensOverProvision float64 // share where completion < 25% of max

	Latency []LatencyRow

	ModelMixDrift []DayModelShare

	Quality DataQuality
}

// prefixGroupMin is the minimum members for a prompt prefix to count as
// "repeated prefix bloat."
const prefixGroupMin = 20

// promptHashPrefix is the number of leading chars of the normalized prompt used
// to group "repeated prefix" requests (a system prompt is a leading prefix).
const promptHashPrefix = 512

// promptHashFor returns a stable hash of the record's normalized prompt. It
// uses the precomputed PromptHash when present, otherwise computes one.
func promptHashFor(r Record) string {
	if r.PromptHash != "" {
		return r.PromptHash
	}
	if r.Prompt == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalizePrompt(r.Prompt)))
	return hex.EncodeToString(sum[:8])
}

// normalizePrompt collapses whitespace so that cosmetic differences do not
// defeat prefix/group matching.
func normalizePrompt(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// Analyze computes the cost/spend findings for a slice of records. It is pure
// (no I/O, no network) and deterministic for a given input + options.
func Analyze(records []Record, opts AnalyzeOptions) Analysis {
	if opts.RetryWindow <= 0 {
		opts.RetryWindow = 60 * time.Second
	}
	a := Analysis{Options: opts, PrefixMinMembers: prefixGroupMin}

	n := len(records)
	if n == 0 {
		return a
	}

	// Per-record cost and running totals.
	costs := make([]Cost, n)
	var pricedCosts []float64 // per-request total cost for priced requests (for percentiles/concentration)
	var pricedByRequest = make([]float64, n)
	totalInput, totalOutput := 0.0, 0.0
	pricedRequests := 0
	var start, end time.Time
	hasWindow := false

	for i, r := range records {
		c := CostOf(r)
		costs[i] = c
		if Priced(r) {
			pricedRequests++
			pricedByRequest[i] = c.Total()
			pricedCosts = append(pricedCosts, c.Total())
			totalInput += c.Input
			totalOutput += c.Output
		}
		if !r.Timestamp.IsZero() {
			if !hasWindow || r.Timestamp.Before(start) {
				start = r.Timestamp
			}
			if !hasWindow || r.Timestamp.After(end) {
				end = r.Timestamp
			}
			hasWindow = true
		}
	}

	a.RequestCount = n
	a.PricedRequests = pricedRequests
	a.SpendTotal = totalInput + totalOutput
	a.InputTotal = totalInput
	a.OutputTotal = totalOutput
	a.HasWindow = hasWindow
	a.WindowStart = start
	a.WindowEnd = end

	// Findings 2: concentration (percentiles + top-share) over priced requests.
	cent := percentiles(pricedCosts, 50, 90, 99)
	a.ConcentrationP50, a.ConcentrationP90, a.ConcentrationP99 = cent[0], cent[1], cent[2]
	a.Top1PctShare, a.Top10PctShare = topShare(pricedCosts)

	// Findings 1: per-day, per-model, per-provider breakdowns.
	a.PerDay = perDayBreakdown(records, costs)
	a.PerModel = perModelBreakdown(records, costs, a.SpendTotal)
	a.PerProvider = perProviderBreakdown(records, costs, a.SpendTotal)

	// Findings 3: repeated-prefix bloat.
	a.PrefixBloatTokens, a.PrefixBloatCost, a.PrefixGroups = prefixBloat(records, costs)

	// Findings 4: top prompt clusters by spend.
	a.TopClusters = topClusters(records, costs, a.SpendTotal, 20)

	// Findings 5: retry/duplicate storms.
	a.RetryStormCount, a.RetryStormCost = retryStorms(records, costs, opts.RetryWindow)

	// Findings 6: error waste.
	a.ErrorWasteRequests, a.ErrorWasteCost = errorWaste(records, costs)

	// Findings 7: max_tokens over-provisioning.
	a.MaxTokensSet, a.MaxTokensOverProvision = maxTokensOverProvision(records)

	// Findings 8: latency by model.
	a.Latency = latencyByModel(records)

	// Findings 9: model-mix drift.
	a.ModelMixDrift = modelMixDrift(records)

	// Findings 10: data quality.
	a.Quality = dataQuality(records, n)

	return a
}

// --- helpers ---------------------------------------------------------------

// percentiles returns the p-values (as given) of the sorted slice. Empty input
// yields zeros. The input is not mutated.
func percentiles(values []float64, ps ...int) []float64 {
	out := make([]float64, len(ps))
	if len(values) == 0 {
		return out
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	for i, p := range ps {
		out[i] = percentileSorted(sorted, p)
	}
	return out
}

func percentileSorted(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := float64(p) / 100.0 * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

// topShare returns the share of total spend held by the top 1% and top 10% of
// requests (by cost). Empty input yields 0.
func topShare(values []float64) (top1, top10 float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	total := 0.0
	for _, v := range sorted {
		total += v
	}
	if total == 0 {
		return 0, 0
	}
	count := len(sorted)
	topN1 := count / 100
	if topN1 < 1 {
		topN1 = 1
	}
	topN10 := count / 10
	if topN10 < 1 {
		topN10 = 1
	}
	sum1 := 0.0
	for i := count - topN1; i < count; i++ {
		sum1 += sorted[i]
	}
	sum10 := 0.0
	for i := count - topN10; i < count; i++ {
		sum10 += sorted[i]
	}
	return sum1 / total, sum10 / total
}

func dayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }

func perDayBreakdown(records []Record, costs []Cost) []DayPoint {
	type acc struct {
		requests int
		cost     float64
	}
	m := map[string]*acc{}
	var days []string
	for i, r := range records {
		if r.Timestamp.IsZero() {
			continue
		}
		d := dayKey(r.Timestamp)
		a, ok := m[d]
		if !ok {
			a = &acc{}
			m[d] = a
			days = append(days, d)
		}
		a.requests++
		if Priced(r) {
			a.cost += costs[i].Total()
		}
	}
	sort.Strings(days)
	out := make([]DayPoint, 0, len(days))
	for _, d := range days {
		a := m[d]
		out = append(out, DayPoint{Day: d, Requests: a.requests, CostUSD: a.cost})
	}
	return out
}

func perModelBreakdown(records []Record, costs []Cost, total float64) []ModelBreakdown {
	type acc struct {
		requests         int
		cost             float64
		priced, unpriced bool
	}
	m := map[string]*acc{}
	for i, r := range records {
		key := r.Model
		if key == "" {
			key = "(unknown)"
		}
		a, ok := m[key]
		if !ok {
			a = &acc{}
			m[key] = a
		}
		a.requests++
		if Priced(r) {
			a.cost += costs[i].Total()
			a.priced = true
		} else {
			a.unpriced = true
		}
	}
	out := make([]ModelBreakdown, 0, len(m))
	for model, a := range m {
		share := 0.0
		if total > 0 {
			share = a.cost / total
		}
		out = append(out, ModelBreakdown{
			Model: model, Requests: a.requests, CostUSD: a.cost, Share: share, Unpriced: a.unpriced && !a.priced,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CostUSD > out[j].CostUSD })
	return out
}

func perProviderBreakdown(records []Record, costs []Cost, total float64) []ProviderBreakdown {
	type acc struct {
		requests         int
		cost             float64
		priced, unpriced bool
	}
	m := map[string]*acc{}
	for i, r := range records {
		key := r.Provider
		if key == "" {
			key = "(unknown)"
		}
		a, ok := m[key]
		if !ok {
			a = &acc{}
			m[key] = a
		}
		a.requests++
		if Priced(r) {
			a.cost += costs[i].Total()
			a.priced = true
		} else {
			a.unpriced = true
		}
	}
	out := make([]ProviderBreakdown, 0, len(m))
	for provider, a := range m {
		share := 0.0
		if total > 0 {
			share = a.cost / total
		}
		out = append(out, ProviderBreakdown{
			Provider: provider, Requests: a.requests, CostUSD: a.cost, Share: share, Unpriced: a.unpriced && !a.priced,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CostUSD > out[j].CostUSD })
	return out
}

// prefixBloat groups priced requests by the hash of the first promptHashPrefix
// characters of the normalized prompt, keeps groups with >= prefixGroupMin
// members, and reports the estimated tokens re-sent (members-1 per group, since
// the first occurrence is not a repeat) and their cost.
func prefixBloat(records []Record, costs []Cost) (tokens int, costUSD float64, groups int) {
	type acc struct {
		members       int
		retransTokens int
		retransCost   float64
	}
	m := map[string]*acc{}
	for i, r := range records {
		if r.Prompt == "" {
			continue
		}
		norm := normalizePrompt(r.Prompt)
		if len(norm) > promptHashPrefix {
			norm = norm[:promptHashPrefix]
		}
		sum := sha256.Sum256([]byte(norm))
		key := hex.EncodeToString(sum[:8])
		a, ok := m[key]
		if !ok {
			a = &acc{}
			m[key] = a
		}
		a.members++
		a.retransTokens += r.PromptTokens
		if Priced(r) {
			a.retransCost += costs[i].Input
		}
	}
	for _, a := range m {
		if a.members >= prefixGroupMin {
			groups++
			// The first occurrence is not a repeat; (members-1) are re-sends.
			avgTokens := a.retransTokens / a.members
			tokens += avgTokens * (a.members - 1)
			avgCost := a.retransCost / float64(a.members)
			costUSD += avgCost * float64(a.members-1)
		}
	}
	return tokens, costUSD, groups
}

func topClusters(records []Record, costs []Cost, total float64, top int) []Cluster {
	type acc struct {
		requests int
		cost     float64
	}
	m := map[string]*acc{}
	for i, r := range records {
		h := promptHashFor(r)
		if h == "" {
			continue
		}
		a, ok := m[h]
		if !ok {
			a = &acc{}
			m[h] = a
		}
		a.requests++
		if Priced(r) {
			a.cost += costs[i].Total()
		}
	}
	out := make([]Cluster, 0, len(m))
	for h, a := range m {
		share := 0.0
		if total > 0 {
			share = a.cost / total
		}
		out = append(out, Cluster{Hash: h, Requests: a.requests, CostUSD: a.cost, Share: share})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CostUSD > out[j].CostUSD })
	if len(out) > top {
		out = out[:top]
	}
	return out
}

// retryStorms counts identical prompts (same hash) repeated within RetryWindow
// of a prior occurrence, and the cost of those repeats.
func retryStorms(records []Record, costs []Cost, window time.Duration) (count int, costUSD float64) {
	// Group by hash; for each group in timestamp order, a record is a storm
	// repeat if it occurs within `window` of the previous record with the same
	// hash. Records without timestamps are ignored (cannot be ordered).
	byHash := map[string][]int{}
	for i, r := range records {
		h := promptHashFor(r)
		if h == "" || r.Timestamp.IsZero() {
			continue
		}
		byHash[h] = append(byHash[h], i)
	}
	for _, idxs := range byHash {
		// sort by timestamp
		sort.Slice(idxs, func(i, j int) bool { return records[idxs[i]].Timestamp.Before(records[idxs[j]].Timestamp) })
		for k := 1; k < len(idxs); k++ {
			prev := records[idxs[k-1]].Timestamp
			cur := records[idxs[k]].Timestamp
			if cur.Sub(prev) <= window {
				count++
				if Priced(records[idxs[k]]) {
					costUSD += costs[idxs[k]].Total()
				}
			}
		}
	}
	return count, costUSD
}

func errorWaste(records []Record, costs []Cost) (count int, costUSD float64) {
	for i, r := range records {
		if r.StatusCode >= 400 && (r.PromptTokens > 0 || r.CompletionTokens > 0) {
			count++
			if Priced(r) {
				costUSD += costs[i].Total()
			}
		}
	}
	return count, costUSD
}

func maxTokensOverProvision(records []Record) (set int, underUsedShare float64) {
	underUsed := 0
	for _, r := range records {
		if r.MaxTokens <= 0 {
			continue
		}
		set++
		// "far more reserved than used": completion < 25% of max.
		if float64(r.CompletionTokens) < 0.25*float64(r.MaxTokens) {
			underUsed++
		}
	}
	if set > 0 {
		underUsedShare = float64(underUsed) / float64(set)
	}
	return set, underUsedShare
}

func latencyByModel(records []Record) []LatencyRow {
	byModel := map[string][]int{}
	for _, r := range records {
		if r.DurationMS <= 0 {
			continue
		}
		key := r.Model
		if key == "" {
			key = "(unknown)"
		}
		byModel[key] = append(byModel[key], r.DurationMS)
	}
	out := make([]LatencyRow, 0, len(byModel))
	for model, v := range byModel {
		sorted := append([]int(nil), v...)
		sort.Ints(sorted)
		out = append(out, LatencyRow{
			Model: model,
			P50:   percentileInt(sorted, 50),
			P95:   percentileInt(sorted, 95),
			Count: len(sorted),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func percentileInt(sorted []int, p int) int {
	if len(sorted) == 0 {
		return 0
	}
	rank := float64(p) / 100.0 * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return int(float64(sorted[lo])*(1-frac) + float64(sorted[hi])*frac + 0.5)
}

func modelMixDrift(records []Record) []DayModelShare {
	type key struct{ day, model string }
	byDayModel := map[key]int{}
	dayTotals := map[string]int{}
	for _, r := range records {
		if r.Timestamp.IsZero() {
			continue
		}
		model := r.Model
		if model == "" {
			model = "(unknown)"
		}
		d := dayKey(r.Timestamp)
		byDayModel[key{d, model}]++
		dayTotals[d]++
	}
	out := make([]DayModelShare, 0, len(byDayModel))
	for k, c := range byDayModel {
		if dayTotals[k.day] == 0 {
			continue
		}
		out = append(out, DayModelShare{Day: k.day, Model: k.model, Share: float64(c) / float64(dayTotals[k.day])})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day < out[j].Day
		}
		return out[i].Model < out[j].Model
	})
	return out
}

func dataQuality(records []Record, n int) DataQuality {
	q := DataQuality{Parsed: n}
	realToken, timestamped, unpricedCount := 0, 0, 0
	seen := map[string]bool{}
	for _, r := range records {
		if !r.TokensEstimated && (r.PromptTokens > 0 || r.CompletionTokens > 0) {
			realToken++
		}
		if !r.Timestamp.IsZero() {
			timestamped++
		}
		if !Priced(r) {
			unpricedCount++
			seen[r.Model] = true
		}
	}
	if n > 0 {
		q.RealTokenShare = float64(realToken) / float64(n)
		q.TimestampedShare = float64(timestamped) / float64(n)
	}
	q.UnpricedCount = unpricedCount
	for m := range seen {
		if m == "" {
			m = "(unknown)"
		}
		q.UnpricedModels = append(q.UnpricedModels, m)
	}
	sort.Strings(q.UnpricedModels)
	return q
}
