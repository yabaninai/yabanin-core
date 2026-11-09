package audit

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/reireirei/yabanin/pkg/cache"
)

// SimCacheMode selects the cache-simulation mode.
type SimCacheMode string

const (
	// ModeExact keys on the production prompt hash and needs no dependencies.
	ModeExact SimCacheMode = "exact"
	// ModeSemantic embeds each prompt and compares via pkg/cache.SquaredL2Distance.
	// Requires an embedder (injected as EmbedFunc; production uses an HTTP
	// embedder, tests use a fixed-vector stub).
	ModeSemantic SimCacheMode = "semantic"
	// ModeOff skips the simulation entirely.
	ModeOff SimCacheMode = "off"
)

// EmbedFunc maps a prompt to an embedding vector. In production this is an
// HTTP call to an embedder service; in tests it is a fixed-vector stub. It is
// injected so the core simulation has no hard network dependency.
type EmbedFunc func(text string) ([]float32, error)

// SimCacheOptions configures the cache simulation.
type SimCacheOptions struct {
	Mode       SimCacheMode
	TTL        time.Duration // default 24h when zero
	MaxEntries int           // LRU cap, default 100_000 when zero
	// Threshold is the cosine-similarity threshold for semantic mode. Default
	// is cache.DefaultSimilarityThreshold (0.95, the production default).
	Threshold float64
	// SemanticMaxRecords caps how many records semantic mode will embed/compare
	// before truncating (brute-force cost guard). Default 50_000 when zero.
	SemanticMaxRecords int
	// CacheNondeterministic, when true, counts requests with Temperature > 0 as
	// cacheable. Default false: those are excluded and reported separately as
	// "potentially cacheable if you accept non-deterministic reuse."
	CacheNondeterministic bool
	// Embed is required for semantic mode; ignored otherwise.
	Embed EmbedFunc
}

// SimCacheResult is the output of the cache simulation.
type SimCacheResult struct {
	Mode      SimCacheMode
	Threshold float64
	TTL       time.Duration

	Requests                 int // records considered (after nondeterministic exclusion)
	Hits                     int
	HitRate                  float64 // Hits / Requests
	TokensAvoided            int
	DollarsAvoided           float64
	PerModelHitRate          map[string]float64
	PerModelRequests         map[string]int
	HitRateByDay             []DayPoint
	ExcludedNondeterministic int
	TruncatedSemantic        bool // true when SemanticMaxRecords capped the run
	// SimilarityHistogram is the distribution of best-match similarity scores in
	// semantic mode (10 buckets over 0..1). Empty for exact/off.
	SimilarityHistogram []float64
}

const (
	defaultCacheTTL           = 24 * time.Hour
	defaultMaxEntries         = 100_000
	defaultSemanticMaxRecords = 50_000
)

// SimulateCache replays records in timestamp order (input order when timestamps
// are absent) and reports what a cache with the given parameters would have
// hit. The first occurrence of a prompt is never a hit; a hit requires the
// earlier entry to still be live (not expired past TTL, not LRU-evicted).
//
// The simulation is honest: it reports hit rate and avoided cost, and the
// caller (A5) emits the caveat that a semantic hit is a similarity match, not a
// verified-equivalent answer.
func SimulateCache(records []Record, opts SimCacheOptions) (SimCacheResult, error) {
	res, _, err := SimulateCacheWithHits(records, opts)
	return res, err
}

// SimulateCacheWithHits is like SimulateCache but also returns the set of
// record indices that were counted as hits. A4 uses this to apply routing to
// cache-misses only (production order).
func SimulateCacheWithHits(records []Record, opts SimCacheOptions) (SimCacheResult, map[int]bool, error) {
	if opts.TTL <= 0 {
		opts.TTL = defaultCacheTTL
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultMaxEntries
	}
	if opts.SemanticMaxRecords <= 0 {
		opts.SemanticMaxRecords = defaultSemanticMaxRecords
	}
	if opts.Threshold <= 0 {
		opts.Threshold = cache.DefaultSimilarityThreshold
	}

	res := SimCacheResult{
		Mode:             opts.Mode,
		Threshold:        opts.Threshold,
		TTL:              opts.TTL,
		PerModelHitRate:  map[string]float64{},
		PerModelRequests: map[string]int{},
	}
	hitSet := map[int]bool{}
	if opts.Mode == ModeOff || len(records) == 0 {
		return res, hitSet, nil
	}
	if opts.Mode == ModeSemantic && opts.Embed == nil {
		return res, hitSet, fmt.Errorf("semantic mode requires an embedder (EmbedFunc)")
	}

	// Order: timestamp order when timestamps exist, else input order.
	order := orderedIndices(records)

	var hits int
	var tokensAvoided int
	var dollarsAvoided float64
	considered := 0

	// Per-day hit accounting for the hit-rate-by-day curve.
	type dayAcc struct{ hits, reqs int }
	dayStats := map[string]*dayAcc{}

	// Reuse one structure per mode.
	exactLive := map[string]*lruEntry{} // key -> entry (LRU via seq)
	seqCounter := 0
	var semanticLive []simEntrySemantic // ordered slice (append = most recent)
	semanticSeen := 0

	// note: liveness is judged relative to the request time during this
	// historical replay, so no wall-clock "now" is needed.

	for _, i := range order {
		r := records[i]
		// Nondeterminism gate: exclude temperature>0 requests unless opted in.
		if r.TemperatureSet && r.Temperature > 0 && !opts.CacheNondeterministic {
			res.ExcludedNondeterministic++
			continue
		}
		considered++
		if r.Model == "" {
			r.Model = "(unknown)"
		}
		res.PerModelRequests[r.Model]++
		if !r.Timestamp.IsZero() {
			d := dayKey(r.Timestamp)
			if _, ok := dayStats[d]; !ok {
				dayStats[d] = &dayAcc{}
			}
			dayStats[d].reqs++
		}

		var hit bool
		var avoidedTokens int
		var avoidedCost float64

		switch opts.Mode {
		case ModeExact:
			key, err := exactKey(r)
			if err != nil {
				continue
			}
			if e, ok := exactLive[key]; ok && liveAt(e.ts, r.Timestamp, opts.TTL) {
				hit = true
				avoidedTokens = r.PromptTokens + r.CompletionTokens
				avoidedCost = CostOf(r).Total()
				seqCounter++
				e.seq = seqCounter // LRU: refresh most-recent on access
			} else {
				if len(exactLive) >= opts.MaxEntries {
					evictOldest(exactLive) // drop the least-recently-used
				}
				seqCounter++
				exactLive[key] = &lruEntry{ts: r.Timestamp, seq: seqCounter}
			}
		case ModeSemantic:
			if semanticSeen >= opts.SemanticMaxRecords {
				res.TruncatedSemantic = true
				continue
			}
			vec, err := opts.Embed(r.Prompt)
			if err != nil {
				continue
			}
			vec = normalizeVec(vec)
			best := -1.0
			bestIdx := -1
			for j := range semanticLive {
				sim := cosineSimilarityFromL2(vec, semanticLive[j].vec)
				if sim > best {
					best = sim
					bestIdx = j
				}
			}
			res.recordSimilarity(best)
			if best >= opts.Threshold && bestIdx >= 0 && liveAt(semanticLive[bestIdx].ts, r.Timestamp, opts.TTL) {
				hit = true
				avoidedTokens = r.PromptTokens + r.CompletionTokens
				avoidedCost = CostOf(r).Total()
				// LRU: refresh the matched entry as most-recently-used.
				matched := semanticLive[bestIdx]
				matched.ts = r.Timestamp
				semanticLive = append(semanticLive[:bestIdx], semanticLive[bestIdx+1:]...)
				semanticLive = append(semanticLive, matched)
			} else {
				if len(semanticLive) >= opts.MaxEntries {
					semanticLive = semanticLive[1:] // evict oldest
				}
				semanticLive = append(semanticLive, simEntrySemantic{ts: r.Timestamp, vec: vec})
				semanticSeen++
			}
		}

		if hit {
			hits++
			tokensAvoided += avoidedTokens
			dollarsAvoided += avoidedCost
			res.PerModelHitRate[r.Model]++
			if !r.Timestamp.IsZero() {
				dayStats[dayKey(r.Timestamp)].hits++
			}
			hitSet[i] = true
		}
	}

	if considered > 0 {
		res.Requests = considered
		res.HitRate = float64(hits) / float64(considered)
	}
	res.Hits = hits
	res.TokensAvoided = tokensAvoided
	res.DollarsAvoided = dollarsAvoided

	// Per-model hit rate (0 when a model had 0 requests).
	for m, reqs := range res.PerModelRequests {
		if reqs > 0 {
			res.PerModelHitRate[m] = res.PerModelHitRate[m] / float64(reqs)
		}
	}

	// Hit rate by day (only when timestamps exist).
	if len(dayStats) > 0 {
		var days []string
		for d := range dayStats {
			days = append(days, d)
		}
		sort.Strings(days)
		res.HitRateByDay = make([]DayPoint, 0, len(days))
		for _, d := range days {
			a := dayStats[d]
			hitRate := 0.0
			if a.reqs > 0 {
				hitRate = float64(a.hits) / float64(a.reqs)
			}
			res.HitRateByDay = append(res.HitRateByDay, DayPoint{Day: d, Requests: a.reqs, CostUSD: hitRate})
		}
	}
	return res, hitSet, nil
}

// --- helpers ---------------------------------------------------------------

// lruEntry is a cached exact-mode entry. seq is a monotonically increasing
// last-access counter; the smallest seq is the least-recently-used entry.
type lruEntry struct {
	ts  time.Time
	seq int
}

type simEntrySemantic struct {
	ts  time.Time
	vec []float32
}

// liveAt reports whether an entry created at entryTS is still live when a
// request at reqTS arrives. TTL is measured from entry creation. The simulation
// is a historical replay, so liveness is judged relative to the request time.
func liveAt(entryTS, reqTS time.Time, ttl time.Duration) bool {
	if entryTS.IsZero() || reqTS.IsZero() {
		return true // no timestamps: treat as live (input-order mode)
	}
	return reqTS.Sub(entryTS) <= ttl
}

// evictOldest removes the least-recently-used entry (smallest seq) from the
// exact-mode LRU map.
func evictOldest(m map[string]*lruEntry) {
	var worstKey string
	var worstSeq int
	first := true
	for k, e := range m {
		if first || e.seq < worstSeq {
			worstKey, worstSeq = k, e.seq
			first = false
		}
	}
	delete(m, worstKey)
}

// exactKey computes the production prompt hash over a reconstructed request
// body, so the simulation matches production keying rather than an ad-hoc hash.
func exactKey(r Record) (string, error) {
	body := map[string]interface{}{
		"model": r.Model,
		"messages": []map[string]string{
			{"role": "user", "content": r.Prompt},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("reconstruct body: %w", err)
	}
	return cache.NormalizePromptHash(raw)
}

// normalizeVec returns a unit-normalized copy of v (zero vector stays zero).
func normalizeVec(v []float32) []float32 {
	var norm float64
	for _, x := range v {
		norm += float64(x) * float64(x)
	}
	if norm == 0 {
		return v
	}
	n := math.Sqrt(norm)
	out := make([]float32, len(v))
	for i, x := range v {
		out[i] = float32(float64(x) / n)
	}
	return out
}

// cosineSimilarityFromL2 converts the squared L2 distance between (unit)
// vectors into a cosine similarity in 0..1, reusing
// pkg/cache.SquaredL2Distance as the single distance implementation. For unit
// vectors L2² = 2 - 2·dot, so similarity = dot = 1 - L2²/2 — the same
// conversion the production semantic path performs between pgvector cosine
// distance and similarity (pkg/cache semantic.go: sim = 1 - d).
func cosineSimilarityFromL2(a, b []float32) float64 {
	d := cache.SquaredL2Distance(a, b)
	sim := 1.0 - d/2.0
	if sim < 0 {
		sim = 0
	}
	if sim > 1 {
		sim = 1
	}
	return sim
}

// orderedIndices returns indices sorted by timestamp when any record has one,
// else 0..n-1 (input order).
func orderedIndices(records []Record) []int {
	hasTS := false
	for _, r := range records {
		if !r.Timestamp.IsZero() {
			hasTS = true
			break
		}
	}
	idx := make([]int, len(records))
	for i := range idx {
		idx[i] = i
	}
	if !hasTS {
		return idx
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return records[idx[a]].Timestamp.Before(records[idx[b]].Timestamp)
	})
	return idx
}

// recordSimilarity bins a best-match similarity score into a 10-bucket
// histogram over 0..1.
func (r *SimCacheResult) recordSimilarity(sim float64) {
	if sim < 0 {
		sim = 0
	}
	if sim > 1 {
		sim = 1
	}
	if len(r.SimilarityHistogram) == 0 {
		r.SimilarityHistogram = make([]float64, 10)
	}
	bucket := int(sim * 10)
	if bucket >= 10 {
		bucket = 9
	}
	r.SimilarityHistogram[bucket]++
}
