package pricing

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/reireirei/yabanin/pkg/money"
)

// Reporting-facing proof for the exact quote-record projection: the detail
// lines a spend report lists must sum to the total the report shows, under
// the documented rounding (half away from zero per line, sub-micro positive
// residue up to the 1 micro-USD visibility floor), the projection must be
// retry/resume-safe (identical records on every recompute, no duplicates,
// no losses), and history must be stable: a late event appends refundlessly
// and a price change never rewrites an already-materialized record.

// stubPricer is a Pricer whose rates a test can flip in place to simulate a
// price update between two quoting moments.
type stubPricer struct{ p Price }

func (s *stubPricer) Lookup(provider, model string) (Price, bool) { return s.p, true }

// fixedOverrideOrg installs a fixed input/output price override for org on
// model (cache lines keep riding the base rates), bypassing the DB lookup
// the way markup_cache_test does.
func fixedOverrideOrg(t *testing.T, mp *MarkupPricer, org, model string, inPerM, outPerM float64) {
	t.Helper()
	mp.cacheMu.Lock()
	mp.cache[org+":"+model] = pricingOverride{
		fixedInputPerM:  &inPerM,
		fixedOutputPerM: &outPerM,
		loadedAt:        time.Now(),
	}
	mp.cacheMu.Unlock()
}

func ptr[T any](v T) *T { return &v }

// quoteRecordCase is one acceptance row: a quoting setup, the usage, and the
// exact expected micro-USD record. Expected values are hand-derived
// constants (probed independently), not recomputed by the same formula the
// code under test uses.
type quoteRecordCase struct {
	name string
	org  string
	p    Price // base rates (cache lines always ride these)

	// fixed rates override markup when both are non-nil
	fixedIn, fixedOut *float64

	model                         string
	inTok, outTok, cacheW, cacheR int64

	// sanity premise: the raw float input line must round to 0 micro alone
	rawInputLineBelowHalfMicro bool

	wantInput, wantOutput, wantCacheW, wantCacheR, wantTotal money.MicroUSD
	wantDetailKinds                                          []QuoteLineKind
}

func TestQuoteRecordDetailMatchesTotalsAndRounding(t *testing.T) {
	cases := []quoteRecordCase{
		{
			name: "clean whole-unit lines, fixed override, base cache rates",
			org:  "org-fixed", model: "gpt-4o",
			p:       Price{InputPerM: 2.5, OutputPerM: 10.0, CacheWritePerM: 3.125, CacheReadPerM: 1.25},
			fixedIn: ptr(2.0), fixedOut: ptr(10.0),
			inTok: 1_300_000, outTok: 500_000, cacheW: 100_000, cacheR: 200_000, // 1M non-cache input
			wantInput: 2_000_000, wantOutput: 5_000_000, wantCacheW: 312_500, wantCacheR: 250_000,
			wantTotal:       7_562_500,
			wantDetailKinds: []QuoteLineKind{LineInput, LineOutput, LineCacheWrite, LineCacheRead},
		},
		{
			name: "sub-micro positive quote stays visible at the 1 micro floor",
			org:  "org-tiny", model: "m",
			p:       Price{InputPerM: 1.0},
			fixedIn: ptr(0.4), fixedOut: ptr(0.0), // 1 token = 0.4 micro: below the 0.5 step
			inTok:                      1,
			rawInputLineBelowHalfMicro: true,
			wantInput:                  1,
			wantTotal:                  1,
			wantDetailKinds:            []QuoteLineKind{LineInput},
		},
		{
			name: "multi-line collapse keeps the floor total on the first positive line",
			org:  "org-tiny2", model: "m",
			p:       Price{InputPerM: 1.0},
			fixedIn: ptr(0.3), fixedOut: ptr(0.3),
			inTok: 1, outTok: 1, // both lines 0.3 micro: each rounds to 0, float sum stays positive
			wantInput:       1, // floor lands on input, the canonical first positive line
			wantTotal:       1,
			wantDetailKinds: []QuoteLineKind{LineInput},
		},
		{
			name: "above-half sub-micro line rounds up without the floor",
			org:  "org-tiny3", model: "m",
			p:       Price{InputPerM: 1.0},
			fixedIn: ptr(0.7), fixedOut: ptr(0.0), // 1 token = 0.7 micro: rounds to 1 directly
			inTok:           1,
			wantInput:       1,
			wantTotal:       1,
			wantDetailKinds: []QuoteLineKind{LineInput},
		},
		{
			name: "genuine zero usage stays a zero record",
			org:  "org-zero", model: "m",
			p:       Price{InputPerM: 1.0, OutputPerM: 2.0},
			fixedIn: ptr(1.0), fixedOut: ptr(2.0),
			wantTotal:       0,
			wantDetailKinds: []QuoteLineKind{},
		},
		{
			name: "default markup path rounds per line and sums exactly",
			org:  "org-markup", model: "gpt-4o-mini",
			p:     Price{InputPerM: 0.15, OutputPerM: 0.6},
			inTok: 2_000_000, outTok: 1_000_000,
			wantInput:       345_000, // 0.30 USD cost, 15% markup, half away from zero
			wantOutput:      690_000,
			wantTotal:       1_035_000,
			wantDetailKinds: []QuoteLineKind{LineInput, LineOutput},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mp := NewMarkupPricer(nil, &stubPricer{p: tc.p}, nil)
			if tc.fixedIn != nil && tc.fixedOut != nil {
				fixedOverrideOrg(t, mp, tc.org, tc.model, *tc.fixedIn, *tc.fixedOut)
			}

			q, err := mp.Quote(context.Background(), tc.org, "prov", tc.model,
				tc.inTok, tc.outTok, tc.cacheW, tc.cacheR)
			if err != nil {
				t.Fatalf("Quote: %v", err)
			}
			if tc.rawInputLineBelowHalfMicro {
				m, err := money.FromUSD(q.InputResaleUSD)
				if err != nil || m != 0 {
					t.Fatalf("premise: raw input line %g should round to 0 micro alone (got %d, %v)",
						q.InputResaleUSD, int64(m), err)
				}
			}

			rec, err := ProjectQuoteRecord("req-"+tc.org, q)
			if err != nil {
				t.Fatalf("ProjectQuoteRecord: %v", err)
			}

			if rec.InputMicro != tc.wantInput || rec.OutputMicro != tc.wantOutput ||
				rec.CacheWriteMicro != tc.wantCacheW || rec.CacheReadMicro != tc.wantCacheR {
				t.Errorf("lines = input %d / output %d / cacheW %d / cacheR %d, want %d / %d / %d / %d",
					int64(rec.InputMicro), int64(rec.OutputMicro), int64(rec.CacheWriteMicro),
					int64(rec.CacheReadMicro), int64(tc.wantInput), int64(tc.wantOutput),
					int64(tc.wantCacheW), int64(tc.wantCacheR))
			}
			if rec.TotalMicro != tc.wantTotal {
				t.Errorf("total = %d, want %d", int64(rec.TotalMicro), int64(tc.wantTotal))
			}

			// The acceptance identity, asserted independently of the
			// constructor: the record's total is the exact sum of its detail
			// lines, and the listed (non-zero) detail sums to the same.
			sum := rec.InputMicro + rec.OutputMicro + rec.CacheWriteMicro + rec.CacheReadMicro
			if rec.TotalMicro != sum {
				t.Errorf("identity broken: total %d != line sum %d", int64(rec.TotalMicro), int64(sum))
			}
			var listed money.MicroUSD
			kinds := make([]QuoteLineKind, 0, 4)
			for _, l := range rec.DetailLines() {
				listed += l.Micro
				kinds = append(kinds, l.Kind)
			}
			if listed != rec.TotalMicro {
				t.Errorf("listed detail sums to %d, total is %d", int64(listed), int64(rec.TotalMicro))
			}
			if diff := cmp.Diff(tc.wantDetailKinds, kinds); diff != "" {
				t.Errorf("detail kinds (-want +got):\n%s", diff)
			}

			// Rounding posture: a positive quote is never invisible, a zero
			// quote never invents money.
			if q.TotalResaleUSD > 0 && rec.TotalMicro < minBillableRecordMicroUSD {
				t.Errorf("positive quote collapsed to invisible: total %d", int64(rec.TotalMicro))
			}
			if q.TotalResaleUSD == 0 && rec.TotalMicro != 0 {
				t.Errorf("zero quote invented money: total %d", int64(rec.TotalMicro))
			}
		})
	}
}

func TestQuoteRecordFailClosed(t *testing.T) {
	big := 9e12 // inside the per-line range; four such lines overflow the micro sum

	cases := []struct {
		name string
		id   string
		q    *ResellerQuote
		want error // sentinel the error must wrap (nil = any error)
	}{
		{name: "nil quote", id: "req-1", q: nil},
		{name: "empty identity", id: "", q: &ResellerQuote{TotalResaleUSD: 0}},
		{name: "blank identity", id: "   ", q: &ResellerQuote{TotalResaleUSD: 0}},
		{
			name: "NaN input line",
			id:   "req-1",
			q:    &ResellerQuote{InputResaleUSD: math.NaN(), TotalResaleUSD: math.NaN()},
			want: money.ErrNonFinite,
		},
		{
			name: "infinite output line",
			id:   "req-1",
			q:    &ResellerQuote{OutputResaleUSD: math.Inf(1), TotalResaleUSD: math.Inf(1)},
			want: money.ErrNonFinite,
		},
		{
			name: "negative cache-write line",
			id:   "req-1",
			q:    &ResellerQuote{CacheWriteResale: -0.5, TotalResaleUSD: -0.5},
			want: money.ErrNegative,
		},
		{
			name: "total disagrees with its detail sum",
			id:   "req-1",
			q:    &ResellerQuote{InputResaleUSD: 1.0, TotalResaleUSD: 5.0},
		},
		{
			name: "positive total with no positive line to carry the floor",
			id:   "req-1",
			q:    &ResellerQuote{TotalResaleUSD: 5e-7}, // within tolerance of a zero line sum
		},
		{
			name: "line sum overflows the micro range",
			id:   "req-1",
			q: &ResellerQuote{
				InputResaleUSD: big, OutputResaleUSD: big,
				CacheWriteResale: big, CacheReadResale: big,
				TotalResaleUSD: 4 * big,
			},
			want: money.ErrRange,
		},
		{
			name: "line past MaxUSD fails closed",
			id:   "req-1",
			q: &ResellerQuote{
				InputResaleUSD: math.Nextafter(money.MaxUSD, math.Inf(1)),
				TotalResaleUSD: math.Nextafter(money.MaxUSD, math.Inf(1)),
			},
			want: money.ErrRange,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := ProjectQuoteRecord(tc.id, tc.q)
			if err == nil {
				t.Fatalf("expected error, got record %+v", rec)
			}
			if rec != (QuoteRecord{}) {
				t.Errorf("failed projection must return the zero record, got %+v", rec)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error %v does not wrap %v", err, tc.want)
			}
			if strings.TrimSpace(tc.id) != "" && !strings.Contains(err.Error(), tc.id) {
				t.Errorf("error %q must carry the request identity for traceability", err)
			}
		})
	}

	// The exact MaxUSD boundary is billable, not rejected: the money
	// conversion saturates it to MaxInt64 µUSD (money boundary table) and
	// the projection carries it as the largest representable positive
	// record — the same classification the consumer boundary battery pins
	// ("exact MaxUSD quote is the largest billable positive").
	maxRec, err := ProjectQuoteRecord("req-max", &ResellerQuote{
		InputResaleUSD: money.MaxUSD,
		TotalResaleUSD: money.MaxUSD,
	})
	if err != nil {
		t.Fatalf("exact MaxUSD boundary saturates and must project without error: %v", err)
	}
	if maxRec.InputMicro != money.MicroUSD(math.MaxInt64) ||
		maxRec.TotalMicro != money.MicroUSD(math.MaxInt64) {
		t.Fatalf("exact MaxUSD = (line %d, total %d), want saturating MaxInt64 on both",
			int64(maxRec.InputMicro), int64(maxRec.TotalMicro))
	}

	// The boundary acceptance is exact, not a blanket cut: one step below
	// the boundary the largest representable line still projects with its
	// exact micro value — no in-range amount changes behavior.
	const belowMax = 9223372036854.7734375 // largest float64 below MaxUSD (one ulp down)
	neighbor, err := ProjectQuoteRecord("req-neighbor", &ResellerQuote{
		InputResaleUSD: belowMax,
		TotalResaleUSD: belowMax,
	})
	if err != nil {
		t.Fatalf("in-range neighbor one step below the boundary must project without error: %v", err)
	}
	const wantNeighborMicro = money.MicroUSD(9_223_372_036_854_773_760)
	if neighbor.InputMicro != wantNeighborMicro || neighbor.TotalMicro != wantNeighborMicro {
		t.Fatalf("in-range neighbor = (line %d, total %d), want exact %d on both",
			int64(neighbor.InputMicro), int64(neighbor.TotalMicro), int64(wantNeighborMicro))
	}
}

// quoteBatch materializes a fixed usage batch once — what a reporting job
// does before (and again after) an interruption.
func quoteBatch(t *testing.T, mp *MarkupPricer, ids []string, org, model string, tok int64) ([]QuoteRecord, []*ResellerQuote) {
	t.Helper()
	recs := make([]QuoteRecord, 0, len(ids))
	quotes := make([]*ResellerQuote, 0, len(ids))
	for i, id := range ids {
		q, err := mp.Quote(context.Background(), org, "prov", model,
			tok+int64(i)*1_000, int64(i)*500, int64(i)*300, int64(i)*100)
		if err != nil {
			t.Fatalf("Quote %s: %v", id, err)
		}
		quotes = append(quotes, q)
		rec, err := ProjectQuoteRecord(id, q)
		if err != nil {
			t.Fatalf("ProjectQuoteRecord %s: %v", id, err)
		}
		recs = append(recs, rec)
	}
	return recs, quotes
}

func canonicalList(recs []QuoteRecord) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.Canonical()
	}
	return out
}

func TestQuoteRecordRetryAndResumeRecoverIdenticalRecords(t *testing.T) {
	mp := NewMarkupPricer(nil, &stubPricer{p: Price{InputPerM: 1.5, OutputPerM: 6.0, CacheWritePerM: 2.0, CacheReadPerM: 0.4}}, nil)
	fixedOverrideOrg(t, mp, "org-f", "m", 2.0, 8.0)

	ids := []string{"req-a", "req-b", "req-c", "req-d"}
	base, storedQuotes := quoteBatch(t, mp, ids, "org-f", "m", 40_000)
	baseCanon := canonicalList(base)
	if len(baseCanon) != len(ids) {
		t.Fatalf("batch = %d records, want %d", len(baseCanon), len(ids))
	}

	// Full recompute after an interruption: every retry reproduces the
	// identical record set — same order, same bytes, one record per identity.
	for retry := 0; retry < 5; retry++ {
		again, _ := quoteBatch(t, mp, ids, "org-f", "m", 40_000)
		if diff := cmp.Diff(baseCanon, canonicalList(again)); diff != "" {
			t.Fatalf("retry %d diverged (-base +retry):\n%s", retry, diff)
		}
		counts := make(map[string]int, len(again))
		for _, r := range again {
			counts[r.RequestID]++
		}
		if len(counts) != len(ids) {
			t.Fatalf("retry %d produced %d distinct identities for %d records: %v",
				retry, len(counts), len(ids), counts)
		}
		for id, n := range counts {
			if n != 1 {
				t.Errorf("retry %d duplicated identity %s (%d records)", retry, id, n)
			}
		}
	}

	// Resume from a partial prefix: the prefix recomputes byte-identical, so
	// a resumed job keeps its earlier work and appends the rest without
	// duplicating or losing anything.
	partial, _ := quoteBatch(t, mp, ids[:2], "org-f", "m", 40_000)
	if diff := cmp.Diff(baseCanon[:2], canonicalList(partial)); diff != "" {
		t.Fatalf("resumed prefix diverged (-base +partial):\n%s", diff)
	}

	// Recovery from the stored quotes (the settlement artifact), not from a
	// live lookup: identical records — the pure projection never re-prices.
	var recovered []QuoteRecord
	for i, id := range ids {
		rec, err := ProjectQuoteRecord(id, storedQuotes[i])
		if err != nil {
			t.Fatalf("recover %s: %v", id, err)
		}
		recovered = append(recovered, rec)
	}
	if diff := cmp.Diff(baseCanon, canonicalList(recovered)); diff != "" {
		t.Fatalf("recovery from stored quotes diverged (-base +recovered):\n%s", diff)
	}

	// The projection is pure: concurrent re-materialization of the same
	// batch yields identical bytes on every goroutine.
	const workers = 8
	var wg sync.WaitGroup
	results := make([][]string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			recs := make([]QuoteRecord, 0, len(ids))
			for i, id := range ids {
				rec, err := ProjectQuoteRecord(id, storedQuotes[i])
				if err != nil {
					t.Errorf("concurrent project %s: %v", id, err)
					return
				}
				recs = append(recs, rec)
			}
			results[w] = canonicalList(recs)
		}(w)
	}
	wg.Wait()
	for w, got := range results {
		if diff := cmp.Diff(baseCanon, got); diff != "" {
			t.Fatalf("worker %d diverged (-base +worker):\n%s", w, diff)
		}
	}
}

func TestQuoteRecordPriceChangeNeverRewritesHistory(t *testing.T) {
	stub := &stubPricer{p: Price{InputPerM: 1.0, OutputPerM: 2.0, CacheWritePerM: 1.5, CacheReadPerM: 0.2}}
	mp := NewMarkupPricer(nil, stub, nil)

	ids := []string{"req-h1", "req-h2"}
	history, storedQuotes := quoteBatch(t, mp, ids, "org-1", "m", 100_000)
	historyCanon := canonicalList(history)

	// The price update is real for new traffic...
	stub.p = Price{InputPerM: 10.0, OutputPerM: 20.0, CacheWritePerM: 15.0, CacheReadPerM: 2.0}
	after, err := mp.Quote(context.Background(), "org-1", "prov", "m", 100_000, 0, 0, 0)
	if err != nil {
		t.Fatalf("Quote under new prices: %v", err)
	}
	newRec, err := ProjectQuoteRecord("req-new", after)
	if err != nil {
		t.Fatalf("ProjectQuoteRecord under new prices: %v", err)
	}
	underOld, err := ProjectQuoteRecord("req-h1", storedQuotes[0])
	if err != nil {
		t.Fatal(err)
	}
	if newRec.InputMicro <= underOld.InputMicro {
		t.Fatalf("price change had no effect on new traffic: new input %d <= historical input %d",
			int64(newRec.InputMicro), int64(underOld.InputMicro))
	}

	// ...and yet rewrites nothing: the materialized history keeps its exact
	// values, and re-projecting the stored quotes (the settlement artifact)
	// after the change returns the identical records — the recovery path
	// cannot see live prices, so it cannot re-price history.
	for i, id := range ids {
		rec, err := ProjectQuoteRecord(id, storedQuotes[i])
		if err != nil {
			t.Fatalf("re-project %s after price change: %v", id, err)
		}
		if diff := cmp.Diff(history[i], rec); diff != "" {
			t.Errorf("price change rewrote history for %s (-before +after):\n%s", id, diff)
		}
		if got := rec.Canonical(); got != historyCanon[i] {
			t.Errorf("price change rewrote canonical bytes for %s:\nbefore %q\nafter  %q", id, historyCanon[i], got)
		}
	}

	// Snapshot semantics: mutating the source quote after materialization
	// cannot reach back into the record.
	storedQuotes[0].InputResaleUSD = 999.0
	if history[0].InputMicro == 999_000_000 {
		t.Error("record tracked a later mutation of its source quote")
	}
}

func TestQuoteRecordLateEventRefundlessAndDuplicateSafe(t *testing.T) {
	mp := NewMarkupPricer(nil, &stubPricer{p: Price{InputPerM: 2.0, OutputPerM: 4.0, CacheWritePerM: 1.0, CacheReadPerM: 0.5}}, nil)

	quote := func(tok, out, cw, cr int64) *ResellerQuote {
		t.Helper()
		q, err := mp.Quote(context.Background(), "org-1", "prov", "m", tok, out, cw, cr)
		if err != nil {
			t.Fatalf("Quote: %v", err)
		}
		return q
	}
	project := func(id string, q *ResellerQuote) QuoteRecord {
		t.Helper()
		rec, err := ProjectQuoteRecord(id, q)
		if err != nil {
			t.Fatalf("ProjectQuoteRecord %s: %v", id, err)
		}
		return rec
	}

	set := map[string]QuoteRecord{}
	var total money.MicroUSD
	for _, id := range []string{"req-1", "req-2", "req-3"} {
		rec := project(id, quote(50_000, 20_000, 0, 0))
		set[id] = rec
		total += rec.TotalMicro
	}
	before := canonicalList([]QuoteRecord{set["req-1"], set["req-2"], set["req-3"]})

	sumSet := func() money.MicroUSD {
		var s money.MicroUSD
		for _, r := range set {
			s += r.TotalMicro
		}
		return s
	}

	// Duplicate delivery of an already-recorded event (same identity, same
	// floats) projects to the identical record: a keep-first merge sees no
	// change — no duplicate money, no loss.
	dupRec := project("req-1", quote(50_000, 20_000, 0, 0))
	if diff := cmp.Diff(set["req-1"], dupRec); diff != "" {
		t.Fatalf("duplicate delivery diverged from the recorded value (-recorded +duplicate):\n%s", diff)
	}
	if got := sumSet(); got != total {
		t.Errorf("duplicate delivery moved the total: %d -> %d", int64(total), int64(got))
	}

	// A late correction under the SAME identity with different usage yields a
	// DIFFERENT record for that identity: the collision is detectable by
	// plain equality, and the keep-first merge preserves history — the
	// discrepancy surfaces as a reportable violation instead of a silent
	// restatement.
	lateSameID := project("req-1", quote(90_000, 20_000, 0, 0))
	if diff := cmp.Diff(set["req-1"], lateSameID); diff == "" {
		t.Fatal("same identity with different usage produced an identical record; collision is undetectable")
	}
	if got := sumSet(); got != total {
		t.Errorf("collision handling moved the total: %d -> %d", int64(total), int64(got))
	}

	// A genuine late event appends refundlessly: prior records stay
	// byte-identical, the total grows by exactly the new record's own total,
	// and nothing anywhere decreases.
	late4 := project("req-4", quote(70_000, 10_000, 5_000, 2_000))
	appended := []QuoteRecord{set["req-1"], set["req-2"], set["req-3"], late4}
	if diff := cmp.Diff(before, canonicalList(appended[:3])); diff != "" {
		t.Fatalf("late event rewrote prior records (-before +after):\n%s", diff)
	}
	var afterLate money.MicroUSD
	for _, r := range appended {
		if r.TotalMicro < 0 {
			t.Errorf("negative record total after late event: %s = %d", r.RequestID, int64(r.TotalMicro))
		}
		for _, l := range r.DetailLines() {
			if l.Micro < 0 {
				t.Errorf("negative detail line after late event: %s/%s = %d", r.RequestID, l.Kind, int64(l.Micro))
			}
		}
		afterLate += r.TotalMicro
	}
	if afterLate != total+late4.TotalMicro {
		t.Errorf("late event total %d != prior %d + late %d", int64(afterLate), int64(total), int64(late4.TotalMicro))
	}
}

func TestQuoteRecordCanonicalStableShape(t *testing.T) {
	mp := NewMarkupPricer(nil, &stubPricer{p: Price{InputPerM: 2.5, OutputPerM: 10.0, CacheWritePerM: 3.125, CacheReadPerM: 1.25}}, nil)
	fixedOverrideOrg(t, mp, "org-c", "gpt-4o", 2.0, 10.0)

	q, err := mp.Quote(context.Background(), "org-c", "openai", "gpt-4o", 1_300_000, 500_000, 100_000, 200_000)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := ProjectQuoteRecord("req-canonical", q)
	if err != nil {
		t.Fatal(err)
	}

	want := "quote-record/v1\treq-canonical\tgpt-4o" +
		"\tinput=2000000\toutput=5000000\tcache_write=312500\tcache_read=250000" +
		"\ttotal=7562500"
	if got := rec.Canonical(); got != want {
		t.Errorf("canonical shape:\ngot  %q\nwant %q", got, want)
	}
	if again := rec.Canonical(); again != want {
		t.Errorf("canonical not stable on the same record: %q", again)
	}

	sameQuoteOtherID := *q
	other, err := ProjectQuoteRecord("req-other", &sameQuoteOtherID)
	if err != nil {
		t.Fatal(err)
	}
	if other.Canonical() == rec.Canonical() {
		t.Error("different request identity rendered the same canonical string")
	}
}
