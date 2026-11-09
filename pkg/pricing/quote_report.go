package pricing

import (
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/money"
)

// minBillableRecordMicroUSD is the visibility floor for a strictly positive
// quote whose detail lines all round to zero: the smallest representable
// charge, 1 micro-USD. A positive charge must never round into an invisible
// zero on a spend report — the sub-micro residue rounds UP to this floor
// instead of vanishing.
const minBillableRecordMicroUSD = money.MicroUSD(1)

// quoteTotalAgreementTolerance is how far a quote's own total may drift from
// the sum of its detail lines before the quote is rejected as internally
// inconsistent (1 micro-USD, one step at the smallest visible unit). Quotes
// produced by Quote agree exactly; only a hand-built or corrupted struct can
// exceed this.
const quoteTotalAgreementTolerance = 1e-6

// QuoteLineKind names one canonical detail line of a QuoteRecord. The kind
// order input → output → cache_write → cache_read is the stable canonical
// order of every exported detail list.
type QuoteLineKind string

// Canonical detail line kinds, in the stable canonical order.
const (
	LineInput      QuoteLineKind = "input"
	LineOutput     QuoteLineKind = "output"
	LineCacheWrite QuoteLineKind = "cache_write"
	LineCacheRead  QuoteLineKind = "cache_read"
)

// QuoteRecord is the reporting-facing materialization of one settled resale
// quote: exact integer micro-USD detail lines plus a total that is, by
// construction, their exact sum. This is the unit the spend-report and
// reconciliation surfaces can sum without ever disagreeing with themselves:
// the Σ detail == total identity holds in every state, not only in the
// happy path.
//
// A record is an immutable value snapshot. It holds copied integers and
// strings only — never a reference into pricer, override or catalog state —
// so a later price change cannot rewrite an already-materialized record, and
// recomputing a record from the stored quote floats (the settlement
// artifact) always returns the identical value. The projection is a pure
// function: it never reads live prices, which is what makes the recovery
// path structurally unable to re-price history.
type QuoteRecord struct {
	// RequestID is the caller-owned request identity. It is carried
	// opaquely and stably: retries and resumed re-materializations of the
	// same request project to records with the same identity, so the
	// consumer's dedup/recovery join has a stable key.
	RequestID string
	// Model is the quoted model name, copied from the quote.
	Model string

	InputMicro      money.MicroUSD
	OutputMicro     money.MicroUSD
	CacheWriteMicro money.MicroUSD
	CacheReadMicro  money.MicroUSD

	// TotalMicro is the exact integer sum of the four detail lines. It is
	// never rounded independently of them.
	TotalMicro money.MicroUSD
}

// QuoteLine is one non-zero detail line of a QuoteRecord.
type QuoteLine struct {
	Kind  QuoteLineKind
	Micro money.MicroUSD
}

// ProjectQuoteRecord materializes a resale quote into an exact record for
// spend reporting and reconciliation.
//
// Rounding: every detail line converts from its float USD value with the
// money package policy (half away from zero); the total is the exact
// integer sum of the rounded lines. Detail lines are never re-rounded into
// the total and the total is never rounded independently, so a report that
// lists the lines can never disagree with its own total.
//
// Visibility floor: a strictly positive quote whose rounded detail sums to
// zero keeps the minimum 1 micro-USD on its first positive line (canonical
// input → output → cache_write → cache_read order) — a positive charge
// stays visible instead of collapsing into an invisible zero.
//
// Fail-closed: a nil quote, an empty request identity, a non-finite or
// negative line, a quote whose total disagrees with its line sum, a positive
// quote with no positive line to carry the floor, or a line set whose exact
// micro sum overflows returns an error and no record. A malformed quote is
// never silently clamped, truncated or billed as zero. The exact MaxUSD
// boundary is billable, not rejected: the money conversion saturates it to
// MaxInt64 µUSD and the projection carries that amount unchanged.
func ProjectQuoteRecord(requestID string, q *ResellerQuote) (QuoteRecord, error) {
	if strings.TrimSpace(requestID) == "" {
		return QuoteRecord{}, fmt.Errorf("quote record: request identity is required")
	}
	if q == nil {
		return QuoteRecord{}, fmt.Errorf("quote record %s: nil quote", requestID)
	}

	src := []struct {
		kind QuoteLineKind
		usd  float64
	}{
		{LineInput, q.InputResaleUSD},
		{LineOutput, q.OutputResaleUSD},
		{LineCacheWrite, q.CacheWriteResale},
		{LineCacheRead, q.CacheReadResale},
	}

	vals := make([]money.MicroUSD, len(src))
	firstPositive := -1
	for i, ln := range src {
		m, err := money.FromUSD(ln.usd)
		if err != nil {
			return QuoteRecord{}, fmt.Errorf("quote record %s, %s line: %w", requestID, ln.kind, err)
		}
		if m < 0 {
			// Defense-in-depth: the money conversion rejects negatives
			// and saturates at the representable maximum, so a
			// successful conversion of a non-negative line must return
			// a non-negative amount. Should a conversion change ever
			// reintroduce a wrap, the wrapped negative line fails
			// closed here instead of surfacing as a billable record.
			return QuoteRecord{}, fmt.Errorf("quote record %s, %s line: %w", requestID, ln.kind, money.ErrRange)
		}
		if ln.usd > 0 && firstPositive < 0 {
			firstPositive = i
		}
		vals[i] = m
	}

	var floatSum float64
	for _, ln := range src {
		floatSum += ln.usd
	}
	if diff := q.TotalResaleUSD - floatSum; diff > quoteTotalAgreementTolerance || diff < -quoteTotalAgreementTolerance {
		return QuoteRecord{}, fmt.Errorf("quote record %s: total %g disagrees with detail sum %g",
			requestID, q.TotalResaleUSD, floatSum)
	}

	total, err := sumMicro(vals)
	if err != nil {
		return QuoteRecord{}, fmt.Errorf("quote record %s: total: %w", requestID, err)
	}
	if total == 0 && q.TotalResaleUSD > 0 {
		if firstPositive < 0 {
			return QuoteRecord{}, fmt.Errorf(
				"quote record %s: positive total %g has no positive detail line to carry the visibility floor",
				requestID, q.TotalResaleUSD)
		}
		vals[firstPositive] = minBillableRecordMicroUSD
		if total, err = sumMicro(vals); err != nil {
			return QuoteRecord{}, fmt.Errorf("quote record %s: total: %w", requestID, err)
		}
	}

	return QuoteRecord{
		RequestID:       requestID,
		Model:           q.ModelName,
		InputMicro:      vals[0],
		OutputMicro:     vals[1],
		CacheWriteMicro: vals[2],
		CacheReadMicro:  vals[3],
		TotalMicro:      total,
	}, nil
}

// sumMicro adds micro amounts with overflow detection: any exact total
// outside the micro-USD range fails closed instead of wrapping around.
func sumMicro(vals []money.MicroUSD) (money.MicroUSD, error) {
	var sum money.MicroUSD
	for _, v := range vals {
		var err error
		if sum, err = sum.Add(v); err != nil {
			return 0, err
		}
	}
	return sum, nil
}

// DetailLines returns the non-zero detail lines in canonical kind order.
// Their sum equals TotalMicro exactly. The returned slice is a fresh copy;
// callers cannot mutate the record through it.
func (r QuoteRecord) DetailLines() []QuoteLine {
	lines := make([]QuoteLine, 0, 4)
	if r.InputMicro != 0 {
		lines = append(lines, QuoteLine{Kind: LineInput, Micro: r.InputMicro})
	}
	if r.OutputMicro != 0 {
		lines = append(lines, QuoteLine{Kind: LineOutput, Micro: r.OutputMicro})
	}
	if r.CacheWriteMicro != 0 {
		lines = append(lines, QuoteLine{Kind: LineCacheWrite, Micro: r.CacheWriteMicro})
	}
	if r.CacheReadMicro != 0 {
		lines = append(lines, QuoteLine{Kind: LineCacheRead, Micro: r.CacheReadMicro})
	}
	return lines
}

// Canonical renders the record as a stable, versioned single-line string.
// Identical records render byte-identical text across processes, retries and
// resumed recomputes, which is what export comparison and content-level
// recovery checks need. The format is additive-only: future fields may be
// appended, but existing fields are never reordered or reinterpreted, so
// previously exported bytes stay comparable.
func (r QuoteRecord) Canonical() string {
	var b strings.Builder
	b.WriteString("quote-record/v1\t")
	b.WriteString(r.RequestID)
	b.WriteByte('\t')
	b.WriteString(r.Model)
	for _, l := range r.DetailLines() {
		fmt.Fprintf(&b, "\t%s=%d", l.Kind, int64(l.Micro))
	}
	fmt.Fprintf(&b, "\ttotal=%d", int64(r.TotalMicro))
	return b.String()
}
