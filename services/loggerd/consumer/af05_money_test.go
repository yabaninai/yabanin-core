package consumer

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/reireirei/yabanin/pkg/money"
)

// jsonRoundTrip re-encodes a quote the way the event wire does: the
// publisher marshals the float64 field, the consumer JSON-decodes it back
// into the event map.
func jsonRoundTrip(t *testing.T, v float64) interface{} {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %v: %v", v, err)
	}
	var out interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return out
}

// AF-05 acceptance: 1000 individual requests priced at $0.004 each bill a
// combined $4.00 — the projection resolves each event to an exact micro-USD
// charge instead of rounding every event independently to whole cents
// (math.Round(0.004*100) == 0), which silently dropped the entire amount.
func TestResaleDeductionMicro_ThousandSubCentRequestsSumToFourDollars(t *testing.T) {
	const requests = 1000
	const priceUSD = 0.004

	price, err := money.FromUSD(priceUSD)
	if err != nil {
		t.Fatalf("FromUSD(0.004): %v", err)
	}
	if price != 4000 {
		t.Fatalf("FromUSD(0.004) = %d micro, want 4000", int64(price))
	}

	var totalMicro int64
	for i := 0; i < requests; i++ {
		micro, state := resaleDeductionMicro(price, price, money.QuotePositive, money.QuotePositive)
		if state != money.QuotePositive {
			t.Fatalf("request %d: charge state = %v, want QuotePositive", i, state)
		}
		totalMicro += int64(micro)
	}

	if totalMicro != 4_000_000 {
		t.Fatalf("1000 x $0.004 billed %d micro ($%.4f), want 4000000 micro ($4.0000)", totalMicro, float64(totalMicro)/1e6)
	}
}

// The durable settlement intent carries the exact micro amount; the legacy
// amount_cents column keeps its rounded compatibility projection.
func TestResaleDeductionMicro_ExactMicroWithCompatCents(t *testing.T) {
	cases := []struct {
		name      string
		costUSD   float64
		resaleUSD float64
		costOk    bool
		resaleOk  bool
		wantMicro int64
		wantCents int64
		wantState money.QuoteState
	}{
		{"sub-cent resale", 0.001, 0.004, true, true, 4000, 0, money.QuotePositive},
		{"exact cents resale", 0, 0.05, true, true, 50000, 5, money.QuotePositive},
		{"falls back to cost", 0.004, 0, true, true, 4000, 0, money.QuotePositive},
		{"genuine zero resale", 0, 0, true, true, 0, 0, money.QuoteZero},
		{"third-of-cent rounds down compat", 0, 0.00333, true, true, 3330, 0, money.QuotePositive},
		{"zero resale falls to positive cost", 0.02, 0, true, true, 20000, 2, money.QuotePositive},
		{"unknown resale valid cost", 0.02, 0, true, false, 20000, 2, money.QuotePositive},
		{"valid resale unknown cost", 0, 0.01, false, true, 10000, 1, money.QuotePositive},
		{"both unknown", 0, 0, false, false, 0, 0, money.QuoteUnknown},
		{"unknown resale zero cost is genuine zero", 0, 0, true, false, 0, 0, money.QuoteZero},
		{"zero resale unknown cost is genuine zero", 0, 0, false, true, 0, 0, money.QuoteZero},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cost, costState := money.MicroUSD(0), money.QuoteUnknown
			if tc.costOk {
				cost, costState = money.QuoteFromUSD(tc.costUSD, true)
			}
			resale, resaleState := money.MicroUSD(0), money.QuoteUnknown
			if tc.resaleOk {
				resale, resaleState = money.QuoteFromUSD(tc.resaleUSD, true)
			}
			micro, state := resaleDeductionMicro(cost, resale, costState, resaleState)
			if int64(micro) != tc.wantMicro || state != tc.wantState {
				t.Fatalf("resaleDeductionMicro = (%d, %v), want (%d, %v)", int64(micro), state, tc.wantMicro, tc.wantState)
			}
			if gotCents := micro.Cents(); gotCents != tc.wantCents {
				t.Fatalf("compat cents = %d, want %d", gotCents, tc.wantCents)
			}
		})
	}
}

// eventQuote validates money fields at the event boundary: missing,
// unparseable, non-finite, negative and out-of-range values are QuoteUnknown
// — a distinct state from a genuine zero, never billed as either.
func TestEventQuote_BoundaryValidation(t *testing.T) {
	t.Run("missing key is unknown", func(t *testing.T) {
		if _, state := eventQuote(map[string]interface{}{}, "resale_cost_usd"); state != money.QuoteUnknown {
			t.Fatalf("missing field state = %v, want QuoteUnknown", state)
		}
	})
	t.Run("nil value is unknown", func(t *testing.T) {
		if _, state := eventQuote(map[string]interface{}{"resale_cost_usd": nil}, "resale_cost_usd"); state != money.QuoteUnknown {
			t.Fatalf("nil field state = %v, want QuoteUnknown", state)
		}
	})
	t.Run("string values parse", func(t *testing.T) {
		micro, state := eventQuote(map[string]interface{}{"resale_cost_usd": "0.004"}, "resale_cost_usd")
		if state != money.QuotePositive || micro != 4000 {
			t.Fatalf("string quote = (%d, %v), want (4000, QuotePositive)", int64(micro), state)
		}
	})
	t.Run("numeric values parse", func(t *testing.T) {
		for _, v := range []interface{}{0.004, float32(0.004), 0, int(0), int64(0)} {
			_, state := eventQuote(map[string]interface{}{"resale_cost_usd": v}, "resale_cost_usd")
			if state != money.QuotePositive && state != money.QuoteZero {
				t.Fatalf("numeric quote %v state = %v", v, state)
			}
		}
	})
	t.Run("unparseable string is unknown", func(t *testing.T) {
		if _, state := eventQuote(map[string]interface{}{"resale_cost_usd": "not-a-number"}, "resale_cost_usd"); state != money.QuoteUnknown {
			t.Fatalf("unparseable state = %v, want QuoteUnknown", state)
		}
	})
	t.Run("non-finite and negative are unknown, never zero", func(t *testing.T) {
		for name, v := range map[string]interface{}{
			"NaN":       "NaN",
			"+Inf":      "Inf",
			"-Inf":      "-Inf",
			"negative":  "-0.01",
			"overflow":  "1e30",
			"bool junk": true,
		} {
			_, state := eventQuote(map[string]interface{}{"resale_cost_usd": v}, "resale_cost_usd")
			if state != money.QuoteUnknown {
				t.Fatalf("%s: state = %v, want QuoteUnknown", name, state)
			}
		}
	})
	t.Run("genuine zero is zero", func(t *testing.T) {
		for _, v := range []interface{}{"0", "0.0", 0.0, int64(0)} {
			micro, state := eventQuote(map[string]interface{}{"resale_cost_usd": v}, "resale_cost_usd")
			if state != money.QuoteZero || micro != 0 {
				t.Fatalf("zero quote %v = (%d, %v), want (0, QuoteZero)", v, int64(micro), state)
			}
		}
	})
}

// Unknown price/usage resolves to a distinct no-charge state — never
// conflated with the zero-quote skip and never charged.
func TestResaleDeductionMicro_UnknownIsNotZero(t *testing.T) {
	micro, state := resaleDeductionMicro(0, 0, money.QuoteUnknown, money.QuoteUnknown)
	if state != money.QuoteUnknown || micro != 0 {
		t.Fatalf("unknown quotes resolved to (%d, %v), want (0, QuoteUnknown)", int64(micro), state)
	}

	// A present zero quote (either source, no positive anywhere) is a
	// genuine zero-cost event: skipped, but as zero — not as unknown.
	micro, state = resaleDeductionMicro(0, 0, money.QuoteZero, money.QuoteUnknown)
	if state != money.QuoteZero || micro != 0 {
		t.Fatalf("valid-zero cost + unknown resale = (%d, %v), want (0, QuoteZero)", int64(micro), state)
	}
}

// (provider, model) as estimated_cost_usd=0 (field present) with
// cost_status="unknown_price". The mapper must classify that zero as
// QuoteUnknown — the unknown path, never a confirmed zero — for both money
// fields, while legacy events (absent cost_status) and every other status
// keep the raw classification.
func TestParseRequestEvent_UnknownPriceZeroIsUnknownNotZero(t *testing.T) {
	cases := []struct {
		name            string
		fields          map[string]interface{}
		wantCostMicro   int64
		wantCostState   money.QuoteState
		wantResaleState money.QuoteState
	}{
		{"unknown_price + published zero is unknown", map[string]interface{}{
			"cost_status":        "unknown_price",
			"estimated_cost_usd": "0",
			"resale_cost_usd":    "0",
		}, 0, money.QuoteUnknown, money.QuoteUnknown},
		{"unknown_price + absent quotes stay unknown", map[string]interface{}{
			"cost_status": "unknown_price",
		}, 0, money.QuoteUnknown, money.QuoteUnknown},
		{"unknown_price keeps a positive quote positive", map[string]interface{}{
			"cost_status":        "unknown_price",
			"estimated_cost_usd": "0.004",
		}, 4000, money.QuotePositive, money.QuoteUnknown},
		{"priced positive with usage none stays positive (T02 unit-priced audio/images)", map[string]interface{}{
			"cost_status":        "priced",
			"usage_source":       "none",
			"estimated_cost_usd": "0.000075",
		}, 75, money.QuotePositive, money.QuoteUnknown},
		{"legacy event keeps the zero classification", map[string]interface{}{
			"estimated_cost_usd": "0",
			"resale_cost_usd":    "0",
		}, 0, money.QuoteZero, money.QuoteZero},
		{"priced zero stays a genuine zero", map[string]interface{}{
			"cost_status":        "priced",
			"estimated_cost_usd": "0",
			"resale_cost_usd":    "0",
		}, 0, money.QuoteZero, money.QuoteZero},
		{"no_usage zero stays zero (pre-provider denial)", map[string]interface{}{
			"cost_status":        "no_usage",
			"estimated_cost_usd": "0",
		}, 0, money.QuoteZero, money.QuoteUnknown},
		{"cache_hit zero stays zero", map[string]interface{}{
			"cost_status":        "cache_hit",
			"estimated_cost_usd": "0",
		}, 0, money.QuoteZero, money.QuoteUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseRequestEvent(tc.fields)
			if int64(ev.costQuote) != tc.wantCostMicro || ev.costQuoteState != tc.wantCostState {
				t.Fatalf("cost quote = (%d, %v), want (%d, %v)", int64(ev.costQuote), ev.costQuoteState, tc.wantCostMicro, tc.wantCostState)
			}
			if ev.resaleQuoteState != tc.wantResaleState {
				t.Fatalf("resale quote state = %v, want %v", ev.resaleQuoteState, tc.wantResaleState)
			}
			// The stored cost_status column is verbatim in every case — the
			// gate refines the money state, never the storage projection.
			if ev.acct.costStatus != tc.fields["cost_status"] && tc.fields["cost_status"] != nil {
				t.Fatalf("cost_status column = %q, want %q", ev.acct.costStatus, tc.fields["cost_status"])
			}
		})
	}
}

// settlement boundary — no wallet intent, never a confirmed zero — while the
func TestResaleDeductionMicro_UnknownPriceEventSettlesUnknown(t *testing.T) {
	ev := parseRequestEvent(map[string]interface{}{
		"org_id":             "org-1",
		"request_id":         "req-r038",
		"team_id":            "team-1",
		"cost_status":        "unknown_price",
		"estimated_cost_usd": "0",
		"resale_cost_usd":    "0",
	})
	micro, state := resaleDeductionMicro(ev.costQuote, ev.resaleQuote, ev.costQuoteState, ev.resaleQuoteState)
	if state != money.QuoteUnknown || micro != 0 {
		t.Fatalf("unknown_price event settled as (%d, %v), want (0, QuoteUnknown)", int64(micro), state)
	}

	plan := scopeChargePlan(ev, micro, state)
	for _, sc := range plan {
		if sc.kind == ChargeKindResaleDeduction {
			t.Fatalf("unknown_price event produced a wallet intent %+v", sc)
		}
		if sc.kind == ChargeKindTeamSpend && (sc.amount != 0 || sc.key == "") {
			t.Fatalf("team count intent = %+v, want zero-amount with attributed key (IMP-13)", sc)
		}
	}
}

// under the gate: a malformed, negative, non-finite or out-of-range quote is
// QuoteUnknown at the boundary gate, and the unknown_price refinement never
// promotes it to a billable or "genuine zero" state. A junk-typed
// cost_status falls back to the "legacy" default and must NOT activate the
// gate: only the producer's verbatim "unknown_price" marker refines.
func TestParseRequestEvent_UnknownPriceGateInvalidInputs(t *testing.T) {
	t.Run("invalid quotes stay unknown under unknown_price", func(t *testing.T) {
		for name, v := range map[string]interface{}{
			"negative": "-0.01",
			"NaN":      "NaN",
			"+Inf":     "Inf",
			"-Inf":     "-Inf",
			"overflow": "1e30",
			"junk":     "not-a-number",
			"bool":     true,
		} {
			ev := parseRequestEvent(map[string]interface{}{
				"cost_status":        "unknown_price",
				"estimated_cost_usd": v,
				"resale_cost_usd":    v,
			})
			if ev.costQuoteState != money.QuoteUnknown || ev.resaleQuoteState != money.QuoteUnknown {
				t.Fatalf("%s: states = (%v, %v), want (unknown, unknown)", name, ev.costQuoteState, ev.resaleQuoteState)
			}
			if ev.costQuote != 0 || ev.resaleQuote != 0 {
				t.Fatalf("%s: invalid quote yielded a nonzero amount (%d, %d)", name, int64(ev.costQuote), int64(ev.resaleQuote))
			}
		}
	})
	t.Run("junk-typed cost_status is legacy and does not activate the gate", func(t *testing.T) {
		ev := parseRequestEvent(map[string]interface{}{
			"cost_status":        123,
			"estimated_cost_usd": "0",
		})
		if ev.acct.costStatus != "legacy" {
			t.Fatalf("non-string cost_status stored = %q, want %q", ev.acct.costStatus, "legacy")
		}
		if ev.costQuoteState != money.QuoteZero {
			t.Fatalf("raw zero under junk cost_status = %v, want QuoteZero (raw classification)", ev.costQuoteState)
		}
	})
}

// a quote beyond MaxUSD is out of range at the boundary gate — QuoteUnknown,
// never billed — under both a priced and an unknown_price status. The exact
// MaxUSD quote is the largest billable amount: positive at MaxInt64 micro,
// with the exact Split round-trip (Split() == m) intact at the boundary.
func TestParseRequestEvent_LargeQuoteBoundariesNeverBill(t *testing.T) {
	t.Run("out-of-range quote is unknown, never billed", func(t *testing.T) {
		for _, status := range []string{"priced", "unknown_price"} {
			ev := parseRequestEvent(map[string]interface{}{
				"cost_status":        status,
				"estimated_cost_usd": "2.25e13",
			})
			if ev.costQuoteState != money.QuoteUnknown || ev.costQuote != 0 {
				t.Fatalf("%s: E5 quote = (%d, %v), want (0, QuoteUnknown)", status, int64(ev.costQuote), ev.costQuoteState)
			}
		}
	})
	t.Run("exact MaxUSD quote is the largest billable positive", func(t *testing.T) {
		ev := parseRequestEvent(map[string]interface{}{
			"cost_status":        "priced",
			"estimated_cost_usd": money.MaxUSD,
		})
		if ev.costQuoteState != money.QuotePositive || int64(ev.costQuote) != math.MaxInt64 {
			t.Fatalf("MaxUSD quote = (%d, %v), want (MaxInt64, QuotePositive)", int64(ev.costQuote), ev.costQuoteState)
		}
		cents, rem := ev.costQuote.Split()
		if rem < 0 || rem >= money.MicroUSD(money.MicroPerCent) || cents*money.MicroPerCent+int64(rem) != int64(ev.costQuote) {
			t.Fatalf("Split at MaxInt64 micro = (%d, %d): round-trip broken", cents, int64(rem))
		}
	})
}

// retry decomposition: the gate is a pure projection of the event —
// redelivery of the identical event (the stream's at-least-once contract,
// deduplicated by the durable inbox) classifies byte-identically. Any
// divergence between redeliveries would be a stateful money gate.
func TestParseRequestEvent_RedeliveryIsDeterministic(t *testing.T) {
	for _, fields := range []map[string]interface{}{
		{
			"org_id":             "org-1",
			"request_id":         "req-r038-retry",
			"cost_status":        "unknown_price",
			"estimated_cost_usd": "0",
			"resale_cost_usd":    "0",
		},
		{
			"org_id":             "org-1",
			"request_id":         "req-r038-retry-priced",
			"cost_status":        "priced",
			"estimated_cost_usd": "0.004",
			"resale_cost_usd":    "0.004",
		},
	} {
		a, b := parseRequestEvent(fields), parseRequestEvent(fields)
		if a.costQuote != b.costQuote || a.resaleQuote != b.resaleQuote ||
			a.costQuoteState != b.costQuoteState || a.resaleQuoteState != b.resaleQuoteState ||
			a.acct.costStatus != b.acct.costStatus {
			t.Fatalf("redelivery of %q diverged: (%d,%v/%d,%v,%q) vs (%d,%v/%d,%v,%q)",
				fields["request_id"],
				int64(a.costQuote), a.costQuoteState, int64(a.resaleQuote), a.resaleQuoteState, a.acct.costStatus,
				int64(b.costQuote), b.costQuoteState, int64(b.resaleQuote), b.resaleQuoteState, b.acct.costStatus)
		}
	}
}

// observability only (ADR-0001 §5.3) — the quote gates decide money, so a
// cancelled or interrupted request keeps its quote classification: an
// unpriced interrupt stays unknown (never a confirmed zero), a genuinely
// free interrupt stays zero, and an invalid termination string is treated
// as absent without touching money.
func TestParseRequestEvent_TerminationNeverFlipsMoneyState(t *testing.T) {
	cases := []struct {
		name          string
		termination   string
		costStatus    string
		costUSD       string
		wantCostState money.QuoteState
	}{
		{"client_cancel of an unpriced request stays unknown", "client_cancel", "unknown_price", "0", money.QuoteUnknown},
		{"idle_timeout of an unpriced request stays unknown", "idle_timeout", "unknown_price", "0", money.QuoteUnknown},
		{"upstream_error of an unpriced request stays unknown", "upstream_error", "unknown_price", "0", money.QuoteUnknown},
		{"client_cancel of a genuinely free request stays zero", "client_cancel", "priced", "0", money.QuoteZero},
		{"invalid termination string is absent for money", "skipped_by_inspection", "unknown_price", "0", money.QuoteUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseRequestEvent(map[string]interface{}{
				"cost_status":        tc.costStatus,
				"estimated_cost_usd": tc.costUSD,
				"termination":        tc.termination,
			})
			if ev.costQuoteState != tc.wantCostState {
				t.Fatalf("termination %q: cost state = %v, want %v", tc.termination, ev.costQuoteState, tc.wantCostState)
			}
		})
	}
}

// cost units and rounding" fixture: a priced request survives the event
// boundary with a byte-reproducible exact micro-USD amount. The gateway's
// float64 cost chain publishes the 1-ulp drift marker (E1:
// 0.007500000000000001); the boundary must classify it identically to the
// clean quote — same exact micro amount (E6 string-round-trip
// reproducibility at the µUSD boundary), positive state, exact Split
// round-trip, rounded compat-cent projection, and an exact wallet intent.
func TestParseRequestEvent_PricedWorkingPathExactReproducible(t *testing.T) {
	cleanFloat, driftFloat := 0.0075, 0.007500000000000001
	a, err := money.FromUSD(cleanFloat)
	if err != nil {
		t.Fatalf("FromUSD(0.0075): %v", err)
	}
	b, err := money.FromUSD(driftFloat)
	if err != nil {
		t.Fatalf("FromUSD(0.007500000000000001): %v", err)
	}
	if a != 7500 || b != 7500 || a != b {
		t.Fatalf("E1/E6 reproducibility broken: FromUSD = (%d, %d), want (7500, 7500)", int64(a), int64(b))
	}

	for name, published := range map[string]interface{}{
		"clean string":     "0.0075",
		"drifted string":   "0.007500000000000001",
		"clean float64":    cleanFloat,
		"drifted float64":  driftFloat,
		"json round-trip":  jsonRoundTrip(t, cleanFloat),
		"json drift round": jsonRoundTrip(t, driftFloat),
	} {
		ev := parseRequestEvent(map[string]interface{}{
			"org_id":             "org-1",
			"request_id":         "req-r038-e1",
			"cost_status":        "priced",
			"estimated_cost_usd": published,
			"resale_cost_usd":    published,
		})
		if ev.costQuoteState != money.QuotePositive || ev.resaleQuoteState != money.QuotePositive {
			t.Fatalf("%s: states = (%v, %v), want (positive, positive)", name, ev.costQuoteState, ev.resaleQuoteState)
		}
		if ev.costQuote != 7500 || ev.resaleQuote != 7500 {
			t.Fatalf("%s: quotes = (%d, %d), want exact (7500, 7500) micro", name, int64(ev.costQuote), int64(ev.resaleQuote))
		}
		// Exact cents + sub-cent remainder recompose to the same amount;
		// the legacy amount_cents column keeps its rounded projection.
		cents, rem := ev.costQuote.Split()
		if cents != 0 || rem != 7500 || cents*money.MicroPerCent+int64(rem) != int64(ev.costQuote) {
			t.Fatalf("%s: Split = (%d, %d), want (0, 7500) with exact recombination", name, cents, int64(rem))
		}
		if ev.costQuote.Cents() != 1 {
			t.Fatalf("%s: compat cents = %d, want 1", name, ev.costQuote.Cents())
		}
		micro, state := resaleDeductionMicro(ev.costQuote, ev.resaleQuote, ev.costQuoteState, ev.resaleQuoteState)
		if state != money.QuotePositive || micro != 7500 {
			t.Fatalf("%s: settled (%d, %v), want (7500, positive)", name, int64(micro), state)
		}
	}
}

// RESOLVED (owner decision 2026-10-12): a present, valid, POSITIVE quote
// below half a micro-USD rounds UP to the 1 µUSD minimum and settles as a
// known, billable price — no invisible zeros, billing always visible. A
// rounded quote is a known price: under cost_status="unknown_price" it stays
// QuotePositive, never the unknown downgrade. Exactly-zero usage keeps the
// genuine QuoteZero classification (unbilled).
func TestParseRequestEvent_SubMicroPositiveQuoteRoundsUpToOneMicro(t *testing.T) {
	t.Run("collapsed positive rounds up to the 1 µUSD minimum and bills", func(t *testing.T) {
		for _, published := range []interface{}{"4.5e-07", "0.00000045", "0.00000049", 4.5e-07} {
			ev := parseRequestEvent(map[string]interface{}{
				"org_id":             "org-1",
				"request_id":         "req-r038-e3",
				"team_id":            "team-1",
				"cost_status":        "priced",
				"estimated_cost_usd": published,
				"resale_cost_usd":    published,
			})
			if ev.costQuote != 1 || ev.costQuoteState != money.QuotePositive || ev.resaleQuoteState != money.QuotePositive {
				t.Fatalf("sub-µUSD quote %v = (%d, %v/%v), want (1, positive/positive)",
					published, int64(ev.costQuote), ev.costQuoteState, ev.resaleQuoteState)
			}
			micro, state := resaleDeductionMicro(ev.costQuote, ev.resaleQuote, ev.costQuoteState, ev.resaleQuoteState)
			if micro != 1 || state != money.QuotePositive {
				t.Fatalf("sub-µUSD quote %v settled (%d, %v), want billed (1, positive)", published, int64(micro), state)
			}
			plan := scopeChargePlan(ev, micro, state)
			var wallet *scopeCharge
			for i := range plan {
				if plan[i].kind == ChargeKindResaleDeduction {
					wallet = &plan[i]
				}
			}
			if wallet == nil {
				t.Fatalf("sub-µUSD quote %v produced no wallet intent (invisible zero)", published)
			}
			if wallet.amount != 1 {
				t.Fatalf("wallet intent amount = %d, want the 1 µUSD minimum", int64(wallet.amount))
			}
		}
	})
	t.Run("half-micro boundary already bills the minimum", func(t *testing.T) {
		ev := parseRequestEvent(map[string]interface{}{
			"cost_status":        "priced",
			"estimated_cost_usd": "0.0000005",
		})
		if ev.costQuote != 1 || ev.costQuoteState != money.QuotePositive {
			t.Fatalf("half-micro quote = (%d, %v), want (1, positive)", int64(ev.costQuote), ev.costQuoteState)
		}
	})
	t.Run("exactly-zero usage stays a genuine zero", func(t *testing.T) {
		for _, published := range []interface{}{"0", "0.0", 0.0} {
			ev := parseRequestEvent(map[string]interface{}{
				"org_id":             "org-1",
				"request_id":         "req-r038-e3-zero",
				"team_id":            "team-1",
				"cost_status":        "priced",
				"estimated_cost_usd": published,
				"resale_cost_usd":    published,
			})
			if ev.costQuote != 0 || ev.costQuoteState != money.QuoteZero || ev.resaleQuoteState != money.QuoteZero {
				t.Fatalf("zero quote %v = (%d, %v/%v), want (0, zero/zero)",
					published, int64(ev.costQuote), ev.costQuoteState, ev.resaleQuoteState)
			}
			micro, state := resaleDeductionMicro(ev.costQuote, ev.resaleQuote, ev.costQuoteState, ev.resaleQuoteState)
			if micro != 0 || state != money.QuoteZero {
				t.Fatalf("zero quote %v settled (%d, %v), want unbilled (0, zero)", published, int64(micro), state)
			}
		}
	})
	t.Run("a rounded quote is a known price, not unknown_price", func(t *testing.T) {
		ev := parseRequestEvent(map[string]interface{}{
			"cost_status":        "unknown_price",
			"estimated_cost_usd": "4.5e-07",
		})
		if ev.costQuote != 1 || ev.costQuoteState != money.QuotePositive {
			t.Fatalf("sub-µUSD quote under unknown_price = (%d, %v), want (1, positive)", int64(ev.costQuote), ev.costQuoteState)
		}
	})
}

// suppress a known resale price. The unknown_price gate downgrades only the
// zero placeholders — a positive resale quote still resolves to the exact
// wallet charge (resale wins over base, resaleDeductionMicro contract),
// while the unknown cost keeps the observability path honest.
func TestResaleDeductionMicro_UnknownPriceEventResaleStillBills(t *testing.T) {
	ev := parseRequestEvent(map[string]interface{}{
		"org_id":             "org-1",
		"request_id":         "req-r038-resale",
		"team_id":            "team-1",
		"cost_status":        "unknown_price",
		"estimated_cost_usd": "0",
		"resale_cost_usd":    "0.004",
	})
	micro, state := resaleDeductionMicro(ev.costQuote, ev.resaleQuote, ev.costQuoteState, ev.resaleQuoteState)
	if state != money.QuotePositive || int64(micro) != 4000 {
		t.Fatalf("unknown cost + positive resale = (%d, %v), want (4000, QuotePositive)", int64(micro), state)
	}

	plan := scopeChargePlan(ev, micro, state)
	var wallet *scopeCharge
	for i := range plan {
		if plan[i].kind == ChargeKindResaleDeduction {
			wallet = &plan[i]
		}
	}
	if wallet == nil {
		t.Fatal("known resale price under unknown cost produced no wallet intent")
	}
	if wallet.amount != 4000 {
		t.Fatalf("wallet intent amount = %d, want exact 4000", int64(wallet.amount))
	}
}
