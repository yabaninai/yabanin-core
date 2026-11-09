package budget

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// fakeRateSource serves hand-picked rates keyed by "provider:model".
type fakeRateSource map[string]struct {
	rates Rates
	ok    bool
}

func (f fakeRateSource) Rates(_ context.Context, _ PriceScope, _, provider, model string) (Rates, bool) {
	e, ok := f[provider+":"+model]
	if !ok {
		return Rates{}, false
	}
	return e.rates, e.ok
}

func fakeEntry(in, out float64) struct {
	rates Rates
	ok    bool
} {
	return struct {
		rates Rates
		ok    bool
	}{Rates{InUSDPerM: in, OutUSDPerM: out}, true}
}

// fakeBasePricer returns one fixed price for every model.
type fakeBasePricer struct{ p pricing.Price }

func (f fakeBasePricer) Lookup(_, _ string) (pricing.Price, bool) { return f.p, true }

func ptr(v int64) *int64 { return &v }

// ADR-0001 rev. 3 §4.3: bound is the max over planned-chain candidates.
func TestEstimateBoundMaxOverChain(t *testing.T) {
	src := fakeRateSource{
		"a:cheap":  fakeEntry(1, 2),
		"b:pricey": fakeEntry(5, 5),
	}
	req := EstimateRequest{
		Chain:      []ChainHop{{Provider: "a", Model: "cheap"}, {Provider: "b", Model: "pricey"}},
		InputBytes: 5, // in_est = ceil(2*5/5) = 2
		MaxTokens:  ptr(1_000_000),
	}
	est, err := EstimateBound(context.Background(), src, PriceScopeTeamMonth, "org1", req)
	if err != nil {
		t.Fatalf("EstimateBound: %v", err)
	}
	// USD per hop = (in_rate*in_est + out_rate*out_cap) / 1e6:
	// cheap: (1*2 + 2*1e6)/1e6 = 2.000002 USD; pricey: (5*2 + 5*1e6)/1e6 = 5.00001 USD.
	if est.BoundMicroUSD != 5_000_010 {
		t.Fatalf("bound = %d, want 5000010", int64(est.BoundMicroUSD))
	}
	if est.MaxHop != "b:pricey" {
		t.Fatalf("max hop = %q, want b:pricey", est.MaxHop)
	}
	if est.InEstTokens != 2 || est.OutCapTokens != 1_000_000 {
		t.Fatalf("in/out = %d/%d, want 2/1000000", est.InEstTokens, est.OutCapTokens)
	}
	if est.PriceBasis != BasisBase {
		t.Fatalf("basis = %q, want %q", est.PriceBasis, BasisBase)
	}
	if len(est.Priced) != 2 || len(est.Unpriced) != 0 {
		t.Fatalf("priced/unpriced = %v/%v", est.Priced, est.Unpriced)
	}
}

// I3: unpriced candidates are excluded; refusal only when none remain.
func TestEstimateBoundUnpricedExcluded(t *testing.T) {
	src := fakeRateSource{
		"a:known": fakeEntry(2, 2),
		"b:miss":  {rates: Rates{}, ok: false},
	}
	req := EstimateRequest{
		Chain:      []ChainHop{{Provider: "a", Model: "known"}, {Provider: "b", Model: "miss"}},
		InputBytes: 5,
		MaxTokens:  ptr(1_000_000),
	}
	est, err := EstimateBound(context.Background(), src, PriceScopeAgentDay, "org1", req)
	if err != nil {
		t.Fatalf("EstimateBound: %v", err)
	}
	// Only the priced candidate contributes: (2*2 + 2*1e6)/1e6 = 2.000004 USD.
	if est.BoundMicroUSD != 2_000_004 {
		t.Fatalf("bound = %d, want 2000004", int64(est.BoundMicroUSD))
	}
	if len(est.Unpriced) != 1 || est.Unpriced[0] != "b:miss" {
		t.Fatalf("unpriced = %v, want [b:miss]", est.Unpriced)
	}

	allMissing := req
	allMissing.Chain = []ChainHop{{Provider: "b", Model: "miss"}}
	_, err = EstimateBound(context.Background(), src, PriceScopeAgentDay, "org1", allMissing)
	if !errors.Is(err, ErrUnpricedModel) {
		t.Fatalf("err = %v, want ErrUnpricedModel", err)
	}
	if !stringsModelUnpriced(err) {
		t.Fatalf("err text %q must carry model_unpriced for the 403 mapping", err)
	}

	empty := req
	empty.Chain = nil
	if _, err := EstimateBound(context.Background(), src, PriceScopeAgentDay, "org1", empty); !errors.Is(err, ErrUnpricedModel) {
		t.Fatalf("empty chain err = %v, want ErrUnpricedModel", err)
	}
}

func stringsModelUnpriced(err error) bool {
	return err != nil && errors.Is(err, ErrUnpricedModel) && fmt.Sprintf("%v", err) != ErrUnpricedModel.Error()
}

// D4/§14: in_est = ceil(bytes/3 * 1.2), plus 1600 tokens per image.
func TestEstimateInputTokensFormula(t *testing.T) {
	cases := []struct {
		bytes int64
		want  int64
	}{
		{0, 0}, {1, 1}, {2, 1}, {3, 2}, {4, 2}, {5, 2}, {6, 3}, {7, 3}, {8, 4},
		{10, 4}, {11, 5}, {2_500_000, 1_000_000}, {2_500_004, 1_000_002},
	}
	for _, c := range cases {
		got, err := EstimateInputTokens(c.bytes, 0)
		if err != nil {
			t.Fatalf("EstimateInputTokens(%d): %v", c.bytes, err)
		}
		if got != c.want {
			t.Fatalf("EstimateInputTokens(%d) = %d, want %d", c.bytes, got, c.want)
		}
		// Integer path must match the ADR float formula exactly in the
		// non-degenerate range (no drift, never an under-estimate).
		floatRef := int64(math.Ceil(float64(c.bytes) / 3 * InputMargin))
		if got != floatRef {
			t.Fatalf("integer in_est %d diverges from ADR float formula %d (bytes=%d)", got, floatRef, c.bytes)
		}
	}
	for b := int64(0); b <= 10_000; b += 7 {
		got, _ := EstimateInputTokens(b, 0)
		ref := int64(math.Ceil(float64(b) / 3 * InputMargin))
		if got != ref {
			t.Fatalf("in_est drift at bytes=%d: %d vs %f", b, got, float64(ref))
		}
	}

	img, err := EstimateInputTokens(0, 3)
	if err != nil || img != 3*ImageTokenEstimate {
		t.Fatalf("image estimate = %d, err %v; want %d", img, err, 3*ImageTokenEstimate)
	}
	mix, _ := EstimateInputTokens(10, 2)
	if want := int64(4 + 2*ImageTokenEstimate); mix != want {
		t.Fatalf("mixed estimate = %d, want %d", mix, want)
	}
	if _, err := EstimateInputTokens(-1, 0); !errors.Is(err, ErrInvalidEstimate) {
		t.Fatalf("negative bytes err = %v, want ErrInvalidEstimate", err)
	}
	if _, err := EstimateInputTokens(0, -2); !errors.Is(err, ErrInvalidEstimate) {
		t.Fatalf("negative images err = %v, want ErrInvalidEstimate", err)
	}
}

// §4.3/D3a: explicit caps win, org default otherwise, embeddings 0.
func TestEstimateOutputCap(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		if got, _ := EstimateOutputCap(EstimateRequest{}); got != DefaultOutputCapTokens {
			t.Fatalf("cap = %d, want %d", got, DefaultOutputCapTokens)
		}
		org := EstimateRequest{DefaultOutCap: 1000}
		if got, _ := EstimateOutputCap(org); got != 1000 {
			t.Fatalf("org default cap = %d, want 1000", got)
		}
		// A non-positive org default falls back to the §14 default.
		bad := EstimateRequest{DefaultOutCap: -5}
		if got, _ := EstimateOutputCap(bad); got != DefaultOutputCapTokens {
			t.Fatalf("fallback cap = %d, want %d", got, DefaultOutputCapTokens)
		}
	})
	t.Run("explicit", func(t *testing.T) {
		req := EstimateRequest{MaxTokens: ptr(100)}
		if got, _ := EstimateOutputCap(req); got != 100 {
			t.Fatalf("cap = %d, want 100", got)
		}
		// Several dialects present: conservative max covers the provider.
		req = EstimateRequest{MaxTokens: ptr(100), MaxCompletionTokens: ptr(50), MaxOutputTokens: ptr(70)}
		if got, _ := EstimateOutputCap(req); got != 100 {
			t.Fatalf("cap = %d, want 100", got)
		}
		// A zero cap counts as unset: the §14 default covers providers that
		// ignore it and generate up to the model maximum.
		zero := EstimateRequest{MaxTokens: ptr(0)}
		if got, _ := EstimateOutputCap(zero); got != DefaultOutputCapTokens {
			t.Fatalf("zero cap = %d, want default %d", got, DefaultOutputCapTokens)
		}
		// An explicit cap beats the (larger) organization default.
		small := EstimateRequest{MaxCompletionTokens: ptr(500)}
		if got, _ := EstimateOutputCap(small); got != 500 {
			t.Fatalf("cap = %d, want 500", got)
		}
	})
	t.Run("embeddings", func(t *testing.T) {
		req := EstimateRequest{Embeddings: true, MaxTokens: ptr(100)}
		if got, _ := EstimateOutputCap(req); got != 0 {
			t.Fatalf("embeddings cap = %d, want 0", got)
		}
	})
	t.Run("negative", func(t *testing.T) {
		req := EstimateRequest{MaxTokens: ptr(-1)}
		if _, err := EstimateOutputCap(req); !errors.Is(err, ErrInvalidEstimate) {
			t.Fatalf("err = %v, want ErrInvalidEstimate", err)
		}
	})
}

// I4: wallet prices at resale, budget scopes at base cost.
func TestEstimateBoundWalletVsBase(t *testing.T) {
	base := fakeBasePricer{p: pricing.Price{InputPerM: 2, OutputPerM: 4}}
	src := ScopedRateSource{
		Base:   BaseRateSource{Pricer: base},
		Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(nil, base, nil)},
	}
	// 2.5M bytes → in_est exactly 1M tokens; embeddings → out_cap 0.
	req := EstimateRequest{Chain: []ChainHop{{Provider: "p", Model: "m"}}, InputBytes: 2_500_000, Embeddings: true}

	wallet, err := EstimateBound(context.Background(), src, PriceScopeWallet, "org1", req)
	if err != nil {
		t.Fatalf("wallet: %v", err)
	}
	team, err := EstimateBound(context.Background(), src, PriceScopeTeamMonth, "org1", req)
	if err != nil {
		t.Fatalf("team: %v", err)
	}
	if wallet.PriceBasis != BasisResale || team.PriceBasis != BasisBase {
		t.Fatalf("basis wallet/team = %q/%q", wallet.PriceBasis, team.PriceBasis)
	}
	// 15% default markup with no DB: 2 * 1.15 = 2.3 USD vs 2 USD base.
	if wallet.BoundMicroUSD != 2_300_000 {
		t.Fatalf("wallet bound = %d, want 2300000", int64(wallet.BoundMicroUSD))
	}
	if team.BoundMicroUSD != 2_000_000 {
		t.Fatalf("team bound = %d, want 2000000", int64(team.BoundMicroUSD))
	}
	if wallet.BoundMicroUSD <= team.BoundMicroUSD {
		t.Fatalf("wallet %d must exceed base %d", int64(wallet.BoundMicroUSD), int64(team.BoundMicroUSD))
	}
}

// Explicit price 0 is a legitimate zero (D7/I3); unknown price never is.
func TestEstimateBoundZeroVsUnknown(t *testing.T) {
	src := fakeRateSource{
		"local:free": fakeEntry(0, 0),
		"p:nan":      {rates: Rates{InUSDPerM: math.NaN(), OutUSDPerM: 1}, ok: true},
	}
	req := EstimateRequest{Chain: []ChainHop{{Provider: "local", Model: "free"}}, InputBytes: 100, MaxTokens: ptr(10)}
	est, err := EstimateBound(context.Background(), src, PriceScopeWallet, "org1", req)
	if err != nil {
		t.Fatalf("free model: %v", err)
	}
	if est.BoundMicroUSD != 0 || est.MaxHop != "local:free" {
		t.Fatalf("bound = %d (hop %s), want 0 on local:free", int64(est.BoundMicroUSD), est.MaxHop)
	}
	if len(est.Priced) != 1 || len(est.Unpriced) != 0 {
		t.Fatalf("a priced zero must stay priced: %v / %v", est.Priced, est.Unpriced)
	}

	nan := req
	nan.Chain = []ChainHop{{Provider: "p", Model: "nan"}}
	_, err = EstimateBound(context.Background(), src, PriceScopeWallet, "org1", nan)
	if !errors.Is(err, ErrUnpricedModel) {
		t.Fatalf("NaN rate err = %v, want ErrUnpricedModel", err)
	}
	if len(est.Unpriced) != 0 {
		t.Fatalf("previous estimate mutated: %v", est.Unpriced)
	}
}

// Nil source for the scope is unpriced, not zero (fail-closed wiring).
func TestEstimateBoundMissingSource(t *testing.T) {
	src := ScopedRateSource{Base: BaseRateSource{Pricer: fakeBasePricer{}}}
	req := EstimateRequest{Chain: []ChainHop{{Provider: "p", Model: "m"}}, MaxTokens: ptr(10)}
	if _, err := EstimateBound(context.Background(), src, PriceScopeWallet, "org1", req); !errors.Is(err, ErrUnpricedModel) {
		t.Fatalf("wallet without resale source err = %v, want ErrUnpricedModel", err)
	}
	team := src
	team.Base = BaseRateSource{}
	if _, err := EstimateBound(context.Background(), team, PriceScopeTeamMonth, "org1", req); !errors.Is(err, ErrUnpricedModel) {
		t.Fatalf("team without base source err = %v, want ErrUnpricedModel", err)
	}
}

// The estimator is pure/read-only: safe under concurrent admission paths.
func TestEstimateBoundConcurrent(t *testing.T) {
	base := fakeBasePricer{p: pricing.Price{InputPerM: 1, OutputPerM: 2}}
	src := ScopedRateSource{
		Base:   BaseRateSource{Pricer: base},
		Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(nil, base, nil)},
	}
	req := EstimateRequest{
		Chain:      []ChainHop{{Provider: "p", Model: "m"}, {Provider: "q", Model: "miss"}},
		InputBytes: 15,
		MaxTokens:  ptr(1000),
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scope := PriceScopeTeamMonth
			if i%2 == 0 {
				scope = PriceScopeWallet
			}
			est, err := EstimateBound(context.Background(), src, scope, "org1", req)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			if est.BoundMicroUSD < 0 {
				t.Errorf("goroutine %d: negative bound", i)
			}
		}(i)
	}
	wg.Wait()
}

func TestBoundEstimateEventFields(t *testing.T) {
	src := fakeRateSource{
		"a:m": fakeEntry(1, 1),
		"b:m": fakeEntry(3, 3),
		"c:m": {rates: Rates{}, ok: false},
	}
	req := EstimateRequest{
		Chain:               []ChainHop{{Provider: "a", Model: "m"}, {Provider: "b", Model: "m"}, {Provider: "c", Model: "m"}},
		InputBytes:          3,
		ImageCount:          1,
		MaxCompletionTokens: ptr(500),
	}
	est, err := EstimateBound(context.Background(), src, PriceScopeSession, "org1", req)
	if err != nil {
		t.Fatalf("EstimateBound: %v", err)
	}
	if est.InEstTokens != 2+ImageTokenEstimate {
		t.Fatalf("in_est = %d, want %d", est.InEstTokens, 2+ImageTokenEstimate)
	}
	if est.OutCapTokens != 500 {
		t.Fatalf("out_cap = %d, want 500", est.OutCapTokens)
	}
	if est.BoundMicroUSD != money.MicroUSD(3*int64(est.InEstTokens)+3*500) {
		t.Fatalf("bound = %d inconsistent with event fields", int64(est.BoundMicroUSD))
	}
	if est.MaxHop != "b:m" || est.PriceBasis != BasisBase {
		t.Fatalf("max/basis = %q/%q", est.MaxHop, est.PriceBasis)
	}
	if fmt.Sprint(est.Priced) != "[a:m b:m]" || fmt.Sprint(est.Unpriced) != "[c:m]" {
		t.Fatalf("chain bookkeeping priced=%v unpriced=%v", est.Priced, est.Unpriced)
	}
}

func TestChainHopKey(t *testing.T) {
	if got := (ChainHop{Provider: "p", Model: "m"}).Key(); got != "p:m" {
		t.Fatalf("key = %q, want p:m", got)
	}
}

// fakeUnitRateSource extends the token stub with per-unit rates keyed by
// "provider:model" (T02 unit pricing path).
type fakeUnitRateSource struct {
	fakeRateSource
	units map[string]struct {
		rate UnitRate
		ok   bool
	}
}

func (f fakeUnitRateSource) UnitRates(_ context.Context, _ PriceScope, _, provider, model string) (UnitRate, bool) {
	e, ok := f.units[provider+":"+model]
	if !ok {
		return UnitRate{}, false
	}
	return e.rate, e.ok
}

func TestEstimateBoundUnitPriced(t *testing.T) {
	src := fakeUnitRateSource{
		// Token rates deliberately absurd: a unit-priced bound must NOT
		// consult them.
		fakeRateSource: fakeRateSource{"openai:tts-1": fakeEntry(1e12, 1e12)},
		units: map[string]struct {
			rate UnitRate
			ok   bool
		}{"openai:tts-1": {UnitRate{Unit: pricing.UnitPerCharacter, Rate: 0.000015}, true}},
	}
	qty := 5.0
	est, err := EstimateBound(context.Background(), src, PriceScopeTeamMonth, "org", EstimateRequest{
		Chain:    []ChainHop{{Provider: "openai", Model: "tts-1"}},
		UnitKind: pricing.UnitPerCharacter,
		UnitQty:  &qty,
	})
	if err != nil {
		t.Fatalf("EstimateBound: %v", err)
	}
	// 5 characters × $0.000015 = $0.000075 = 75 micro-USD, exact.
	if est.BoundMicroUSD != 75 {
		t.Errorf("BoundMicroUSD = %d, want 75", int64(est.BoundMicroUSD))
	}
	if est.PriceBasis != BasisBase {
		t.Errorf("PriceBasis = %s, want %s", est.PriceBasis, BasisBase)
	}
	if len(est.Priced) != 1 || est.Priced[0] != "openai:tts-1" {
		t.Errorf("Priced = %v", est.Priced)
	}
}

func TestEstimateBoundUnitWalletUsesBaseRate(t *testing.T) {
	// Non-token workloads have no resale pipeline: the wallet scope is
	// priced at the SAME base unit rate (T02).
	src := fakeUnitRateSource{
		units: map[string]struct {
			rate UnitRate
			ok   bool
		}{"openai:tts-1": {UnitRate{Unit: pricing.UnitPerCharacter, Rate: 0.000015}, true}},
	}
	qty := 2.0
	wallet, err := EstimateBound(context.Background(), src, PriceScopeWallet, "org", EstimateRequest{
		Chain: []ChainHop{{Provider: "openai", Model: "tts-1"}}, UnitKind: pricing.UnitPerCharacter, UnitQty: &qty,
	})
	if err != nil {
		t.Fatalf("wallet estimate: %v", err)
	}
	if wallet.PriceBasis != BasisResale {
		t.Errorf("wallet PriceBasis = %s", wallet.PriceBasis)
	}
	if wallet.BoundMicroUSD != 30 {
		t.Errorf("wallet BoundMicroUSD = %d, want 30 (base rate)", int64(wallet.BoundMicroUSD))
	}
}

func TestEstimateBoundUnitQuantityValidation(t *testing.T) {
	src := fakeUnitRateSource{
		units: map[string]struct {
			rate UnitRate
			ok   bool
		}{"openai:tts-1": {UnitRate{Unit: pricing.UnitPerCharacter, Rate: 0.000015}, true}},
	}
	req := EstimateRequest{Chain: []ChainHop{{Provider: "openai", Model: "tts-1"}}, UnitKind: pricing.UnitPerCharacter}

	if _, err := EstimateBound(context.Background(), src, PriceScopeSession, "org", req); !errors.Is(err, ErrInvalidEstimate) {
		t.Errorf("nil quantity = %v, want ErrInvalidEstimate", err)
	}
	neg := -1.0
	if _, err := EstimateBound(context.Background(), src, PriceScopeSession, "org", EstimateRequest{Chain: req.Chain, UnitKind: req.UnitKind, UnitQty: &neg}); !errors.Is(err, ErrInvalidEstimate) {
		t.Errorf("negative quantity = %v, want ErrInvalidEstimate", err)
	}
	inf := math.Inf(1)
	if _, err := EstimateBound(context.Background(), src, PriceScopeSession, "org", EstimateRequest{Chain: req.Chain, UnitKind: req.UnitKind, UnitQty: &inf}); !errors.Is(err, ErrInvalidEstimate) {
		t.Errorf("infinite quantity = %v, want ErrInvalidEstimate", err)
	}
	// An explicitly priced ZERO quantity is legitimate: bound 0.
	zero := 0.0
	est, err := EstimateBound(context.Background(), src, PriceScopeSession, "org", EstimateRequest{Chain: req.Chain, UnitKind: req.UnitKind, UnitQty: &zero})
	if err != nil {
		t.Fatalf("zero quantity: %v", err)
	}
	if est.BoundMicroUSD != 0 {
		t.Errorf("zero-quantity bound = %d, want 0", int64(est.BoundMicroUSD))
	}
}

func TestEstimateBoundUnitFailClosed(t *testing.T) {
	qty := 10.0
	// Unit-kind mismatch: the catalog prices per_second_audio, the request
	// bills per character.
	mismatch := fakeUnitRateSource{
		units: map[string]struct {
			rate UnitRate
			ok   bool
		}{"openai:whisper-1": {UnitRate{Unit: pricing.UnitPerAudioSecond, Rate: 0.0001}, true}},
	}
	if _, err := EstimateBound(context.Background(), mismatch, PriceScopeTeamMonth, "org", EstimateRequest{
		Chain: []ChainHop{{Provider: "openai", Model: "whisper-1"}}, UnitKind: pricing.UnitPerCharacter, UnitQty: &qty,
	}); !errors.Is(err, ErrUnpricedModel) {
		t.Errorf("unit-kind mismatch = %v, want ErrUnpricedModel", err)
	}

	// Unpriced model in the unit catalog.
	if _, err := EstimateBound(context.Background(), fakeUnitRateSource{}, PriceScopeTeamMonth, "org", EstimateRequest{
		Chain: []ChainHop{{Provider: "openai", Model: "tts-1"}}, UnitKind: pricing.UnitPerCharacter, UnitQty: &qty,
	}); !errors.Is(err, ErrUnpricedModel) {
		t.Errorf("unit-unpriced model = %v, want ErrUnpricedModel", err)
	}

	// A rate source that only prices tokens (no UnitRateSource) must NOT
	// fall back to token rates for a unit request.
	tokenOnly := fakeRateSource{"openai:tts-1": fakeEntry(10, 30)}
	if _, err := EstimateBound(context.Background(), tokenOnly, PriceScopeTeamMonth, "org", EstimateRequest{
		Chain: []ChainHop{{Provider: "openai", Model: "tts-1"}}, UnitKind: pricing.UnitPerCharacter, UnitQty: &qty,
	}); !errors.Is(err, ErrUnpricedModel) {
		t.Errorf("token-only source + unit request = %v, want ErrUnpricedModel", err)
	}
}

func TestEstimateBoundUnitMaxOverChain(t *testing.T) {
	src := fakeUnitRateSource{
		units: map[string]struct {
			rate UnitRate
			ok   bool
		}{
			"openai:whisper-1": {UnitRate{Unit: pricing.UnitPerAudioSecond, Rate: 0.0001}, true},
			// tts-1 prices only characters — unpriced for a per-second
			// request and excluded per I3.
		},
	}
	qty := 60.0
	est, err := EstimateBound(context.Background(), src, PriceScopeAgentDay, "org", EstimateRequest{
		Chain: []ChainHop{
			{Provider: "openai", Model: "tts-1"},
			{Provider: "openai", Model: "whisper-1"},
		},
		UnitKind: pricing.UnitPerAudioSecond,
		UnitQty:  &qty,
	})
	if err != nil {
		t.Fatalf("EstimateBound: %v", err)
	}
	// 60 seconds × $0.0001 = $0.006 = 6000 micro-USD.
	if est.BoundMicroUSD != 6000 {
		t.Errorf("BoundMicroUSD = %d, want 6000", int64(est.BoundMicroUSD))
	}
	if est.MaxHop != "openai:whisper-1" {
		t.Errorf("MaxHop = %s", est.MaxHop)
	}
	if len(est.Unpriced) != 1 || est.Unpriced[0] != "openai:tts-1" {
		t.Errorf("Unpriced = %v, want [openai:tts-1]", est.Unpriced)
	}
}

func TestScopedRateSourceUnitRates(t *testing.T) {
	unitPricer, err := pricing.NewUnitFilePricer(pricing.UnitFile{
		Source: "s", Date: "2026-09-30", Currency: "USD",
		Units: []pricing.UnitEntry{
			{Provider: "openai", Model: "tts-1", Unit: pricing.UnitPerCharacter, Rate: 0.000015},
			{Provider: "azure", Model: "tts-1", Unit: pricing.UnitPerCharacter, Rate: 0.000016},
		},
	}, "sha256:x")
	if err != nil {
		t.Fatalf("NewUnitFilePricer: %v", err)
	}

	// Nil Units: fail-closed for every scope.
	var empty ScopedRateSource
	if _, ok := empty.UnitRates(context.Background(), PriceScopeWallet, "org", "openai", "tts-1"); ok {
		t.Error("nil Units reported a unit rate")
	}

	src := ScopedRateSource{Base: BaseRateSource{Units: unitPricer}}
	// The base unit rate applies to EVERY scope, wallet included.
	for _, scope := range []PriceScope{PriceScopeWallet, PriceScopeTeamMonth, PriceScopeAgentDay, PriceScopeSession} {
		ur, ok := src.UnitRates(context.Background(), scope, "org", "openai", "tts-1")
		if !ok || ur.Unit != pricing.UnitPerCharacter || ur.Rate != 0.000015 {
			t.Errorf("UnitRates(%s) = %+v, %v", scope, ur, ok)
		}
	}
	// Catalog provider alias resolves (azure-openai → azure).
	ur, ok := src.UnitRates(context.Background(), PriceScopeSession, "org", "azure-openai", "tts-1")
	if !ok || ur.Rate != 0.000016 {
		t.Errorf("UnitRates(azure-openai) = %+v, %v", ur, ok)
	}
	if _, ok := src.UnitRates(context.Background(), PriceScopeSession, "org", "openai", "gpt-4o-mini-tts"); ok {
		t.Error("token-only TTS unexpectedly reported a unit rate")
	}
}

// stubPricePricer serves one fixed price row, cache rates included.
type stubPricePricer struct{ p pricing.Price }

func (s stubPricePricer) Lookup(_, _ string) (pricing.Price, bool) { return s.p, true }

// N03-P06-T03: the pre-request bound (§4.3) prices the whole estimated input
// at the full input rate — provider cache prices are post-execution facts and
// must never LOWER the reservation. The read discount would under-reserve;
// the Anthropic write premium (CacheWritePerM > InputPerM) is a known §4.3
// approximation of the byte-derived in_est, not a license to shave the bound.
func TestEstimateBound_IgnoresCacheRates(t *testing.T) {
	withCache := stubPricePricer{p: pricing.Price{
		InputPerM: 3.0, OutputPerM: 15.0, CacheWritePerM: 3.75, CacheReadPerM: 0.3,
	}}
	cacheStripped := stubPricePricer{p: pricing.Price{InputPerM: 3.0, OutputPerM: 15.0}}

	req := EstimateRequest{
		Chain:      []ChainHop{{Provider: "anthropic", Model: "claude-3-5-sonnet"}},
		InputBytes: 150_000,
		MaxTokens:  ptr(4_096),
	}

	base := BaseRateSource{Pricer: withCache}
	estCache, err := EstimateBound(context.Background(), base, PriceScopeTeamMonth, "org1", req)
	if err != nil {
		t.Fatalf("EstimateBound (cache-priced row): %v", err)
	}
	plain := BaseRateSource{Pricer: cacheStripped}
	estPlain, err := EstimateBound(context.Background(), plain, PriceScopeTeamMonth, "org1", req)
	if err != nil {
		t.Fatalf("EstimateBound (cache-stripped row): %v", err)
	}
	if estCache.BoundMicroUSD != estPlain.BoundMicroUSD {
		t.Fatalf("bound changed with cache rates: %d vs %d (cache prices must not enter the pre-request bound)",
			estCache.BoundMicroUSD, estPlain.BoundMicroUSD)
	}

	// The bound is the full-input-rate product — pin the exact value so a
	// future "optimization" that discounts the bound by CacheReadPerM fails.
	// in_est = ceil(2*150000/5) = 60000; out_cap = 4096.
	want, convErr := money.FromUSD(3.0*float64(estCache.InEstTokens)/1_000_000 + 15.0*float64(estCache.OutCapTokens)/1_000_000)
	if convErr != nil {
		t.Fatalf("FromUSD: %v", convErr)
	}
	if estCache.BoundMicroUSD != want {
		t.Fatalf("bound %d, want full-rate %d", estCache.BoundMicroUSD, want)
	}
}
