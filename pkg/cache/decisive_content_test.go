package cache

// N03-P04-T05 unit tests for the decisive-content admission guard. These run
// always (also in -short): the detector's contract against the frozen
// holdout corpus is enforced here WITHOUT Docker — every decisive-axis pair
// must stamp differently (the guard will veto) and every true-duplicate pair
// must stamp identically (the guard must not over-invalidate). The
// Docker-backed replay of the real decision path stays in
// TestHoldoutConfusionMatrix (holdout_test.go).

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stampOf(t *testing.T, prompt string) (string, string) {
	t.Helper()
	ver, fp := DecisiveContentStamp([]byte(prompt))
	require.Equal(t, DecisiveContentVer, ver)
	return ver, fp
}

func TestDecisiveContentStamp_Deterministic(t *testing.T) {
	p := "Summarize the Q3 2025 revenue for Acme Manufacturing"
	_, fp1 := stampOf(t, p)
	_, fp2 := stampOf(t, p)
	require.Equal(t, fp1, fp2, "the stamp must be a pure function of the input")
	require.Len(t, fp1, 3+16+2+16, "s=<16 hex>;o=<16 hex>")
}

func TestDecisiveContentStamp_NoDecisiveContent_Matches(t *testing.T) {
	_, a := stampOf(t, "Какая сегодня погода и что посоветуешь на выходных?")
	_, b := stampOf(t, "What is the weather like and what do you suggest for the weekend?")
	assert.Equal(t, a, b, "prompts without decisive content must not veto each other")
}

func TestDecisiveContentStamp_Classes(t *testing.T) {
	cases := []struct {
		name     string
		cached   string
		lookup   string
		wantVeto bool
	}{
		{"ISO date", "window starting 2025-03-31 close", "window starting 2025-06-30 close", true},
		{"dot date", "инвентаризация на 31.03.2025 готова", "инвентаризация на 30.06.2025 готова", true},
		{"EN long date", "invoice run of March 15, 2025 done", "invoice run of March 22, 2025 done", true},
		{"RU month-year", "статистика за март 2025 года готова", "статистика за апрель 2025 года готова", true},
		{"quarter with year", "churn in Q1 2025 against", "churn in Q2 2025 against", true},
		{"bare quarter", "the Q3 cycle bands now", "the Q4 cycle bands now", true},
		{"grouped number", "forecast assumed 45,200 dollars", "forecast assumed 48,200 dollars", true},
		{"RU spaced number", "система показывает 1 240 штук", "система показывает 1 420 штук", true},
		{"decimal", "showed 99.95 percent uptime", "showed 99.59 percent uptime", true},
		{"multi-digit", "balance was 12 working days", "balance was 21 working days", true},
		{"quoted entity", "поставки от ООО «Ромашка» за", "поставки от ООО «Лютик» за", true},
		{"capitalized entity", "contract status for Acme Manufacturing is", "contract status for Acme Manufacturing Ltd is", true},
		{"access marker EN", "open the restricted compensation review", "open the public compensation review", true},
		{"access marker RU", "покажи обезличенную сводку команды", "покажи персональную сводку команды", true},
		// Non-veto cases: the paraphrase-safety half of the contract.
		{"identical prompt", "revenue figures for Q3 2025 now", "revenue figures for Q3 2025 now", false},
		{"date spelled differently", "deadline on 2025-03-31 exactly", "deadline on 31.03.2025 exactly", false},
		{"reworded, same decisive tokens", "open the restricted figures for Acme Manufacturing Q3 2025", "these restricted figures of Acme Manufacturing for Q3 2025", false},
		{"small integers are noise", "took 1 of 2 days off", "took 2 of 3 days off", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, fpC := stampOf(t, tc.cached)
			_, fpL := stampOf(t, tc.lookup)
			if tc.wantVeto {
				assert.NotEqual(t, fpC, fpL, "the guard must veto different decisive content")
			} else {
				assert.Equal(t, fpC, fpL, "the guard must not veto equal decisive content")
			}
		})
	}
}

func TestDecisiveContentStamp_OrderSwapVeto(t *testing.T) {
	// nn-ru-qty: the two quantities trade roles; the multiset is unchanged,
	// so only the ORDERED numeric/date hash can separate the prompts.
	cached := "система показывает 1 240 штук, но в накладной фигурирует 1 420"
	lookup := "система показывает 1 420 штук, но в накладной фигурирует 1 240"
	_, fpC := stampOf(t, cached)
	_, fpL := stampOf(t, lookup)
	require.NotEqual(t, fpC, fpL, "a numeric role swap must veto even with an equal multiset")
}

func TestDecisiveContentStamp_SingleDigitDatesNotNumbers(t *testing.T) {
	// The detector must see through spellings to the same canonical date,
	// and must not count date digits twice (masking).
	_, a := stampOf(t, "report of 2025-03-31 and 15:00")
	_, b := stampOf(t, "report of 31.03.2025 and 15:00")
	assert.Equal(t, a, b, "ISO and dotted spellings of one date are the same decisive token")
}

func TestDecisiveContent_StampContractAgainstHoldoutCorpus(t *testing.T) {
	for _, p := range holdoutCorpus() {
		t.Run(p.ID, func(t *testing.T) {
			_, fpC := stampOf(t, p.CachedPrompt)
			_, fpL := stampOf(t, p.LookupPrompt)
			switch p.Class {
			case holdoutClassTrueDup, holdoutClassCrossLang:
				// True duplicates normalize to identical bytes → identical
				// stamps. Cross-language pairs are the SPACE guard's job
				// (tags differ); the decisive stamp MAY differ or not — the
				// guard must simply never be the layer that decides them.
				if p.Class == holdoutClassTrueDup {
					assert.Equal(t, fpC, fpL, "true duplicates must stamp identically (no over-invalidation)")
				}
			default:
				assert.NotEqual(t, fpC, fpL, "decisive-axis pair must stamp differently (the guard must veto)")
			}
		})
	}
}

func TestDecisiveMatch_Semantics(t *testing.T) {
	p := Provenance{}
	assert.True(t, p.DecisiveMatch("", ""), "two stamp-less sides stay compatible (legacy readers)")
	assert.False(t, p.DecisiveMatch(DecisiveContentVer, "fp"), "an unstamped entry never matches a versioning stamp")

	stamped := Provenance{DecisiveVer: DecisiveContentVer, DecisiveFP: "s=aa;o=bb"}
	assert.True(t, stamped.DecisiveMatch(DecisiveContentVer, "s=aa;o=bb"))
	assert.False(t, stamped.DecisiveMatch(DecisiveContentVer, "s=cc;o=dd"), "a different fingerprint vetoes")
	assert.False(t, stamped.DecisiveMatch("dc0", "s=aa;o=bb"), "a different detector version vetoes")
	assert.False(t, stamped.DecisiveMatch("", ""), "a stamped entry never matches a stamp-less lookup")
}

func TestSealEntryVersionedContent_RoundTrip(t *testing.T) {
	ri := RouteIdentity{OrgID: "org-1", Model: "m"}
	sealed, err := SealEntryVersionedContent(json.RawMessage(`{"id":"c1"}`), ri, "emb1:a", "sem1:0.95", DecisiveContentVer, "s=aa;o=bb")
	require.NoError(t, err)

	prov, data, ok := OpenEntry(sealed)
	require.True(t, ok)
	assert.JSONEq(t, `{"id":"c1"}`, string(data))
	assert.Equal(t, "emb1:a", prov.EmbedVer)
	assert.Equal(t, "sem1:0.95", prov.ThresholdVer)
	assert.Equal(t, DecisiveContentVer, prov.DecisiveVer)
	assert.Equal(t, "s=aa;o=bb", prov.DecisiveFP)
	assert.True(t, prov.DecisiveMatch(DecisiveContentVer, "s=aa;o=bb"))

	// The versioned seal without content stays legacy-compatible: empty
	// decisive fields, exactly the pre-T05 envelope layout plus nothing.
	legacy, err := SealEntryVersioned(json.RawMessage(`{"id":"c1"}`), ri, "emb1:a", "sem1:0.95")
	require.NoError(t, err)
	provL, _, okL := OpenEntry(legacy)
	require.True(t, okL)
	assert.Empty(t, provL.DecisiveVer)
	assert.Empty(t, provL.DecisiveFP)
	assert.False(t, provL.DecisiveMatch(DecisiveContentVer, "s=aa;o=bb"))
}

func TestDecisiveContent_EnvelopeOmitEmpty(t *testing.T) {
	// A pre-T05 payload layout must not grow new keys when the writer does
	// not stamp: older readers unmarshal the same envelope unchanged.
	sealed, err := SealEntry([]byte(`{"id":"c1"}`), RouteIdentity{OrgID: "o", Model: "m"})
	require.NoError(t, err)
	assert.NotContains(t, string(sealed), "decisive_ver")
	assert.NotContains(t, string(sealed), "decisive_fp")
}

// TestDecisiveGuard_MissThenOwnHitThroughService proves the full loop on real
// backends with the holdout embedder and the nd-en-iso corpus pair: the
// near-duplicate variant scores ~0.97 cosine (geometry ADMITS — that is the
// T04 defect), so the decisive-content guard is the deciding layer that
// vetoes it; the cached prompt itself still hits; and after the variant is
// written (the refill path) it is served from its OWN stamped entry, whose
// identical vector beats the near-duplicate row in the ANN ranking.
// Docker-backed like the T02 negatives; skips in -short.
func TestDecisiveGuard_MissThenOwnHitThroughService(t *testing.T) {
	if testing.Short() {
		t.Skip("Docker-backed")
	}
	var pair holdoutPair
	for _, p := range holdoutCorpus() {
		if p.ID == "nd-en-iso" {
			pair = p
			break
		}
	}
	require.NotEmpty(t, pair.ID, "the nd-en-iso corpus pair must exist")
	variantResponse := `{"id":"cmpl-decisive-lookup","choices":[{"message":{"content":"answer-lookup"}}]}`

	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	emb := holdoutEmbedder{}
	w := NewWriter(ctx, pool, emb, slog.New(slog.DiscardHandler))
	require.True(t, w.Submit(writerJob{
		orgID: orgID, modelTier: embedVerModel, modelVer: RouteVersion,
		promptJSON: json.RawMessage(pair.CachedPrompt),
		response:   json.RawMessage(embedVerResponseA),
		tokensIn:   10, tokensOut: 5,
	}))
	require.True(t, w.Stop())

	svc := NewCacheService(ctx, pool, rdb, emb, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)
	ri := RouteIdentity{OrgID: orgID, Model: embedVerModel}

	// 1. The decisive variant must MISS even though geometry admits it
	// (corpus similarity > 0.95 threshold by design).
	hit, err := svc.LookupWithResult(ctx, ri, []byte(pair.LookupPrompt))
	require.NoError(t, err, "an admission veto is a miss, never an error")
	assert.Nil(t, hit, "a different decisive content must not be answered from this entry")

	// 2. The cached question itself still hits through the guard.
	hitSame, err := svc.LookupWithResult(ctx, ri, []byte(pair.CachedPrompt))
	require.NoError(t, err)
	require.NotNil(t, hitSame, "the identical question must still hit")
	assert.Equal(t, "semantic", hitSame.SourceType)
	assert.JSONEq(t, embedVerResponseA, string(hitSame.Data))

	// 3. Refill path: writing the variant stamps it separately; a
	// subsequent lookup of the variant serves its own freshly stamped
	// answer, not the cached one and not a permanent miss.
	w2 := NewWriter(ctx, pool, emb, slog.New(slog.DiscardHandler))
	require.True(t, w2.Submit(writerJob{
		orgID: orgID, modelTier: embedVerModel, modelVer: RouteVersion,
		promptJSON: json.RawMessage(pair.LookupPrompt),
		response:   json.RawMessage(variantResponse),
		tokensIn:   10, tokensOut: 5,
	}))
	require.True(t, w2.Stop())

	hitVariant, err := svc.LookupWithResult(ctx, ri, []byte(pair.LookupPrompt))
	require.NoError(t, err)
	require.NotNil(t, hitVariant, "the variant must hit after its own write")
	assert.JSONEq(t, variantResponse, string(hitVariant.Data), "the variant must be served its own answer")
}
