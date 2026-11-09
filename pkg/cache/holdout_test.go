package cache

// N03-P04-T05: independent-holdout acceptance of the decisive-content
// admission guard (built on the N03-P04-T04 measurement harness).
//
// T03 (accepted) delivered script/domain qualifiers; T04 measured the
// residual defect: on a frozen corpus of near-duplicate pairs that differ in
// DECISIVE content (date, number, access level, entity), the decision path
// answered 10/14 with someone else's cached answer (similarity 0.97-0.99
// against the 0.95 threshold). T05 closes that axis: the writer stamps a
// one-way decisive-content fingerprint (DecisiveContentStamp) into the
// provenance, and the semantic lookup serves an entry only when the stamp of
// the lookup prompt matches (Provenance.DecisiveMatch, strict equality like
// SpaceMatch; stamp-less legacy entries degrade to self-healing misses).
//
// This file replays the same frozen corpus through the REAL production
// decision path — CacheService.LookupWithResult with Redis exact, real
// pgvector ANN (SemanticCache.Lookup, cosine threshold 0.95, ef 100), real
// provenance matching (OpenEntry + SpaceMatch + DecisiveMatch) and the real
// ScriptQualifier (N03-P04-T03) — driven by the same deterministic embedding
// stub. The stub (holdoutEmbedder) models the geometry of a strong
// lexical-overlap embedder: hashed character 3/4-grams make near-duplicates
// that differ only in a short decisive token score ABOVE the 0.95 admission
// threshold, exactly the contraction production multilingual embedders
// exhibit on such pairs — i.e. geometry ADMITS every decisive-axis pair and
// only the T05 guard stands between the lookup and the foreign answer.
//
// Outcomes per class:
//   - true-dup        -> hit   = correct;  miss = false miss (over-invalidation)
//   - near-date       -> miss  = correct (T05 guard); hit = decision-path defect
//   - near-number     -> same as near-date
//   - near-access     -> same as near-date
//   - near-entity     -> same as near-date
//   - cross-lang      -> miss  = correct (T03 guarantee); hit = FALSE HIT
//
// Honest-reporting policy (cards N03-P04-T04/T05): both error directions are
// counted and logged loudly, NOT tuned away. With the T05 guard in place the
// FALSE-HIT total is a hard require.Zero; a decisive-axis false miss (the
// guard over-invalidating a genuinely different-stamp pair) is a defect. The
// accepted residue is exactly the td-ru-ws formatting pair (see
// TestHoldoutFormattingPairGeometry): a true duplicate that the byte-level
// path legitimately sees as different text, measured as a self-healing miss
// below the threshold — unchanged by T05. Structural guarantees stay hard:
// no cross-language reuse, no cross-pair leakage (JSONEq), no same-tag
// above-threshold miss. Threshold tuning remains out of scope.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Deterministic embedding stub — the holdout's model of a strong embedder
// ---------------------------------------------------------------------------

const (
	// holdoutDim matches cache_entries.embedding vector(384).
	holdoutDim = 384
	// holdoutSpaceVer is the stub's base embedding-space identity (T02);
	// the cache composes "holdout-ngram-emb1|q:<tag>" per input (T03).
	holdoutSpaceVer = "holdout-ngram-emb1"
	// holdoutModel is the shared route model for every holdout pair.
	holdoutModel = "gpt-4o"
)

// holdoutHash is FNV-1a 64-bit: pure integer arithmetic, identical on every
// platform and run. The stub's determinism rests on it.
func holdoutHash(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// holdoutEmbedText maps text to a unit vector of hashed character 3- and
// 4-grams (hashing trick, signed buckets). Whitespace runs collapse first, so
// formatting-only edits do not move the vector, while any short decisive
// token edit (a date, a number, an entity name) removes only the n-grams that
// cross it — the pair stays geometrically close, which is exactly how strong
// real embedders behave on such near-duplicates. The stub embeds the same
// bytes production embeds: the qualifier-prefixed normalized prompt JSON.
func holdoutEmbedText(text string) []float32 {
	acc := make([]float64, holdoutDim)
	runes := []rune(strings.Join(strings.Fields(text), " "))
	for n := 3; n <= 4; n++ {
		for i := 0; i+n <= len(runes); i++ {
			h := holdoutHash(string(runes[i : i+n]))
			idx := int(h % holdoutDim)
			if h>>63 == 1 {
				acc[idx]--
			} else {
				acc[idx]++
			}
		}
	}
	var norm float64
	for _, v := range acc {
		norm += v * v
	}
	out := make([]float32, holdoutDim)
	if norm == 0 {
		out[0] = 1
		return out
	}
	inv := 1 / math.Sqrt(norm)
	for i, v := range acc {
		out[i] = float32(v * inv)
	}
	return out
}

// holdoutEmbedder is the holdout stand-in for *embeddings.HTTPClient with
// QualifyScripts on: it implements the exact interface set the production
// embedder satisfies (Client + SpaceVersioner + InputQualifier), so the real
// CacheService resolves qualifier tags and space versions from it unchanged.
type holdoutEmbedder struct{}

func (holdoutEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	return holdoutEmbedText(text), nil
}

func (holdoutEmbedder) SpaceVersion() string { return holdoutSpaceVer }

func (holdoutEmbedder) InputQualifierTag(text string) string {
	// Same derivation the qualifier-ON production client performs
	// (pkg/embeddings HTTPClient.InputQualifierTag with an empty domain).
	return embeddings.ScriptQualifier(text)
}

var (
	_ embeddings.Client         = holdoutEmbedder{}
	_ embeddings.SpaceVersioner = holdoutEmbedder{}
	_ embeddings.InputQualifier = holdoutEmbedder{}
)

// holdoutCosine reports the cosine similarity of the two vectors. The real
// path computes it inside pgvector (<=>, 1 - distance); this harness-side
// value exists only for REPORTING (attribution of guards on misses and
// margins), never for the decision itself.
func holdoutCosine(a, b []float32) float64 {
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / math.Sqrt(na*nb)
}

// ---------------------------------------------------------------------------
// Independent holdout corpus (fixed, deterministic, hand-written)
// ---------------------------------------------------------------------------

const (
	holdoutClassTrueDup    = "true-dup"
	holdoutClassNearDate   = "near-date"
	holdoutClassNearNumber = "near-number"
	holdoutClassNearAccess = "near-access"
	holdoutClassNearEntity = "near-entity"
	holdoutClassCrossLang  = "cross-lang"
)

// holdoutPair is one holdout scenario. Each pair runs in its own org, so the
// ANN candidate set per lookup is exactly one row and the outcome is
// unambiguous: a hit can only be a reuse of THIS pair's cached answer.
type holdoutPair struct {
	ID           string
	Class        string
	Note         string // the decisive difference, for the report
	CachedPrompt string // JSON body written to the cache (the "someone" whose answer must not leak)
	LookupPrompt string // JSON body looked up afterwards
	CachedAnswer string // response sealed into the cached entry

	// expectSameHash marks pairs whose members normalize to identical bytes
	// (byte/key-order duplicates) — they exercise the exact layer.
	expectSameHash bool
}

// holdoutPrompt builds a chat body with a deterministic field order.
func holdoutPrompt(content string) string {
	type message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	body, err := json.Marshal(struct {
		Messages []message `json:"messages"`
	}{Messages: []message{{Role: "user", Content: content}}})
	if err != nil {
		panic(fmt.Sprintf("holdout corpus: static prompt cannot fail to marshal: %v", err))
	}
	return string(body)
}

// holdoutPromptKeyOrderSwapped builds the same chat body with message keys in
// the opposite order (Go marshals maps with sorted keys: content < role).
func holdoutPromptKeyOrderSwapped(content string) string {
	raw, err := json.Marshal(map[string]any{
		"messages": []any{map[string]any{"content": content, "role": "user"}},
	})
	if err != nil {
		panic(fmt.Sprintf("holdout corpus: static prompt cannot fail to marshal: %v", err))
	}
	return string(raw)
}

// swapRuStockQty swaps the two decisive quantities in the RU stock pair
// (system balance 1 240 ↔ supplier invoice 1 420) via distinct placeholders,
// so both numbers change exactly once each.
func swapRuStockQty(stock string) string {
	swapped := strings.Replace(stock, "1 240 штук", "@@SYS@@", 1)
	swapped = strings.Replace(swapped, "1 420", "1 240", 1)
	return strings.Replace(swapped, "@@SYS@@", "1 420 штук", 1)
}

// holdoutAnswer is a distinct response body per pair: any hit must serve
// EXACTLY this body, proving which question's answer was reused.
func holdoutAnswer(id string) string {
	return fmt.Sprintf(`{"id":"cmpl-holdout-%s","choices":[{"message":{"content":"answer for %s"}}]}`, id, id)
}

// holdoutCorpus returns the frozen holdout: 20 pairs across the six classes.
// The corpus is independent of the code under test: it was written once, from
// the card's axis definition (different date / number / access / entity,
// true duplicates, cross-language), and must only be extended, never tuned
// against outcomes.
func holdoutCorpus() []holdoutPair {
	enQBR := "Our quarterly business review is tomorrow at 15:00. Please summarize the coverage ratio for the platform team for the sprint that ended on 2025-03-31, list the three largest unfinished epics, and note any flaky end-to-end tests that blocked the release candidate last week."
	ruSupport := "Собери, пожалуйста, статистику по обращениям в поддержку за март 2025 года: сколько тикетов открыто, сколько закрыто, среднее время первого ответа и топ-5 самых частых тем обращений. Сводка нужна к ежемесячному отчёту перед советом директоров."
	enCapacity := "Planning capacity for the next release train. Look at the deployment logs of the billing service for the window starting 2025-03-31 and tell me the peak requests per second, the error budget burn for that window, and whether any canary rollout was automatically rolled back."
	enInvoice := "Finance asked me to reconcile the invoice run of March 15, 2025. Pull the total invoiced amount, the number of failed charges, and the retry success rate for that run, then format everything as a short table I can paste into the finance channel."
	enChurn := "Compare the churn rate of the enterprise segment in Q1 2025 against the previous quarter, include net revenue retention for the same period, and highlight any accounts that downgraded their plan. The board deck is due on Friday."
	ruInventory := "Подготовь краткую справку по инвентаризации склада на 31.03.2025: общее количество позиций, позиции с нулевым остатком, расхождения между учётной системой и фактом, а также ожидаемую дату следующей полной проверки. Справка нужна для внешнего аудита."
	enLeave := "The HR portal says I should have vacation days left this year, but the booking tool keeps rejecting my request. My balance as of January was 12 working days. Check the accrual rules, tell me how many days I actually have now, and explain why the two systems disagree."
	enSpend := "Pull the cloud bill breakdown for the analytics account for November. The finance forecast assumed 45,200 dollars of compute spend for that month; tell me the actual amount, the top three services by cost, and any month-over-month jump above ten percent."
	enUptime := "The on-call handover template asks for the current availability of the payment gateway. Last month the SLO report showed 99.95 percent uptime. Compute the trailing thirty-day availability from the status history and tell me whether we are still inside the error budget."
	ruStock := "Проверь остатки по артикулу A-1743 на основном складе: система показывает 1 240 штук, но в накладной от поставщика фигурирует 1 420. Разбери движения за последние две недели и объясни, на каком шаге возникло расхождение."
	enHR := "I am an HR business partner preparing calibration. Open the restricted compensation review spreadsheet for the infrastructure group for the Q3 cycle and summarize the individual salary bands and the proposed raises, including employee names."
	enHRAggr := "I am a team lead preparing a hiring pitch. Open the publicly published salary summary for the infrastructure group and summarize the aggregated pay ranges by level, without any individual employee data."
	ruPayPersonal := "Покажи мои начисления и удержания за март: оклад, премию, налоги и удержания по исполнительным листам, если они есть. Разбей всё по строкам расчётного листка и объясни, как сформировалась сумма к выплате."
	ruPayTeam := "Покажи обезличенную сводку по начислениям всей команды за март: средние значения по отделам и суммарный фонд оплаты труда, без персональных данных и без разбивки по сотрудникам."
	enDraft := "Summarize the unannounced internal draft of the pricing memo (restricted, pre-launch, do not distribute) and list the new enterprise tiers together with their launch discounts and the approval window."
	enPublished := "Summarize the already published pricing announcement from the public website and list the new enterprise tiers together with their discounts and the availability window."
	enHelios := "List the still-open milestones of the Helios data-migration project, the owner of each milestone, and the date each one last slipped. I need this before the steering committee sync on Thursday."
	ruRomashka := "Собери историю поставок от ООО «Ромашка» за последний квартал: количество поставок, среднюю задержку, сумму штрафов за просрочку и рекомендацию по продлению контракта на следующий год."
	enAcme := "What is the current contract status for Acme Manufacturing: renewal date, annual contract value, open support escalations, and the health score from the last customer success review?"
	enVAT := "What is the filing deadline for the quarterly VAT declaration covering April, May and June 2025 for a small business registered in Spain, and what are the penalties for missing the deadline?"
	ruVAT := "Какой срок подачи квартальной декларации по НДС за апрель, май и июнь 2025 года для малого бизнеса, зарегистрированного в Испании, и какие штрафы предусмотрены за пропуск срока?"
	ruLeave := "Сколько дней отпуска мне положено в этом году с учётом переноса с прошлого года, если я отработал пять полных месяцев и брал одну неделю отпуска за свой счёт?"
	enLeaveCarry := "How many vacation days am I entitled to this year, including carry-over from last year, if I have worked five full months and took one week of unpaid leave?"
	enInvestor := "Draft the monthly investor update for March: key metrics, hiring progress, burn rate and the single biggest risk. Keep it under four hundred words and friendly for non-technical readers."
	ruInvestor := "Подготовь ежемесячный отчёт для инвесторов за март: ключевые метрики, прогресс найма, расход и главный риск. Уложись в четыреста слов и пиши простым языком для не-технических читателей."

	return []holdoutPair{
		{
			ID: "td-en-byte", Class: holdoutClassTrueDup,
			Note:         "byte-identical prompt (exact layer must serve it)",
			CachedPrompt: holdoutPrompt(enQBR), LookupPrompt: holdoutPrompt(enQBR),
			CachedAnswer: holdoutAnswer("td-en-byte"), expectSameHash: true,
		},
		{
			ID: "td-en-keyorder", Class: holdoutClassTrueDup,
			Note:         "JSON key order only (normalization must equalize; exact or semantic hit both correct)",
			CachedPrompt: holdoutPrompt(enQBR), LookupPrompt: holdoutPromptKeyOrderSwapped(enQBR),
			CachedAnswer: holdoutAnswer("td-en-keyorder"), expectSameHash: true,
		},
		{
			ID: "td-ru-ws", Class: holdoutClassTrueDup,
			Note:         "same RU words, line breaks instead of comma spaces (hash differs, meaning identical)",
			CachedPrompt: holdoutPrompt(ruSupport), LookupPrompt: holdoutPrompt(strings.ReplaceAll(ruSupport, ", ", ",\n")),
			CachedAnswer: holdoutAnswer("td-ru-ws"),
		},
		{
			ID: "nd-en-iso", Class: holdoutClassNearDate,
			Note:         "sprint window 2025-03-31 → 2025-06-30 (ISO date)",
			CachedPrompt: holdoutPrompt(enCapacity), LookupPrompt: holdoutPrompt(strings.Replace(enCapacity, "2025-03-31", "2025-06-30", 1)),
			CachedAnswer: holdoutAnswer("nd-en-iso"),
		},
		{
			ID: "nd-en-words", Class: holdoutClassNearDate,
			Note:         "invoice run March 15, 2025 → March 22, 2025 (long-form date)",
			CachedPrompt: holdoutPrompt(enInvoice), LookupPrompt: holdoutPrompt(strings.Replace(enInvoice, "March 15, 2025", "March 22, 2025", 1)),
			CachedAnswer: holdoutAnswer("nd-en-words"),
		},
		{
			ID: "nd-en-quarter", Class: holdoutClassNearDate,
			Note:         "Q1 2025 → Q2 2025 (one-character quarter)",
			CachedPrompt: holdoutPrompt(enChurn), LookupPrompt: holdoutPrompt(strings.Replace(enChurn, "Q1 2025", "Q2 2025", 1)),
			CachedAnswer: holdoutAnswer("nd-en-quarter"),
		},
		{
			ID: "nd-ru-date", Class: holdoutClassNearDate,
			Note:         "инвентаризация на 31.03.2025 → 30.06.2025",
			CachedPrompt: holdoutPrompt(ruInventory), LookupPrompt: holdoutPrompt(strings.Replace(ruInventory, "31.03.2025", "30.06.2025", 1)),
			CachedAnswer: holdoutAnswer("nd-ru-date"),
		},
		{
			ID: "nn-en-leave", Class: holdoutClassNearNumber,
			Note:         "leave balance 12 → 21 working days",
			CachedPrompt: holdoutPrompt(enLeave), LookupPrompt: holdoutPrompt(strings.Replace(enLeave, "12 working days", "21 working days", 1)),
			CachedAnswer: holdoutAnswer("nn-en-leave"),
		},
		{
			ID: "nn-en-spend", Class: holdoutClassNearNumber,
			Note:         "forecast $45,200 → $48,200",
			CachedPrompt: holdoutPrompt(enSpend), LookupPrompt: holdoutPrompt(strings.Replace(enSpend, "45,200 dollars", "48,200 dollars", 1)),
			CachedAnswer: holdoutAnswer("nn-en-spend"),
		},
		{
			ID: "nn-en-pct", Class: holdoutClassNearNumber,
			Note:         "uptime 99.95 → 99.59 percent (digit transposition)",
			CachedPrompt: holdoutPrompt(enUptime), LookupPrompt: holdoutPrompt(strings.Replace(enUptime, "99.95 percent", "99.59 percent", 1)),
			CachedAnswer: holdoutAnswer("nn-en-pct"),
		},
		{
			ID: "nn-ru-qty", Class: holdoutClassNearNumber,
			Note:         "остатки 1 240 / накладная 1 420 → свопнуты",
			CachedPrompt: holdoutPrompt(ruStock), LookupPrompt: holdoutPrompt(swapRuStockQty(ruStock)),
			CachedAnswer: holdoutAnswer("nn-ru-qty"),
		},
		{
			ID: "na-en-hr", Class: holdoutClassNearAccess,
			Note:         "restricted individual compensation data → public aggregated ranges",
			CachedPrompt: holdoutPrompt(enHR), LookupPrompt: holdoutPrompt(enHRAggr),
			CachedAnswer: holdoutAnswer("na-en-hr"),
		},
		{
			ID: "na-ru-personal", Class: holdoutClassNearAccess,
			Note:         "персональные начисления → обезличенная командная сводка",
			CachedPrompt: holdoutPrompt(ruPayPersonal), LookupPrompt: holdoutPrompt(ruPayTeam),
			CachedAnswer: holdoutAnswer("na-ru-personal"),
		},
		{
			ID: "na-en-draft", Class: holdoutClassNearAccess,
			Note:         "restricted pre-launch draft → already published announcement",
			CachedPrompt: holdoutPrompt(enDraft), LookupPrompt: holdoutPrompt(enPublished),
			CachedAnswer: holdoutAnswer("na-en-draft"),
		},
		{
			ID: "ne-en-project", Class: holdoutClassNearEntity,
			Note:         "project Helios → Selene (data-migration)",
			CachedPrompt: holdoutPrompt(enHelios), LookupPrompt: holdoutPrompt(strings.Replace(enHelios, "Helios", "Selene", 1)),
			CachedAnswer: holdoutAnswer("ne-en-project"),
		},
		{
			ID: "ne-ru-supplier", Class: holdoutClassNearEntity,
			Note:         "поставщик ООО «Ромашка» → ООО «Лютик»",
			CachedPrompt: holdoutPrompt(ruRomashka), LookupPrompt: holdoutPrompt(strings.Replace(ruRomashka, "Ромашка", "Лютик", 1)),
			CachedAnswer: holdoutAnswer("ne-ru-supplier"),
		},
		{
			ID: "ne-en-customer", Class: holdoutClassNearEntity,
			Note:         "customer Acme Manufacturing → Zenith Robotics",
			CachedPrompt: holdoutPrompt(enAcme), LookupPrompt: holdoutPrompt(strings.Replace(enAcme, "Acme Manufacturing", "Zenith Robotics", 1)),
			CachedAnswer: holdoutAnswer("ne-en-customer"),
		},
		{
			ID: "cl-vat", Class: holdoutClassCrossLang,
			Note:         "EN cached → RU translation near-duplicate (same dates)",
			CachedPrompt: holdoutPrompt(enVAT), LookupPrompt: holdoutPrompt(ruVAT),
			CachedAnswer: holdoutAnswer("cl-vat"),
		},
		{
			ID: "cl-leave", Class: holdoutClassCrossLang,
			Note:         "RU cached → EN translation near-duplicate (same rules)",
			CachedPrompt: holdoutPrompt(ruLeave), LookupPrompt: holdoutPrompt(enLeaveCarry),
			CachedAnswer: holdoutAnswer("cl-leave"),
		},
		{
			ID: "cl-report", Class: holdoutClassCrossLang,
			Note:         "EN cached → RU translation near-duplicate (same brief)",
			CachedPrompt: holdoutPrompt(enInvestor), LookupPrompt: holdoutPrompt(ruInvestor),
			CachedAnswer: holdoutAnswer("cl-report"),
		},
	}
}

// holdoutPairAttribution is the harness-side derivation of everything the
// report needs per pair, computed the same way BOTH production paths compute
// it (service.go lookup branch and writer.go write branch): normalize →
// qualifierSourceText → InputQualifierTag → qualifiedEmbedInput → Embed, and
// — since T05 — normalize → DecisiveContentStamp.
type holdoutPairAttribution struct {
	cachedTag  string
	lookupTag  string
	cachedVec  []float32
	lookupVec  []float32
	cachedHash string // ComputePromptHash over normalized bytes
	lookupHash string
	cachedDec  string // DecisiveContentStamp fingerprint over normalized bytes
	lookupDec  string
}

// sameDecisive reports whether the T05 decisive-content guard would let the
// cached entry answer the lookup prompt (equal stamps, including the
// stamp-less legacy case).
func (a holdoutPairAttribution) sameDecisive() bool {
	return a.cachedDec == a.lookupDec
}

func holdoutAttribute(stub holdoutEmbedder, cachedPrompt, lookupPrompt string) holdoutPairAttribution {
	normC := normalizeForCache([]byte(cachedPrompt))
	normL := normalizeForCache([]byte(lookupPrompt))
	tagC := embedderInputTag(stub, qualifierSourceText(normC))
	tagL := embedderInputTag(stub, qualifierSourceText(normL))
	_, decC := DecisiveContentStamp(normC)
	_, decL := DecisiveContentStamp(normL)
	return holdoutPairAttribution{
		cachedTag:  tagC,
		lookupTag:  tagL,
		cachedVec:  holdoutEmbedText(qualifiedEmbedInput(string(normC), tagC)),
		lookupVec:  holdoutEmbedText(qualifiedEmbedInput(string(normL), tagL)),
		cachedHash: ComputePromptHash(normC),
		lookupHash: ComputePromptHash(normL),
		cachedDec:  decC,
		lookupDec:  decL,
	}
}

// holdoutOutcome records one replayed pair.
type holdoutOutcome struct {
	hit      bool
	source   string  // exact | pg_exact | semantic ("" on miss)
	sim      float32 // similarity reported by the real path on hits
	cos      float64 // harness-side cosine (reporting only)
	guard    string  // who rejected (misses) / who failed to reject (false hits)
	correct  bool
	falseHit bool
	falseMis bool
}

// ---------------------------------------------------------------------------
// Always-on unit tests: stub determinism and corpus integrity (run in -short)
// ---------------------------------------------------------------------------

func TestHoldoutStubDeterminism(t *testing.T) {
	a := holdoutEmbedText("Отчёт за 2025-03-31 по платформенной команде, покрыть основные метрики и риски релиза")
	b := holdoutEmbedText("Отчёт за 2025-03-31 по платформенной команде, покрыть основные метрики и риски релиза")
	require.Equal(t, a, b, "the stub must be a pure function of the text")
	require.Len(t, a, holdoutDim)

	var sq float64
	for _, v := range a {
		sq += float64(v) * float64(v)
	}
	assert.InDelta(t, 1.0, math.Sqrt(sq), 1e-5, "stub vectors must be unit-normalized (pgvector cosine relies on it)")

	// Geometric sanity: same-content variants sit closest, decisive-token
	// edits stay high (the false-hit axis under strong-embedder geometry),
	// other-script different questions sit far away.
	dateA := holdoutEmbedText("Summarize the deployment window starting 2025-03-31 with peak traffic and error budget burn for the billing service")
	dateB := holdoutEmbedText("Summarize the deployment window starting 2025-06-30 with peak traffic and error budget burn for the billing service")
	other := holdoutEmbedText("Какой срок подачи квартальной декларации по НДС за апрель 2025 года для малого бизнеса в Испании?")
	assert.Greater(t, holdoutCosine(dateA, dateB), 0.90, "a decisive-token near-duplicate must stay geometrically close under the stub")
	assert.Less(t, holdoutCosine(dateA, other), 0.60, "different-script different questions must sit far apart")
}

func TestHoldoutCorpusIntegrity(t *testing.T) {
	stub := holdoutEmbedder{}
	seenAnswers := map[string]string{}
	seenOrgNames := map[string]bool{}
	for _, p := range holdoutCorpus() {
		t.Run(p.ID, func(t *testing.T) {
			require.NotEmpty(t, p.CachedPrompt, "cached prompt must be non-empty")
			require.NotEmpty(t, p.LookupPrompt, "lookup prompt must be non-empty")

			// Answers are unique per pair: any hit must serve exactly the
			// pair's own body, so a leaked answer is attributable.
			owner, seen := seenAnswers[p.CachedAnswer]
			require.False(t, seen, "answer bodies must be unique: %s reuses %s", p.ID, owner)
			seenAnswers[p.CachedAnswer] = p.ID

			attr := holdoutAttribute(stub, p.CachedPrompt, p.LookupPrompt)
			if p.expectSameHash {
				assert.Equal(t, attr.cachedHash, attr.lookupHash, "%s: normalization-equal pair must hash identically", p.ID)
			} else {
				assert.NotEqual(t, attr.cachedHash, attr.lookupHash, "%s: a decisive-content difference must survive normalization into distinct exact keys", p.ID)
			}

			// Qualifier expectation per class: cross-language pairs must
			// resolve to DIFFERENT qualifier tags (the T03 guarantee does not
			// depend on vectors), same-language pairs to the SAME tag.
			if p.Class == holdoutClassCrossLang {
				assert.NotEqual(t, attr.cachedTag, attr.lookupTag, "%s: cross-language pair must separate by qualifier tag", p.ID)
			} else {
				assert.Equal(t, attr.cachedTag, attr.lookupTag, "%s: same-language pair must share one qualifier tag", p.ID)
			}
			assert.NotEmpty(t, attr.cachedTag, "holdout prompts must classify to a script bucket")

			// Org names are unique per pair (one org per scenario).
			orgName := "holdout-" + p.ID
			require.False(t, seenOrgNames[orgName])
			seenOrgNames[orgName] = true
		})
	}
}

// TestHoldoutFormattingPairGeometry documents the mechanism behind the
// td-ru-ws outcome: the decision path embeds the NORMALIZED JSON BYTES, so a
// newline inside a content string is present as the two-character escape
// \n — not as whitespace — and the stub's whitespace collapse (which models
// what a real embedder sees after decoding) cannot equalize it. The pair is
// therefore measured as a semantic MISS (honest over-invalidation, the
// fail-safe direction) even though the decoded prompts carry identical text.
func TestHoldoutFormattingPairGeometry(t *testing.T) {
	var pairs []holdoutPair
	for _, p := range holdoutCorpus() {
		if p.ID == "td-ru-ws" {
			pairs = append(pairs, p)
		}
	}
	require.Len(t, pairs, 1)
	p := pairs[0]

	// Intent check: on DECODED, whitespace-collapsed text the two members
	// are byte-identical — the stub scores them at exactly 1.0.
	decoded := func(prompt string) string {
		var body struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		require.NoError(t, json.Unmarshal([]byte(prompt), &body))
		require.Len(t, body.Messages, 1)
		return strings.Join(strings.Fields(body.Messages[0].Content), " ")
	}
	cachedDecoded := decoded(p.CachedPrompt)
	require.Equal(t, cachedDecoded, decoded(p.LookupPrompt),
		"td-ru-ws members must decode to identical whitespace-collapsed text")
	assert.InDelta(t, 1.0, holdoutCosine(holdoutEmbedText(cachedDecoded), holdoutEmbedText(cachedDecoded)), 1e-9)

	// Representation check: on the bytes the path actually embeds (normalized
	// JSON, newline escaped) the vectors diverge below the admission
	// threshold — this IS the measured td-ru-ws false miss.
	normC := normalizeForCache([]byte(p.CachedPrompt))
	normL := normalizeForCache([]byte(p.LookupPrompt))
	require.NotEqual(t, string(normC), string(normL), "the escape difference must survive normalization (hash layer)")
	cos := holdoutCosine(holdoutEmbedText(string(normC)), holdoutEmbedText(string(normL)))
	assert.Less(t, cos, float64(DefaultSimilarityThreshold),
		"td-ru-ws must measure below the threshold on embedded bytes (the reported false miss)")
	assert.Greater(t, cos, 0.90, "the divergence must stay small: a formatting artifact, not a topic change")
}

// ---------------------------------------------------------------------------
// Docker-backed holdout replay: the confusion matrix over the real path
// ---------------------------------------------------------------------------

// TestHoldoutConfusionMatrix replays the whole frozen corpus through the real
// production decision path and reports the confusion counts. Docker-backed
// (testdb/redisContainer) like embed_version_test.go; skips in -short. Run:
//
//	go test ./pkg/cache -run 'TestHoldoutConfusionMatrix' -v
//
// The printed matrix is the reproducible source of
// artifacts/internal-delivery-program/N03-P04/T04-holdout-report-20261025.md.
func TestHoldoutConfusionMatrix(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	stub := holdoutEmbedder{}
	svc := NewCacheService(ctx, pool, rdb, stub, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)

	corpus := holdoutCorpus()

	// Write phase: the REAL write path (normalize → seal with space/threshold
	// versions → qualifier-conditioned embed → pgvector row + Redis exact).
	orgOf := make(map[string]string, len(corpus))
	attrOf := make(map[string]holdoutPairAttribution, len(corpus))
	for _, p := range corpus {
		orgID := seedCacheOrg(t, pool, "holdout-"+p.ID, true, "semantic")
		orgOf[p.ID] = orgID
		require.NoError(t, svc.Write(ctx, RouteIdentity{OrgID: orgID, Model: holdoutModel}, []byte(p.CachedPrompt), json.RawMessage(p.CachedAnswer), 10, 5), "%s: write must succeed", p.ID)
		attrOf[p.ID] = holdoutAttribute(stub, p.CachedPrompt, p.LookupPrompt)
	}
	require.True(t, svc.writer.Stop(), "the writer must drain before any lookup")

	// Provenance receipt: every row must carry the qualifier-extended space
	// version, the admission stamp and the T05 decisive-content stamp this
	// configuration resolves — the identities the lookup-side SpaceMatch and
	// DecisiveMatch will compare against.
	store := NewStore(pool)
	for _, p := range corpus {
		attr := attrOf[p.ID]
		ri := RouteIdentity{OrgID: orgOf[p.ID], Model: holdoutModel}.Resolved()
		entry, err := store.GetExact(ctx, ri.OrgID, ri.Model, attr.cachedHash, ri.Version)
		require.NoError(t, err, p.ID)
		require.NotNil(t, entry, "%s: the writer must have persisted a row", p.ID)
		prov, _, ok := OpenEntry(entry.Response)
		require.True(t, ok, p.ID)
		assert.Equal(t, embeddings.QualifiedSpaceVersion(holdoutSpaceVer, attr.cachedTag), prov.EmbedVer,
			"%s: row must be stamped with the qualifier-extended space version", p.ID)
		assert.Equal(t, SemanticAdmissionVersion(), prov.ThresholdVer,
			"%s: row must be stamped with the current admission epoch", p.ID)
		assert.Equal(t, DecisiveContentVer, prov.DecisiveVer,
			"%s: row must be stamped with the decisive-content detector version", p.ID)
		assert.Equal(t, attr.cachedDec, prov.DecisiveFP,
			"%s: row must carry the decisive fingerprint of the normalized cached prompt", p.ID)
	}

	// Lookup phase: the REAL decision path decides; the harness only observes.
	threshold := float64(DefaultSimilarityThreshold)
	outcomes := make(map[string]holdoutOutcome, len(corpus))
	for _, p := range corpus {
		attr := attrOf[p.ID]
		hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgOf[p.ID], Model: holdoutModel}, []byte(p.LookupPrompt))
		require.NoError(t, err, "%s: a holdout lookup must never error", p.ID)

		out := holdoutOutcome{cos: holdoutCosine(attr.cachedVec, attr.lookupVec)}
		wantHit := p.Class == holdoutClassTrueDup

		switch {
		case hit != nil:
			out.hit, out.source, out.sim = true, hit.SourceType, hit.Similarity
			// A hit must serve THIS pair's cached answer — a different body
			// would mean cross-pair leakage (a structural defect, not a count).
			require.JSONEq(t, p.CachedAnswer, string(hit.Data),
				"%s: the served body must be the pair's own cached answer (cross-pair leakage is a defect, not a confusion count)", p.ID)

			switch {
			case wantHit:
				out.correct = true
				out.guard = "n/a (expected hit)"
			case attr.cachedTag != attr.lookupTag:
				// A cross-language hit is impossible if the space guard works:
				// SpaceMatch compares strict versions and the tags differ.
				t.Errorf("%s: cross-language pair HIT (sim=%.4f) — the qualifier space guard must make this impossible; decision-path defect", p.ID, out.sim)
				out.falseHit, out.guard = true, "NONE — space guard failed to reject a different-tag entry"
			case !attr.sameDecisive():
				// N03-P04-T05: a decisive-content hit is impossible if the
				// guard works: DecisiveMatch compares strict stamps and the
				// pair's stamps differ (the writer's receipt was verified
				// above), so this hit bypassed or postdates the guard.
				t.Errorf("%s: decisive-content pair HIT (sim=%.4f) — the T05 decisive-content guard must make this impossible; decision-path defect", p.ID, out.sim)
				out.falseHit, out.guard = true, "NONE — decisive-content guard failed to reject a different decisive content"
			default:
				out.falseHit = true
				out.guard = fmt.Sprintf("NONE — exact: hash differs (not consulted); qualifier: same tag %q (by design); space: same embedder config; threshold: %.4f ≥ %.2f passed",
					attr.cachedTag, out.sim, threshold)
				t.Logf("FALSE HIT [%s] (%s)\n  cached : %s\n  lookup : %s\n  diff   : %s\n  sim    : %.4f  source=%s\n  served : %s\n  guards : %s",
					p.ID, p.Class, p.CachedPrompt, p.LookupPrompt, p.Note, out.sim, out.source, p.CachedAnswer, out.guard)
			}

		default: // miss
			switch {
			case wantHit:
				out.falseMis = true
				out.guard = fmt.Sprintf("over-invalidation — tags %q==%q, harness cosine %.4f (threshold %.2f)", attr.cachedTag, attr.lookupTag, out.cos, threshold)
				t.Logf("FALSE MISS [%s] (%s)\n  cached : %s\n  lookup : %s\n  cos    : %.4f\n  note   : %s",
					p.ID, p.Class, p.CachedPrompt, p.LookupPrompt, out.cos, p.Note)
			case attr.cachedTag != attr.lookupTag:
				out.correct = true
				out.guard = fmt.Sprintf("qualifier-space guard (SpaceMatch: %q vs %q); threshold would %s (%.4f vs %.2f)",
					attr.cachedTag, attr.lookupTag, map[bool]string{true: "also reject", false: "not reject (sim above threshold!)"}[out.cos < threshold], out.cos, threshold)
			case !attr.sameDecisive():
				// N03-P04-T05: the entry answers a different decisive
				// content than the lookup asks; the guard degrades it to a
				// self-healing miss. Correct regardless of geometry — but
				// recorded honestly: if the cosine were below the threshold,
				// the threshold guard alone would have sufficed.
				out.correct = true
				out.guard = fmt.Sprintf("decisive-content guard (T05: decisive stamps differ); threshold would %s (%.4f vs %.2f)",
					map[bool]string{true: "also reject", false: "not reject (sim above threshold — the guard decided)"}[out.cos < threshold], out.cos, threshold)
			case out.cos >= threshold+0.001:
				// Same tag, harness cosine above the threshold, still a miss:
				// pgvector sees the same float32 vectors, so this is a decision
				// (or harness-assumption) defect worth failing on.
				t.Errorf("%s: same-tag miss with harness cosine %.4f ≥ %.2f — measurement-blocking decision-path defect", p.ID, out.cos, threshold)
			default:
				out.correct = true
				out.guard = fmt.Sprintf("threshold guard (cos %.4f < %.2f, margin %.4f)", out.cos, threshold, threshold-out.cos)
			}
		}
		outcomes[p.ID] = out
	}

	// --- Confusion matrix ---------------------------------------------------
	type classCounts struct{ pairs, hitOK, missOK, falseHit, falseMiss int }
	order := []string{holdoutClassTrueDup, holdoutClassNearDate, holdoutClassNearNumber, holdoutClassNearAccess, holdoutClassNearEntity, holdoutClassCrossLang}
	counts := map[string]*classCounts{}
	for _, c := range order {
		counts[c] = &classCounts{}
	}
	for _, p := range corpus {
		o := outcomes[p.ID]
		c := counts[p.Class]
		c.pairs++
		switch {
		case o.correct && o.hit:
			c.hitOK++
		case o.correct && !o.hit:
			c.missOK++
		case o.falseHit:
			c.falseHit++
		case o.falseMis:
			c.falseMiss++
		}
	}

	t.Logf("HOLDOUT DECISION PATH: CacheService.LookupWithResult → Redis exact → pgvector ANN (SemanticCache.Lookup, cosine ≥ %.2f, ef 100) → OpenEntry+Matches → SpaceMatch(qualified embed_ver, threshold_ver) → DecisiveMatch(decisive_ver, decisive_fp) [T05]; embedder=holdout-ngram stub (char 3/4-gram FNV-1a, d=%d), ScriptQualifier ON", threshold, holdoutDim)
	t.Logf("HOLDOUT CONFUSION MATRIX (corpus=%d pairs, threshold=%.2f):", len(corpus), threshold)
	t.Logf("%-12s %5s %11s %12s %10s %11s", "class", "pairs", "hit=correct", "miss=correct", "FALSE-HIT", "false-miss")
	total := classCounts{}
	for _, c := range order {
		cc := counts[c]
		t.Logf("%-12s %5d %11d %12d %10d %11d", c, cc.pairs, cc.hitOK, cc.missOK, cc.falseHit, cc.falseMiss)
		total.pairs += cc.pairs
		total.hitOK += cc.hitOK
		total.missOK += cc.missOK
		total.falseHit += cc.falseHit
		total.falseMiss += cc.falseMiss
	}
	t.Logf("%-12s %5d %11d %12d %10d %11d", "TOTAL", total.pairs, total.hitOK, total.missOK, total.falseHit, total.falseMiss)

	// Per-pair transcript (stable order): the report's evidence lines.
	for _, p := range corpus {
		o := outcomes[p.ID]
		attr := attrOf[p.ID]
		status := "MISS(corr)"
		switch {
		case o.falseHit:
			status = "FALSE-HIT"
		case o.falseMis:
			status = "false-miss"
		case o.hit:
			status = "HIT(corr)"
		}
		t.Logf("PAIR %-14s %-11s %-9s sim=%s cos=%.4f tags=%s→%s margin=%s | %s",
			p.ID, p.Class, status,
			func() string {
				if o.hit {
					return fmt.Sprintf("%.4f/%s", o.sim, o.source)
				}
				return "  -   "
			}(),
			o.cos, attr.cachedTag, attr.lookupTag,
			func() string {
				if !o.hit && attr.cachedTag == attr.lookupTag {
					return fmt.Sprintf("%.4f", threshold-o.cos)
				}
				return "n/a"
			}(),
			p.Note)
	}

	// Structural invariants (the guarantees the stack MUST uphold regardless
	// of embedder geometry):
	for _, p := range corpus {
		o := outcomes[p.ID]
		if p.Class == holdoutClassCrossLang {
			assert.False(t, o.hit, "%s: cross-language reuse must be impossible (T03 space separation)", p.ID)
		}
		if strings.HasPrefix(p.Class, "near-") {
			assert.False(t, o.hit, "%s: decisive-content reuse must be impossible (T05 admission guard)", p.ID)
			assert.False(t, o.falseMis, "%s: a decisive-axis false miss means the T05 guard over-invalidates a genuinely-different-content pair", p.ID)
		}
	}

	// CARD NOTE (N03-P04-T05): with the decisive-content admission guard in
	// the path, false hits on the decisive-content axis are a HARD guarantee
	// (require.Zero) — T04 measured 10/14 there, every one now degrades to a
	// self-healing miss. The accepted residue on the miss side is exactly the
	// td-ru-ws formatting pair (TestHoldoutFormattingPairGeometry): a true
	// duplicate whose normalized JSON bytes legitimately differ, measured
	// below the threshold — the guard correctly leaves it alone (equal
	// stamps), and the path recomputes instead of serving. Both error
	// directions would still be reported loudly if they reappeared; the
	// counts above are the reproducible source for the T05 record.
	require.Zero(t, total.falseHit,
		"false hits on the decisive-content axis must be zero under the T05 guard (T04 measured 10)")
	require.Equal(t, 1, total.falseMiss,
		"the only accepted over-invalidation is the td-ru-ws formatting pair (self-healing, threshold-layer)")
	t.Logf("CARD NOTE: false hits (decisive-content axis) = %d (hard zero, T05 guard); false misses = %d (the td-ru-ws formatting artifact only) — see artifacts/internal-delivery-program/N03-P04/T05-record-20261025.md and T04-holdout-report-20261025.md", total.falseHit, total.falseMiss)
}
