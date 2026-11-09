package cache

// N03-P04-T06: semantic-cache quality under a JOINT user scenario.
//
// T04 froze a near-duplicate corpus and measured the decision path one pair
// per org; T05 closed the false-hit axis with the decisive-content admission
// guard and accepted exactly one formatting false miss (td-ru-ws). The dc1
// detector has known residual collision classes (wave-19 acceptance
// findings F1-F6), and this card turns both facts into a standing quality
// contract:
//
//  1. A JOINT scenario: all pairs share ONE org/model, the way a single
//     user's workspace actually fills a cache. Every lookup lands in an ANN
//     candidate set of 30 rows, so attribution, guard order and cross-pair
//     leakage are exercised the way production behaves — T04/T05's one-row
//     orgs could not see this.
//  2. A confusion-matrix quality report (TP/FN/TN/FP per category) with
//     CONCRETE erroneous-reuse examples: every false hit must name the
//     served answer, similarity, decisive token sets and — crucially — the
//     documented dc2 class it belongs to. A false hit WITHOUT a documented
//     class is a defect (hard zero); a false miss is allowed only for the
//     formatting-artifact duplicate, mirroring T05's accepted residue.
//  3. A near-miss negative battery: structural near-* pairs (date, number,
//     access, entity) must MISS with an observable reason (the decisive-
//     content guard, named by its concrete token sets), independent of
//     embedder geometry — and the stub geometry is asserted to keep
//     admitting every near pair (cos >= 0.95), so the guard, not the
//     threshold, is what decides.
//
// The corpus reuses the T04/T05 holdout harness (holdoutEmbedder stub,
// holdoutAttribute, holdoutCosine, ScriptQualifier) unchanged — same
// geometry model, same attribution math — and extends it with the residual
// (dc2-blind) pair classes r-*. Residual pairs are REPORTED, not failed:
// their collisions are the recorded owner decision input for dc2 (fixing
// them requires a DecisiveContentVer bump, out of scope for this card).
// Every outcome is still attributed honestly in the report.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Joint-scenario corpus (fixed, deterministic, hand-written)
// ---------------------------------------------------------------------------

const (
	// n03p4t06OrgName: the ONE workspace every pair shares (the joint
	// scenario — the deliberate difference from T04/T05's per-pair orgs).
	n03p4t06OrgName = "n03p4t06-joint-workspace"
)

// n03p4t06DC2 describes the residual collision classes the dc1 detector
// cannot separate (wave-19 acceptance findings F1-F6). A false hit on a pair
// labeled with one of these is REPORTED as a concrete erroneous-reuse
// example — measurement input for a future detector version; a false hit
// with any other label is a defect.
var n03p4t06DC2 = map[string]string{
	"F1": "year-less day-month dates (15 марта): the day leaks into the number class, so same-digit dates keep one stamp",
	"F2": "slash / unpadded dotted dates (01/03/2025, 1.3.2025): not captured — slash forms keep only the year token, unpadded dotted runs are skipped",
	"F3": "ALL-CAPS acronyms (NASA/ESA): excluded from the entity class by design",
	"F4": "entity role swaps: the ordered fingerprint half covers numeric/date tokens only, so swapped names keep one stamp",
	"F5": "timezone designators (UTC/PST): all-caps tokens invisible to every decisive class",
	"F6": "comma vs space thousands grouping (1,240 vs 1 240): both canonicalize to the same number",
}

// n03p4t06Pair is one joint-scenario scenario. Unlike the holdout, members
// share one org: the lookup sees all 29 other cached rows in its ANN set.
type n03p4t06Pair struct {
	ID     string
	Class  string // true-dup | near-date | near-number | near-access | near-entity | cross-lang | other-topic
	Note   string // the decisive difference, for the report
	Cached string // prompt JSON written to the cache
	Lookup string // prompt JSON looked up afterwards
	Answer string // response sealed into the cached entry (unique per pair)

	ExpectHit      bool   // confusion-matrix label: should-hit
	ExpectSameHash bool   // members normalize to identical bytes (exact-layer pairs)
	Residual       bool   // documented dc2 collision class expected (stamp-blind by design)
	DC2Class       string // "F1".."F6" when Residual
	AllowMiss      bool   // documented formatting artifact: a should-hit pair whose miss is the accepted residue
}

// n03p4t06Prompt builds a chat body with a deterministic field order
// (reuses the holdout helper — same normalization both files).
var n03p4t06Prompt = holdoutPrompt

// n03p4t06Answer is a distinct response body per pair: any hit must serve
// EXACTLY this body, proving which question's answer was reused.
func n03p4t06Answer(id string) string {
	return fmt.Sprintf(`{"id":"cmpl-holdout-n03p4t06-%s","choices":[{"message":{"content":"answer for %s"}}]}`, id, id)
}

// n03p4t06SwapEntities swaps two quoted entities via placeholders so both
// change exactly once (the r-entity-swap residual class).
func n03p4t06SwapEntities(s, a, b string) string {
	step1 := strings.Replace(s, a, "@@A@@", 1)
	step2 := strings.Replace(step1, b, a, 1)
	return strings.Replace(step2, "@@A@@", b, 1)
}

// n03p4t06Corpus returns the frozen joint corpus: 30 pairs across seven
// classes — 3 true-dup, 20 structural should-miss, 7 documented-residual
// should-miss. Written once from the card's axis definition and the dc2
// review's class list; extended only, never tuned against outcomes.
func n03p4t06Corpus() []n03p4t06Pair {
	// --- true duplicates (should-hit) -------------------------------------
	enReliability := "Our platform reliability review is scheduled for Thursday. Please pull the availability dashboard for the checkout service, summarize the incident timeline from last week, and list the action items still owned by the infrastructure group."
	enOnCall := "Prepare the weekly on-call summary for the payments team: how many pages fired, which alerts were the noisiest, and whether the escalation policy needs tuning before the next rotation starts."
	ruLogistics := "Собери еженедельную сводку по логистике: сколько рейсов выполнено, сколько отменено из-за погоды, средняя задержка доставки и топ маршрутов с наибольшим числом опозданий. Сводка нужна к планёрке в пятницу."

	// --- structural near-date (should-miss, guard decides) ----------------
	enBackup := "Audit the database backups for the cluster whose baseline snapshot was taken on 2025-03-31: list the failed jobs since then, measure the restore time trend, and flag any snapshot older than the retention policy allows."
	enSettlement := "Reconcile the card settlement batch of March 15, 2025: the total settled amount, the number of declined transactions, the chargebacks opened within a week, and any merchant flagged for review by the risk engine."
	enChurn := "Compare the enterprise churn rate in Q1 2025 with the previous quarter, include net revenue retention for the same period, and list the accounts that downgraded their plan despite the renewal campaign."
	ruAccount := "Подготовь справку по расчётному счёту компании на 31.01.2025: входящий остаток, обороты за день, банковские комиссии и все отклонения от планового бюджета. Справка нужна для совета директоров."
	ruOffice := "Мы договорились встретиться 15 марта и обсудить переезд офиса: подготовь список вопросов по договору аренды, оценки от подрядчиков и черновик графика переезда на новую площадку."

	// --- residual near-date (should-miss, dc2-blind by design) ------------
	ruAbsence := "Собери статистику отсутствий сотрудников на 15 марта: сколько людей было на больничном, сколько в отпуске, сколько работало удалённо, и сравни с обычным днём недели."
	ruRegister := "Проверь отчёт по кассовым сменам за 01/03/2025: выручка по точкам, расхождения между сменами и возвраты, а также все аннуляции, оформленные старшим кассиром вручную."
	ruMaintenance := "Обнови план обслуживания серверов с даты 1.3.2025: какие окна уже использованы, какие пропущены, и что нужно перенести, чтобы не пересекаться с ночными копиями."
	ruSync := "Перенеси ежемесячный созвон с командой аналитики с 15:00 UTC на удобное время: проверь пересечения с регулярными встречами, предложи два свободных слота и черновик письма участникам."

	// --- structural near-number (should-miss, guard decides) --------------
	enUptime := "The uptime report for the payment gateway showed 99.95 percent last month. Recompute the trailing availability from the status history and say whether we are still inside the error budget for the quarter."
	enForecast := "The finance forecast assumed 45,200 dollars of compute spend for the analytics account; pull the actual bill, the top services by cost, and any jump above ten percent month over month."
	ruWarehouse := "Проверь остатки по артикулу A-1743 на основном складе: система показывает 1 240 штук, а в накладной поставщика указано другое число. Разбери движения за последние две недели и найди шаг, где возникло расхождение."
	ruCoffee := "Пересчитай средний чек по кофейне за неделю, если выручка составила 210 тысяч рублей при 12,5 тысячи покупок: покажи динамику по дням, сравни с прошлой неделей и выдели самые доходные часы."
	ruChurn := "Посчитай прогноз оттока для тарифа со ставкой удержания 0,5 в месяц: сколько клиентов останется через квартал, как изменится выручка и какие шаги удержания предложить маркетингу."

	// --- residual near-number (dc2-blind by design) -----------------------
	ruManifest := "Check the warehouse count for SKU B-2207: the system recorded 1,240 units, while the paper manifest shows a different figure; walk through the movements of the last two weeks and find the step where the mismatch appeared."

	// --- near-access (should-miss, guard decides) -------------------------
	// Same-scaffolding ACCESS-WORD edits: geometry admits the pair (like
	// every other near-* battery member), so the decisive guard — not the
	// threshold — is what must reject it. That is the leak scenario:
	// identical question shape, one access-level word apart.
	enCompensation := "Open the restricted compensation review spreadsheet for the infrastructure group and summarize the individual salary bands, the proposed raises and the employees flagged as flight risks."
	ruPayroll := "Покажи мои персональные начисления и удержания за прошлый месяц: оклад, премию, налоги, удержания по исполнительным листам и разбивку по строкам расчётного листка."
	enPricing := "Summarize the unannounced internal draft of the pricing memo: the new enterprise tiers, their launch discounts and the approval window."

	// --- structural near-entity (should-miss, guard decides) --------------
	enHelios := "List the still-open milestones of the Helios data-migration project, the owner of each milestone, the date each one last slipped, and the biggest blocker to raise at the steering committee."
	ruSupplier := "Собери историю поставок от ООО «Ромашка» за последний квартал: количество поставок, среднюю задержку, сумму штрафов за просрочку и рекомендацию по продлению контракта."
	enCustomer := "What is the current contract status for Acme Manufacturing: the renewal window, the annual contract value, the open support escalations, and the health score from the last customer success review?"

	// --- residual near-entity (dc2-blind by design) -----------------------
	ruPacking := "Сравни требования NASA и требования заказчика к упаковке оборудования для миссии наблюдения: какие пункты жёстче, где нужны дополнительные испытания, и составь таблицу отличий для инженеров."
	ruContracts := "Сравни условия договоров с ООО «Ромашка» и ООО «Лютик»: сроки оплаты, штрафы за просрочку, объёмы скидок и предложи, с кем продлевать контракт на следующий год."

	// --- cross-language (should-miss, qualifier-space guard decides) ------
	enVAT := "What is the filing deadline for the quarterly VAT return covering April, May and June 2025 for a small business registered in Spain, and what penalties apply for missing the deadline?"
	ruVAT := "Какой срок подачи квартальной декларации по НДС за апрель, май и июнь 2025 года для малого бизнеса, зарегистрированного в Испании, и какие штрафы за пропуск срока?"
	enInvestor := "Draft the monthly investor update: the key metrics, the hiring progress, the burn rate and the single biggest risk; keep it short and friendly for non-technical readers."
	ruInvestor := "Подготовь ежемесячный отчёт для инвесторов: ключевые метрики, прогресс найма, расход и главный риск; сделай коротко и понятным языком для не-технических читателей."

	// --- other-topic controls (should-miss, threshold guard decides) ------
	ruRoom := "Забронируй переговорную на два часа в четверг после обеда: проверь занятость комнат, выбери ту, где есть экран и доска, и отправь приглашение участникам синка по продукту."
	ru2FA := "Подскажи, как настроить двухфакторную аутентификацию для нового ноутбука: какие приложения поддерживаются, что делать при потере телефона и как восстановить доступ без кодов."
	enTranslate := "Translate the onboarding handbook paragraph into simple wording so that a new support agent can follow it without asking questions; keep the formatting plain and the steps short."
	enRewrite := "Rewrite the incident postmortem summary so that an external partner can read it without sensitive details; keep the timeline and the action items."

	return []n03p4t06Pair{
		// -- true duplicates -------------------------------------------------
		{
			ID: "td-en-byte", Class: holdoutClassTrueDup,
			Note:   "byte-identical prompt in the shared org (exact layer must serve it)",
			Cached: n03p4t06Prompt(enReliability), Lookup: n03p4t06Prompt(enReliability),
			Answer: n03p4t06Answer("td-en-byte"), ExpectHit: true, ExpectSameHash: true,
		},
		{
			ID: "td-en-keyorder", Class: holdoutClassTrueDup,
			Note:   "JSON key order only, different content than td-en-byte (normalization must equalize)",
			Cached: n03p4t06Prompt(enOnCall), Lookup: holdoutPromptKeyOrderSwapped(enOnCall),
			Answer: n03p4t06Answer("td-en-keyorder"), ExpectHit: true, ExpectSameHash: true,
		},
		{
			ID: "td-ru-fmt", Class: holdoutClassTrueDup,
			Note:   "same RU words, line breaks instead of comma spaces (hash differs, meaning identical; the accepted T05-style residue)",
			Cached: n03p4t06Prompt(ruLogistics), Lookup: n03p4t06Prompt(strings.ReplaceAll(ruLogistics, ", ", ",\n")),
			Answer: n03p4t06Answer("td-ru-fmt"), ExpectHit: true, AllowMiss: true,
		},

		// -- structural near-date ---------------------------------------------
		{
			ID: "nd-en-iso", Class: holdoutClassNearDate,
			Note:   "baseline snapshot 2025-03-31 → 2025-06-30 (ISO date)",
			Cached: n03p4t06Prompt(enBackup), Lookup: n03p4t06Prompt(strings.Replace(enBackup, "2025-03-31", "2025-06-30", 1)),
			Answer: n03p4t06Answer("nd-en-iso"),
		},
		{
			ID: "nd-en-longform", Class: holdoutClassNearDate,
			Note:   "settlement batch March 15, 2025 → March 29, 2025 (long-form date)",
			Cached: n03p4t06Prompt(enSettlement), Lookup: n03p4t06Prompt(strings.Replace(enSettlement, "March 15, 2025", "March 29, 2025", 1)),
			Answer: n03p4t06Answer("nd-en-longform"),
		},
		{
			ID: "nd-quarter", Class: holdoutClassNearDate,
			Note:   "churn window Q1 2025 → Q2 2025 (one-character quarter)",
			Cached: n03p4t06Prompt(enChurn), Lookup: n03p4t06Prompt(strings.Replace(enChurn, "Q1 2025", "Q2 2025", 1)),
			Answer: n03p4t06Answer("nd-quarter"),
		},
		{
			ID: "nd-ru-dotted", Class: holdoutClassNearDate,
			Note:   "справка на 31.01.2025 → 28.02.2025",
			Cached: n03p4t06Prompt(ruAccount), Lookup: n03p4t06Prompt(strings.Replace(ruAccount, "31.01.2025", "28.02.2025", 1)),
			Answer: n03p4t06Answer("nd-ru-dotted"),
		},
		{
			ID: "nd-ru-yearless-day", Class: holdoutClassNearDate,
			Note:   "встреча 15 марта → 16 марта (year-less: the day digit IS captured, as a number token)",
			Cached: n03p4t06Prompt(ruOffice), Lookup: n03p4t06Prompt(strings.Replace(ruOffice, "15 марта", "16 марта", 1)),
			Answer: n03p4t06Answer("nd-ru-yearless-day"),
		},

		// -- residual near-date (dc2-blind) ------------------------------------
		{
			ID: "r-yearless-month", Class: holdoutClassNearDate, Residual: true, DC2Class: "F1",
			Note:   "статистика на 15 марта → 15 июня (same digits, different month — dc1 sees only n:15 on both sides)",
			Cached: n03p4t06Prompt(ruAbsence), Lookup: n03p4t06Prompt(strings.Replace(ruAbsence, "15 марта", "15 июня", 1)),
			Answer: n03p4t06Answer("r-yearless-month"),
		},
		{
			ID: "r-slash-date", Class: holdoutClassNearDate, Residual: true, DC2Class: "F2",
			Note:   "смены за 01/03/2025 → 01/04/2025 (slash dates: only the year token survives)",
			Cached: n03p4t06Prompt(ruRegister), Lookup: n03p4t06Prompt(strings.Replace(ruRegister, "01/03/2025", "01/04/2025", 1)),
			Answer: n03p4t06Answer("r-slash-date"),
		},
		{
			ID: "r-unpadded-date", Class: holdoutClassNearDate, Residual: true, DC2Class: "F2",
			Note:   "обслуживание с 1.3.2025 → 1.4.2025 (unpadded dotted run is skipped entirely)",
			Cached: n03p4t06Prompt(ruMaintenance), Lookup: n03p4t06Prompt(strings.Replace(ruMaintenance, "1.3.2025", "1.4.2025", 1)),
			Answer: n03p4t06Answer("r-unpadded-date"),
		},
		{
			ID: "r-tz", Class: holdoutClassNearDate, Residual: true, DC2Class: "F5",
			Note:   "созвон 15:00 UTC → 15:00 PST (timezone designators invisible to every class)",
			Cached: n03p4t06Prompt(ruSync), Lookup: n03p4t06Prompt(strings.Replace(ruSync, "15:00 UTC", "15:00 PST", 1)),
			Answer: n03p4t06Answer("r-tz"),
		},

		// -- structural near-number --------------------------------------------
		{
			ID: "nn-en-decimal", Class: holdoutClassNearNumber,
			Note:   "uptime 99.95 → 99.59 percent (digit transposition)",
			Cached: n03p4t06Prompt(enUptime), Lookup: n03p4t06Prompt(strings.Replace(enUptime, "99.95 percent", "99.59 percent", 1)),
			Answer: n03p4t06Answer("nn-en-decimal"),
		},
		{
			ID: "nn-en-grouping", Class: holdoutClassNearNumber,
			Note:   "forecast 45,200 → 48,200 dollars (comma grouping)",
			Cached: n03p4t06Prompt(enForecast), Lookup: n03p4t06Prompt(strings.Replace(enForecast, "45,200 dollars", "48,200 dollars", 1)),
			Answer: n03p4t06Answer("nn-en-grouping"),
		},
		{
			ID: "nn-ru-space", Class: holdoutClassNearNumber,
			Note:   "остатки 1 240 → 1 420 штук (space grouping)",
			Cached: n03p4t06Prompt(ruWarehouse), Lookup: n03p4t06Prompt(strings.Replace(ruWarehouse, "1 240 штук", "1 420 штук", 1)),
			Answer: n03p4t06Answer("nn-ru-space"),
		},
		{
			ID: "nn-ru-comma-value", Class: holdoutClassNearNumber,
			Note:   "12,5 → 13,5 тысячи покупок (RU decimal comma carries the value)",
			Cached: n03p4t06Prompt(ruCoffee), Lookup: n03p4t06Prompt(strings.Replace(ruCoffee, "12,5 тысячи", "13,5 тысячи", 1)),
			Answer: n03p4t06Answer("nn-ru-comma-value"),
		},
		{
			ID: "nn-ru-comma-frac", Class: holdoutClassNearNumber,
			Note:   "удержание 0,5 → 0,7 в месяц (fractional RU decimal)",
			Cached: n03p4t06Prompt(ruChurn), Lookup: n03p4t06Prompt(strings.Replace(ruChurn, "0,5 в месяц", "0,7 в месяц", 1)),
			Answer: n03p4t06Answer("nn-ru-comma-frac"),
		},

		// -- residual near-number (dc2-blind) -----------------------------------
		{
			ID: "r-comma-grouping", Class: holdoutClassNearNumber, Residual: true, DC2Class: "F6",
			Note:   "1,240 units → 1 240 units (comma vs space grouping canonicalize to one number)",
			Cached: n03p4t06Prompt(ruManifest), Lookup: n03p4t06Prompt(strings.Replace(ruManifest, "1,240 units", "1 240 units", 1)),
			Answer: n03p4t06Answer("r-comma-grouping"),
		},

		// -- near-access ---------------------------------------------------------
		{
			ID: "na-en-marker", Class: holdoutClassNearAccess,
			Note:   "restricted → public compensation review (access-word edit, same scaffolding)",
			Cached: n03p4t06Prompt(enCompensation), Lookup: n03p4t06Prompt(strings.Replace(enCompensation, "restricted", "public", 1)),
			Answer: n03p4t06Answer("na-en-marker"),
		},
		{
			ID: "na-ru-personal", Class: holdoutClassNearAccess,
			Note:   "персональные → обезличенные начисления (access-word edit, same scaffolding)",
			Cached: n03p4t06Prompt(ruPayroll), Lookup: n03p4t06Prompt(strings.Replace(ruPayroll, "персональные", "обезличенные", 1)),
			Answer: n03p4t06Answer("na-ru-personal"),
		},
		{
			ID: "na-en-draft", Class: holdoutClassNearAccess,
			Note:   "unannounced → announced internal draft (access-word edit)",
			Cached: n03p4t06Prompt(enPricing), Lookup: n03p4t06Prompt(strings.Replace(enPricing, "unannounced", "announced", 1)),
			Answer: n03p4t06Answer("na-en-draft"),
		},

		// -- structural near-entity ----------------------------------------------
		{
			ID: "ne-en-project", Class: holdoutClassNearEntity,
			Note:   "project Helios → Selene (data-migration)",
			Cached: n03p4t06Prompt(enHelios), Lookup: n03p4t06Prompt(strings.Replace(enHelios, "Helios", "Selene", 1)),
			Answer: n03p4t06Answer("ne-en-project"),
		},
		{
			ID: "ne-ru-quoted", Class: holdoutClassNearEntity,
			Note:   "поставщик ООО «Ромашка» → ООО «Лютик»",
			Cached: n03p4t06Prompt(ruSupplier), Lookup: n03p4t06Prompt(strings.Replace(ruSupplier, "Ромашка", "Лютик", 1)),
			Answer: n03p4t06Answer("ne-ru-quoted"),
		},
		{
			ID: "ne-en-two-word", Class: holdoutClassNearEntity,
			Note:   "customer Acme Manufacturing → Zenith Robotics",
			Cached: n03p4t06Prompt(enCustomer), Lookup: n03p4t06Prompt(strings.Replace(enCustomer, "Acme Manufacturing", "Zenith Robotics", 1)),
			Answer: n03p4t06Answer("ne-en-two-word"),
		},

		// -- residual near-entity (dc2-blind) -------------------------------------
		{
			ID: "r-acronym", Class: holdoutClassNearEntity, Residual: true, DC2Class: "F3",
			Note:   "требования NASA → ESA (ALL-CAPS acronyms excluded from the entity class)",
			Cached: n03p4t06Prompt(ruPacking), Lookup: n03p4t06Prompt(strings.Replace(ruPacking, "NASA", "ESA", 1)),
			Answer: n03p4t06Answer("r-acronym"),
		},
		{
			ID: "r-entity-swap", Class: holdoutClassNearEntity, Residual: true, DC2Class: "F4",
			Note:   "«Ромашка»/«Лютик» traded places (multiset equal, ordered half is numeric-only)",
			Cached: n03p4t06Prompt(ruContracts), Lookup: n03p4t06Prompt(n03p4t06SwapEntities(ruContracts, "Ромашка", "Лютик")),
			Answer: n03p4t06Answer("r-entity-swap"),
		},

		// -- cross-language ---------------------------------------------------------
		{
			ID: "cl-vat", Class: holdoutClassCrossLang,
			Note:   "EN cached → RU translation near-duplicate (same deadline, different script tag)",
			Cached: n03p4t06Prompt(enVAT), Lookup: n03p4t06Prompt(ruVAT),
			Answer: n03p4t06Answer("cl-vat"),
		},
		{
			ID: "cl-investor", Class: holdoutClassCrossLang,
			Note:   "EN cached → RU translation near-duplicate (same brief, different script tag)",
			Cached: n03p4t06Prompt(enInvestor), Lookup: n03p4t06Prompt(ruInvestor),
			Answer: n03p4t06Answer("cl-investor"),
		},

		// -- other-topic controls (threshold must separate) ---------------------------
		{
			ID: "ot-ru-room", Class: "other-topic",
			Note:   "two different RU questions, stamp-less on both sides (threshold guard decides)",
			Cached: n03p4t06Prompt(ruRoom), Lookup: n03p4t06Prompt(ru2FA),
			Answer: n03p4t06Answer("ot-ru-room"),
		},
		{
			ID: "ot-en-translate", Class: "other-topic",
			Note:   "two different EN questions, stamp-less on both sides (threshold guard decides)",
			Cached: n03p4t06Prompt(enTranslate), Lookup: n03p4t06Prompt(enRewrite),
			Answer: n03p4t06Answer("ot-en-translate"),
		},
	}
}

// n03p4t06Attrs computes the harness-side attribution for every pair with
// the shared T04/T05 helpers (same derivation as both production paths).
func n03p4t06Attrs(stub holdoutEmbedder, corpus []n03p4t06Pair) map[string]holdoutPairAttribution {
	attrs := make(map[string]holdoutPairAttribution, len(corpus))
	for _, p := range corpus {
		attrs[p.ID] = holdoutAttribute(stub, p.Cached, p.Lookup)
	}
	return attrs
}

// n03p4t06TokenSet renders the decisive token set of a normalized prompt
// for the report (sorted, joined; ∅ when the detector extracted nothing).
func n03p4t06TokenSet(norm []byte) string {
	set, _ := extractDecisive(qualifierSourceText(norm))
	if len(set) == 0 {
		return "∅"
	}
	sort.Strings(set)
	return strings.Join(set, " ")
}

// ---------------------------------------------------------------------------
// Always-on unit tests (run in -short): corpus integrity + structural contract
// ---------------------------------------------------------------------------

// TestN03P04T06_CorpusIntegrity pins the corpus-level invariants the joint
// scenario depends on: unique answers (attribution), unique prompts (no
// shared rows), label consistency, and the tag/stamp geometry each class
// needs so exactly ONE guard is responsible for each should-miss.
func TestN03P04T06_CorpusIntegrity(t *testing.T) {
	stub := holdoutEmbedder{}
	seenAnswers := map[string]string{}
	seenCached := map[string]string{}
	seenLookup := map[string]string{}
	corpus := n03p4t06Corpus()
	attrs := n03p4t06Attrs(stub, corpus)

	for _, p := range corpus {
		t.Run(p.ID, func(t *testing.T) {
			require.NotEmpty(t, p.Cached)
			require.NotEmpty(t, p.Lookup)

			// Attribution uniqueness: in a shared org a duplicate answer or
			// duplicate prompt would make a hit unattributable.
			if owner, seen := seenAnswers[p.Answer]; seen {
				t.Fatalf("answer bodies must be unique: %s reuses %s", p.ID, owner)
			}
			seenAnswers[p.Answer] = p.ID
			if owner, seen := seenCached[p.Cached]; seen {
				t.Fatalf("cached prompts must be unique in the joint org: %s reuses %s", p.ID, owner)
			}
			seenCached[p.Cached] = p.ID
			if owner, seen := seenLookup[p.Lookup]; seen {
				t.Fatalf("lookup prompts must be unique: %s reuses %s", p.ID, owner)
			}
			seenLookup[p.Lookup] = p.ID

			attr := attrs[p.ID]

			// Exact-layer expectations.
			if p.ExpectSameHash {
				assert.Equal(t, attr.cachedHash, attr.lookupHash, "%s: normalization-equal pair must hash identically", p.ID)
			} else {
				assert.NotEqual(t, attr.cachedHash, attr.lookupHash, "%s: a decisive-content difference must survive normalization into distinct exact keys", p.ID)
			}

			// Residual labels must reference a documented dc2 class; nothing
			// else may carry one.
			if p.Residual {
				assert.Contains(t, n03p4t06DC2, p.DC2Class, "%s: residual pair must name a documented dc2 class", p.ID)
				assert.False(t, p.ExpectHit, "%s: residual pairs are should-miss by definition", p.ID)
			} else {
				assert.Empty(t, p.DC2Class, "%s: only residual pairs carry a dc2 class", p.ID)
			}

			// Qualifier-tag expectations: cross-language pairs must resolve
			// to DIFFERENT tags (T03 guarantee), same-language pairs to one.
			if p.Class == holdoutClassCrossLang {
				assert.NotEqual(t, attr.cachedTag, attr.lookupTag, "%s: cross-language pair must separate by qualifier tag", p.ID)
			} else {
				assert.Equal(t, attr.cachedTag, attr.lookupTag, "%s: same-language pair must share one qualifier tag", p.ID)
			}
			assert.NotEmpty(t, attr.cachedTag, "%s: prompts must classify to a script bucket", p.ID)
		})
	}
}

// TestN03P04T06_StructuralSeparationContract pins WHICH guard owns each
// should-miss, purely from text (no backend): decisive-axis structural
// pairs must differ in decisive stamps (DecisiveMatch decides regardless
// of geometry); residual pairs must carry EQUAL stamps (the documented dc1
// blindness — logged with the colliding token sets as dc2 evidence);
// other-topic pairs are stamp-less on both sides (threshold decides).
func TestN03P04T06_StructuralSeparationContract(t *testing.T) {
	stub := holdoutEmbedder{}
	corpus := n03p4t06Corpus()
	attrs := n03p4t06Attrs(stub, corpus)

	for _, p := range corpus {
		t.Run(p.ID, func(t *testing.T) {
			attr := attrs[p.ID]
			stampsEqual := attr.sameDecisive()

			switch {
			case p.ExpectHit && !p.AllowMiss:
				assert.True(t, stampsEqual, "%s: dc1 must never veto a true duplicate (byte/key-order exact pair)", p.ID)
			case p.AllowMiss:
				// The formatting artifact: identical meaning, different
				// normalized bytes. Stamps equal (nothing decisive differs);
				// only geometry can separate it — measured in the geometry
				// test, never asserted here.
				assert.True(t, stampsEqual, "%s: the formatting artifact must be stamp-identical", p.ID)
			case p.Residual:
				// DOCUMENTED dc1 blindness: the pair differs decisively to a
				// human, but the dc1 token sets collide. Log the colliding
				// sets — this line is the dc2 decision evidence.
				assert.True(t, stampsEqual, "%s: residual pair %s must collide at stamp level (else re-label as structural)", p.ID, p.DC2Class)
				normC := normalizeForCache([]byte(p.Cached))
				normL := normalizeForCache([]byte(p.Lookup))
				t.Logf("RESIDUAL %s [%s] stamps equal; cached tokens: %s | lookup tokens: %s | %s",
					p.ID, p.DC2Class, n03p4t06TokenSet(normC), n03p4t06TokenSet(normL), n03p4t06DC2[p.DC2Class])
			case p.Class == holdoutClassCrossLang:
				// Separation is the qualifier tag (asserted in integrity);
				// stamps may legitimately be equal — log which.
				t.Logf("CROSS-LANG %s tags %q→%q; stamps equal = %v (separation is the space guard)",
					p.ID, attr.cachedTag, attr.lookupTag, stampsEqual)
			case p.Class == "other-topic":
				// Stamp-less controls: equal (empty) stamps BY DESIGN, so the
				// threshold guard is the only separator — geometry must sit
				// below it (asserted in the geometry test).
				assert.True(t, stampsEqual, "%s: other-topic controls must be stamp-less on both sides (else they test the wrong guard)", p.ID)
			default:
				// Structural decisive-axis pair: the stamp MUST differ — the
				// guard's decision is geometry-independent.
				assert.False(t, stampsEqual, "%s: structural pair must separate by decisive stamp (geometry-independent)", p.ID)
				normC := normalizeForCache([]byte(p.Cached))
				normL := normalizeForCache([]byte(p.Lookup))
				t.Logf("STRUCTURAL %s separated by decisive guard; cached tokens: %s | lookup tokens: %s",
					p.ID, n03p4t06TokenSet(normC), n03p4t06TokenSet(normL))
			}
		})
	}
}

// TestN03P04T06_GeometryAdmitsNearMisses pins the stub geometry the guard
// contract rests on: every structural near-* pair sits at or above the
// admission threshold (so the DECISIVE guard, not the threshold, is what
// must reject it), every true byte/key-order duplicate embeds identically,
// other-topic controls sit below the threshold, and the formatting
// artifact stays a small divergence (logged honestly either way — if it
// clears the threshold the joint report will show a hit, which is fine).
func TestN03P04T06_GeometryAdmitsNearMisses(t *testing.T) {
	stub := holdoutEmbedder{}
	corpus := n03p4t06Corpus()
	attrs := n03p4t06Attrs(stub, corpus)
	threshold := float64(DefaultSimilarityThreshold)

	for _, p := range corpus {
		t.Run(p.ID, func(t *testing.T) {
			attr := attrs[p.ID]
			cos := holdoutCosine(attr.cachedVec, attr.lookupVec)

			switch {
			case p.ExpectSameHash:
				assert.InDelta(t, 1.0, cos, 1e-9, "%s: identical embedded bytes must score 1.0", p.ID)
			case p.AllowMiss:
				assert.Greater(t, cos, 0.90, "%s: the formatting divergence must stay a formatting artifact, not a topic change", p.ID)
				t.Logf("GEOMETRY %s cos=%.4f (threshold %.2f) — %s", p.ID, cos, threshold,
					map[bool]string{true: "will HIT (serves the true duplicate)", false: "will MISS (the accepted self-healing residue)"}[cos >= threshold])
			case strings.HasPrefix(p.Class, "near-") && !p.Residual:
				assert.GreaterOrEqual(t, cos, threshold, "%s: stub geometry must ADMIT the near pair (>= threshold) so the decisive guard — not the threshold — is what rejects it", p.ID)
				t.Logf("GEOMETRY %s cos=%.4f (admitted above %.2f; guard must decide)", p.ID, cos, threshold)
			case p.Residual:
				// Residual pairs: geometry ADMITS (else there is nothing to
				// report — the pair misses at the threshold and dc2 is moot
				// for it). Log the admission so the report can predict the
				// outcome.
				assert.GreaterOrEqual(t, cos, threshold, "%s: residual pair must be geometrically admitted for the dc2 residue to manifest at all", p.ID)
				t.Logf("GEOMETRY %s cos=%.4f (admitted; stamps equal → expect HIT = documented %s residue)", p.ID, cos, p.DC2Class)
			case p.Class == "other-topic":
				assert.Less(t, cos, threshold, "%s: other-topic controls must sit below the threshold (they test the threshold guard)", p.ID)
				t.Logf("GEOMETRY %s cos=%.4f (below %.2f; threshold decides)", p.ID, cos, threshold)
			default: // cross-lang
				t.Logf("GEOMETRY %s cos=%.4f (cross-script vectors are far apart under the stub; the tag guard decides regardless)", p.ID, cos)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Docker-backed joint replay: the confusion matrix over the real path
// ---------------------------------------------------------------------------

// n03p4t06Outcome records one replayed pair in the joint org.
type n03p4t06Outcome struct {
	hit      bool
	source   string  // exact | pg_exact | semantic ("" on miss)
	sim      float32 // similarity reported by the real path on hits
	cos      float64 // harness-side own-twin cosine (reporting only)
	nearest  string  // harness-side nearest same-tag cached row for the lookup
	nearestC float64 // its cosine
	guard    string  // who decided (miss reason / hit note)
	class    string  // TP | FN | TN | FP | DEFECT
}

// n03p4t06ReuseExample is one concrete erroneous-reuse (or false-miss)
// line for the quality report.
type n03p4t06ReuseExample struct {
	PairID   string
	Class    string
	DC2Class string
	Sim      float32
	Cos      float64
	Cached   string
	Lookup   string
	DecC     string
	DecL     string
	Note     string
}

// TestN03P04T06_JointScenarioQualityReport replays the whole frozen corpus
// through the REAL production decision path — with all 30 entries sharing
// ONE org, the way a real workspace fills a cache — and prints the
// confusion-matrix quality report with concrete erroneous-reuse examples.
// Docker-backed (testdb/redisContainer) like the holdout; skips in -short.
// Run:
//
//	go test ./pkg/cache -run 'TestN03P04T06_JointScenarioQualityReport' -v
//
// The printed report is the reproducible source of
// artifacts/internal-delivery-program/N03-P04/T06-record-20261026.md.
func TestN03P04T06_JointScenarioQualityReport(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	stub := holdoutEmbedder{}
	svc := NewCacheService(ctx, pool, rdb, stub, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)

	corpus := n03p4t06Corpus()
	attrs := n03p4t06Attrs(stub, corpus)

	// Write phase: ONE shared org (the joint scenario), the REAL write path.
	orgID := seedCacheOrg(t, pool, n03p4t06OrgName, true, "semantic")
	for _, p := range corpus {
		require.NoError(t, svc.Write(ctx, RouteIdentity{OrgID: orgID, Model: holdoutModel}, []byte(p.Cached), json.RawMessage(p.Answer), 10, 5),
			"%s: write must succeed", p.ID)
	}
	require.True(t, svc.writer.Stop(), "the writer must drain before any lookup")

	// Provenance receipt: every row must carry the qualifier-extended space
	// version, the admission stamp and the decisive-content stamp this
	// configuration resolves — the identities SpaceMatch/DecisiveMatch
	// compare against during the lookups below.
	store := NewStore(pool)
	for _, p := range corpus {
		attr := attrs[p.ID]
		ri := RouteIdentity{OrgID: orgID, Model: holdoutModel}.Resolved()
		entry, err := store.GetExact(ctx, ri.OrgID, ri.Model, attr.cachedHash, ri.Version)
		require.NoError(t, err, p.ID)
		require.NotNil(t, entry, "%s: the writer must have persisted a row in the shared org", p.ID)
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

	// Lookup phase: the REAL decision path decides; the harness observes and
	// attributes. In the joint org a miss reason is reported against the
	// harness-side nearest same-tag row (SpaceMatch restricts service to one
	// qualifier tag, so only same-tag rows are ever servable).
	threshold := float64(DefaultSimilarityThreshold)
	nearestSameTag := func(tag string, vec []float32) (string, float64) {
		bestID, bestCos := "", -1.0
		for _, q := range corpus {
			qa := attrs[q.ID]
			if qa.cachedTag != tag {
				continue
			}
			if c := holdoutCosine(qa.cachedVec, vec); c > bestCos {
				bestID, bestCos = q.ID, c
			}
		}
		return bestID, bestCos
	}

	outcomes := make(map[string]n03p4t06Outcome, len(corpus))
	var reuse []n03p4t06ReuseExample  // documented erroneous reuses (FP)
	var missed []n03p4t06ReuseExample // false misses (FN)
	defects := 0

	for _, p := range corpus {
		attr := attrs[p.ID]
		hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: holdoutModel}, []byte(p.Lookup))
		require.NoError(t, err, "%s: a joint lookup must never error", p.ID)

		out := n03p4t06Outcome{cos: holdoutCosine(attr.cachedVec, attr.lookupVec)}
		out.nearest, out.nearestC = nearestSameTag(attr.lookupTag, attr.lookupVec)

		switch {
		case hit != nil:
			out.hit, out.source, out.sim = true, hit.SourceType, hit.Similarity
			// A hit must serve THIS pair's cached answer — a different body
			// would be cross-pair leakage (a structural defect, not a count).
			require.JSONEq(t, p.Answer, string(hit.Data),
				"%s: the served body must be the pair's own cached answer (cross-pair leakage is a defect, not a confusion count)", p.ID)

			switch {
			case p.ExpectHit:
				out.class, out.guard = "TP", fmt.Sprintf("served own answer via %s (sim %.4f)", out.source, out.sim)
			case p.Residual:
				// Documented erroneous reuse: REPORT with its dc2 class —
				// this line feeds the owner's dc2 decision.
				out.class = "FP"
				out.guard = fmt.Sprintf("NONE — stamps equal (dc2 class %s: %s); threshold %.2f passed at sim %.4f",
					p.DC2Class, n03p4t06DC2[p.DC2Class], threshold, out.sim)
				reuse = append(reuse, n03p4t06ReuseExample{
					PairID: p.ID, Class: p.Class, DC2Class: p.DC2Class, Sim: out.sim, Cos: out.cos,
					Cached: p.Cached, Lookup: p.Lookup,
					DecC: n03p4t06TokenSet(normalizeForCache([]byte(p.Cached))),
					DecL: n03p4t06TokenSet(normalizeForCache([]byte(p.Lookup))),
					Note: p.Note,
				})
			default:
				// A false hit WITHOUT a documented class: a defect.
				out.class = "DEFECT"
				defects++
				out.guard = fmt.Sprintf("NONE — no documented dc2 class covers this hit (sim %.4f ≥ %.2f)", out.sim, threshold)
				t.Errorf("%s: should-miss pair HIT (%s, sim=%.4f) with NO documented dc2 class — decision-path defect",
					p.ID, out.source, out.sim)
			}

		default: // miss
			nearestNote := fmt.Sprintf("harness nearest same-tag row=%s cos=%.4f", out.nearest, out.nearestC)
			switch {
			case p.ExpectHit && !p.AllowMiss:
				out.class = "DEFECT"
				defects++
				out.guard = fmt.Sprintf("over-invalidation — %s", nearestNote)
				t.Errorf("%s: byte/key-order true duplicate MISSED in the joint org — decision-path defect", p.ID)
			case p.AllowMiss:
				// The accepted formatting residue (T05's td-ru-ws analog).
				out.class = "FN"
				out.guard = fmt.Sprintf("threshold guard (own-twin cos %.4f < %.2f) — accepted formatting residue; %s", out.cos, threshold, nearestNote)
				missed = append(missed, n03p4t06ReuseExample{
					PairID: p.ID, Class: p.Class, Cos: out.cos, Cached: p.Cached, Lookup: p.Lookup, Note: p.Note,
				})
			case p.Class == holdoutClassCrossLang:
				out.class = "TN"
				out.guard = fmt.Sprintf("qualifier-space guard (SpaceMatch: own row tag %q ≠ lookup tag %q); %s",
					attr.cachedTag, attr.lookupTag, nearestNote)
			case p.Residual:
				// A residual pair that MISSED anyway (threshold happened to
				// reject): honest TN — the dc2 residue did not manifest for
				// this pair under this geometry.
				out.class = "TN"
				out.guard = fmt.Sprintf("threshold guard rejected a stamp-equal entry (cos %.4f < %.2f) — dc2 residue did not manifest; %s",
					out.cos, threshold, nearestNote)
			default:
				out.class = "TN"
				out.guard = fmt.Sprintf("decisive-content guard (DecisiveMatch: stamps differ; own-twin cos %.4f); %s", out.cos, nearestNote)
			}
		}
		outcomes[p.ID] = out
	}

	// --- Quality report ------------------------------------------------------
	classOrder := []string{holdoutClassTrueDup, holdoutClassNearDate, holdoutClassNearNumber,
		holdoutClassNearAccess, holdoutClassNearEntity, holdoutClassCrossLang, "other-topic"}
	type catCounts struct{ pairs, tp, fn, tn, fp, defects int }
	counts := map[string]*catCounts{}
	for _, c := range classOrder {
		counts[c] = &catCounts{}
	}
	for _, p := range corpus {
		cc := counts[p.Class]
		cc.pairs++
		switch outcomes[p.ID].class {
		case "TP":
			cc.tp++
		case "FN":
			cc.fn++
		case "TN":
			cc.tn++
		case "FP":
			cc.fp++
		case "DEFECT":
			cc.defects++
		}
	}

	t.Logf("N03-P04-T06 JOINT SCENARIO: CacheService.LookupWithResult → Redis exact → pg_exact → pgvector ANN (SemanticCache.Lookup, cosine ≥ %.2f, ef 100, ONE candidate) → Provenance.Matches → SpaceMatch(qualified embed_ver, threshold_ver) → DecisiveMatch(dc1, decisive_fp); org=%s (ALL %d pairs share it), model=%s, embedder=holdout-ngram stub, ScriptQualifier ON",
		threshold, n03p4t06OrgName, len(corpus), holdoutModel)
	t.Logf("N03-P04-T06 QUALITY REPORT (corpus=%d pairs, threshold=%.2f):", len(corpus), threshold)
	t.Logf("%-14s %5s %4s %4s %4s %4s %8s", "category", "pairs", "TP", "FN", "TN", "FP", "DEFECT")
	total := catCounts{}
	for _, c := range classOrder {
		cc := counts[c]
		t.Logf("%-14s %5d %4d %4d %4d %4d %8d", c, cc.pairs, cc.tp, cc.fn, cc.tn, cc.fp, cc.defects)
		total.pairs += cc.pairs
		total.tp += cc.tp
		total.fn += cc.fn
		total.tn += cc.tn
		total.fp += cc.fp
		total.defects += cc.defects
	}
	t.Logf("%-14s %5d %4d %4d %4d %4d %8d", "TOTAL", total.pairs, total.tp, total.fn, total.tn, total.fp, total.defects)

	// Per-pair transcript (stable order): the record's evidence lines.
	for _, p := range corpus {
		o := outcomes[p.ID]
		attr := attrs[p.ID]
		simStr := "  -   "
		if o.hit {
			simStr = fmt.Sprintf("%.4f/%s", o.sim, o.source)
		}
		t.Logf("PAIR %-17s %-11s %-6s sim=%s cos=%.4f tags=%s→%s nearest=%s(%.4f) | %s",
			p.ID, p.Class, o.class, simStr, o.cos, attr.cachedTag, attr.lookupTag, o.nearest, o.nearestC, o.guard)
	}

	if len(reuse) > 0 {
		t.Logf("ERRONEOUS REUSE EXAMPLES (documented dc2 residue — owner decision input, NOT defects):")
		for _, ex := range reuse {
			t.Logf("  REUSE [%s | %s | %s] sim=%.4f cos=%.4f\n    cached  : %s\n    lookup  : %s\n    decisive cached: %s\n    decisive lookup: %s\n    why     : %s",
				ex.PairID, ex.Class, ex.DC2Class, ex.Sim, ex.Cos, ex.Cached, ex.Lookup, ex.DecC, ex.DecL, ex.Note)
		}
	} else {
		t.Logf("ERRONEOUS REUSE EXAMPLES: none (no documented dc2 residue manifested under this geometry)")
	}
	if len(missed) > 0 {
		t.Logf("FALSE MISSES (accepted formatting residue):")
		for _, ex := range missed {
			t.Logf("  MISS [%s | %s] cos=%.4f | %s", ex.PairID, ex.Class, ex.Cos, ex.Note)
		}
	}

	// --- Hard guarantees (card contract) --------------------------------------
	require.Zero(t, total.defects,
		"every false hit must carry a documented dc2 class, and byte/key-order true duplicates must hit — defects found")
	require.Equal(t, len(corpus), total.pairs,
		"report totals must cover the corpus exactly")
	for _, p := range corpus {
		o := outcomes[p.ID]
		if p.Class == holdoutClassCrossLang {
			assert.False(t, o.hit, "%s: cross-language reuse must be impossible (T03 space separation)", p.ID)
		}
		if strings.HasPrefix(p.Class, "near-") && !p.Residual {
			assert.False(t, o.hit, "%s: structural decisive-content reuse must be impossible (T05 admission guard)", p.ID)
		}
		if o.class == "FN" {
			assert.True(t, p.AllowMiss, "%s: the only accepted false miss is the formatting artifact", p.ID)
		}
	}
	t.Logf("CARD NOTE (N03-P04-T06): defects=%d (hard zero); documented erroneous reuses=%d (dc2 decision input); false misses=%d (formatting artifact only) — joint single-org scenario, T04/T05 guarantees hold with 30-row ANN candidate sets",
		total.defects, len(reuse), len(missed))
}
