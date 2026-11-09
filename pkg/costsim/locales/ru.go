package locales

// Russian (ru) audit-report render templates — machine translation, needs
// review (I18N-12). Terminology follows docs/i18n/glossary.md:
//   - "lineage" → «линия происхождения» (not «родословная»)
//   - "audit"   → «аудит» (cost/quality audit, not security audit)
//   - "sovereign" → «суверенность»
//
// Headings are stored numbered (mdNum*) because both the markdown and HTML
// renderers need "1. …" — the HTML <h2> keeps the number. Interpolation tokens
// (%s, %d, %.1f%%) are preserved exactly. Bullet labels carry no leading "- "
// so the same label renders correctly as a markdown bullet and an HTML <li>.

func init() {
	register(Catalog{
		lang: "ru",
		strs: map[string]string{
			"docTitle":      "Yabanin — аудит расходов",
			"generated":     "_сформировано: %s_",
			"insuffBanner":  "> **Недостаточная выборка.** %d запросов за %s. Приведённые ниже числа ориентировочные и статистически ненадёжны.",
			"source":        "Источник: `%s`",
			"pricingBlk":    "Источник цен: %s\n\nВерсия: `%s`\n\nНа дату: %s\n\n%s\n\n",
			"simUnavail":    "> **Симуляция недоступна:** %s",
			"unknownWindow": "неизвестное окно",

			"htmlInsuffBanner": "<div class=\"banner\"><strong>Недостаточная выборка.</strong> %d запросов за %s. Приведённые числа ориентировочные и статистически ненадёжны.</div>",
			"htmlSource":       "<p>Источник: <code>%s</code></p>",
			"htmlPricingBlk":   "<p>Источник цен: %s</p><p>Версия: <code style=\"overflow-wrap:anywhere\">%s</code></p><p>На дату: %s</p><p>%s</p>",
			"htmlSimUnavail":   "<p class=\"banner\">Симуляция недоступна: %s</p>",
			"htmlUnknown":      `<span class="unknown">Неизвестно</span>`,
			"htmlScrollSuffix": " — прокручивается по горизонтали",

			"summaryHeading":     "Сводка",
			"summaryNum":         "1.",
			"summaryRequests":    "Запросы: %d",
			"summaryTotalCost":   "Итоговая стоимость: %s (вход %s, выход %s)",
			"summaryUnpriced":    "Запросы без цены (неизвестная цена, исключены из сумм $): %d",
			"summaryWindow":      "Окно: %s",
			"modelHead":          "| Модель | Запросы | Стоимость | Доля | Без цены |",
			"providerHead":       "| Провайдер | Запросы | Доля |",
			"yes":                "да",
			"modelTableLabel":    "Топ-модели",
			"providerTableLabel": "Топ-провайдеры",

			"findingsHeading": "Что обнаружено",
			"findingsNum":     "2.",
			"noFindings":      "Найденных превышений порога для этой выборки нет.",

			"cacheHeading":      "Симуляция кэша (%s)",
			"cacheNum":          "3.",
			"cacheHitRate":      "Попадания: %.1f%%",
			"cacheTokensAvoid":  "Токенов сэкономлено: %d",
			"cacheDollarsAvoid": "Сэкономлено: %s",
			"cacheCaveat":       "_Примечание: %s._",
			"cacheModelHead":    "| Модель | Запросы | Попадания |",
			"cacheTableLabel":   "Попадания кэша по моделям",

			"routingHeading":      "Симуляция маршрутизации (%s)",
			"routingNum":          "4.",
			"routingClassHead":    "| Класс | Запросы |",
			"routingOnly":         "Только маршрутизация (все запросы): %s",
			"routingOnMisses":     "Маршрутизация на промахах (боевой порядок): %s",
			"routingUnpricedDrop": "Отброшено целей без цены: %d",
			"routingCombined":     "**Итоговая экономия (кэш + маршрутизация на промахах): %s** (пересечение %s не подсчитано дважды)",
			"routingTableLabel":   "Распределение классов маршрутизации",

			"qualityHeading":        "Качество данных",
			"qualityNum":            "5.",
			"qualityParsed":         "Разобрано: %d, пропущено: %d",
			"qualityDenominator":    "Знаменатель инжеста: %d строк (разобранные + пропущенные)",
			"qualityCap":            "Лимит инжеста: %d записей",
			"qualityRealTokens":     "Строки с реальным числом токенов: %.1f%%",
			"qualityTimestamps":     "Строки с отметками времени: %.1f%%",
			"qualityUnpriced":       "Запросы без цены: %d",
			"qualityUnpricedModels": "Модели без цены: %s",

			"recsHeading": "Рекомендации",
			"recsNum":     "6.",
			"noRecs":      "Рекомендаций для этой выборки не сработало.",
		},
	})
}
