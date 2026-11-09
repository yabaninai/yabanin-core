// I18N-11 frontend ICU formatters.
//
// The Go backend (pkg/i18n) holds the canonical CLDR value formatters for
// server-side text (webhook messages, audit reports). The browser does the
// same job with the platform ICU via Intl, so currency/number/date rendering
// is locale-correct in both places without duplicating CLDR data here.
//
// All of these read the *applied* org's presentation settings (currency +
// timezone) plus the active UI locale, so a single org switch re-renders
// every amount and date in that org's currency and timezone.

import i18n from './index'
import { formatDateIn, formatDateTimeIn } from './date'
import { formatUsdMoney } from './money'

export const DEFAULT_CURRENCY = 'USD'
export const DEFAULT_TIMEZONE = 'UTC'

/** The active UI locale tag (e.g. "ja", "pt-BR"); falls back to "en". */
export function uiLocale(): string {
  return i18n.language || 'en'
}

/**
 * Format a USD amount as a money string in the active UI locale.
 * `amount` is in *currency units* (dollars), NOT cents.
 *
 * TP-05: every money value the dashboard renders is USD by origin
 * (`*_usd` / USD cents). The `currency` argument is the org's presentation
 * code — a non-USD code is NOT a conversion (no FX is applied), so the
 * amount keeps its honest unit: a locale-formatted number with an explicit
 * `USD` suffix ("12,34 USD" in ru). A USD presentation renders the familiar
 * "$12.34". See money.ts for the pure core and its unit tests.
 */
export function formatMoney(amount: number, currency?: string): string {
  return formatUsdMoney(amount, currency, uiLocale())
}

/** Format a plain number (counts, percentages) with the locale's grouping. */
export function formatNumber(value: number): string {
  try {
    return new Intl.NumberFormat(uiLocale()).format(value)
  } catch {
    return String(value)
  }
}

/**
 * Format an instant (ISO string or Date) as a localized date in the org's
 * timezone. Empty/unknown timezone falls back to UTC. A zero or unparseable
 * instant (year < 2000) renders as "—" (IMP-11), never as "Jan 1, 1".
 */
export function formatDate(value: string | Date, timezone?: string): string {
  return formatDateIn(uiLocale(), value, timezone)
}

/**
 * Format an instant as a localized date+time in the org's timezone, with the
 * same zero/invalid guard as formatDate.
 */
export function formatDateTime(value: string | Date, timezone?: string): string {
  return formatDateTimeIn(uiLocale(), value, timezone)
}
