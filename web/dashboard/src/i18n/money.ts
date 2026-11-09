// TP-05: honest USD money rendering — pure core (no i18n import) so the
// locale/separator contract is unit-testable under `node --test`.
//
// All money the dashboard displays is USD by origin: backend `*_usd` fields
// and USD cents / 100. The org `currency` is a PRESENTATION code, not a
// conversion — the dashboard applies no FX (no rates/cache, see TP-05), so a
// non-USD presentation must never relabel USD amounts with a foreign symbol
// (that would invent a conversion). Instead the amount keeps its honest unit:
// the number is formatted with the active locale's conventions and an
// explicit `USD` code suffix ("12,34 USD" in ru). A USD presentation keeps
// the familiar currency form ("$12.34").
//
// Zero and unknown stay distinct here: 0 formats as "$0.00"/"0.00 USD";
// "unknown" is a caller concern (e.g. unpriced data renders the unknown
// state, never a zero amount).

/** The storage unit every dashboard money value is expressed in. */
export const MONEY_UNIT = 'USD'

export function formatUsdMoney(amount: number, presentationCurrency: string | undefined, locale: string): string {
  const cur =
    presentationCurrency && presentationCurrency.length === 3
      ? presentationCurrency.toUpperCase()
      : MONEY_UNIT
  // Per-request LLM costs live in the 1e-5 range: a real $0.000009 must not
  // collapse to "$0.00" (indistinguishable from free). Widen the fraction
  // digits whenever the 2-decimal view would round a nonzero amount to zero.
  const digits = amount !== 0 && Math.abs(amount) < 0.005 ? 6 : 2
  try {
    if (cur === MONEY_UNIT) {
      return new Intl.NumberFormat(locale, {
        style: 'currency',
        currency: MONEY_UNIT,
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      }).format(amount)
    }
    // Non-USD presentation: no FX exists, so the amount stays USD —
    // locale-correct number + explicit code, never the foreign symbol.
    const n = new Intl.NumberFormat(locale, {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    }).format(amount)
    return `${n} ${MONEY_UNIT}`
  } catch {
    // Unknown locale tag — degrade to a plain number with the honest unit
    // rather than throwing (presentation must not break the screen).
    return `${amount.toFixed(digits)} ${MONEY_UNIT}`
  }
}
