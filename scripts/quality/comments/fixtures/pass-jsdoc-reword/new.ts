/**
 * Formats a cents amount into the org's currency string. Never render more
 * than two fraction digits.
 */
export function money(cents: number, currency: string): string {
  return new Intl.NumberFormat('en', { style: 'currency', currency }).format(cents / 100)
}
