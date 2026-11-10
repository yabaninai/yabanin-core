import type { UnitSpendLine } from '../api/currencies.ts'

export function labelSpendLines(lines: UnitSpendLine[]) {
  let usdIndex = 0
  return lines.map((line, index) => {
    let labelKey: string | undefined
    if (line.unit === 'USD') {
      // The API orders actual and counterfactual USD; both can be exact zero or unknown.
      labelKey = ['budgets.unitsSpend.actualCost', 'budgets.unitsSpend.counterfactualCost'][usdIndex++]
    } else {
      labelKey = ({
        credits: 'budgets.unitsSpend.creditsSpent',
        tokens: 'budgets.unitsSpend.tokensUsed',
        gCO2e: 'budgets.unitsSpend.carbonEstimate',
      } as Record<string, string>)[line.unit]
    }
    return { line, labelKey, id: `${line.unit}-${index}` }
  })
}

export function formatUnitAmount(amount: number | null, locale: string): string | null {
  if (amount === null || !Number.isFinite(amount)) return null
  return new Intl.NumberFormat(locale, { maximumSignificantDigits: 10 }).format(amount)
}
