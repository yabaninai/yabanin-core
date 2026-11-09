import React, { lazy, Suspense } from 'react'

// Load the chart library only when a page has data to visualize.
// The app-level Suspense boundary provides an accessible loading state;
// the local boundary below additionally reserves each chart's box with a
// fixed min-height fallback, so a late chunk arrival cannot shift the
// layout (UI-contract #12: waterfall improvement without CLS). The a11y
// contract is unchanged — ChartCard still pairs the decorative chart
// with the toggleable data table (ASTR-10).
export const ChartFallback = () => (
  <div
    aria-hidden="true"
    className="flex min-h-[220px] w-full items-center justify-center rounded border border-dashed border-[color:var(--astra-rule)] text-xs text-[color:var(--astra-text-muted)]"
  >
    …
  </div>
)

const AsyncBarChart = lazy(() => import('./index').then(m => ({ default: m.BarChart })))
const AsyncLineChart = lazy(() => import('./index').then(m => ({ default: m.LineChart })))
const AsyncPieChartSmall = lazy(() => import('./index').then(m => ({ default: m.PieChartSmall })))
const AsyncAnalyticsSeriesChart = lazy(() => import('./index').then(m => ({ default: m.AnalyticsSeriesChart })))

// Type-only re-exports: erased at build time, so the lazy boundary stays the
// only runtime import path for the chart bundle.
export type { AnalyticsSeries, AnalyticsPointClick } from './index'

export const BarChart = (props: React.ComponentProps<typeof AsyncBarChart>) => (
  <Suspense fallback={<ChartFallback />}>
    <AsyncBarChart {...props} />
  </Suspense>
)

export const LineChart = (props: React.ComponentProps<typeof AsyncLineChart>) => (
  <Suspense fallback={<ChartFallback />}>
    <AsyncLineChart {...props} />
  </Suspense>
)

export const AnalyticsSeriesChart = (props: React.ComponentProps<typeof AsyncAnalyticsSeriesChart>) => (
  <Suspense fallback={<ChartFallback />}>
    <AsyncAnalyticsSeriesChart {...props} />
  </Suspense>
)

export const PieChartSmall = (props: React.ComponentProps<typeof AsyncPieChartSmall>) => (
  <Suspense fallback={<ChartFallback />}>
    <AsyncPieChartSmall {...props} />
  </Suspense>
)
