import { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toCSV, downloadCSV } from './csv'

// Astra primitive: ChartCard. Accessibility contract for charts:
//   - the chart is announced as an image with a generated summary;
//   - the same data is available as an HTML table (chart = table, toggleable);
//   - units and timezone are labeled next to the title (never implied);
//   - Export CSV serializes exactly the table's data with proper escaping.

export interface ChartColumn<T> {
  key: keyof T & string
  label: string
  align?: 'left' | 'right'
  /** Formats the table/CSV cell (chart formatting may differ). */
  format?: (row: T) => string
  /**
   * Rich table-cell renderer (e.g. a drill-down link on the entity
   * name). Display only — CSV export always uses `format`/the raw value, so
   * the downloaded artifact stays plain data.
   */
  renderCell?: (row: T) => ReactNode
}

export interface ChartCardProps<T extends object> {
  title: string
  /** Chart element (recharts ResponsiveContainer). Rendered decorative — the
   *  data table is the accessible representation. */
  children: ReactNode
  data: T[]
  columns: ChartColumn<T>[]
  /** Physical unit of the plotted values, e.g. "USD". */
  unit?: string
  /** Timezone the labels are expressed in, e.g. "UTC". */
  timezone?: string
  /** File name for Export CSV (without extension). */
  filename?: string
}

export function ChartCard<T extends object>({ title, children, data, columns, unit, timezone, filename }: ChartCardProps<T>) {
  const { t } = useTranslation()
  const summary = data
    .slice(0, 3)
    .map(r => columns[0].key in r ? String((r as Record<string, unknown>)[columns[0].key]) : '')
    .join(', ')
  const ariaLabel =
    `${title}. ${t('chart.rows', { count: data.length })}` +
    (unit ? `, ${t('chart.valuesIn', { unit })}` : '') +
    (timezone ? `, ${t('chart.timesIn', { timezone })}` : '')
    + (summary ? `. ${t('chart.firstRows', { summary })}.` : '.')

  const exportCSV = () => {
    downloadCSV(
      `${filename ?? title.toLowerCase().replace(/\s+/g, '-')}.csv`,
      toCSV(
        columns.map(c => c.label),
        data.map(r => columns.map(c => (c.format ? c.format(r) : String((r as Record<string, unknown>)[c.key] ?? '')))),
      ),
    )
  }

  return (
    // Text-enlarge safe: min-w-0 + max-w-full so the chart and its
    // data table bound to the viewport and scroll locally when the root font
    // is enlarged, instead of pushing the document wider.
    <figure className="flex min-w-0 max-w-full flex-col gap-2">
      <figcaption className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-sm font-medium text-[color:var(--astra-ink)]">
          {title}
          {unit && <span className="ms-1 font-normal text-[color:var(--astra-text-muted)]">· {unit}</span>}
          {timezone && <span className="ms-1 font-normal text-[color:var(--astra-text-muted)]">· {timezone}</span>}
        </span>
        <button
          type="button"
          onClick={exportCSV}
          className="btn-secondary px-2 font-normal"
        >
          {t('common.exportCsv')}
        </button>
      </figcaption>
      {/* Text-enlarge safe: min-w-0 + overflow-hidden bounds the
          chart (and its Recharts tooltip) to the card width so an enlarged
          tooltip scrolls/clips locally instead of widening the document. */}
      <div role="img" aria-label={ariaLabel} className="relative min-w-0 max-w-full overflow-hidden">
        {children}
      </div>
      <details>
        <summary className="cursor-pointer text-xs font-medium text-[color:var(--astra-text-muted)]">{t('chart.dataTableSummary')}</summary>
        <div className="mt-2 max-h-64 w-full min-w-0 overflow-auto border border-[color:var(--astra-rule)]">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr>
                {columns.map(c => (
                  <th
                    key={c.key}
                    scope="col"
                    className={`whitespace-nowrap border-b border-[color:var(--astra-rule-strong)] px-2 py-1.5 text-[color:var(--astra-text-muted)] ${c.align === 'right' ? 'text-right' : 'text-start'}`}
                  >
                    {c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((r, i) => (
                <tr key={i}>
                  {columns.map(c => (
                    <td
                      key={c.key}
                      className={`border-b border-[color:var(--astra-rule)] px-2 py-1 text-[color:var(--astra-ink)] ${c.align === 'right' ? 'text-right' : ''}`}
                      style={{ fontVariantNumeric: 'tabular-nums' }}
                    >
                      {c.renderCell ? c.renderCell(r) : c.format ? c.format(r) : String((r as Record<string, unknown>)[c.key] ?? '')}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  )
}
