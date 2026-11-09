// node-testable without the i18n runtime; format.ts binds the active UI
// locale on top).
//
// The journal must never render the zero/placeholder instant as a real date
// ("Jan 1, 1"): a pre-2000 (Go zero time is year 1) or unparseable value
// renders as an em dash instead.

export const INVALID_DATE = '—'

// A date is renderable only when it parses and is not a pre-2000 placeholder.
export function renderableDate(value: string | Date): Date | null {
  const d = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(d.getTime())) return null
  if (d.getUTCFullYear() < 2000) return null
  return d
}

function timeZoneOr(fallback: string, timezone?: string): string {
  return timezone && timezone.length > 0 ? timezone : fallback
}

/** Localized medium date; zero/invalid input renders as INVALID_DATE. */
export function formatDateIn(
  locale: string,
  value: string | Date,
  timezone?: string,
): string {
  const tz = timeZoneOr('UTC', timezone)
  const d = renderableDate(value)
  if (!d) return INVALID_DATE
  try {
    return new Intl.DateTimeFormat(locale, {
      dateStyle: 'medium',
      timeZone: tz,
    }).format(d)
  } catch {
    return d.toISOString().slice(0, 10)
  }
}

/** Localized medium date+time; zero/invalid input renders as INVALID_DATE. */
export function formatDateTimeIn(
  locale: string,
  value: string | Date,
  timezone?: string,
): string {
  const tz = timeZoneOr('UTC', timezone)
  const d = renderableDate(value)
  if (!d) return INVALID_DATE
  try {
    return new Intl.DateTimeFormat(locale, {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone: tz,
    }).format(d)
  } catch {
    return d.toISOString()
  }
}
