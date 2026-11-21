// Canonical org-presentation defaults. Leaf module (no i18n runtime
// imports) so node:test can load the presentation contract without the
// browser-only i18n barrel; format.ts re-exports them for compatibility.

/** ISO-4217 fallback when an org carries no currency setting. */
export const DEFAULT_CURRENCY = 'USD'

/** IANA fallback when an org carries no timezone setting. */
export const DEFAULT_TIMEZONE = 'UTC'
