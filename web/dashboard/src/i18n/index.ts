import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from './en.json'
import { buildPseudo } from './pseudo'
import { createLocaleSwitcher, type LocaleSwitcher } from './switcher'

// Dashboard internationalization scaffold.
// Only the fallback locale (`en`) ships in the entry bundle; the seven
// machine-translated locales are dynamically imported on demand (one Vite
// chunk per locale). The active locale's chunk is fetched at boot and applied
// when it lands — the screen renders useful `en` content meanwhile and is
// never hidden behind a loading gate.
//
// - `en` is the canonical source of truth (the seven machine-translated
//   locales are each flagged needs-review).
// - `pseudo` is a QA-only pseudo-locale that wraps every string in «…» and
//   stretches it by a fixed factor. It is used by the pseudo-localization gate
//   (eslint i18next/no-literal-string on the screens, see eslint.config.js)
//   and by Playwright specs. It is DERIVED from `en` only when a QA request
//   selects it (?locale=pseudo) — it is never built or shipped for a normal
//   load, and pseudo text must NEVER ship to a real locale.
//
// The locale is selected from ?locale= on the static preview (the harness
// never sets it in production), falling back to en.

// The seven machine-translated locales (each needs-review —
// see docs/i18n/glossary.md). `en` remains
// the canonical source of truth; a real locale is only registered here once
// its translation file lands, so the locale switch never offers a broken
// locale (the same invariant as the site's docusaurus `locales` list).
export const LOCALES = ['en', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar'] as const
export type Locale = (typeof LOCALES)[number]

// html lang/dir per locale. RTL (ar) is registered here; html attributes are
// applied synchronously at boot for the requested locale (so RTL geometry is
// correct from the first paint) and re-applied whenever a language change is
// actually applied.
const LOCALE_HTML: Record<Locale | 'pseudo', { lang: string; dir: 'ltr' | 'rtl' }> = {
  en: { lang: 'en', dir: 'ltr' },
  ja: { lang: 'ja', dir: 'ltr' },
  ko: { lang: 'ko', dir: 'ltr' },
  hi: { lang: 'hi', dir: 'ltr' },
  id: { lang: 'id', dir: 'ltr' },
  'pt-BR': { lang: 'pt-BR', dir: 'ltr' },
  es: { lang: 'es', dir: 'ltr' },
  ar: { lang: 'ar', dir: 'rtl' },
  pseudo: { lang: 'en', dir: 'ltr' },
}

// One dynamic chunk per locale. `en` is intentionally NOT here — it is
// statically imported above because the runtime needs it synchronously as the
// fallbackLng (and the cold start renders with it until the active locale's
// chunk lands).
const LOCALE_LOADERS: Record<Exclude<Locale, 'en'>, () => Promise<{ default: Record<string, unknown> }>> = {
  ja: () => import('./ja.json'),
  ko: () => import('./ko.json'),
  hi: () => import('./hi.json'),
  id: () => import('./id.json'),
  'pt-BR': () => import('./pt-BR.json'),
  es: () => import('./es.json'),
  ar: () => import('./ar.json'),
}

const SWITCHABLE = new Set<string>([...LOCALES, 'pseudo'])

async function loadBundle(lng: string): Promise<Record<string, unknown>> {
  if (lng === 'en') return en
  if (lng === 'pseudo') return buildPseudo(en as unknown as Record<string, unknown>)
  const loader = LOCALE_LOADERS[lng as Exclude<Locale, 'en'>]
  if (!loader) throw new Error(`no bundle loader for locale ${lng}`)
  return (await loader()).default
}

function initialLocale(): Locale | 'pseudo' {
  try {
    // Hash-routed app: the locale query lives in the hash fragment
    // (e.g. #overview?locale=pseudo) — window.location.search is empty for
    // hash routes. The search string is also checked so plain URLs keep
    // working (?locale=pseudo#page).
    const hash = window.location.hash
    const inHash = hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : ''
    const p = new URLSearchParams(inHash).get('locale')
      ?? new URLSearchParams(window.location.search).get('locale')
    if (p === 'pseudo') return 'pseudo'
    if (LOCALES.includes(p as Locale)) return p as Locale
  } catch {
    // Non-browser environment — fall through.
  }
  return 'en'
}

function applyHtmlLocale(lng: Locale | 'pseudo' | string) {
  try {
    const known = (LOCALES as readonly string[]).includes(lng) || lng === 'pseudo'
      ? (lng as Locale | 'pseudo')
      : 'en'
    const { lang, dir } = LOCALE_HTML[known]
    document.documentElement.lang = lang
    document.documentElement.dir = dir
  } catch {
    // Non-browser environment.
  }
}

const initial = initialLocale()

// Entry resources hold ONLY the fallback locale (+ pseudo when a QA
// request selected it — derived from en on the spot, never for normal loads).
const resources: Record<string, { translation: Record<string, unknown> }> = {
  en: { translation: en as unknown as Record<string, unknown> },
}
if (initial === 'pseudo') resources.pseudo = { translation: buildPseudo(en as unknown as Record<string, unknown>) }

void i18n.use(initReactI18next).init({
  resources,
  // The runtime always STARTS on a synchronously available language (`en`,
  // or pseudo for a QA request) and switches to the requested locale when its
  // chunk lands — the first paint is useful content, never a blank screen.
  lng: initial === 'pseudo' ? 'pseudo' : 'en',
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
  // Unknown keys fall back to the key itself; the lint gate catches those at
  // build time, so a missing key is a CI failure, not a silent runtime gap.
  parseMissingKeyHandler: (k: string) => `[missing:${k}]`,
  // Language changes are pre-loaded via the switcher (bundle
  // registered BEFORE changeLanguage), so nothing ever waits on i18next —
  // there is no Suspense boundary and the screen must never be hidden.
  react: { useSuspense: false },
})

// Generation-guarded locale switching (rapid switch → last request
// wins; stale load never resurrects an old locale; failed download keeps the
// app on the currently rendered language with truthful html attributes).
const switcher: LocaleSwitcher = createLocaleSwitcher({
  addBundle: (lng, bundle) => {
    i18n.addResourceBundle(lng, 'translation', bundle, true, true)
  },
  changeLanguage: (lng) => i18n.changeLanguage(lng),
  currentLanguage: () => i18n.language,
  applyHtml: applyHtmlLocale,
  loadBundle,
})

// Runtime locale switch (the URL query remains the cold-start selector).
// Resolves true when THIS request is the one that got applied.
export function changeLocale(lng: string): Promise<boolean> {
  if (!SWITCHABLE.has(lng)) return Promise.resolve(false)
  return switcher.changeLocale(lng)
}

applyHtmlLocale(initial)
i18n.on('languageChanged', (lng: string) => {
  applyHtmlLocale(lng)
})

// Boot: fetch + apply the requested locale when it is not synchronously
// available. Fire-and-forget by design (the en fallback renders meanwhile);
// failures keep the dashboard usable in en.
if (initial !== 'en' && initial !== 'pseudo') {
  void switcher.changeLocale(initial)
}

export default i18n
