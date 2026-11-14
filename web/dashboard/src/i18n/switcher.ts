// Runtime locale switching over async (dynamically imported) locale
// bundles. The orchestration is dependency-injected (no i18next/vite imports
// here) so node --test can exercise the contract directly:
//
//   - rapid switches: the LAST requested locale wins; a load that resolves
//     after a newer request is stale and must NOT be applied (never brings an
//     old locale back);
//   - failed download: the app stays usable in the current language (en at
//     cold start) and the html lang/dir are reverted to the language that is
//     actually rendered — the attributes never lie about the content;
//   - a request never rejects: failures resolve to `false` for diagnostics.
//
// The html lang/dir are applied for the requested locale once the switch is
// APPLIED (bundle registered + language applied), so RTL geometry follows the
// rendered content rather than the load order.

export type SwitchableLocale = string

export interface LocaleSwitcherDeps {
  // Register a fetched bundle under (lng, 'translation').
  addBundle: (lng: SwitchableLocale, bundle: Record<string, unknown>) => void
  // Apply the language to the i18n runtime (fires languageChanged downstream).
  changeLanguage: (lng: SwitchableLocale) => Promise<unknown>
  // Language currently rendered by the i18n runtime.
  currentLanguage: () => SwitchableLocale
  // Apply html lang/dir for a locale (idempotent).
  applyHtml: (lng: SwitchableLocale) => void
  // Fetch the parsed translation bundle for a locale. May reject (network).
  loadBundle: (lng: SwitchableLocale) => Promise<Record<string, unknown>>
}

export interface LocaleSwitcher {
  // Request a locale switch. Resolves true when the requested locale is the
  // one applied to the runtime when the function finishes; false when the
  // request went stale (a newer switch superseded it) or the download failed.
  changeLocale: (lng: SwitchableLocale) => Promise<boolean>
  // Monotonic request generation — diagnostic for tests/races.
  generation: () => number
}

export function createLocaleSwitcher(deps: LocaleSwitcherDeps): LocaleSwitcher {
  let gen = 0

  async function changeLocale(lng: SwitchableLocale): Promise<boolean> {
    gen += 1
    const myGen = gen
    try {
      let bundle: Record<string, unknown>
      try {
        bundle = await deps.loadBundle(lng)
      } catch {
        // Failed download: keep the runtime on the language that actually
        // renders (the previous/current one) and make the html attributes
        // tell the truth about it. No retry loop here — a new changeLocale
        // call is the retry.
        if (myGen === gen) deps.applyHtml(deps.currentLanguage())
        return false
      }
      if (myGen !== gen) return false // stale load — a newer switch won
      deps.addBundle(lng, bundle)
      await deps.changeLanguage(lng)
      if (myGen !== gen) return false
      deps.applyHtml(lng)
      return true
    } catch {
      // changeLanguage/addBundle must not reject out of a fire-and-forget
      // bootstrap call; treat like a failed switch.
      if (myGen === gen) deps.applyHtml(deps.currentLanguage())
      return false
    }
  }

  return {
    changeLocale,
    generation: () => gen,
  }
}
