import { useTranslation } from 'react-i18next'

// prefix (the brand already names the product) and no repeated segment: the
// section and the page are always distinct labels resolved from the nav
// table at render time, so a locale switch re-renders them.

export function Breadcrumbs({ sectionKey, pageKey }: { sectionKey: string; pageKey: string }) {
  const { t } = useTranslation()
  // «Раздел / Страница» collapses to the page alone when the section and the
  // page share one label (e.g. Overview) — a repeated segment is noise.
  const section = t(sectionKey)
  const page = t(pageKey)
  if (section === page) {
    return (
      <nav aria-label={t('app.breadcrumb')} className="px-4 pt-3 text-xs text-[color:var(--astra-text-muted)] md:px-6">
        <ol className="flex flex-wrap gap-2">
          <li aria-current="page" className="text-[color:var(--astra-ink)]">{page}</li>
        </ol>
      </nav>
    )
  }
  return (
    <nav aria-label={t('app.breadcrumb')} className="px-4 pt-3 text-xs text-[color:var(--astra-text-muted)] md:px-6">
      <ol className="flex flex-wrap gap-2">
        <li>
          <span>{section}</span>
          <span aria-hidden="true"> /</span>
        </li>
        <li aria-current="page" className="text-[color:var(--astra-ink)]">{page}</li>
      </ol>
    </nav>
  )
}
