import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CircleUserRound, Languages, LogOut } from 'lucide-react'
import { sendMutation } from '../../api/transport'
import { resetMeCache, usePermissions } from '../../hooks/usePermissions'
import { changeLocale, LOCALES } from '../../i18n'
import type { ShellScopeController } from '../../hooks/useGlobalScope'
import type { MeOrganization } from '../../hooks/usePermissions'

// runtime language switcher (AF-12 locales), and sign-out via the CSRF-protected
// swaps for the signed-out gate (App) — the server cleared the session cookie.
//
// Honesty rules: a failed sign-out request keeps the menu open with an inline
// error (the session may still be alive — never fake a signed-out state);
// the real backend answers the POST with a redirect-to-login HTML body, which
// is a COMPLETED sign-out (the transport's JSON parse fails on it — treated
// as success here, everything else is an error).

const LOCALE_LABEL_KEYS: Record<string, string> = {
  en: 'userMenu.lang.en',
  ja: 'userMenu.lang.ja',
  ko: 'userMenu.lang.ko',
  hi: 'userMenu.lang.hi',
  id: 'userMenu.lang.id',
  'pt-BR': 'userMenu.lang.ptBR',
  es: 'userMenu.lang.es',
  ar: 'userMenu.lang.ar',
}

function orgRole(memberships: MeOrganization[] | undefined, orgId: string): string {
  if (!memberships || memberships.length === 0) return ''
  const current = memberships.find(o => o.id === orgId)
  return (current ?? memberships[0]).role ?? ''
}

export function UserMenu({ scope, onSignedOut }: { scope: ShellScopeController; onSignedOut: () => void }) {
  const { t, i18n } = useTranslation()
  const perms = usePermissions()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [failed, setFailed] = useState(false)
  const rootRef = useRef<HTMLDivElement | null>(null)
  const triggerRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    if (!open) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        setOpen(false)
        triggerRef.current?.focus()
      }
    }
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('pointerdown', onPointerDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('pointerdown', onPointerDown)
    }
  }, [open])

  const signOut = async () => {
    setBusy(true)
    setFailed(false)
    try {
      await sendMutation('/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      })
    } catch (error) {
      // A SyntaxError means the server ANSWERED (redirect to the login page —
      // non-JSON body): the session is over. Anything else never reached it.
      if (!(error instanceof SyntaxError)) {
        setFailed(true)
        setBusy(false)
        return
      }
    }
    resetMeCache()
    onSignedOut()
  }

  const email = perms.me?.email ?? ''
  const role = perms.loading
    ? ''
    : perms.isRoot
      ? t('userMenu.roleRoot')
      : orgRole(perms.me?.organizations, scope.org)
  const currentLocale = LOCALES.includes(i18n.language as never) ? i18n.language : 'en'

  return (
    <div ref={rootRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={t('userMenu.open')}
        onClick={() => { setOpen(o => !o); setFailed(false) }}
        className="inline-flex min-h-[44px] min-w-[44px] items-center justify-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]"
      >
        <CircleUserRound size={20} aria-hidden="true" />
      </button>

      {open && (
        <div
          role="menu"
          aria-label={t('userMenu.open')}
          className="absolute end-0 z-30 mt-2 w-64 rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] p-1 shadow-lg"
        >
          <div className="min-w-0 px-3 pb-2 pt-2">
            {/* The identity is data, not UI copy — rendered verbatim. */}
            <p className="truncate text-sm font-semibold text-[color:var(--astra-ink)]" data-testid="user-menu-email">{email || perms.me?.name || '—'}</p>
            {role && <p className="truncate text-xs text-[color:var(--astra-text-muted)]" data-testid="user-menu-role">{role}</p>}
          </div>

          <label className="flex min-h-[44px] items-center gap-2 border-t border-[color:var(--astra-rule)] px-3 text-sm">
            <Languages size={14} aria-hidden="true" className="shrink-0 text-[color:var(--astra-text-muted)]" />
            <span className="min-w-0 flex-1 truncate text-[color:var(--astra-text-muted)]">{t('userMenu.language')}</span>
            <select
              value={currentLocale}
              aria-label={t('userMenu.language')}
              onChange={e => void changeLocale(e.target.value)}
              className="control w-32"
            >
              {LOCALES.map(l => (
                <option key={l} value={l}>{t(LOCALE_LABEL_KEYS[l]!)}</option>
              ))}
            </select>
          </label>

          {failed && (
            <p role="alert" className="border-t border-[color:var(--astra-rule)] px-3 py-1.5 text-xs text-[color:var(--astra-danger)]">
              {t('userMenu.signOutFailed')}
            </p>
          )}

          <button
            type="button"
            role="menuitem"
            disabled={busy}
            onClick={() => void signOut()}
            className="mt-1 flex min-h-[44px] w-full items-center gap-2 border-t border-[color:var(--astra-rule)] px-3 text-start text-sm text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] disabled:opacity-50"
          >
            <LogOut size={14} aria-hidden="true" className="shrink-0 text-[color:var(--astra-text-muted)]" />
            {t('userMenu.signOut')}
          </button>
        </div>
      )}
    </div>
  )
}
