import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { loginNextUrl, onUnauthorized } from '../../api/transport'

// per 401 response; the first one swaps the whole shell for a full-screen
// paper notice — the session has ended, sign in again. The sign-in link
// carries the current deep link (path + query + hash, e.g. #keys?org=…) as
// `next`, so the server returns the operator to the same screen after login.

export function SessionGate({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [expired, setExpired] = useState(false)
  const signInRef = useRef<HTMLAnchorElement>(null)
  useEffect(() => onUnauthorized(() => setExpired(true)), [])
  // Keyboard access: when the gate appears, focus lands on the one action.
  useEffect(() => {
    if (expired) signInRef.current?.focus()
  }, [expired])
  if (!expired) return <>{children}</>
  return (
    <div
      role="alertdialog"
      aria-labelledby="session-gate-title"
      aria-describedby="session-gate-message"
      className="fixed inset-0 z-50 flex items-center justify-center bg-[color:var(--astra-paper)] px-4"
    >
      <div className="astra-panel flex w-full max-w-md flex-col gap-2 px-6 py-8">
        <span className="flex items-center gap-2 text-base font-semibold text-[color:var(--astra-ink)]">
          <span aria-hidden="true" style={{ color: 'var(--astra-warning)' }}>△</span>
          <span id="session-gate-title">{t('session.expiredTitle')}</span>
        </span>
        <p id="session-gate-message" className="text-sm text-[color:var(--astra-text-muted)]">
          {t('session.expiredMessage')}
        </p>
        <a ref={signInRef} href={loginNextUrl(window.location)} className="btn-primary mt-2 w-fit">
          {t('session.signIn')}
        </a>
      </div>
    </div>
  )
}
