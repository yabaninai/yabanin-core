import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { firstRequestLink } from '../../lib/onboarding'
import type { SetupRequestEntryState } from './useSetupRequestEvidence'

interface SetupRequestEvidenceProps {
  org: string
  evidenceRequest: string | null
  requestEntry: string
  setRequestEntry: (value: string) => void
  entryState: SetupRequestEntryState
  requestIdParam: string
  setRequestIdParam: (id: string) => void
  retryCheck: () => void
}

// CUI-02: the ONE operator action for the setup-request identity -
// rendered in BOTH the pending steps view and the completed (allSet)
// view, so a plain reopen of a completed org can still enter or correct
// the id. The operator pastes the X-Request-ID their client's response
// carried; the exact org-scoped persisted read validates it; the
// confirmed id rides the onboarding URL (`request` param) so
// reload/resume keeps it. Never derived from list position or
// timestamps. A failed lookup is not a no-match: the unavailable state
// offers an honest retry through this same control.
export function SetupRequestEvidence(props: SetupRequestEvidenceProps): ReactNode {
  const { t } = useTranslation()
  return (
    <>
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          const id = props.requestEntry.trim()
          if (!id) return
          // A changed id rides the URL param (the reload/resume contract).
          // Re-verifying the SAME id must still re-run the org-scoped
          // lookup — an unchanged param alone would not re-trigger the
          // effect — so it takes the explicit retry path.
          if (id === props.requestIdParam.trim()) props.retryCheck()
          else props.setRequestIdParam(id)
        }}
      >
        <label htmlFor="welcome-setup-request-input" className="sr-only">
          {t('welcome.setupRequestIdLabel')}
        </label>
        <input
          id="welcome-setup-request-input"
          data-testid="welcome-setup-request-input"
          className="input min-h-[44px] max-w-[24rem] flex-1 font-mono text-xs"
          placeholder={t('welcome.setupRequestIdPlaceholder')}
          value={props.requestEntry}
          onChange={(e) => props.setRequestEntry(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <button type="submit" className="btn-secondary min-h-[44px]" data-testid="welcome-setup-request-verify">
          {t('welcome.setupRequestIdVerify')}
        </button>
      </form>
      {props.entryState === 'invalid' && (
        <p className="text-sm" role="alert" data-testid="welcome-setup-request-invalid">
          {t('welcome.setupRequestNotFound')}
        </p>
      )}
      {props.entryState === 'unavailable' && (
        <p className="text-sm" role="alert" data-testid="welcome-setup-request-unavailable">
          {t('welcome.setupRequestUnavailable')}
        </p>
      )}
      {props.evidenceRequest && (
        <a href={firstRequestLink(props.org, props.evidenceRequest)} className="btn-secondary w-fit min-h-[44px]" data-testid="welcome-first-request-link">
          {t('welcome.viewFirstRequest')}
        </a>
      )}
    </>
  )
}
