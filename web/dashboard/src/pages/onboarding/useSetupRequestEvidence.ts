import { useEffect, useState } from 'react'
import { listRequests } from '../../api/requests'

export type SetupRequestEntryState = 'idle' | 'checking' | 'invalid'

// CUI-02: verify the setup-request identity for THIS org. The id comes only
// from the URL (`request` param - the wizard entry control writes it there).
// listRequests with an exact requestId collapses to that one org-scoped
// record, so a foreign org, a typo or a not-yet-persisted id yields no row
// and no link - the identity is revalidated on every org/param change (no
// cross-tenant carryover, no list-position or timestamp inference).
export function useSetupRequestEvidence(org: string, requestIdParam: string): {
  evidenceRequest: string | null
  requestEntry: string
  setRequestEntry: (value: string) => void
  entryState: SetupRequestEntryState
} {
  const [evidenceRequest, setEvidenceRequest] = useState<string | null>(null)
  // The entry control's draft + its verification outcome (invalid shows the
  // not-found feedback; a confirmed id renders the evidence link).
  const [requestEntry, setRequestEntry] = useState('')
  const [entryState, setEntryState] = useState<SetupRequestEntryState>('idle')

  useEffect(() => {
    setEvidenceRequest(null)
    const id = requestIdParam.trim()
    if (!org || !id) { setEntryState('idle'); return }
    let cancelled = false
    setEntryState('checking')
    void (async () => {
      const res = await listRequests({ orgId: org, page: 1, pageSize: 1, requestId: id })
      if (cancelled) return
      if (res?.data?.some(r => r.request_id === id)) { setEvidenceRequest(id); setEntryState('idle') }
      else setEntryState('invalid')
    })().catch(() => { if (!cancelled) setEntryState('invalid') })
    return () => { cancelled = true }
  }, [org, requestIdParam])

  return { evidenceRequest, requestEntry, setRequestEntry, entryState }
}
