import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { revealExchange, type RequestDetail } from '../api/requests'

function question(raw: RequestDetail['upstream_request']): string | undefined {
  if (!raw) return undefined
  let body = raw
  if (typeof raw === 'string') {
    try { body = JSON.parse(raw) } catch { return raw }
  }
  if (body && typeof body === 'object' && 'messages' in body && Array.isArray(body.messages)) {
    const msg = [...body.messages].reverse().find(m => m?.role === 'user')
    if (typeof msg?.content === 'string') return msg.content
  }
  return JSON.stringify(body, null, 2)
}

// Parent keys this component to the exact selected row; closing the drawer,
// enabling privacy, or switching rows discards the disclosed content.
export function RequestExchange({org, id, rowKeys}: {org: string; id: string; rowKeys: string[]}) {
  const { t } = useTranslation()
  const [data, setData] = useState<RequestDetail | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const flight = useRef<AbortController | null>(null)
  useEffect(() => () => flight.current?.abort(), [])
  async function show() {
    if (flight.current) return
    const ctrl = new AbortController()
    flight.current = ctrl
    setBusy(true); setError('')
    try {
      const result = await revealExchange(org, id, rowKeys, ctrl.signal)
      if (!ctrl.signal.aborted) setData(result)
    } catch (e) {
      if (!ctrl.signal.aborted) setError(e instanceof Error ? e.message : t('states.failedToLoad'))
    } finally {
      flight.current = null
      if (!ctrl.signal.aborted) setBusy(false)
    }
  }
  return <section className="flex flex-col gap-2" data-testid="request-exchange">
    <button type="button" className="btn-secondary self-start" disabled={busy}
      onClick={() => data ? setData(null) : void show()}>
      {busy ? t('states.loading') : data ? t('common.close') : t('explorer.showExchange')}
    </button>
    {error && <span role="alert">{error}</span>}
    {data && <dl>
      <dt>{t('explorer.detailBodyNote')} · {t('explorer.detailSent')}</dt>
      <dd>{data.upstream_request && data.upstream_request !== 'null'
        ? <pre data-testid="upstream-request-body" className="max-h-80 overflow-auto whitespace-pre-wrap break-all p-2 text-xs">{typeof data.upstream_request === 'string' ? data.upstream_request : JSON.stringify(data.upstream_request, null, 2)}</pre>
        : <span>{t('explorer.detailBodyNoteText')}</span>}</dd>
      <dt>{t('explorer.detailSent')}</dt><dd className="whitespace-pre-wrap break-words">{question(data.upstream_request) || '—'}</dd>
      <dt>{t('explorer.detailAnswer')}</dt><dd className="whitespace-pre-wrap break-words">{data.response_view?.content || (data.response ? JSON.stringify(data.response, null, 2) : '—')}</dd>
      {data.upstream_response && data.upstream_response !== 'null' && <dd><details>
        <summary>{t('explorer.detailModelResponse')}</summary>
        <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all p-2 text-xs">{typeof data.upstream_response === 'string' ? data.upstream_response : JSON.stringify(data.upstream_response, null, 2)}</pre>
      </details></dd>}
      {!!data.tool_call_invocations?.length && <><dt>{t('explorer.detailToolCalls')}</dt><dd><ol>
        {data.tool_call_invocations.map(tc => <li key={tc.seq}><code>{tc.tool_name}</code>
          <pre className="whitespace-pre-wrap break-all">{tc.arguments}</pre></li>)}
      </ol></dd></>}
    </dl>}
  </section>
}
